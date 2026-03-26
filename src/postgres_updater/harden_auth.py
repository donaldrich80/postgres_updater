from __future__ import annotations

import argparse
import re
from datetime import datetime
from pathlib import Path

import psycopg

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


def log(message: str) -> None:
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{stamp}] {message}", flush=True)


def build_dsn(section: dict[str, object]) -> str:
    if "dsn" in section and isinstance(section["dsn"], str):
        return section["dsn"]
    host = str(section.get("host", "127.0.0.1"))
    port = int(section.get("port", 5432))
    database = str(section.get("database", "postgres"))
    user = str(section.get("user", "postgres"))
    password = str(section.get("password", ""))
    sslmode = str(section.get("sslmode", "prefer"))
    return (
        f"host={host} port={port} dbname={database} user={user} "
        f"password={password} sslmode={sslmode}"
    )


def load_dsns(config_path: Path) -> list[tuple[str, str]]:
    config = tomllib.loads(config_path.read_text())
    source = config.get("source", {})
    target = config.get("target", {})
    dsns: list[tuple[str, str]] = []
    if isinstance(source, dict):
        dsns.append(("source", build_dsn(source)))
    if isinstance(target, dict):
        dsns.append(("target", build_dsn(target)))
    return dsns


def pick_live_dsn(candidates: list[tuple[str, str]]) -> tuple[str, str]:
    errors: list[str] = []
    for label, dsn in candidates:
        try:
            with psycopg.connect(dsn):
                return label, dsn
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{label}: {exc}")
    raise RuntimeError("Could not connect to any configured server: " + " | ".join(errors))


def toml_key(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def load_password_map(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    data = tomllib.loads(path.read_text())
    passwords = data.get("passwords", {})
    if not isinstance(passwords, dict):
        raise RuntimeError(f"Invalid password map: [passwords] table missing in {path}")
    result: dict[str, str] = {}
    for role, password in passwords.items():
        if not isinstance(role, str) or not isinstance(password, str):
            raise RuntimeError(f"Invalid password map entry for role {role!r} in {path}")
        if password.strip():
            result[role] = password
    return result


def write_template(path: Path, roles: list[str]) -> None:
    lines = [
        "# Fill plaintext passwords used by each application DB user.",
        "# This file is local-only and should not be committed.",
        "[passwords]",
    ]
    for role in roles:
        lines.append(f"{toml_key(role)} = \"\"")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")


def fetch_md5_roles(conn: psycopg.Connection) -> list[str]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT rolname
            FROM pg_authid
            WHERE rolcanlogin
              AND rolpassword LIKE 'md5%%'
            ORDER BY rolname
            """
        )
        return [row[0] for row in cur.fetchall()]


def patch_hba_method(conn: psycopg.Connection, from_method: str, to_method: str) -> tuple[bool, str]:
    with conn.cursor() as cur:
        cur.execute("CREATE EXTENSION IF NOT EXISTS adminpack")
        cur.execute("SHOW hba_file")
        hba_file = str(cur.fetchone()[0])
        cur.execute("SELECT pg_read_file(%s)", (hba_file,))
        current_hba = str(cur.fetchone()[0])
        pattern = rf"(?m)^(\s*host\s+all\s+all\s+all\s+){re.escape(from_method)}(\s*(?:#.*)?)$"
        updated_hba = re.sub(pattern, rf"\1{to_method}\2", current_hba)
        if updated_hba == current_hba:
            return False, hba_file

        backup = f"{hba_file}.bak_codex_harden_auth_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        cur.execute("SELECT pg_file_write(%s, %s, false)", (backup, current_hba))
        cur.execute("SELECT pg_file_unlink(%s)", (hba_file,))
        cur.execute("SELECT pg_file_write(%s, %s, false)", (hba_file, updated_hba))
        cur.execute("SELECT pg_reload_conf()")
        cur.fetchone()
    return True, backup


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Harden PostgreSQL auth after cutover: convert MD5 role hashes to SCRAM and enforce SCRAM in pg_hba."
    )
    parser.add_argument("--config", default="data/config.toml", help="Path to config TOML file.")
    parser.add_argument(
        "--password-map",
        default="data/role_passwords.toml",
        help="Path to TOML file containing plaintext role passwords under [passwords].",
    )
    args = parser.parse_args()

    config_path = Path(args.config)
    password_map_path = Path(args.password_map)
    if not config_path.exists():
        raise RuntimeError(f"Config file not found: {config_path}")

    label, dsn = pick_live_dsn(load_dsns(config_path))
    log(f"Connected to live server using [{label}] DSN.")

    with psycopg.connect(dsn, autocommit=True) as conn:
        md5_roles = fetch_md5_roles(conn)
        if not md5_roles:
            log("No MD5 login roles found.")
            changed, backup = patch_hba_method(conn, "md5", "scram-sha-256")
            if changed:
                log(f"Updated pg_hba host all/all rule to scram-sha-256. Backup: {backup}")
            else:
                log("No host all/all md5 rule found to change.")
            return 0

        passwords = load_password_map(password_map_path)
        missing = [role for role in md5_roles if role not in passwords]
        if missing:
            write_template(password_map_path, md5_roles)
            sample = ", ".join(missing[:10])
            log(f"Missing plaintext passwords for {len(missing)} role(s): {sample}")
            log(f"Wrote/updated template: {password_map_path}")
            return 2

        with conn.cursor() as cur:
            cur.execute("ALTER SYSTEM SET password_encryption = 'scram-sha-256'")
            cur.execute("SELECT pg_reload_conf()")
            cur.fetchone()

            for role in md5_roles:
                cur.execute(f'ALTER ROLE {toml_key(role)} WITH PASSWORD %s', (passwords[role],))
            log(f"Updated {len(md5_roles)} role password hash(es) to SCRAM.")

        remaining_md5 = fetch_md5_roles(conn)
        if remaining_md5:
            sample = ", ".join(remaining_md5[:10])
            log(f"Some roles still have MD5 hashes ({len(remaining_md5)}): {sample}")
            return 2

        changed, backup = patch_hba_method(conn, "md5", "scram-sha-256")
        if changed:
            log(f"Updated pg_hba host all/all rule to scram-sha-256. Backup: {backup}")
        else:
            log("No host all/all md5 rule found to change.")

        log("Auth hardening complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
