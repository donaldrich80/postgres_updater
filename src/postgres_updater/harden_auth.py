"""harden_auth: convert MD5 role hashes to SCRAM and enforce SCRAM in pg_hba.

Purpose: the follow-up to auth_fix. Re-sets each MD5 login role's password (from a
local, gitignored password map) so it is stored as SCRAM, then switches the
`host all all all md5` rule to scram-sha-256. Run on demand (`task harden-auth`).
Last verified: 2026-10-07 (offline suite).

Flow:
  1. Load data/config.toml; missing file -> E30, RuntimeError raised.
  2. External call: connect to [source] then [target]; none reachable -> E31, raised.
  3. Read MD5 login roles. Branch: none -> patch pg_hba md5->scram, S30 exit 0.
  4. Branch: any role missing from the password map -> write a template map, E32 exit 2.
  5. External call: ALTER SYSTEM password_encryption, reload, ALTER ROLE ... PASSWORD each role.
  6. Branch: roles still MD5 afterwards -> E33 exit 2.
  7. External call: patch pg_hba md5->scram (backup first), reload -> S31 exit 0.
  8. main() logs a RUN SUMMARY line on every path.
"""
from __future__ import annotations

import argparse
import re
import time
from datetime import datetime
from pathlib import Path

import psycopg

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


# Event codes seen during this process, in order; reported by the RUN SUMMARY line.
# Codes are permanent: never renumber or reuse one (table in docs/spec.md).
RUN_EVENTS: list[str] = []


def log(message: str, code: str | None = None) -> None:
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if code:
        RUN_EVENTS.append(code)
        message = f"[{code}] {message}"
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
    # Error path: no candidate answered; logged with a code, then raised (uncaught, traceback).
    log("Could not connect to any configured server.", "E31")
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

        # External call: writes a backup, replaces pg_hba.conf on the server's disk, reloads config.
        backup = f"{hba_file}.bak_codex_harden_auth_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        cur.execute("SELECT pg_file_write(%s, %s, false)", (backup, current_hba))
        cur.execute("SELECT pg_file_unlink(%s)", (hba_file,))
        cur.execute("SELECT pg_file_write(%s, %s, false)", (hba_file, updated_hba))
        cur.execute("SELECT pg_reload_conf()")
        cur.fetchone()
    return True, backup


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Harden PostgreSQL auth after cutover: convert MD5 role hashes to SCRAM and enforce SCRAM in pg_hba."
    )
    parser.add_argument("--config", default="data/config.toml", help="Path to config TOML file.")
    parser.add_argument(
        "--password-map",
        default="data/role_passwords.toml",
        help="Path to TOML file containing plaintext role passwords under [passwords].",
    )
    return parser.parse_args()


def _main(args: argparse.Namespace) -> int:
    config_path = Path(args.config)
    password_map_path = Path(args.password_map)
    if not config_path.exists():
        # Error path: missing config is raised uncaught (traceback, exit 1) after a coded log line.
        log(f"Config file not found: {config_path}", "E30")
        raise RuntimeError(f"Config file not found: {config_path}")

    # External call: try [source] then [target] DSN; the first that connects is the live server.
    label, dsn = pick_live_dsn(load_dsns(config_path))
    log(f"Connected to live server using [{label}] DSN.")

    with psycopg.connect(dsn, autocommit=True) as conn:
        md5_roles = fetch_md5_roles(conn)
        if not md5_roles:
            log("No MD5 login roles found.", "S30")
            changed, backup = patch_hba_method(conn, "md5", "scram-sha-256")
            if changed:
                log(f"Updated pg_hba host all/all rule to scram-sha-256. Backup: {backup}")
            else:
                log("No host all/all md5 rule found to change.")
            return 0

        passwords = load_password_map(password_map_path)
        missing = [role for role in md5_roles if role not in passwords]
        # Branch: refuse to touch any role until every MD5 role has a password; leave a template to fill.
        if missing:
            write_template(password_map_path, md5_roles)
            sample = ", ".join(missing[:10])
            log(f"Missing plaintext passwords for {len(missing)} role(s): {sample}", "E32")
            log(f"Wrote/updated template: {password_map_path}")
            return 2

        with conn.cursor() as cur:
            # External call: changes server config, then rewrites each role's stored password hash.
            cur.execute("ALTER SYSTEM SET password_encryption = 'scram-sha-256'")
            cur.execute("SELECT pg_reload_conf()")
            cur.fetchone()

            for role in md5_roles:
                cur.execute(f'ALTER ROLE {toml_key(role)} WITH PASSWORD %s', (passwords[role],))
            log(f"Updated {len(md5_roles)} role password hash(es) to SCRAM.")

        remaining_md5 = fetch_md5_roles(conn)
        if remaining_md5:
            sample = ", ".join(remaining_md5[:10])
            log(f"Some roles still have MD5 hashes ({len(remaining_md5)}): {sample}", "E33")
            return 2

        changed, backup = patch_hba_method(conn, "md5", "scram-sha-256")
        if changed:
            log(f"Updated pg_hba host all/all rule to scram-sha-256. Backup: {backup}")
        else:
            log("No host all/all md5 rule found to change.")

        log("Auth hardening complete.", "S31")
    return 0


def main() -> int:
    args = parse_args()  # argparse exits (--help, bad flags) happen before the run is timed
    started = time.monotonic()
    RUN_EVENTS.clear()
    exit_code: int | None = None
    try:
        exit_code = _main(args)
        return exit_code
    finally:
        # Run summary is logged on every path, including the uncaught RuntimeError ones.
        state = {0: "ok", 2: "action_required"}.get(exit_code, "error")
        log(
            f"RUN SUMMARY tool=harden_auth state={state} exit={exit_code if exit_code is not None else 'raised'} "
            f"codes={','.join(RUN_EVENTS) or '-'} duration={time.monotonic() - started:.2f}s",
            "S00" if exit_code == 0 else "E00",
        )


if __name__ == "__main__":
    raise SystemExit(main())
