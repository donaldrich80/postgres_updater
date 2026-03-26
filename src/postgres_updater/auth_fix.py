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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Automatically repair pg_hba auth mismatch after cutover (SCRAM rule with MD5 role passwords)."
    )
    parser.add_argument("--config", default="data/config.toml", help="Path to config TOML file.")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        raise RuntimeError(f"Config file not found: {config_path}")

    label, dsn = pick_live_dsn(load_dsns(config_path))
    log(f"Connected to live server using [{label}] DSN.")

    with psycopg.connect(dsn, autocommit=True) as conn:
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
            md5_roles = [row[0] for row in cur.fetchall()]

            cur.execute(
                """
                SELECT line_number, auth_method
                FROM pg_hba_file_rules
                WHERE type='host'
                  AND database @> ARRAY['all']
                  AND user_name @> ARRAY['all']
                ORDER BY line_number
                """
            )
            host_all_rules = cur.fetchall()

            has_scram_all_rule = any(method == "scram-sha-256" for _, method in host_all_rules)
            if not md5_roles:
                log("No login roles with MD5 password hashes found; nothing to repair.")
                return 0
            if not has_scram_all_rule:
                log("No host all/all SCRAM rule detected; nothing to repair.")
                return 0

            cur.execute("CREATE EXTENSION IF NOT EXISTS adminpack")
            cur.execute("SHOW hba_file")
            hba_file = str(cur.fetchone()[0])
            cur.execute("SELECT pg_read_file(%s)", (hba_file,))
            current_hba = str(cur.fetchone()[0])
            updated_hba = re.sub(
                r"(?m)^(\s*host\s+all\s+all\s+all\s+)scram-sha-256(\s*(?:#.*)?)$",
                r"\1md5\2",
                current_hba,
            )
            if updated_hba == current_hba:
                log("Could not find a literal 'host all all all scram-sha-256' line to patch.")
                return 1

            backup_file = f"{hba_file}.bak_codex_auth_fix_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            cur.execute("SELECT pg_file_write(%s, %s, false)", (backup_file, current_hba))
            cur.execute("SELECT pg_file_unlink(%s)", (hba_file,))
            cur.execute("SELECT pg_file_write(%s, %s, false)", (hba_file, updated_hba))
            cur.execute("SELECT pg_reload_conf()")
            reload_ok = bool(cur.fetchone()[0])

            log(f"Patched pg_hba.conf and created backup: {backup_file}")
            log(f"Reloaded PostgreSQL config: {reload_ok}")
            log(f"MD5 login roles still present: {len(md5_roles)}")
            sample = ", ".join(md5_roles[:10])
            if sample:
                log(f"Sample roles: {sample}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
