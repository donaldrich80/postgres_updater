"""auth_fix: repair a post-cutover auth mismatch (SCRAM pg_hba rule, MD5 role hashes).

Purpose: after cutover, roles restored with MD5 hashes cannot log in through a
`host all all all scram-sha-256` rule. This tool downgrades that one rule to md5 so
logins work until harden_auth converts the hashes. Run on demand (`task auth-fix`).
Last verified: 2026-10-07 (offline suite).

Flow:
  1. Load data/config.toml; missing file -> E20, RuntimeError raised.
  2. External call: connect to [source] then [target]; none reachable -> E21, raised.
  3. Read MD5 login roles (pg_authid) and host all/all rules (pg_hba_file_rules).
  4. Branch: no MD5 roles -> S20 exit 0; no SCRAM all/all rule -> S21 exit 0.
  5. External call: read pg_hba.conf via adminpack; no literal line to patch -> E22 exit 1.
  6. External call: write a timestamped backup, rewrite pg_hba.conf, pg_reload_conf -> S22.
  7. main() logs a RUN SUMMARY line on every path.
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
    log("Could not connect to any configured server.", "E21")
    raise RuntimeError("Could not connect to any configured server: " + " | ".join(errors))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Automatically repair pg_hba auth mismatch after cutover (SCRAM rule with MD5 role passwords)."
    )
    parser.add_argument("--config", default="data/config.toml", help="Path to config TOML file.")
    return parser.parse_args()


def _main(args: argparse.Namespace) -> int:
    config_path = Path(args.config)
    if not config_path.exists():
        # Error path: missing config is raised uncaught (traceback, exit 1) after a coded log line.
        log(f"Config file not found: {config_path}", "E20")
        raise RuntimeError(f"Config file not found: {config_path}")

    # External call: try [source] then [target] DSN; the first that connects is the live server.
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
            # Branch: only act when MD5 roles AND a SCRAM all/all rule coexist.
            if not md5_roles:
                log("No login roles with MD5 password hashes found; nothing to repair.", "S20")
                return 0
            if not has_scram_all_rule:
                log("No host all/all SCRAM rule detected; nothing to repair.", "S21")
                return 0

            # External call: installs adminpack on the live server, then reads pg_hba.conf through it.
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
                log("Could not find a literal 'host all all all scram-sha-256' line to patch.", "E22")
                return 1

            backup_file = f"{hba_file}.bak_codex_auth_fix_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            # External call: writes the backup, replaces pg_hba.conf on the server's disk, reloads config.
            cur.execute("SELECT pg_file_write(%s, %s, false)", (backup_file, current_hba))
            cur.execute("SELECT pg_file_unlink(%s)", (hba_file,))
            cur.execute("SELECT pg_file_write(%s, %s, false)", (hba_file, updated_hba))
            cur.execute("SELECT pg_reload_conf()")
            reload_ok = bool(cur.fetchone()[0])

            log(f"Patched pg_hba.conf and created backup: {backup_file}", "S22")
            log(f"Reloaded PostgreSQL config: {reload_ok}")
            log(f"MD5 login roles still present: {len(md5_roles)}")
            sample = ", ".join(md5_roles[:10])
            if sample:
                log(f"Sample roles: {sample}")

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
            f"RUN SUMMARY tool=auth_fix state={state} exit={exit_code if exit_code is not None else 'raised'} "
            f"codes={','.join(RUN_EVENTS) or '-'} duration={time.monotonic() - started:.2f}s",
            "S00" if exit_code == 0 else "E00",
        )


if __name__ == "__main__":
    raise SystemExit(main())
