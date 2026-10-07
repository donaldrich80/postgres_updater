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
from pathlib import Path

import psycopg

from postgres_updater.auth_common import (
    build_dsn,
    connect_live,
    fetch_md5_roles,
    load_dsns,
    log,
    patch_hba_method,
    run_with_summary,
)

__all__ = ["build_dsn", "load_dsns", "main"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Automatically repair pg_hba auth mismatch after cutover (SCRAM rule with MD5 role passwords)."
    )
    parser.add_argument("--config", default="data/config.toml", help="Path to config TOML file.")
    return parser.parse_args()


def _main(args: argparse.Namespace) -> int:
    dsn = connect_live(Path(args.config), missing_code="E20", unreachable_code="E21")

    with psycopg.connect(dsn, autocommit=True) as conn:
        md5_roles = fetch_md5_roles(conn)
        with conn.cursor() as cur:
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

        patched = patch_hba_method(conn, "scram-sha-256", "md5", "auth_fix")
        if patched is None:
            log("Could not find a literal 'host all all all scram-sha-256' line to patch.", "E22")
            return 1
        backup_file, reload_ok = patched

        log(f"Patched pg_hba.conf and created backup: {backup_file}", "S22")
        log(f"Reloaded PostgreSQL config: {reload_ok}")
        log(f"MD5 login roles still present: {len(md5_roles)}")
        sample = ", ".join(md5_roles[:10])
        if sample:
            log(f"Sample roles: {sample}")

    return 0


def main() -> int:
    args = parse_args()  # argparse exits (--help, bad flags) happen before the run is timed
    return run_with_summary("auth_fix", _main, args)


if __name__ == "__main__":
    raise SystemExit(main())
