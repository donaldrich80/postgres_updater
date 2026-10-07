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
from pathlib import Path

import psycopg
from psycopg import sql

from postgres_updater.auth_common import (
    build_dsn,
    connect_live,
    fetch_md5_roles,
    load_dsns,
    log,
    patch_hba_method,
    run_with_summary,
    tomllib,
)

__all__ = ["build_dsn", "load_dsns", "load_password_map", "main", "toml_key", "write_template"]


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
    # Keep passwords the operator already filled in; only missing roles get a blank entry.
    existing: dict[str, object] = {}
    if path.exists():
        existing = tomllib.loads(path.read_text()).get("passwords", {})
        if not isinstance(existing, dict):
            existing = {}
    for role in [*roles, *(name for name in existing if name not in roles)]:
        value = existing.get(role, "")
        lines.append(f"{toml_key(role)} = {toml_key(value if isinstance(value, str) else '')}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")


def enforce_scram_rule(conn: psycopg.Connection) -> None:
    patched = patch_hba_method(conn, "md5", "scram-sha-256", "harden_auth")
    if patched:
        log(f"Updated pg_hba host all/all rule to scram-sha-256. Backup: {patched[0]}")
    else:
        log("No host all/all md5 rule found to change.")


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
    password_map_path = Path(args.password_map)
    dsn = connect_live(Path(args.config), missing_code="E30", unreachable_code="E31")

    with psycopg.connect(dsn, autocommit=True) as conn:
        md5_roles = fetch_md5_roles(conn)
        if not md5_roles:
            log("No MD5 login roles found.", "S30")
            enforce_scram_rule(conn)
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
                # Hash client-side (as psql's \password does) so plaintext never reaches the
                # server log; ALTER ROLE takes no bind parameters, so the verifier is a literal.
                verifier = conn.pgconn.encrypt_password(
                    passwords[role].encode(), role.encode(), b"scram-sha-256"
                ).decode()
                cur.execute(
                    sql.SQL("ALTER ROLE {} WITH PASSWORD {}").format(
                        sql.Identifier(role), sql.Literal(verifier)
                    )
                )
            log(f"Updated {len(md5_roles)} role password hash(es) to SCRAM.")

        remaining_md5 = fetch_md5_roles(conn)
        if remaining_md5:
            sample = ", ".join(remaining_md5[:10])
            log(f"Some roles still have MD5 hashes ({len(remaining_md5)}): {sample}", "E33")
            return 2

        enforce_scram_rule(conn)
        log("Auth hardening complete.", "S31")
    return 0


def main() -> int:
    args = parse_args()  # argparse exits (--help, bad flags) happen before the run is timed
    return run_with_summary("harden_auth", _main, args)


if __name__ == "__main__":
    raise SystemExit(main())
