"""Helpers shared by the post-cutover auth tools (auth_fix, harden_auth).

Coded logging, DSN loading from data/config.toml, live-server selection, the MD5-role
query, the pg_hba.conf rewrite and the RUN SUMMARY wrapper. Event codes stay owned by
each tool (docs/spec.md); callers pass theirs in.
"""
from __future__ import annotations

import argparse
import re
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import psycopg
from psycopg.conninfo import make_conninfo

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
    # make_conninfo quotes values, so empty passwords or ones with spaces/quotes survive.
    return make_conninfo(
        host=str(section.get("host", "127.0.0.1")),
        port=int(section.get("port", 5432)),
        dbname=str(section.get("database", "postgres")),
        user=str(section.get("user", "postgres")),
        password=str(section.get("password", "")),
        sslmode=str(section.get("sslmode", "prefer")),
    )


def load_dsns(config_path: Path) -> list[tuple[str, str]]:
    config = tomllib.loads(config_path.read_text())
    dsns: list[tuple[str, str]] = []
    for label in ("source", "target"):
        section = config.get(label, {})
        if isinstance(section, dict):
            dsns.append((label, build_dsn(section)))
    return dsns


def pick_live_dsn(candidates: list[tuple[str, str]], code: str) -> tuple[str, str]:
    errors: list[str] = []
    for label, dsn in candidates:
        try:
            with psycopg.connect(dsn):
                return label, dsn
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{label}: {exc}")
    # Error path: no candidate answered; logged with a code, then raised (uncaught, traceback).
    log("Could not connect to any configured server.", code)
    raise RuntimeError("Could not connect to any configured server: " + " | ".join(errors))


def connect_live(config_path: Path, missing_code: str, unreachable_code: str) -> str:
    """Return the DSN of the first configured server ([source], then [target]) that connects."""
    if not config_path.exists():
        # Error path: missing config is raised uncaught (traceback, exit 1) after a coded log line.
        log(f"Config file not found: {config_path}", missing_code)
        raise RuntimeError(f"Config file not found: {config_path}")
    # External call: try [source] then [target] DSN; the first that connects is the live server.
    label, dsn = pick_live_dsn(load_dsns(config_path), unreachable_code)
    log(f"Connected to live server using [{label}] DSN.")
    return dsn


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


def patch_hba_method(
    conn: psycopg.Connection, from_method: str, to_method: str, tool: str
) -> tuple[str, bool] | None:
    """Rewrite the `host all all all <from_method>` line; return (backup path, reload ok) or None."""
    with conn.cursor() as cur:
        # External call: installs adminpack on the live server, then reads pg_hba.conf through it.
        cur.execute("CREATE EXTENSION IF NOT EXISTS adminpack")
        cur.execute("SHOW hba_file")
        hba_file = str(cur.fetchone()[0])
        cur.execute("SELECT pg_read_file(%s)", (hba_file,))
        current_hba = str(cur.fetchone()[0])
        pattern = rf"(?m)^(\s*host\s+all\s+all\s+all\s+){re.escape(from_method)}(\s*(?:#.*)?)$"
        updated_hba = re.sub(pattern, rf"\1{to_method}\2", current_hba)
        if updated_hba == current_hba:
            return None

        # External call: writes a backup, replaces pg_hba.conf on the server's disk, reloads config.
        backup = f"{hba_file}.bak_codex_{tool}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        cur.execute("SELECT pg_file_write(%s, %s, false)", (backup, current_hba))
        cur.execute("SELECT pg_file_unlink(%s)", (hba_file,))
        cur.execute("SELECT pg_file_write(%s, %s, false)", (hba_file, updated_hba))
        cur.execute("SELECT pg_reload_conf()")
        reload_ok = bool(cur.fetchone()[0])
    return backup, reload_ok


def run_with_summary(tool: str, body: Callable[[argparse.Namespace], int], args: argparse.Namespace) -> int:
    """Run a tool body and log one RUN SUMMARY line on every path, including raised errors."""
    started = time.monotonic()
    RUN_EVENTS.clear()
    exit_code: int | None = None
    try:
        exit_code = body(args)
        return exit_code
    finally:
        state = {0: "ok", 2: "action_required"}.get(exit_code, "error")
        log(
            f"RUN SUMMARY tool={tool} state={state} exit={exit_code if exit_code is not None else 'raised'} "
            f"codes={','.join(RUN_EVENTS) or '-'} duration={time.monotonic() - started:.2f}s",
            "S00" if exit_code == 0 else "E00",
        )
