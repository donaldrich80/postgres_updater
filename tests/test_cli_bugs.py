"""Regression tests for cli.py bugs fixed in the refactor stage (offline; psycopg faked)."""
from __future__ import annotations

import argparse

import pytest

from postgres_updater import cli

POLICY = cli.build_policy(
    cli.ServerVersion("12.1", 120001, 12, 1, 0), cli.ServerVersion("16.1", 160001, 16, 1, 0)
)


class FakeCursor:
    def __init__(self, conn: "FakeConn") -> None:
        self.conn = conn
        self.last: tuple | None = None

    def __enter__(self) -> "FakeCursor":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def execute(self, query: object, params: object = None) -> None:
        text = query if isinstance(query, str) else query.as_string(None)
        self.conn.calls.append((text, params))
        self.last = self.conn.answer(text)

    def fetchone(self) -> tuple | None:
        return self.last


class FakeConn:
    def __init__(self, answer=lambda query: None) -> None:
        self.answer = answer
        self.calls: list[tuple[str, object]] = []

    def __enter__(self) -> "FakeConn":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def execute(self, query: str) -> None:
        self.calls.append((query, None))

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)


def ns(**overrides: object) -> argparse.Namespace:
    base = dict(
        command="verify", source_dsn="host=a dbname=app", target_dsn="host=b dbname=app",
        include=[], exclude=[], scope="database", engine="pg_dump", skip_globals=False, no_verify=False,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def test_sync_table_sequences_quotes_mixed_case_table_name() -> None:
    # Bug: "Sales.Orders" was passed raw; pg_get_serial_sequence lowercases unquoted names,
    # so the lookup failed with "relation sales.orders does not exist".
    def answer(query: str):
        if "pg_get_serial_sequence" in query:
            return ('"Sales"."Orders_id_seq"',)
        if "max(" in query:
            return (41,)
        return (41,)

    conn = FakeConn(answer)
    table = cli.TableSpec("Sales", "Orders", "r", ("id",))
    assert cli.sync_table_sequences(conn, table) == 1
    lookup = conn.calls[0]
    assert "quote_ident(%s) || '.' || quote_ident(%s)" in lookup[0]
    assert lookup[1] == ("Sales", "Orders", "id")


@pytest.mark.parametrize("scope", ["database", "server"])
def test_verify_command_ignores_no_verify(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], scope: str
) -> None:
    # Bug: [migration].verify = false made the explicit `verify` command skip all
    # per-database parity checks and exit 0.
    monkeypatch.setattr(cli.psycopg, "connect", lambda *a, **k: FakeConn())
    monkeypatch.setattr(cli, "list_source_databases", lambda conn: ["app"])
    monkeypatch.setattr(cli, "list_target_databases", lambda conn: ["app"])
    monkeypatch.setattr(cli, "verify_global_signatures", lambda s, t: ([], []))
    monkeypatch.setattr(cli, "verify_database_object_signatures", lambda s, t: (["view x missing"], []))
    assert cli.run_verify_only(ns(scope=scope, no_verify=True), POLICY, None, None) == 2
    assert "[E13] [db:app] Object parity failed: 1 issue(s)." in capsys.readouterr().out


def test_run_path_still_honours_no_verify(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path
) -> None:
    monkeypatch.setattr(cli.psycopg, "connect", lambda *a, **k: FakeConn(lambda q: ("snap-1",)))
    monkeypatch.setattr(cli, "run_command", lambda cmd, context: None)

    def fail(*a, **k):
        raise AssertionError("verification ran despite --no-verify")

    monkeypatch.setattr(cli, "verify_database_object_signatures", fail)
    args = ns(command="run", no_verify=True)
    assert cli.replicate_database_with_pg_dump(
        args, POLICY, args.source_dsn, args.target_dsn, "app", tmp_path
    ) == 0
    assert "[db:app] Verification skipped (--no-verify)." in capsys.readouterr().out


def test_globals_import_failure_is_e09_with_output_tail(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    import subprocess

    def fake_run(cmd, **kwargs):
        if cmd[0] == "psql":
            return subprocess.CompletedProcess(cmd, 3, stdout="ok\nlast out\n", stderr="x\nFATAL: denied\n")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    with pytest.raises(cli.CodedError) as raised:
        cli.replicate_globals_with_pg_dumpall("host=a", "host=b", tmp_path)
    assert raised.value.code == "E09"
    assert str(raised.value) == "Importing global objects failed with exit code 3: FATAL: denied | last out"
