"""One test per documented event code (docs/spec.md), plus stage timing and run summary.

Offline: every database call is faked at the psycopg boundary or one level above it.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import psycopg
import pytest

from postgres_updater import auth_fix, cli, harden_auth

CLI = "postgres_updater.cli"
CONFIG = """
[source]
host = "src.example"
database = "old"
user = "u"
password = "p"

[target]
dsn = "host=dst.example dbname=new"
"""


def version(major: int) -> cli.ServerVersion:
    return cli.ServerVersion(f"{major}.1", major * 10000 + 1, major, 1, 0)


POLICY = cli.build_policy(version(12), version(16))


def ns(**overrides: object) -> argparse.Namespace:
    base = dict(
        command="verify",
        source_dsn="host=a dbname=app",
        target_dsn="host=b dbname=app",
        include=[],
        exclude=[],
        scope="server",
        engine="pg_dump",
        skip_globals=False,
        no_verify=False,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


# --- cli: process-level codes and run summary --------------------------------


def test_cli_config_error_is_e02_with_summary(run_module) -> None:
    result = run_module(CLI, "--config", "absent.toml")
    assert result.returncode == 1
    assert "[E02] ERROR: Missing source DSN." in result.stdout
    assert "[E00] RUN SUMMARY command=run state=error exit=1 codes=E02 duration=" in result.stdout


def test_cli_connection_refused_is_e03(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path, refuse_connections
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["postgres-updater", "verify", "--config", str(tmp_path / "absent.toml"),
         "--source-dsn", "host=a dbname=x", "--target-dsn", "host=b dbname=x"],
    )
    assert cli.main() == 1
    out = capsys.readouterr().out
    assert "[E03] ERROR: connection refused (test fake)" in out
    assert "RUN SUMMARY command=verify state=error exit=1 codes=E03" in out


@pytest.mark.parametrize(
    ("exc", "code"),
    [
        (ValueError("bad"), "E02"),
        (psycopg.OperationalError("refused"), "E03"),
        (RuntimeError("pg_dump failed"), "E04"),
        (psycopg.errors.UndefinedTable("nope"), "E05"),
        (KeyError("x"), "E01"),
    ],
)
def test_error_code_mapping(exc: BaseException, code: str) -> None:
    assert cli.error_code(exc) == code


def test_missing_binary_is_e06() -> None:
    with pytest.raises(cli.CodedError) as info:
        cli.require_binaries(["definitely-not-a-pg-tool"])
    assert cli.error_code(info.value) == "E06"


def test_version_policy_rejection_is_e07() -> None:
    with pytest.raises(cli.CodedError) as info:
        cli.build_policy(version(16), version(12))
    assert cli.error_code(info.value) == "E07"


def test_partitioned_table_missing_on_target_is_e08() -> None:
    table = cli.TableSpec("public", "events", "p", ("id",))
    with pytest.raises(cli.CodedError, match="partitioned table is missing") as info:
        cli.create_missing_target_table(None, None, table)
    assert cli.error_code(info.value) == "E08"


def test_external_tool_failure_is_e09(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    failed = subprocess.CompletedProcess(["pg_dump"], 1, stdout="", stderr="pg_dump: error: boom")
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: failed)
    with pytest.raises(cli.CodedError, match="pg_dump failed with exit code 1: pg_dump: error: boom") as info:
        cli.run_command(["pg_dump", "host=a"], "pg_dump")
    assert cli.error_code(info.value) == "E09"


def test_run_summary_success_is_s00(capsys: pytest.CaptureFixture[str]) -> None:
    cli.RUN_EVENTS[:] = ["S01"]
    cli.log_run_summary("preflight", 0, started=0.0)
    assert "[S00] RUN SUMMARY command=preflight state=ok exit=0 codes=S01 duration=" in capsys.readouterr().out
    # The summary reports the codes seen before it, then records its own.
    assert cli.RUN_EVENTS == ["S01", "S00"]


def test_stage_logs_duration_even_when_it_raises(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(RuntimeError):
        with cli.stage("globals"):
            raise RuntimeError("boom")
    out = capsys.readouterr().out
    assert "Stage globals: start." in out
    assert "Stage globals: finished in " in out


# --- cli: preflight / verify branch codes --------------------------------------


def fake_preflight(monkeypatch: pytest.MonkeyPatch, can_create_db: bool) -> None:
    monkeypatch.setattr(cli, "require_binaries", lambda names: None)
    monkeypatch.setattr(cli, "list_source_databases", lambda conn: ["app", "crm"])
    monkeypatch.setattr(cli, "list_target_databases", lambda conn: ["app"])
    monkeypatch.setattr(cli, "fetch_role_capabilities", lambda conn: (can_create_db, True))


def test_preflight_missing_db_without_createdb_is_e10(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_preflight(monkeypatch, can_create_db=False)
    assert cli.run_preflight(ns(), POLICY, None, None) == 1
    assert "[E10] Preflight FAIL" in capsys.readouterr().out


def test_preflight_ok_is_s01(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    fake_preflight(monkeypatch, can_create_db=True)
    assert cli.run_preflight(ns(), POLICY, None, None) == 0
    assert "[S01] Preflight OK" in capsys.readouterr().out


def test_verify_global_parity_failure_is_e11(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "list_source_databases", lambda conn: ["app"])
    monkeypatch.setattr(cli, "verify_global_signatures", lambda s, t: (["roles: missing app_user"], []))
    assert cli.run_verify_only(ns(), POLICY, None, None) == 2
    assert "[E11] Global parity failed: 1 issue(s)." in capsys.readouterr().out


def test_verify_missing_target_db_is_e12(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(cli, "list_source_databases", lambda conn: ["app"])
    monkeypatch.setattr(cli, "list_target_databases", lambda conn: [])
    monkeypatch.setattr(cli, "verify_global_signatures", lambda s, t: ([], []))
    assert cli.run_verify_only(ns(), POLICY, None, None) == 2
    assert "[E12] [db:app] Verification failed: target database is missing." in capsys.readouterr().out


def test_object_parity_failure_is_e13(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(cli, "verify_database_object_signatures", lambda s, t: (["view x missing"], []))
    result = cli.verify_database_after_restore_with_connections(ns(), POLICY, None, None, "app")
    assert result == 2
    assert "[E13] [db:app] Object parity failed: 1 issue(s)." in capsys.readouterr().out


@pytest.mark.parametrize(("mismatches", "code", "exit_code"), [(["public.t: count 1 != 2"], "E14", 2), ([], "S02", 0)])
def test_table_verification_codes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mismatches: list[str],
    code: str,
    exit_code: int,
) -> None:
    table = object()
    monkeypatch.setattr(cli, "verify_database_object_signatures", lambda s, t: ([], []))
    monkeypatch.setattr(cli, "discover_source_tables", lambda *a, **k: [table])
    monkeypatch.setattr(cli, "verify_tables", lambda *a, **k: mismatches)
    assert cli.verify_database_after_restore_with_connections(ns(), POLICY, None, None, "app") == exit_code
    assert f"[{code}] [db:app] Verification" in capsys.readouterr().out


# --- auth tools ---------------------------------------------------------------


@pytest.mark.parametrize(("module", "code"), [("postgres_updater.auth_fix", "E20"), ("postgres_updater.harden_auth", "E30")])
def test_auth_missing_config_code_and_summary(run_module, module: str, code: str) -> None:
    result = run_module(module, "--config", "absent.toml")
    assert result.returncode == 1
    assert f"[{code}] Config file not found: absent.toml" in result.stdout
    assert f"[E00] RUN SUMMARY tool={module.rsplit('.', 1)[1]} state=error exit=raised codes={code}" in result.stdout


@pytest.mark.parametrize(("mod", "code"), [(auth_fix, "E21"), (harden_auth, "E31")])
def test_auth_no_live_server_code(
    mod, code: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str], refuse_connections
) -> None:
    config = tmp_path / "c.toml"
    config.write_text(CONFIG)
    monkeypatch.setattr(sys, "argv", ["prog", "--config", str(config)])
    with pytest.raises(RuntimeError):
        mod.main()
    assert f"[{code}] Could not connect to any configured server." in capsys.readouterr().out


class ScriptedCursor:
    """Answers each query by the first matching substring in `answers`."""

    def __init__(self, answers: dict[str, list[tuple]]) -> None:
        self.answers = answers
        self.executed: list[str] = []
        self.last: list[tuple] = []

    def __enter__(self) -> "ScriptedCursor":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def execute(self, query: str, params: object = None) -> None:
        self.executed.append(query)
        self.last = next((rows for key, rows in self.answers.items() if key in query), [])
        if callable(self.last):
            self.last = self.last()

    def fetchall(self) -> list[tuple]:
        return list(self.last)

    def fetchone(self) -> tuple:
        return self.last[0]


class ScriptedConnection:
    def __init__(self, answers: dict[str, list[tuple]]) -> None:
        self.cursor_obj = ScriptedCursor(answers)

    def __enter__(self) -> "ScriptedConnection":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def cursor(self) -> ScriptedCursor:
        return self.cursor_obj

    def writes(self) -> list[str]:
        return [q for q in self.cursor_obj.executed if "pg_file_write" in q or "ALTER" in q]


def run_tool(mod, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, conn: ScriptedConnection, *extra: str) -> int:
    config = tmp_path / "c.toml"
    config.write_text(CONFIG)
    monkeypatch.setattr(mod.psycopg, "connect", lambda *a, **k: conn)
    monkeypatch.setattr(sys, "argv", ["prog", "--config", str(config), *extra])
    return mod.main()


HBA_SCRAM = "local all all trust\nhost all all all scram-sha-256\n"
HBA_MD5 = "local all all trust\nhost all all all md5\n"


@pytest.mark.parametrize(
    ("answers", "exit_code", "code"),
    [
        ({"pg_authid": [], "pg_hba_file_rules": []}, 0, "S20"),
        ({"pg_authid": [("app",)], "pg_hba_file_rules": [(1, "md5")]}, 0, "S21"),
        (
            {"pg_authid": [("app",)], "pg_hba_file_rules": [(1, "scram-sha-256")],
             "SHOW hba_file": [("/pg/hba.conf",)], "pg_read_file": [("host all all 10.0.0.0/8 scram-sha-256\n",)]},
            1,
            "E22",
        ),
        (
            {"pg_authid": [("app",)], "pg_hba_file_rules": [(1, "scram-sha-256")],
             "SHOW hba_file": [("/pg/hba.conf",)], "pg_read_file": [(HBA_SCRAM,)], "pg_reload_conf": [(True,)]},
            0,
            "S22",
        ),
    ],
)
def test_auth_fix_branch_codes(
    answers: dict, exit_code: int, code: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    conn = ScriptedConnection(answers)
    assert run_tool(auth_fix, monkeypatch, tmp_path, conn) == exit_code
    out = capsys.readouterr().out
    assert f"[{code}] " in out
    assert "RUN SUMMARY tool=auth_fix" in out
    # Only the patching path writes to the server.
    assert bool(conn.writes()) == (code == "S22")


def test_harden_auth_missing_passwords_is_e32(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    conn = ScriptedConnection({"pg_authid": [("app",)]})
    assert run_tool(harden_auth, monkeypatch, tmp_path, conn, "--password-map", str(tmp_path / "pw.toml")) == 2
    assert "[E32] Missing plaintext passwords for 1 role(s): app" in capsys.readouterr().out
    assert conn.writes() == []


def test_harden_auth_no_md5_roles_is_s30(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    conn = ScriptedConnection({"pg_authid": [], "SHOW hba_file": [("/pg/hba.conf",)], "pg_read_file": [(HBA_SCRAM,)]})
    assert run_tool(harden_auth, monkeypatch, tmp_path, conn) == 0
    out = capsys.readouterr().out
    assert "[S30] No MD5 login roles found." in out
    assert "[S00] RUN SUMMARY tool=harden_auth state=ok exit=0 codes=S30 duration=" in out


@pytest.mark.parametrize(("still_md5", "exit_code", "code"), [(True, 2, "E33"), (False, 0, "S31")])
def test_harden_auth_conversion_codes(
    still_md5: bool, exit_code: int, code: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls = {"n": 0}

    def md5_roles() -> list[tuple]:
        calls["n"] += 1
        return [("app",)] if calls["n"] == 1 or still_md5 else []

    passwords = tmp_path / "pw.toml"
    passwords.write_text('[passwords]\napp = "s3cret"\n')
    conn = ScriptedConnection({
        "pg_authid": md5_roles, "pg_reload_conf": [(True,)],
        "SHOW hba_file": [("/pg/hba.conf",)], "pg_read_file": [(HBA_MD5,)],
    })
    assert run_tool(harden_auth, monkeypatch, tmp_path, conn, "--password-map", str(passwords)) == exit_code
    assert f"[{code}] " in capsys.readouterr().out
