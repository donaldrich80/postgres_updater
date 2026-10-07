"""Characterization tests for the auth_fix and harden_auth module doors."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from psycopg.conninfo import conninfo_to_dict

from postgres_updater import auth_fix, harden_auth

CONFIG = """
[source]
host = "src.example"
port = 5433
database = "old"
user = "u"
password = "p"

[target]
dsn = "host=dst.example dbname=new"
"""


@pytest.mark.parametrize("module", ["postgres_updater.auth_fix", "postgres_updater.harden_auth"])
def test_help_exits_zero(run_module, module: str) -> None:
    result = run_module(module, "--help")
    assert result.returncode == 0
    assert "--config" in result.stdout


@pytest.mark.parametrize("module", ["postgres_updater.auth_fix", "postgres_updater.harden_auth"])
def test_missing_config_is_uncaught_runtime_error(run_module, tmp_path: Path, module: str) -> None:
    # Current behaviour: a traceback with exit 1, not a logged error.
    result = run_module(module, "--config", str(tmp_path / "absent.toml"))
    assert result.returncode == 1
    assert "RuntimeError: Config file not found" in result.stderr


def test_harden_auth_help_lists_password_map(run_module) -> None:
    assert "--password-map" in run_module("postgres_updater.harden_auth", "--help").stdout


@pytest.mark.parametrize("mod", [auth_fix, harden_auth])
def test_build_dsn_and_load_dsns(mod, tmp_path: Path) -> None:
    assert mod.build_dsn({"dsn": "host=x"}) == "host=x"
    # The old pin here was "... password= sslmode=prefer", which libpq parses as
    # password="sslmode=prefer"; compare parsed fields instead.
    assert conninfo_to_dict(mod.build_dsn({})) == {
        "host": "127.0.0.1", "port": "5432", "dbname": "postgres", "user": "postgres",
        "password": "", "sslmode": "prefer",
    }
    config = tmp_path / "c.toml"
    config.write_text(CONFIG)
    assert mod.load_dsns(config) == [
        ("source", "host=src.example port=5433 dbname=old user=u password=p sslmode=prefer"),
        ("target", "host=dst.example dbname=new"),
    ]


@pytest.mark.parametrize("mod", [auth_fix, harden_auth])
def test_main_raises_when_no_server_reachable(
    mod, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, refuse_connections
) -> None:
    config = tmp_path / "c.toml"
    config.write_text(CONFIG)
    monkeypatch.setattr(sys, "argv", ["prog", "--config", str(config)])
    with pytest.raises(RuntimeError, match=r"Could not connect to any configured server: source: .* \| target: "):
        mod.main()
    assert len(refuse_connections) == 2


def test_toml_key_quotes_and_escapes() -> None:
    assert harden_auth.toml_key('app"user\\x') == '"app\\"user\\\\x"'


def test_password_map_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "role_passwords.toml"
    assert harden_auth.load_password_map(path) == {}

    harden_auth.write_template(path, ["app", 'we"ird'])
    assert path.read_text().splitlines()[2:] == ["[passwords]", '"app" = ""', '"we\\"ird" = ""']
    assert harden_auth.load_password_map(path) == {}

    path.write_text('[passwords]\napp = "s3cret"\nblank = "  "\n')
    assert harden_auth.load_password_map(path) == {"app": "s3cret"}

    path.write_text("[passwords]\napp = 1\n")
    with pytest.raises(RuntimeError, match="Invalid password map entry for role 'app'"):
        harden_auth.load_password_map(path)

    path.write_text('passwords = "nope"\n')
    with pytest.raises(RuntimeError, match=r"\[passwords\] table missing"):
        harden_auth.load_password_map(path)


class FakeCursor:
    def __init__(self, rows: list[tuple[str]]) -> None:
        self.rows = rows
        self.executed: list[str] = []

    def __enter__(self) -> "FakeCursor":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def execute(self, query: str, params: object = None) -> None:
        self.executed.append(query)

    def fetchall(self) -> list[tuple[str]]:
        return self.rows


class FakeConnection:
    def __init__(self, rows: list[tuple[str]]) -> None:
        self.cursor_obj = FakeCursor(rows)

    def __enter__(self) -> "FakeConnection":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def cursor(self) -> FakeCursor:
        return self.cursor_obj


def test_harden_auth_writes_template_and_exits_two_when_passwords_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "c.toml"
    config.write_text(CONFIG)
    password_map = tmp_path / "role_passwords.toml"
    conn = FakeConnection([("app",), ("reporting",)])
    monkeypatch.setattr(harden_auth.psycopg, "connect", lambda *a, **k: conn)
    monkeypatch.setattr(
        sys, "argv", ["prog", "--config", str(config), "--password-map", str(password_map)]
    )

    assert harden_auth.main() == 2
    assert password_map.read_text().splitlines()[2:] == ["[passwords]", '"app" = ""', '"reporting" = ""']
    out = capsys.readouterr().out
    assert "Missing plaintext passwords for 2 role(s): app, reporting" in out
    # Nothing beyond the read-only role query ran against the server.
    assert len(conn.cursor_obj.executed) == 1
    assert "pg_authid" in conn.cursor_obj.executed[0]


class RecordingCursor:
    """Answers queries by substring and records every (query, params) pair."""

    def __init__(self, answers: dict[str, list[tuple]]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, object]] = []
        self.last: list[tuple] = []

    def __enter__(self) -> "RecordingCursor":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def execute(self, query: object, params: object = None) -> None:
        text = query if isinstance(query, str) else query.as_string(None)
        self.calls.append((text, params))
        self.last = next((rows for key, rows in self.answers.items() if key in text), [])
        if callable(self.last):
            self.last = self.last()

    def fetchall(self) -> list[tuple]:
        return list(self.last)

    def fetchone(self) -> tuple:
        return self.last[0]


class FakePgconn:
    def encrypt_password(self, passwd: bytes, user: bytes, algorithm: bytes) -> bytes:
        assert algorithm == b"scram-sha-256"
        return b"SCRAM-SHA-256$4096:fake"


class RecordingConnection(FakeConnection):
    def __init__(self, answers: dict[str, list[tuple]]) -> None:
        self.cursor_obj = RecordingCursor(answers)
        self.pgconn = FakePgconn()


def test_harden_auth_alter_role_quotes_identifier_and_sends_scram_verifier(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Bug: the role was quoted with TOML escaping and the password sent as a bind
    # parameter, which ALTER ROLE (a utility statement) cannot accept. The fix sends a
    # client-side SCRAM verifier so the plaintext never appears in a statement.
    calls = {"n": 0}

    def md5_roles() -> list[tuple]:
        calls["n"] += 1
        return [('we"ird',)] if calls["n"] == 1 else []

    config = tmp_path / "c.toml"
    config.write_text(CONFIG)
    passwords = tmp_path / "pw.toml"
    passwords.write_text("[passwords]\n'we\"ird' = \"it's\"\n")
    conn = RecordingConnection({
        "pg_authid": md5_roles, "pg_reload_conf": [(True,)],
        "SHOW hba_file": [("/pg/hba.conf",)], "pg_read_file": [("host all all all md5\n",)],
    })
    monkeypatch.setattr(harden_auth.psycopg, "connect", lambda *a, **k: conn)
    monkeypatch.setattr(
        sys, "argv", ["prog", "--config", str(config), "--password-map", str(passwords)]
    )

    assert harden_auth.main() == 0
    alters = [call for call in conn.cursor_obj.calls if call[0].startswith("ALTER ROLE")]
    assert alters == [('ALTER ROLE "we""ird" WITH PASSWORD \'SCRAM-SHA-256$4096:fake\'', None)]
    assert not any("it's" in query or "it''s" in query for query, _ in conn.cursor_obj.calls)


def test_harden_auth_template_keeps_passwords_already_filled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Bug: rewriting the template for missing roles erased passwords the operator had filled in.
    config = tmp_path / "c.toml"
    config.write_text(CONFIG)
    passwords = tmp_path / "pw.toml"
    passwords.write_text('[passwords]\napp = "s3cret"\n')
    conn = RecordingConnection({"pg_authid": [("app",), ("reporting",)]})
    monkeypatch.setattr(harden_auth.psycopg, "connect", lambda *a, **k: conn)
    monkeypatch.setattr(
        sys, "argv", ["prog", "--config", str(config), "--password-map", str(passwords)]
    )

    assert harden_auth.main() == 2
    assert harden_auth.load_password_map(passwords) == {"app": "s3cret"}
    assert '"reporting" = ""' in passwords.read_text()


@pytest.mark.parametrize("mod", [auth_fix, harden_auth])
@pytest.mark.parametrize("password", ["", "with space", "q'uote\\"])
def test_build_dsn_round_trips_awkward_passwords(mod, password: str) -> None:
    # Bug: an unquoted empty password made libpq read "sslmode=prefer" as the password.
    assert conninfo_to_dict(mod.build_dsn({"password": password})) == {
        "host": "127.0.0.1", "port": "5432", "dbname": "postgres", "user": "postgres",
        "password": password, "sslmode": "prefer",
    }
