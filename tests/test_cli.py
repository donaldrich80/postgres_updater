"""Characterization tests for the `postgres-updater` CLI door (postgres_updater.cli)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pytest

from postgres_updater import cli

MODULE = "postgres_updater.cli"


def write_config(path: Path, body: str) -> Path:
    path.write_text(body)
    return path


# --- process-level door -----------------------------------------------------


def test_help_exits_zero_and_lists_commands(run_module) -> None:
    result = run_module(MODULE, "--help")
    assert result.returncode == 0
    assert "{run,preflight,verify}" in result.stdout
    for flag in ("--config", "--source-dsn", "--target-dsn", "--engine", "--scope", "--dry-run"):
        assert flag in result.stdout


def test_unknown_command_is_argparse_error(run_module) -> None:
    result = run_module(MODULE, "bogus")
    assert result.returncode == 2
    assert "invalid choice" in result.stderr


def test_missing_source_dsn_exits_one_with_error_line(run_module, tmp_path: Path) -> None:
    result = run_module(MODULE, "--config", str(tmp_path / "absent.toml"))
    assert result.returncode == 1
    assert "ERROR: Missing source DSN." in result.stdout


def test_same_source_and_target_dsn_rejected_before_connecting(run_module, tmp_path: Path) -> None:
    dsn = "host=203.0.113.1 dbname=x user=u password=p"
    result = run_module(
        MODULE, "--config", str(tmp_path / "absent.toml"), "--source-dsn", dsn, "--target-dsn", dsn
    )
    assert result.returncode == 1
    assert "ERROR: Source and target DSN are the same" in result.stdout


def test_include_rejected_with_pg_dump_engine(run_module, tmp_path: Path) -> None:
    result = run_module(
        MODULE,
        "--config", str(tmp_path / "absent.toml"),
        "--source-dsn", "host=a dbname=x user=u password=p",
        "--target-dsn", "host=b dbname=x user=u password=p",
        "--include", "public.users",
    )
    assert result.returncode == 1
    assert "ERROR: --include/--exclude are only supported with --engine table_copy." in result.stdout


# --- main() with the psycopg boundary faked ----------------------------------


def test_main_returns_one_when_connection_fails(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path, refuse_connections
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "postgres-updater",
            "preflight",
            "--config", str(tmp_path / "absent.toml"),
            "--source-dsn", "host=a dbname=x user=u password=p",
            "--target-dsn", "host=b dbname=x user=u password=p",
        ],
    )
    assert cli.main() == 1
    assert refuse_connections == ["host=a dbname=x user=u password=p"]
    assert "ERROR: connection refused (test fake)" in capsys.readouterr().out


# --- public functions -------------------------------------------------------


def namespace(**overrides: object) -> argparse.Namespace:
    base = dict(
        command="run",
        config="absent.toml",
        source_dsn=None,
        target_dsn=None,
        include=[],
        exclude=[],
        batch_size=None,
        scope=None,
        engine=None,
        skip_globals=False,
        skip_truncate=False,
        no_verify=False,
        dry_run=False,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def test_resolve_args_defaults_without_config() -> None:
    args, exists = cli.resolve_args_from_config(namespace())
    assert exists is False
    assert (args.source_dsn, args.target_dsn) == (None, None)
    assert (args.batch_size, args.scope, args.engine) == (5000, "server", "pg_dump")
    assert (args.skip_globals, args.skip_truncate, args.no_verify) == (False, False, False)


def test_resolve_args_reads_config_file(tmp_path: Path) -> None:
    config = write_config(
        tmp_path / "c.toml",
        """
[source]
host = "src.example"
port = 5433
database = "old"
user = "u"
password = "p"
sslmode = "disable"

[target]
dsn = "host=dst.example dbname=new"

[migration]
scope = "database"
engine = "table_copy"
replicate_globals = false
batch_size = 10
skip_truncate = true
verify = false
include = ["public.*"]
exclude = ["public.tmp"]
""",
    )
    args, exists = cli.resolve_args_from_config(namespace(config=str(config)))
    assert exists is True
    assert args.source_dsn == "host=src.example port=5433 dbname=old user=u password=p sslmode=disable"
    assert args.target_dsn == "host=dst.example dbname=new"
    assert (args.batch_size, args.scope, args.engine) == (10, "database", "table_copy")
    assert (args.include, args.exclude) == (["public.*"], ["public.tmp"])
    assert (args.skip_globals, args.skip_truncate, args.no_verify) == (True, True, True)


def test_resolve_args_precedence_cli_over_env_over_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = write_config(
        tmp_path / "c.toml",
        '[source]\ndsn = "host=file-src"\n[target]\ndsn = "host=file-dst"\n',
    )
    monkeypatch.setenv("SOURCE_DSN", "host=env-src")
    monkeypatch.setenv("TARGET_DSN", "host=env-dst")
    args, _ = cli.resolve_args_from_config(namespace(config=str(config), source_dsn="host=cli-src"))
    assert args.source_dsn == "host=cli-src"
    assert args.target_dsn == "host=env-dst"


def test_resolve_args_rejects_invalid_toml(tmp_path: Path) -> None:
    config = write_config(tmp_path / "c.toml", "not = [valid")
    with pytest.raises(ValueError, match="Invalid TOML"):
        cli.resolve_args_from_config(namespace(config=str(config)))


def test_build_dsn_from_section_shapes() -> None:
    assert cli.build_dsn_from_section({}, "source") is None
    assert cli.build_dsn_from_section({"other": 1}, "source") is None
    assert cli.build_dsn_from_section({"dsn": "host=h"}, "source") == "host=h"
    with pytest.raises(ValueError, match=r"\[source\] is missing required field\(s\): database, user, password"):
        cli.build_dsn_from_section({"host": "h"}, "source")
    with pytest.raises(ValueError, match=r"\[target\]\.port must be an integer"):
        cli.build_dsn_from_section(
            {"host": "h", "port": "5432", "database": "d", "user": "u", "password": "p"}, "target"
        )


def test_dsn_helpers() -> None:
    assert cli.dsn_database_name("host=h user=u") == "postgres"
    assert cli.dsn_database_name("host=h dbname=app") == "app"
    assert cli.maintenance_dsn("host=h dbname=app") == "dbname=postgres host=h"
    assert cli.dsn_with_database("host=h dbname=app", "other") == "dbname=other host=h"
    assert cli.safe_dump_filename("my db/1.v-2_x") == "my_db_1.v-2_x"


def test_command_display_redacts_dsns() -> None:
    cmd = ["pg_dump", "--dbname", "postgresql://u:p@h/db", "host=h password=secret", "-Fc"]
    assert cli.command_display(cmd) == "pg_dump --dbname <redacted-dsn> <redacted-dsn> -Fc"


@pytest.mark.parametrize(
    ("num", "expected"),
    [(160002, (16, 2, 0)), (100000, (10, 0, 0)), (90624, (9, 6, 24)), (90500, (9, 5, 0))],
)
def test_parse_server_version_num(num: int, expected: tuple[int, int, int]) -> None:
    assert cli.parse_server_version_num(num) == expected


def version(num: int) -> cli.ServerVersion:
    major, minor, patch = cli.parse_server_version_num(num)
    return cli.ServerVersion(version_text=str(num), version_num=num, major=major, minor=minor, patch=patch)


def test_build_policy_modes_and_rejection() -> None:
    upgrade = cli.build_policy(version(90624), version(160002))
    assert upgrade.mode == "major-upgrade-copy"
    assert upgrade.use_identity_override is True
    assert upgrade.supports_relispartition is False

    same = cli.build_policy(version(150001), version(150004))
    assert same.mode == "same-major-copy"
    assert same.supports_relispartition is True

    with pytest.raises(RuntimeError, match="Target server major version must be >= source"):
        cli.build_policy(version(160002), version(150004))


@pytest.mark.parametrize(
    ("source", "target", "expected"),
    [("1.2", "1.2", 0), ("1.2", "1.2.0", 0), ("1.2", "1.3", 1), ("2.0", "1.9", -1), ("1.2a", "1.3", None)],
)
def test_compare_extension_version(source: str, target: str, expected: int | None) -> None:
    assert cli.compare_extension_version(source, target) == expected


def test_matches_pattern() -> None:
    table = cli.TableSpec(schema="public", name="users", relkind="r", columns=("id",))
    assert cli.matches_pattern(table, ["public.users"]) is True
    assert cli.matches_pattern(table, ["user*"]) is True
    assert cli.matches_pattern(table, ["other.*"]) is False


def test_require_binaries_names_missing_tools() -> None:
    with pytest.raises(RuntimeError, match="Missing required PostgreSQL CLI tool\\(s\\): definitely-not-a-binary-xyz"):
        cli.require_binaries(["definitely-not-a-binary-xyz"])
