from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
ISOLATED_ENV_VARS = ("SOURCE_DSN", "TARGET_DSN", "POSTGRES_UPDATER_CONFIG")


@pytest.fixture(autouse=True)
def isolate_from_live_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Never let a test pick up real DSNs from the environment or data/config.toml."""
    for name in ISOLATED_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def run_module(tmp_path: Path):
    def _run(module: str, *args: str) -> subprocess.CompletedProcess[str]:
        env = {k: v for k, v in os.environ.items() if k not in ISOLATED_ENV_VARS}
        env["PYTHONPATH"] = str(SRC)
        return subprocess.run(
            [sys.executable, "-m", module, *args],
            cwd=tmp_path,
            env=env,
            text=True,
            capture_output=True,
            timeout=60,
        )

    return _run


@pytest.fixture
def refuse_connections(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Fake the psycopg boundary: every connect attempt is recorded and refused."""
    import psycopg

    attempts: list[str] = []

    def fake_connect(dsn: str, *args: object, **kwargs: object):
        attempts.append(dsn)
        raise psycopg.OperationalError("connection refused (test fake)")

    monkeypatch.setattr(psycopg, "connect", fake_connect)
    return attempts
