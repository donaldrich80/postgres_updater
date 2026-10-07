# AGENTS.md — postgres-updater

Notes for coding agents. `CLAUDE.md` imports this file, so Claude Code and Codex read the same rules.

- **What it is:** a Python CLI that replicates a PostgreSQL server/database onto a newer
  version and verifies parity, plus two post-cutover auth repair tools. Spec, doors, exit
  codes and the permanent event-code table: `docs/spec.md`.
- **Layout:** `src/postgres_updater/` (code: `cli.py`, `auth_fix.py`, `harden_auth.py`),
  `tests/` (offline pytest suite), `docs/`, `data/*.example.toml`, `Taskfile.yml`.
- **Test command** (must pass before any commit; do not edit `.test-command`):
  `uv run --no-project --python 3.12 --with-requirements requirements-dev.txt pytest -rs`
- **Never** connect to a real server from tests or while developing: the suite fakes
  `psycopg.connect`. `data/config.toml` and `data/role_passwords.toml` hold live
  credentials and are gitignored — never read, print or commit them.
- **Event codes are permanent.** New failure mode → new code in `docs/spec.md` plus a test
  in `tests/test_observability.py`. Never renumber or reuse a code, and keep the message text
  after the code stable (tests pin it).
- **Logging:** use `log(message, code)` / `db_log(...)`; wrap new long-running stages in
  `cli.stage(name)`. Stdout only — never add log files or rotation.
- **No schedulers:** these are operator-run tools. Do not add cron/launchd/systemd jobs.
