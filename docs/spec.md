# postgres-updater — spec

Last reviewed: 2026-10-07.

## Purpose

Replicate as much of a PostgreSQL server as possible from an older instance onto a newer
one, then prove parity. A single-unit Python CLI tool (`folder-layouts.md` type: CLI tool /
type 1 shape): code in `src/postgres_updater/`, tests in `tests/`, docs here.

## Doors

| Door | Invocation | Exit codes |
|---|---|---|
| `postgres-updater [run\|preflight\|verify]` | `postgres_updater.cli:main` (`task run`/`preflight`/`verify`) | 0 ok · 1 error · 2 verification/parity failure |
| auth_fix | `python -m postgres_updater.auth_fix --config …` (`task auth-fix`) | 0 ok/nothing to do · 1 pg_hba line not found · uncaught `RuntimeError` (traceback, 1) on missing config or no reachable server |
| harden_auth | `python -m postgres_updater.harden_auth --config … --password-map …` (`task harden-auth`) | 0 ok · 2 action required (passwords missing / MD5 remains) · uncaught `RuntimeError` as above |

The uncaught `RuntimeError` in the auth tools is current, characterized behaviour; it is
pinned by tests and should only change as its own reviewed change.

## Test command

```bash
uv run --no-project --python 3.12 --with-requirements requirements-dev.txt pytest -rs
```

Also recorded in `.test-command` (machine-readable) and the README. The suite is offline:
the `psycopg` boundary is faked, the env DSNs are cleared and each test runs in a temp dir.
`-rs` lists every skip with its reason; there are no skips today.

## Observability

All output goes to stdout as `[YYYY-MM-DD HH:MM:SS] [CODE] message`; uncoded lines are
progress/detail. The tools never write or rotate log files — capture with `| tee -a` if a
persistent log is wanted, and rotation is the OS's job.

- **Stage timing:** `Stage <name>: start.` / `Stage <name>: finished in Ns.` around
  preflight, verify, `replicate:<engine>`, `globals`, and each `db:<name>` in server scope.
  Table copy also logs per-table durations.
- **Run summary:** every run ends with one `RUN SUMMARY` line (`S00` on exit 0, `E00`
  otherwise): command/tool, state, exit code, every code seen, total duration. These are
  operator-run tools, so the terminal is the notification surface.

### Event codes (permanent — never renumber or reuse)

| Code | Door | Meaning |
|---|---|---|
| S00 | all | Run summary, exit 0 |
| E00 | all | Run summary, non-zero exit or raised |
| E01 | cli | Unexpected error (exit 1) |
| E02 | cli | Invalid arguments or config file (`ValueError`, exit 1) |
| E03 | cli | Could not connect / connection lost (`psycopg.OperationalError`, exit 1) |
| E04 | cli | Other runtime failure: source DB attributes or table fingerprint unreadable (`RuntimeError`, exit 1) |
| E05 | cli | SQL error from source or target (`psycopg.Error`, exit 1) |
| E06 | cli | Required PostgreSQL CLI tool missing from PATH (exit 1) |
| E07 | cli | Version policy: source major newer than target (exit 1) |
| E08 | cli | Target schema incompatible / table cannot be created (table_copy, exit 1) |
| E09 | cli | pg_dump, pg_restore, pg_dumpall or psql exited non-zero (exit 1) |
| E10 | cli | Preflight: target missing databases and user lacks CREATEDB (exit 1) |
| E11 | cli | Global (roles/tablespaces) parity failed (exit 2) |
| E12 | cli | Verify: target database missing (exit 2) |
| E13 | cli | Per-database object parity failed (exit 2) |
| E14 | cli | Table count/checksum mismatch (exit 2) |
| S01 | cli | Preflight OK |
| S02 | cli | Table verification passed for a database |
| E20 | auth_fix | Config file not found (raised) |
| E21 | auth_fix | No configured server reachable (raised) |
| E22 | auth_fix | No literal `host all all all scram-sha-256` line to patch (exit 1) |
| S20 | auth_fix | No MD5 login roles; nothing to repair |
| S21 | auth_fix | No SCRAM all/all rule; nothing to repair |
| S22 | auth_fix | pg_hba.conf patched (backup written) and reloaded |
| E30 | harden_auth | Config file not found (raised) |
| E31 | harden_auth | No configured server reachable (raised) |
| E32 | harden_auth | Plaintext passwords missing; template written (exit 2) |
| E33 | harden_auth | Roles still MD5 after conversion (exit 2) |
| S30 | harden_auth | No MD5 login roles; pg_hba md5→scram attempted |
| S31 | harden_auth | Hardening complete |

Each code has a test in `tests/test_observability.py`.

## Scheduling

None. Host-schedulers rung 1: every door is run on demand by an operator (directly or via
`Taskfile.yml`) during a cutover. No cron/launchd/systemd entry exists or is wanted.

## State

Live config and secrets — `data/config.toml`, `data/role_passwords.toml` — are gitignored;
only `*.example.toml` is committed. Dumps go to a `tempfile` directory removed after each run.
No generated or vendored files exist in the repo.

## Backlog

- auth_fix/harden_auth duplicate `log`/`build_dsn`/`load_dsns`/`pick_live_dsn`; extract a
  shared module once a refactor stage is scheduled.
- Decide whether the auth tools should catch their `RuntimeError`s and exit 1 with a coded
  ERROR line like the CLI (behaviour change — needs its own failing test first).
- Backup filenames still carry a `bak_codex_` prefix from the original author tooling.
