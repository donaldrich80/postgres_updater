# Postgres Updater

Replicate as much of a PostgreSQL server as possible from an older instance onto a newer
one, then verify parity. Ships two post-cutover auth repair tools. Operator-run only: there
is no scheduler. Full spec, exit codes and the permanent event-code table:
[`docs/spec.md`](docs/spec.md).

## Doors

| Door | Invocation | Task | Exit codes |
|---|---|---|---|
| Replicate / check / verify | `postgres-updater [run\|preflight\|verify] [flags]` | `task run` / `task preflight` / `task verify` | 0 ok · 1 error · 2 verification/parity failure |
| Auth fix | `python -m postgres_updater.auth_fix --config data/config.toml` | `task auth-fix` | 0 ok or nothing to do · 1 pg_hba line not found |
| Auth harden | `python -m postgres_updater.harden_auth --config data/config.toml --password-map data/role_passwords.toml` | `task harden-auth` | 0 ok · 2 action required |

The auth tools currently raise an uncaught `RuntimeError` (traceback, exit 1) when the
config file is missing or no configured server is reachable.

## What `postgres-updater` does

1. Connects to source and target and detects both versions (`SHOW server_version_num`).
   Source major newer than target fails fast; otherwise it runs in same-major or
   cross-major mode.
2. Replicates either one database (`--scope database`) or the whole server (default
   `server`: every non-template database), creating missing target databases.
3. Default engine `pg_dump`: in server scope, global objects (roles, tablespaces) via
   `pg_dumpall --globals-only --no-role-passwords` piped to `psql` (skip with
   `--skip-globals`); then per database a snapshot-consistent `pg_dump --format=custom`
   restored with `pg_restore --clean --if-exists` (existing target objects are dropped and
   recreated, with ownership and privileges).
4. Fallback engine `table_copy`: copies table rows only, creating missing target
   databases/schemas/tables/columns; supports `--include`/`--exclude` globs,
   `--batch-size` and `--skip-truncate`.
5. Verifies parity (unless `--no-verify`):
   - roles/tablespaces (server scope)
   - per-database object signatures (schemas, tables, views, functions, types,
     extensions, triggers)
   - per-table row count and order-independent checksum
   Missing objects on target fail; extra objects warn. Extension version drift: target
   newer warns, target older fails.
6. Shows progress bars for table copy and verification loops.

`preflight` checks the CLI tools are on PATH, the target user's CREATEDB/CREATEROLE rights
and which databases are missing. `verify` runs only step 5.

It does not clone physical server state (`postgresql.conf`, WAL, replication slots, OS
settings). Verification on very large databases is expensive; use `--no-verify`, then run
`verify` later.

## Auth repair tools

Roles restored from an older server may still carry MD5 password hashes, which cannot log in
through a `host all all all scram-sha-256` rule.

- `auth_fix` downgrades that one pg_hba rule to `md5` (backup written first) and reloads,
  so apps can log in. It does nothing if there are no MD5 login roles or no such rule.
- `harden_auth` re-sets each MD5 login role's password from `data/role_passwords.toml`
  (sent as a client-side SCRAM verifier), then switches the `md5` rule back to
  `scram-sha-256`. If passwords are missing it writes a template map and exits 2.

Both edit `pg_hba.conf` through the `adminpack` extension, which PostgreSQL 17 removed, so
they cannot patch pg_hba on a 17+ server (see the backlog in `docs/spec.md`).

## Requirements

- Python 3.10+
- Network access to both PostgreSQL instances
- PostgreSQL CLI tools on PATH: `pg_dump`, `pg_restore`, `pg_dumpall`, `psql`
- In `server` scope, permission to `CREATE DATABASE` on the target

## Install and run

Via [Task](https://taskfile.dev) (creates `.venv`, installs `requirements.txt`, runs with
`PYTHONPATH=src` and `--config data/config.toml`):

```bash
cp data/config.example.toml data/config.toml   # then fill in real source/target values
task preflight
task run
task verify
```

Or install the package to get the `postgres-updater` command:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
pip install -r requirements.txt
postgres-updater preflight
postgres-updater                 # same as: postgres-updater run
postgres-updater verify
```

Common flags:

```bash
postgres-updater --scope database                # single database instead of full server
postgres-updater --engine table_copy             # row copy instead of pg_dump/pg_restore
postgres-updater --engine table_copy --include "public.users" --include "public.orders"
postgres-updater --engine table_copy --skip-truncate --batch-size 1000
postgres-updater --dry-run                       # only print matched tables
postgres-updater --no-verify
postgres-updater --skip-globals
postgres-updater --config /path/to/config.toml
postgres-updater --source-dsn "postgresql://..." --target-dsn "postgresql://..."
```

## Configuration

- Precedence: CLI flags > env vars (`SOURCE_DSN`, `TARGET_DSN`) > config file.
- Config path: `--config`, else `POSTGRES_UPDATER_CONFIG`, else `data/config.toml`.
- `[source]` / `[target]` take either `dsn` or discrete `host`/`port`/`database`/`user`/
  `password`/`sslmode`. `[migration]` sets `scope`, `engine`, `replicate_globals`,
  `batch_size`, `skip_truncate`, `verify`, `include`, `exclude`. See
  `data/config.example.toml`.
- `data/config.toml` and `data/role_passwords.toml` hold live credentials and are
  gitignored; only the `*.example.toml` files are committed.
- Global import can fail on pre-existing conflicting roles/tablespaces; use a clean target
  or resolve conflicts first.

## Logs and event codes

Every run prints timestamped lines to stdout; failure and outcome lines carry a permanent
event code (`[E11] Global parity failed…`), long stages log their duration, and the last
line is a `RUN SUMMARY` with state, exit code, codes seen and total duration. No log files
are written; pipe through `tee -a` if you want one. The code table is in
[`docs/spec.md`](docs/spec.md).

## Testing

The suite is offline: it never connects to PostgreSQL (the `psycopg` boundary is faked) and
ignores `SOURCE_DSN`, `TARGET_DSN`, `POSTGRES_UPDATER_CONFIG` and `data/config.toml`. Run it
with the command recorded in `.test-command`:

```bash
uv run --no-project --python 3.12 --with-requirements requirements-dev.txt pytest -rs
```

`-rs` prints every skipped test with its reason. Tests live in `tests/`; dev dependencies
are in `requirements-dev.txt`.
