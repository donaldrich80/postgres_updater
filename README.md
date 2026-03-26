# Postgres Updater

Replicate as much of a PostgreSQL server as possible from an older instance to a newer instance, then verify migrated data.

## What it does

1. Connects to source and target PostgreSQL instances.
2. Detects both server versions automatically.
3. Uses `pg_dump`/`pg_restore` by default for full logical replication.
4. In server scope, optionally replicates global objects (`pg_dumpall --globals-only`) including roles/tablespaces.
5. Replicates either a single database or the full server (all non-template databases).
6. Auto-creates missing target databases in server mode.
7. Restores full database objects and data (tables, indexes, constraints, views, functions, triggers, extensions, large objects, etc.).
8. Restores with ownership/privileges for cutover-grade fidelity.
9. Verifies cutover parity:
  - global objects (roles/tablespaces)
  - per-database object signatures (schemas/tables/views/functions/types/extensions/triggers)
  - table data checksums and counts
10. Keeps a fallback `table_copy` engine for partial/special-case migrations.
11. Shows progress bars for database/table/verification phases.

## Requirements

- Python 3.10+
- Network access to both PostgreSQL instances
- In `server` mode, permission to `CREATE DATABASE` on target
- PostgreSQL CLI tools on PATH: `pg_dump`, `pg_restore`, `pg_dumpall`, `psql`

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

Create your local config from the example:

```bash
cp data/config.example.toml data/config.toml
```

Edit `data/config.toml` with your real source/target values.

Run migration + verification (uses `data/config.toml` by default):

```bash
postgres-updater
```

Run preflight checks only:

```bash
postgres-updater preflight
```

Run verification only (no migration):

```bash
postgres-updater verify
```

Single-database mode (instead of full-server mode):

```bash
postgres-updater --scope database
```

Use the fallback table copy engine (not full object replication):

```bash
postgres-updater --engine table_copy
```

Dry run (only print matched tables):

```bash
postgres-updater --dry-run
```

Migrate specific tables only:

```bash
postgres-updater --engine table_copy --include "public.users" --include "public.orders"
```

Skip verification:

```bash
postgres-updater --no-verify
```

Skip truncate (append mode):

```bash
postgres-updater --engine table_copy --skip-truncate
```

Use a custom config path:

```bash
postgres-updater --config /path/to/config.toml
```

Override config with DSNs:

```bash
postgres-updater --source-dsn "postgresql://..." --target-dsn "postgresql://..."
```

Skip globals in server scope pg_dump mode:

```bash
postgres-updater --skip-globals
```

## Notes

- `data/config.example.toml` is safe to commit.
- `data/config.toml` is gitignored for local secrets/edits.
- `data/role_passwords.example.toml` is safe to commit.
- `data/role_passwords.toml` is gitignored for local role plaintext passwords used by `harden-auth`.
- Settings precedence is: CLI args > env vars (`SOURCE_DSN`/`TARGET_DSN`) > config file.
- Default scope is `server` (all non-template databases).
- Default engine is `pg_dump` (recommended for full-clone cutovers).
- Use `postgres-updater preflight` to validate tools/permissions before running migration.
- Use `postgres-updater verify` to run validation only without copying data.
- Use `task auth-fix` after cutover if apps fail with SCRAM errors and roles are still MD5-hashed.
- Use `task harden-auth` to convert MD5 role hashes to SCRAM and enforce `scram-sha-256` in `pg_hba.conf`.
- The app auto-detects source/target versions using `SHOW server_version_num`.
- If source major version is newer than target major version, it fails fast.
- If source major version is older than target major version, it runs in cross-major copy mode.
- If both are the same major version, it runs in same-major copy mode.
- In server + `pg_dump` mode, global objects are replicated unless `--skip-globals` is set.
- Global export uses `--no-role-passwords` to avoid overwriting target role passwords during replication.
- Global object import can fail on pre-existing conflicting roles/tablespaces; use a clean target or resolve conflicts first.
- `--include` / `--exclude` filters are available only with `--engine table_copy`.
- `--skip-truncate` applies only to `--engine table_copy`.
- In `table_copy` mode, missing target databases/schemas/tables/columns are created automatically.
- This tool still does not clone physical-level server state such as `postgresql.conf`, WAL/replication slots, or OS-level settings.
- Verification checks:
  - roles/tablespaces parity (server scope)
  - object signature parity per database
  - row count + order-independent checksum (sum of row digests)
- Missing objects on target are treated as failures; extra objects on target are reported as warnings.
- Extension version drift is treated as: target newer -> warning, target older -> failure.
- For very large databases, verification can be expensive. Run with `--no-verify` if you need a faster migration pass, then verify later.
- Progress bars are shown during live run phases (database and table/verification loops).
