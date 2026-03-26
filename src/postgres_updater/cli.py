from __future__ import annotations

import argparse
import hashlib
import fnmatch
import os
import shutil
import subprocess
import tempfile
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime, time as dt_time, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

TABLE_DISCOVERY_SQL_MODERN = """
SELECT
  n.nspname AS schema_name,
  c.relname AS table_name,
  c.relkind AS relkind
FROM pg_catalog.pg_class AS c
JOIN pg_catalog.pg_namespace AS n
  ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p')
  AND c.relispartition = FALSE
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND n.nspname NOT LIKE 'pg_toast%%'
ORDER BY n.nspname, c.relname
"""

TABLE_DISCOVERY_SQL_LEGACY = """
SELECT
  n.nspname AS schema_name,
  c.relname AS table_name,
  c.relkind AS relkind
FROM pg_catalog.pg_class AS c
JOIN pg_catalog.pg_namespace AS n
  ON n.oid = c.relnamespace
WHERE c.relkind = 'r'
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND n.nspname NOT LIKE 'pg_toast%%'
ORDER BY n.nspname, c.relname
"""

FK_DEPENDENCY_SQL = """
SELECT
  child_ns.nspname AS child_schema,
  child.relname AS child_table,
  parent_ns.nspname AS parent_schema,
  parent.relname AS parent_table
FROM pg_catalog.pg_constraint AS con
JOIN pg_catalog.pg_class AS child
  ON child.oid = con.conrelid
JOIN pg_catalog.pg_namespace AS child_ns
  ON child_ns.oid = child.relnamespace
JOIN pg_catalog.pg_class AS parent
  ON parent.oid = con.confrelid
JOIN pg_catalog.pg_namespace AS parent_ns
  ON parent_ns.oid = parent.relnamespace
WHERE con.contype = 'f'
  AND child_ns.nspname NOT IN ('pg_catalog', 'information_schema')
  AND parent_ns.nspname NOT IN ('pg_catalog', 'information_schema')
"""

COLUMN_DISCOVERY_SQL = """
SELECT column_name
FROM information_schema.columns
WHERE table_schema = %s
  AND table_name = %s
ORDER BY ordinal_position
"""

DATABASE_DISCOVERY_SQL = """
SELECT datname
FROM pg_catalog.pg_database
WHERE datallowconn = TRUE
  AND datistemplate = FALSE
ORDER BY datname
"""

DATABASE_ATTRS_SQL = """
SELECT
  pg_catalog.pg_encoding_to_char(encoding) AS encoding_name,
  datcollate,
  datctype
FROM pg_catalog.pg_database
WHERE datname = %s
"""

SOURCE_COLUMN_DEFINITION_SQL = """
SELECT
  a.attname AS column_name,
  pg_catalog.format_type(a.atttypid, a.atttypmod) AS data_type_sql,
  pg_catalog.pg_get_expr(ad.adbin, ad.adrelid) AS default_sql,
  a.attnotnull AS is_not_null,
  a.attidentity AS identity_kind
FROM pg_catalog.pg_attribute AS a
JOIN pg_catalog.pg_class AS c
  ON c.oid = a.attrelid
JOIN pg_catalog.pg_namespace AS n
  ON n.oid = c.relnamespace
LEFT JOIN pg_catalog.pg_attrdef AS ad
  ON ad.adrelid = a.attrelid
  AND ad.adnum = a.attnum
WHERE n.nspname = %s
  AND c.relname = %s
  AND a.attnum > 0
  AND a.attisdropped = FALSE
ORDER BY a.attnum
"""

DB_OBJECT_SIGNATURE_SQL = """
WITH schemas AS (
  SELECT n.oid, n.nspname
  FROM pg_catalog.pg_namespace AS n
  WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
    AND n.nspname NOT LIKE 'pg_toast%%'
),
objects AS (
  SELECT 'schema' AS kind, s.nspname AS signature
  FROM schemas AS s

  UNION ALL
  SELECT
    CASE c.relkind
      WHEN 'r' THEN 'table'
      WHEN 'p' THEN 'partitioned_table'
      WHEN 'v' THEN 'view'
      WHEN 'm' THEN 'materialized_view'
      WHEN 'S' THEN 'sequence'
      WHEN 'f' THEN 'foreign_table'
      ELSE 'relation'
    END AS kind,
    s.nspname || '.' || c.relname AS signature
  FROM pg_catalog.pg_class AS c
  JOIN schemas AS s ON s.oid = c.relnamespace
  WHERE c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')

  UNION ALL
  SELECT
    'function' AS kind,
    s.nspname || '.' || p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')' AS signature
  FROM pg_catalog.pg_proc AS p
  JOIN schemas AS s ON s.oid = p.pronamespace

  UNION ALL
  SELECT
    'type' AS kind,
    s.nspname || '.' || t.typname AS signature
  FROM pg_catalog.pg_type AS t
  JOIN schemas AS s ON s.oid = t.typnamespace
  LEFT JOIN pg_catalog.pg_class AS c ON c.oid = t.typrelid
  WHERE t.typisdefined
    AND (
      t.typtype IN ('d', 'e', 'r', 'm')
      OR (t.typtype = 'c' AND c.relkind = 'c')
    )

  UNION ALL
  SELECT
    'trigger' AS kind,
    s.nspname || '.' || c.relname || '.' || t.tgname || ':' || t.tgenabled AS signature
  FROM pg_catalog.pg_trigger AS t
  JOIN pg_catalog.pg_class AS c ON c.oid = t.tgrelid
  JOIN schemas AS s ON s.oid = c.relnamespace
  WHERE NOT t.tgisinternal
)
SELECT kind || ':' || signature
FROM objects
ORDER BY 1
"""

DB_EXTENSION_SIGNATURE_SQL = """
SELECT
  e.extname,
  e.extversion,
  n.nspname
FROM pg_catalog.pg_extension AS e
JOIN pg_catalog.pg_namespace AS n ON n.oid = e.extnamespace
ORDER BY 1, 3
"""

ROLE_SIGNATURE_SQL = """
SELECT
  rolname || ':' ||
  rolsuper || ':' ||
  rolcreatedb || ':' ||
  rolcreaterole || ':' ||
  rolcanlogin || ':' ||
  rolreplication || ':' ||
  rolbypassrls || ':' ||
  rolconnlimit
FROM pg_catalog.pg_roles
WHERE rolname NOT LIKE 'pg_%%'
ORDER BY 1
"""

TABLESPACE_SIGNATURE_SQL = """
SELECT
  spc.spcname || ':' ||
  pg_catalog.pg_get_userbyid(spc.spcowner) || ':' ||
  COALESCE(pg_catalog.pg_tablespace_location(spc.oid), '')
FROM pg_catalog.pg_tablespace AS spc
WHERE spc.spcname NOT IN ('pg_default', 'pg_global')
ORDER BY 1
"""

DEFAULT_BATCH_SIZE = 5_000
DEFAULT_CONFIG_PATH = "data/config.toml"
DEFAULT_SCOPE = "server"
DEFAULT_ENGINE = "pg_dump"


@dataclass(frozen=True, slots=True)
class TableSpec:
    schema: str
    name: str
    relkind: str
    columns: tuple[str, ...]

    @property
    def fq_name(self) -> str:
        return f"{self.schema}.{self.name}"


@dataclass(frozen=True, slots=True)
class ColumnDef:
    name: str
    data_type_sql: str
    default_sql: str | None
    is_not_null: bool
    identity_kind: str


@dataclass(frozen=True, slots=True)
class ServerVersion:
    version_text: str
    version_num: int
    major: int
    minor: int
    patch: int

    @property
    def concise(self) -> str:
        if self.major >= 10:
            return f"{self.major}.{self.minor}"
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass(frozen=True, slots=True)
class MigrationPolicy:
    source: ServerVersion
    target: ServerVersion
    mode: str
    use_identity_override: bool
    supports_relispartition: bool


@dataclass(slots=True)
class ProgressBar:
    label: str
    total: int
    width: int = 28
    current: int = 0

    def advance(self, suffix: str = "") -> None:
        if self.total <= 0:
            return
        self.current = min(self.current + 1, self.total)
        self._render(suffix)

    def finish(self, suffix: str = "") -> None:
        if self.total <= 0:
            return
        if self.current < self.total:
            self.current = self.total
        self._render(suffix)
        print("", flush=True)

    def _render(self, suffix: str) -> None:
        if self.total <= 0:
            return
        ratio = self.current / self.total
        filled = int(self.width * ratio)
        bar = "#" * filled + "-" * (self.width - filled)
        message = f"\r{self.label} [{bar}] {self.current}/{self.total}"
        if suffix:
            message = f"{message} {suffix}"
        print(message, end="", flush=True)


def log(message: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}", flush=True)


def db_log(database_name: str, message: str) -> None:
    log(f"[db:{database_name}] {message}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Migrate data from a source PostgreSQL instance to a target instance and verify it."
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=("run", "preflight", "verify"),
        default="run",
        help="Command to execute: run migration, preflight checks, or verification only.",
    )
    parser.add_argument(
        "--config",
        default=os.getenv("POSTGRES_UPDATER_CONFIG", DEFAULT_CONFIG_PATH),
        help=(
            "Path to TOML config file "
            f"(default: {DEFAULT_CONFIG_PATH} or POSTGRES_UPDATER_CONFIG env var)."
        ),
    )
    parser.add_argument(
        "--source-dsn",
        default=None,
        help="Source PostgreSQL DSN. Overrides SOURCE_DSN env var and config file.",
    )
    parser.add_argument(
        "--target-dsn",
        default=None,
        help="Target PostgreSQL DSN. Overrides TARGET_DSN env var and config file.",
    )
    parser.add_argument(
        "--include",
        action="append",
        default=[],
        metavar="PATTERN",
        help="Include table pattern (glob). Match against schema.table and table (table_copy engine only).",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="Exclude table pattern (glob). Match against schema.table and table (table_copy engine only).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=None,
        help=f"Number of rows per insert batch (default from config or {DEFAULT_BATCH_SIZE}).",
    )
    parser.add_argument(
        "--scope",
        choices=("database", "server"),
        default=None,
        help=f"Replication scope (default from config or {DEFAULT_SCOPE}).",
    )
    parser.add_argument(
        "--engine",
        choices=("pg_dump", "table_copy"),
        default=None,
        help=f"Replication engine (default from config or {DEFAULT_ENGINE}).",
    )
    parser.add_argument(
        "--skip-globals",
        action="store_true",
        help="Skip global object replication (roles/tablespaces) in server scope pg_dump mode.",
    )
    parser.add_argument(
        "--skip-truncate",
        action="store_true",
        help="Do not truncate target tables before migration (table_copy engine only).",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip post-migration verification.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only print matched tables and exit.",
    )
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    if not args.source_dsn:
        raise ValueError(
            "Missing source DSN. Set source config in data/config.toml, "
            "or pass --source-dsn, or set SOURCE_DSN."
        )
    if not args.target_dsn:
        raise ValueError(
            "Missing target DSN. Set target config in data/config.toml, "
            "or pass --target-dsn, or set TARGET_DSN."
        )
    if args.source_dsn == args.target_dsn:
        raise ValueError("Source and target DSN are the same. Use different instances.")
    if args.batch_size <= 0:
        raise ValueError("--batch-size must be greater than zero.")
    if args.scope not in {"database", "server"}:
        raise ValueError("--scope must be either 'database' or 'server'.")
    if args.engine not in {"pg_dump", "table_copy"}:
        raise ValueError("--engine must be either 'pg_dump' or 'table_copy'.")
    if args.command == "run" and args.engine == "pg_dump" and (args.include or args.exclude):
        raise ValueError("--include/--exclude are only supported with --engine table_copy.")


def as_mapping(value: Any, name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a TOML table.")
    return value


def as_bool(value: Any, name: str) -> bool:
    if isinstance(value, bool):
        return value
    raise ValueError(f"{name} must be a boolean.")


def as_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer.")
    return value


def as_string(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string.")
    if not value.strip():
        raise ValueError(f"{name} must not be empty.")
    return value


def as_string_list(value: Any, name: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list of strings.")
    items: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise ValueError(f"{name}[{index}] must be a string.")
        items.append(item)
    return items


def as_choice(value: Any, name: str, choices: set[str]) -> str:
    text = as_string(value, name)
    if text not in choices:
        allowed = ", ".join(sorted(choices))
        raise ValueError(f"{name} must be one of: {allowed}.")
    return text


def load_config_file(path: str) -> tuple[dict[str, Any], bool]:
    config_path = Path(path)
    if not config_path.exists():
        return {}, False

    try:
        with config_path.open("rb") as handle:
            config = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"Invalid TOML in config file {config_path}: {exc}") from exc

    if not isinstance(config, dict):
        raise ValueError(f"Config file {config_path} must contain TOML tables.")
    return config, True


def build_dsn_from_section(section: dict[str, Any], section_name: str) -> str | None:
    if not section:
        return None

    dsn_raw = section.get("dsn")
    if dsn_raw is not None:
        return as_string(dsn_raw, f"[{section_name}].dsn")

    keys = ("host", "port", "database", "user", "password", "sslmode")
    if not any(key in section for key in keys):
        return None

    required = ("host", "database", "user", "password")
    missing = [key for key in required if key not in section]
    if missing:
        missing_csv = ", ".join(missing)
        raise ValueError(f"[{section_name}] is missing required field(s): {missing_csv}")

    conninfo_kwargs: dict[str, Any] = {
        "host": as_string(section["host"], f"[{section_name}].host"),
        "port": as_int(section.get("port", 5432), f"[{section_name}].port"),
        "dbname": as_string(section["database"], f"[{section_name}].database"),
        "user": as_string(section["user"], f"[{section_name}].user"),
        "password": as_string(section["password"], f"[{section_name}].password"),
    }
    if "sslmode" in section:
        conninfo_kwargs["sslmode"] = as_string(section["sslmode"], f"[{section_name}].sslmode")
    return make_conninfo(**conninfo_kwargs)


def resolve_args_from_config(args: argparse.Namespace) -> tuple[argparse.Namespace, bool]:
    config, config_exists = load_config_file(args.config)
    source_cfg = as_mapping(config.get("source"), "[source]")
    target_cfg = as_mapping(config.get("target"), "[target]")
    migration_cfg = as_mapping(config.get("migration"), "[migration]")

    args.source_dsn = args.source_dsn or os.getenv("SOURCE_DSN") or build_dsn_from_section(source_cfg, "source")
    args.target_dsn = args.target_dsn or os.getenv("TARGET_DSN") or build_dsn_from_section(target_cfg, "target")

    if args.batch_size is None:
        if "batch_size" in migration_cfg:
            args.batch_size = as_int(migration_cfg["batch_size"], "[migration].batch_size")
        else:
            args.batch_size = DEFAULT_BATCH_SIZE

    if args.scope is None:
        if "scope" in migration_cfg:
            args.scope = as_choice(migration_cfg["scope"], "[migration].scope", {"database", "server"})
        else:
            args.scope = DEFAULT_SCOPE

    if args.engine is None:
        if "engine" in migration_cfg:
            args.engine = as_choice(migration_cfg["engine"], "[migration].engine", {"pg_dump", "table_copy"})
        else:
            args.engine = DEFAULT_ENGINE

    if not args.include and "include" in migration_cfg:
        args.include = as_string_list(migration_cfg["include"], "[migration].include")
    if not args.exclude and "exclude" in migration_cfg:
        args.exclude = as_string_list(migration_cfg["exclude"], "[migration].exclude")

    if not args.skip_truncate and "skip_truncate" in migration_cfg:
        args.skip_truncate = as_bool(migration_cfg["skip_truncate"], "[migration].skip_truncate")
    if not args.no_verify and "verify" in migration_cfg:
        args.no_verify = not as_bool(migration_cfg["verify"], "[migration].verify")
    if not args.skip_globals and "replicate_globals" in migration_cfg:
        args.skip_globals = not as_bool(migration_cfg["replicate_globals"], "[migration].replicate_globals")

    return args, config_exists


def dsn_with_database(dsn: str, dbname: str) -> str:
    fields = conninfo_to_dict(dsn)
    fields["dbname"] = dbname
    return make_conninfo(**fields)


def dsn_database_name(dsn: str) -> str:
    fields = conninfo_to_dict(dsn)
    dbname = fields.get("dbname")
    if not dbname:
        return "postgres"
    return str(dbname)


def command_display(cmd: list[str]) -> str:
    parts: list[str] = []
    for part in cmd:
        lowered = part.lower()
        if "password=" in lowered or "postgresql://" in lowered or "postgres://" in lowered:
            parts.append("<redacted-dsn>")
            continue
        parts.append(part)
    return " ".join(parts)


def run_command(cmd: list[str], context: str) -> None:
    log(f"{context}: {command_display(cmd)}")
    completed = subprocess.run(
        cmd,
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode == 0:
        return

    stderr = (completed.stderr or "").strip()
    stdout = (completed.stdout or "").strip()
    snippets: list[str] = []
    if stderr:
        snippets.append(stderr.splitlines()[-1])
    if stdout:
        snippets.append(stdout.splitlines()[-1])
    detail = " | ".join(snippets) if snippets else "no output captured"
    raise RuntimeError(f"{context} failed with exit code {completed.returncode}: {detail}")


def require_binaries(names: list[str]) -> None:
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        csv = ", ".join(missing)
        raise RuntimeError(f"Missing required PostgreSQL CLI tool(s): {csv}")


def maintenance_dsn(dsn: str) -> str:
    return dsn_with_database(dsn, "postgres")


def list_source_databases(source_admin_conn: psycopg.Connection) -> list[str]:
    with source_admin_conn.cursor() as cur:
        cur.execute(DATABASE_DISCOVERY_SQL)
        rows = cur.fetchall()
    return [str(row[0]) for row in rows]


def list_target_databases(target_admin_conn: psycopg.Connection) -> list[str]:
    with target_admin_conn.cursor() as cur:
        cur.execute(DATABASE_DISCOVERY_SQL)
        rows = cur.fetchall()
    return [str(row[0]) for row in rows]


def fetch_role_capabilities(conn: psycopg.Connection) -> tuple[bool, bool]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT COALESCE(r.rolcreatedb, FALSE), COALESCE(r.rolcreaterole, FALSE)
            FROM pg_catalog.pg_roles AS r
            WHERE r.rolname = current_user
            """
        )
        row = cur.fetchone()
    if row is None:
        return False, False
    return bool(row[0]), bool(row[1])


def target_database_exists(target_admin_conn: psycopg.Connection, dbname: str) -> bool:
    with target_admin_conn.cursor() as cur:
        cur.execute("SELECT 1 FROM pg_catalog.pg_database WHERE datname = %s", (dbname,))
        return cur.fetchone() is not None


def create_target_database_from_source(
    source_admin_conn: psycopg.Connection,
    target_admin_conn: psycopg.Connection,
    dbname: str,
) -> None:
    with source_admin_conn.cursor() as cur:
        cur.execute(DATABASE_ATTRS_SQL, (dbname,))
        attrs = cur.fetchone()

    if attrs is None:
        raise RuntimeError(f"Could not read source database attributes for {dbname}")

    encoding_name, datcollate, datctype = attrs
    create_stmt = sql.SQL(
        "CREATE DATABASE {} WITH TEMPLATE template0 ENCODING {} LC_COLLATE {} LC_CTYPE {}"
    ).format(
        sql.Identifier(dbname),
        sql.Literal(encoding_name),
        sql.Literal(datcollate),
        sql.Literal(datctype),
    )
    with target_admin_conn.cursor() as cur:
        cur.execute(create_stmt)


def parse_server_version_num(version_num: int) -> tuple[int, int, int]:
    if version_num >= 100000:
        major = version_num // 10000
        minor = version_num % 10000
        patch = 0
        return major, minor, patch

    major = version_num // 10000
    minor = (version_num // 100) % 100
    patch = version_num % 100
    return major, minor, patch


def detect_server_version(conn: psycopg.Connection) -> ServerVersion:
    with conn.cursor() as cur:
        cur.execute("SHOW server_version")
        version_text = str(cur.fetchone()[0])
        cur.execute("SHOW server_version_num")
        version_num = int(cur.fetchone()[0])
    major, minor, patch = parse_server_version_num(version_num)
    return ServerVersion(
        version_text=version_text,
        version_num=version_num,
        major=major,
        minor=minor,
        patch=patch,
    )


def build_policy(source: ServerVersion, target: ServerVersion) -> MigrationPolicy:
    if source.major > target.major:
        raise RuntimeError(
            "Target server major version must be >= source major version. "
            f"Got source {source.concise}, target {target.concise}."
        )

    mode = "major-upgrade-copy" if source.major < target.major else "same-major-copy"
    return MigrationPolicy(
        source=source,
        target=target,
        mode=mode,
        use_identity_override=target.major >= 10,
        supports_relispartition=source.major >= 10,
    )


def table_identifier(table: TableSpec) -> sql.Composed:
    return sql.SQL("{}.{}").format(sql.Identifier(table.schema), sql.Identifier(table.name))


def column_list_sql(columns: tuple[str, ...]) -> sql.Composed:
    return sql.SQL(", ").join(sql.Identifier(name) for name in columns)


def matches_pattern(table: TableSpec, patterns: list[str]) -> bool:
    fq_name = table.fq_name
    for pattern in patterns:
        if fnmatch.fnmatch(fq_name, pattern) or fnmatch.fnmatch(table.name, pattern):
            return True
    return False


def fetch_table_columns(conn: psycopg.Connection, schema: str, table: str) -> tuple[str, ...]:
    with conn.cursor() as cur:
        cur.execute(COLUMN_DISCOVERY_SQL, (schema, table))
        rows = cur.fetchall()
    return tuple(row[0] for row in rows)


def discover_source_tables(
    source_conn: psycopg.Connection,
    include_patterns: list[str],
    exclude_patterns: list[str],
    supports_relispartition: bool,
) -> list[TableSpec]:
    discovery_sql = TABLE_DISCOVERY_SQL_MODERN if supports_relispartition else TABLE_DISCOVERY_SQL_LEGACY
    with source_conn.cursor() as cur:
        cur.execute(discovery_sql)
        candidates = cur.fetchall()

    selected: list[TableSpec] = []
    for schema_name, table_name, relkind in candidates:
        table = TableSpec(schema_name, table_name, relkind=relkind, columns=())
        if include_patterns and not matches_pattern(table, include_patterns):
            continue
        if exclude_patterns and matches_pattern(table, exclude_patterns):
            continue
        columns = fetch_table_columns(source_conn, schema_name, table_name)
        if not columns:
            continue
        selected.append(TableSpec(schema_name, table_name, relkind=relkind, columns=columns))
    return selected


def order_tables_by_dependencies(
    source_conn: psycopg.Connection,
    tables: list[TableSpec],
) -> tuple[list[TableSpec], list[str]]:
    by_name = {table.fq_name: table for table in tables}
    dependencies = {name: set() for name in by_name}
    dependents: dict[str, set[str]] = {name: set() for name in by_name}

    with source_conn.cursor() as cur:
        cur.execute(FK_DEPENDENCY_SQL)
        rows = cur.fetchall()

    for child_schema, child_table, parent_schema, parent_table in rows:
        child_name = f"{child_schema}.{child_table}"
        parent_name = f"{parent_schema}.{parent_table}"
        if child_name not in by_name or parent_name not in by_name:
            continue
        if child_name == parent_name:
            continue
        if parent_name in dependencies[child_name]:
            continue
        dependencies[child_name].add(parent_name)
        dependents[parent_name].add(child_name)

    ready = sorted(name for name, needed in dependencies.items() if not needed)
    ordered: list[TableSpec] = []
    while ready:
        current = ready.pop(0)
        ordered.append(by_name[current])
        for dependent in sorted(dependents[current]):
            dependencies[dependent].discard(current)
            if not dependencies[dependent]:
                ready.append(dependent)
        ready.sort()

    cycles = sorted(name for name, needed in dependencies.items() if needed)
    if cycles:
        seen = {table.fq_name for table in ordered}
        for name in cycles:
            if name not in seen:
                ordered.append(by_name[name])
    return ordered, cycles


def fetch_source_column_definitions(source_conn: psycopg.Connection, table: TableSpec) -> list[ColumnDef]:
    with source_conn.cursor() as cur:
        cur.execute(SOURCE_COLUMN_DEFINITION_SQL, (table.schema, table.name))
        rows = cur.fetchall()

    columns: list[ColumnDef] = []
    for column_name, data_type_sql, default_sql, is_not_null, identity_kind in rows:
        columns.append(
            ColumnDef(
                name=str(column_name),
                data_type_sql=str(data_type_sql),
                default_sql=None if default_sql is None else str(default_sql),
                is_not_null=bool(is_not_null),
                identity_kind=str(identity_kind or ""),
            )
        )
    return columns


def column_definition_sql(column: ColumnDef) -> sql.Composed:
    parts: list[sql.Composable] = [
        sql.Identifier(column.name),
        sql.SQL(column.data_type_sql),
    ]
    if column.identity_kind == "a":
        parts.append(sql.SQL("GENERATED ALWAYS AS IDENTITY"))
    elif column.identity_kind == "d":
        parts.append(sql.SQL("GENERATED BY DEFAULT AS IDENTITY"))
    elif column.default_sql:
        parts.append(sql.SQL(f"DEFAULT {column.default_sql}"))
    if column.is_not_null:
        parts.append(sql.SQL("NOT NULL"))
    return sql.SQL(" ").join(parts)


def create_missing_target_table(
    source_conn: psycopg.Connection,
    target_conn: psycopg.Connection,
    table: TableSpec,
) -> None:
    if table.relkind == "p":
        raise RuntimeError(
            f"{table.fq_name}: partitioned table is missing on target. "
            "Create partitioned table structure first."
        )

    source_columns = fetch_source_column_definitions(source_conn, table)
    if not source_columns:
        raise RuntimeError(f"{table.fq_name}: source table has no columns.")

    with target_conn.cursor() as cur:
        cur.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(table.schema)))
        column_sql = sql.SQL(", ").join(column_definition_sql(column) for column in source_columns)
        create_stmt = sql.SQL("CREATE TABLE IF NOT EXISTS {} ({})").format(table_identifier(table), column_sql)
        cur.execute(create_stmt)


def add_missing_target_columns(
    source_conn: psycopg.Connection,
    target_conn: psycopg.Connection,
    table: TableSpec,
    missing_columns: list[str],
) -> None:
    source_columns = fetch_source_column_definitions(source_conn, table)
    by_name = {column.name: column for column in source_columns}
    with target_conn.cursor() as cur:
        for column_name in missing_columns:
            column = by_name.get(column_name)
            if column is None:
                raise RuntimeError(f"{table.fq_name}: source definition for column {column_name} not found.")
            alter_stmt = sql.SQL("ALTER TABLE {} ADD COLUMN {}").format(
                table_identifier(table),
                column_definition_sql(column),
            )
            cur.execute(alter_stmt)


def validate_target_schema(
    source_conn: psycopg.Connection,
    target_conn: psycopg.Connection,
    source_tables: list[TableSpec],
    auto_create_missing: bool,
    database_name: str,
) -> None:
    problems: list[str] = []
    for table in source_tables:
        target_columns = fetch_table_columns(target_conn, table.schema, table.name)
        if not target_columns:
            if auto_create_missing:
                db_log(database_name, f"Auto-creating missing table {table.fq_name}.")
                try:
                    create_missing_target_table(source_conn, target_conn, table)
                except Exception as exc:
                    problems.append(f"{table.fq_name}: missing table on target ({exc})")
                    continue
                target_columns = fetch_table_columns(target_conn, table.schema, table.name)
                if not target_columns:
                    problems.append(f"{table.fq_name}: table creation on target did not succeed")
                    continue
            else:
                problems.append(f"{table.fq_name}: missing table on target")
                continue

        missing_columns = [name for name in table.columns if name not in target_columns]
        if missing_columns:
            if auto_create_missing:
                db_log(
                    database_name,
                    f"Adding {len(missing_columns)} missing column(s) to {table.fq_name}.",
                )
                try:
                    add_missing_target_columns(source_conn, target_conn, table, missing_columns)
                except Exception as exc:
                    joined = ", ".join(missing_columns)
                    problems.append(f"{table.fq_name}: could not add missing column(s) ({joined}): {exc}")
                    continue
                target_columns = fetch_table_columns(target_conn, table.schema, table.name)
                missing_columns = [name for name in table.columns if name not in target_columns]

        if missing_columns:
            joined = ", ".join(missing_columns)
            problems.append(f"{table.fq_name}: missing column(s) on target: {joined}")

    if problems:
        preview = "\n".join(f"  - {problem}" for problem in problems[:30])
        suffix = ""
        if len(problems) > 30:
            suffix = f"\n  - ... plus {len(problems) - 30} more issue(s)"
        raise RuntimeError(f"Target schema is incompatible:\n{preview}{suffix}")


def truncate_target_tables(target_conn: psycopg.Connection, tables: list[TableSpec]) -> None:
    table_sql = sql.SQL(", ").join(table_identifier(table) for table in tables)
    statement = sql.SQL("TRUNCATE TABLE {} RESTART IDENTITY CASCADE").format(table_sql)
    with target_conn.cursor() as cur:
        cur.execute(statement)


def migrate_table(
    source_conn: psycopg.Connection,
    target_conn: psycopg.Connection,
    table: TableSpec,
    batch_size: int,
    use_identity_override: bool,
) -> int:
    cols_sql = column_list_sql(table.columns)
    select_stmt = sql.SQL("SELECT {} FROM {}").format(cols_sql, table_identifier(table))
    placeholders = sql.SQL(", ").join(sql.Placeholder() for _ in table.columns)
    if use_identity_override:
        insert_stmt = sql.SQL("INSERT INTO {} ({}) OVERRIDING SYSTEM VALUE VALUES ({})").format(
            table_identifier(table),
            cols_sql,
            placeholders,
        )
    else:
        insert_stmt = sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
            table_identifier(table),
            cols_sql,
            placeholders,
        )
    cursor_name = f"src_{abs(hash((table.schema, table.name))) % 1_000_000_000}"
    copied = 0

    with source_conn.cursor(name=cursor_name) as source_cur:
        source_cur.itersize = batch_size
        source_cur.execute(select_stmt)
        with target_conn.cursor() as target_cur:
            while True:
                rows = source_cur.fetchmany(batch_size)
                if not rows:
                    break
                target_cur.executemany(insert_stmt, rows)
                copied += len(rows)
    return copied


def sync_table_sequences(target_conn: psycopg.Connection, table: TableSpec) -> int:
    updated = 0
    for column_name in table.columns:
        with target_conn.cursor() as cur:
            cur.execute("SELECT pg_get_serial_sequence(%s, %s)", (table.fq_name, column_name))
            sequence_name = cur.fetchone()[0]
        if not sequence_name:
            continue

        max_stmt = sql.SQL("SELECT max({})::bigint FROM {}").format(
            sql.Identifier(column_name),
            table_identifier(table),
        )
        with target_conn.cursor() as cur:
            cur.execute(max_stmt)
            max_value = cur.fetchone()[0]
            if max_value is None:
                continue
            cur.execute("SELECT setval(%s::regclass, %s, true)", (sequence_name, int(max_value)))
        updated += 1
    return updated


def fetch_fingerprint(conn: psycopg.Connection, table: TableSpec) -> tuple[int, int]:
    cols_sql = column_list_sql(table.columns)
    statement = sql.SQL(
        """
        SELECT
          count(*)::bigint AS row_count,
          COALESCE(
            sum(
              ((('x' || substr(md5(row_to_json(ROW(t.*))::text), 1, 16))::bit(64)::bigint)::numeric)
            ),
            0
          ) AS checksum
        FROM (SELECT {} FROM {}) AS t
        """
    ).format(cols_sql, table_identifier(table))
    with conn.cursor() as cur:
        cur.execute(statement)
        row = cur.fetchone()
    if row is None:
        raise RuntimeError(f"Could not compute fingerprint for {table.fq_name}")
    return int(row[0]), int(row[1])


def rows_match_exactly(
    source_conn: psycopg.Connection,
    target_conn: psycopg.Connection,
    table: TableSpec,
    batch_size: int = 2_000,
) -> bool:
    def normalize_value(value: Any) -> Any:
        if value is None:
            return ("null", None)
        if isinstance(value, bool):
            return ("bool", value)
        if isinstance(value, int):
            return ("int", value)
        if isinstance(value, float):
            return ("float", repr(value))
        if isinstance(value, Decimal):
            return ("decimal", format(value, "f"))
        if isinstance(value, str):
            return ("str", value)
        if isinstance(value, bytes):
            return ("bytes", value.hex())
        if isinstance(value, bytearray):
            return ("bytes", bytes(value).hex())
        if isinstance(value, memoryview):
            return ("bytes", bytes(value).hex())
        if isinstance(value, datetime):
            if value.tzinfo is not None:
                value = value.astimezone(timezone.utc)
            return ("datetime", value.isoformat(timespec="microseconds"))
        if isinstance(value, date):
            return ("date", value.isoformat())
        if isinstance(value, dt_time):
            return ("time", value.isoformat(timespec="microseconds"))
        if isinstance(value, timedelta):
            return ("timedelta", value.total_seconds())
        if isinstance(value, UUID):
            return ("uuid", str(value))
        if isinstance(value, list):
            return ("list", tuple(normalize_value(item) for item in value))
        if isinstance(value, tuple):
            return ("tuple", tuple(normalize_value(item) for item in value))
        if isinstance(value, dict):
            normalized_items = tuple(
                (str(key), normalize_value(val))
                for key, val in sorted(value.items(), key=lambda item: str(item[0]))
            )
            return ("dict", normalized_items)
        return ("repr", repr(value))

    def row_digest(row: tuple[Any, ...]) -> bytes:
        normalized_row = tuple(normalize_value(value) for value in row)
        encoded = repr(normalized_row).encode("utf-8")
        return hashlib.sha256(encoded).digest()

    cols_sql = column_list_sql(table.columns)
    select_stmt = sql.SQL("SELECT {} FROM {}").format(
        cols_sql,
        table_identifier(table),
    )
    source_cursor_name = f"verify_src_{abs(hash((table.schema, table.name))) % 1_000_000_000}"
    target_cursor_name = f"verify_tgt_{abs(hash((table.schema, table.name, 'target'))) % 1_000_000_000}"
    digests: dict[bytes, int] = defaultdict(int)

    with source_conn.cursor(name=source_cursor_name) as source_cur, target_conn.cursor(name=target_cursor_name) as target_cur:
        source_cur.itersize = batch_size
        target_cur.itersize = batch_size
        source_cur.execute(select_stmt)
        target_cur.execute(select_stmt)

        while True:
            source_rows = source_cur.fetchmany(batch_size)
            if not source_rows:
                break
            for row in source_rows:
                digest = row_digest(row)
                digests[digest] += 1

        while True:
            target_rows = target_cur.fetchmany(batch_size)
            if not target_rows:
                break
            for row in target_rows:
                digest = row_digest(row)
                digests[digest] -= 1

    return all(count == 0 for count in digests.values())


def verify_tables(
    source_conn: psycopg.Connection,
    target_conn: psycopg.Connection,
    tables: list[TableSpec],
    progress: ProgressBar | None = None,
) -> list[str]:
    mismatches: list[str] = []
    for table in tables:
        source_count, source_checksum = fetch_fingerprint(source_conn, table)
        target_count, target_checksum = fetch_fingerprint(target_conn, table)
        has_count_or_checksum_mismatch = source_count != target_count or source_checksum != target_checksum
        if has_count_or_checksum_mismatch and not rows_match_exactly(source_conn, target_conn, table):
            mismatches.append(
                (
                    f"{table.fq_name}: "
                    f"source(count={source_count}, checksum={source_checksum}) vs "
                    f"target(count={target_count}, checksum={target_checksum})"
                )
            )
        if progress is not None:
            progress.advance(table.fq_name)
    return mismatches


def fetch_signature_set(conn: psycopg.Connection, query: str) -> set[str]:
    with conn.cursor() as cur:
        cur.execute(query)
        rows = cur.fetchall()
    return {str(row[0]) for row in rows}


def summarize_set_mismatch(
    label: str,
    source: set[str],
    target: set[str],
    limit: int = 20,
) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    missing = sorted(source - target)
    extra = sorted(target - source)
    if missing:
        preview = ", ".join(missing[:limit])
        suffix = "" if len(missing) <= limit else f", ... +{len(missing) - limit} more"
        errors.append(f"{label}: missing on target ({len(missing)}): {preview}{suffix}")
    if extra:
        preview = ", ".join(extra[:limit])
        suffix = "" if len(extra) <= limit else f", ... +{len(extra) - limit} more"
        warnings.append(f"{label}: extra on target ({len(extra)}): {preview}{suffix}")
    return errors, warnings


def parse_version_parts(version: str) -> list[int] | None:
    parts: list[int] = []
    for token in version.split("."):
        if not token.isdigit():
            return None
        parts.append(int(token))
    return parts


def compare_extension_version(source_version: str, target_version: str) -> int | None:
    if source_version == target_version:
        return 0
    source_parts = parse_version_parts(source_version)
    target_parts = parse_version_parts(target_version)
    if source_parts is None or target_parts is None:
        return None

    length = max(len(source_parts), len(target_parts))
    padded_source = source_parts + [0] * (length - len(source_parts))
    padded_target = target_parts + [0] * (length - len(target_parts))
    if padded_source == padded_target:
        return 0
    return 1 if padded_target > padded_source else -1


def fetch_extension_map(conn: psycopg.Connection) -> dict[tuple[str, str], str]:
    with conn.cursor() as cur:
        cur.execute(DB_EXTENSION_SIGNATURE_SQL)
        rows = cur.fetchall()

    result: dict[tuple[str, str], str] = {}
    for extname, extversion, schema_name in rows:
        key = (str(extname), str(schema_name))
        result[key] = str(extversion)
    return result


def verify_extension_signatures(
    source_conn: psycopg.Connection,
    target_conn: psycopg.Connection,
) -> tuple[list[str], list[str]]:
    source_ext = fetch_extension_map(source_conn)
    target_ext = fetch_extension_map(target_conn)

    errors: list[str] = []
    warnings: list[str] = []
    source_keys = set(source_ext)
    target_keys = set(target_ext)

    for key in sorted(source_keys - target_keys):
        errors.append(f"extensions: missing on target: {key[0]}::{key[1]}@{source_ext[key]}")
    for key in sorted(target_keys - source_keys):
        warnings.append(f"extensions: extra on target: {key[0]}::{key[1]}@{target_ext[key]}")

    for key in sorted(source_keys & target_keys):
        s_ver = source_ext[key]
        t_ver = target_ext[key]
        cmp = compare_extension_version(s_ver, t_ver)
        if cmp == 0:
            continue
        if cmp == 1:
            warnings.append(f"extensions: version newer on target: {key[0]}::{key[1]} source={s_ver} target={t_ver}")
        elif cmp == -1:
            errors.append(f"extensions: version older on target: {key[0]}::{key[1]} source={s_ver} target={t_ver}")
        else:
            warnings.append(f"extensions: version differs (unranked): {key[0]}::{key[1]} source={s_ver} target={t_ver}")

    return errors, warnings


def verify_database_object_signatures(
    source_conn: psycopg.Connection,
    target_conn: psycopg.Connection,
) -> tuple[list[str], list[str]]:
    source_signatures = fetch_signature_set(source_conn, DB_OBJECT_SIGNATURE_SQL)
    target_signatures = fetch_signature_set(target_conn, DB_OBJECT_SIGNATURE_SQL)
    errors, warnings = summarize_set_mismatch("database_objects", source_signatures, target_signatures)

    ext_errors, ext_warnings = verify_extension_signatures(source_conn, target_conn)
    errors.extend(ext_errors)
    warnings.extend(ext_warnings)
    return errors, warnings


def verify_global_signatures(
    source_admin_conn: psycopg.Connection,
    target_admin_conn: psycopg.Connection,
) -> tuple[list[str], list[str]]:
    source_roles = fetch_signature_set(source_admin_conn, ROLE_SIGNATURE_SQL)
    target_roles = fetch_signature_set(target_admin_conn, ROLE_SIGNATURE_SQL)
    source_tablespaces = fetch_signature_set(source_admin_conn, TABLESPACE_SIGNATURE_SQL)
    target_tablespaces = fetch_signature_set(target_admin_conn, TABLESPACE_SIGNATURE_SQL)

    role_errors, role_warnings = summarize_set_mismatch("roles", source_roles, target_roles)
    ts_errors, ts_warnings = summarize_set_mismatch("tablespaces", source_tablespaces, target_tablespaces)
    return role_errors + ts_errors, role_warnings + ts_warnings


def migrate_database(
    args: argparse.Namespace,
    policy: MigrationPolicy,
    source_dsn: str,
    target_dsn: str,
    database_name: str,
) -> int:
    with psycopg.connect(source_dsn) as source_conn:
        source_conn.execute("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")

        source_tables = discover_source_tables(
            source_conn,
            args.include,
            args.exclude,
            supports_relispartition=policy.supports_relispartition,
        )
        if not source_tables:
            db_log(database_name, "No matching source tables found.")
            return 0

        source_tables, cyclic_tables = order_tables_by_dependencies(source_conn, source_tables)
        db_log(database_name, f"Matched {len(source_tables)} source table(s).")
        if cyclic_tables:
            db_log(
                database_name,
                "Detected FK cycles in "
                f"{len(cyclic_tables)} table(s); those tables are copied after acyclic dependencies.",
            )

        if args.dry_run:
            for table in source_tables:
                if args.scope == "server":
                    print(f"{database_name}:{table.fq_name}")
                else:
                    print(table.fq_name)
            return 0

        with psycopg.connect(target_dsn) as target_conn:
            db_log(database_name, "Starting target transaction.")
            target_conn.execute("BEGIN")
            total_rows = 0
            total_sequences = 0
            table_progress = ProgressBar(f"[db:{database_name}] Copy", len(source_tables))
            try:
                db_log(database_name, "Validating target schema compatibility.")
                validate_target_schema(
                    source_conn,
                    target_conn,
                    source_tables,
                    auto_create_missing=(args.scope == "server"),
                    database_name=database_name,
                )

                target_conn.execute("SET CONSTRAINTS ALL DEFERRED")

                if args.skip_truncate:
                    db_log(database_name, "Skipping target truncate (--skip-truncate).")
                else:
                    db_log(database_name, "Truncating target tables.")
                    truncate_target_tables(target_conn, source_tables)

                for index, table in enumerate(source_tables, start=1):
                    table_start = time.time()
                    db_log(database_name, f"[{index}/{len(source_tables)}] Migrating {table.fq_name}")
                    copied = migrate_table(
                        source_conn,
                        target_conn,
                        table,
                        args.batch_size,
                        use_identity_override=policy.use_identity_override,
                    )
                    elapsed = time.time() - table_start
                    total_rows += copied
                    db_log(
                        database_name,
                        f"[{index}/{len(source_tables)}] {table.fq_name}: copied {copied} row(s) in {elapsed:.2f}s",
                    )
                    table_progress.advance(table.fq_name)

                for table in source_tables:
                    total_sequences += sync_table_sequences(target_conn, table)
                db_log(database_name, f"Adjusted {total_sequences} owned sequence value(s).")

                target_conn.commit()
                table_progress.finish("copy complete")
                db_log(database_name, f"Committed target transaction. Total copied rows: {total_rows}.")
            except Exception:
                table_progress.finish("copy aborted")
                target_conn.rollback()
                raise

            if args.no_verify:
                db_log(database_name, "Verification skipped (--no-verify).")
            else:
                db_log(database_name, "Running post-migration verification.")
                verify_progress = ProgressBar(f"[db:{database_name}] Verify", len(source_tables))
                mismatches = verify_tables(source_conn, target_conn, source_tables, progress=verify_progress)
                verify_progress.finish("verify complete")
                if mismatches:
                    db_log(database_name, f"Verification failed: {len(mismatches)} table(s) differ.")
                    for detail in mismatches[:30]:
                        db_log(database_name, f"  - {detail}")
                    if len(mismatches) > 30:
                        db_log(database_name, f"  - ... plus {len(mismatches) - 30} more mismatch(es)")
                    return 2
                db_log(database_name, "Verification passed for all migrated tables.")

    return 0


def verify_database_after_restore(
    args: argparse.Namespace,
    policy: MigrationPolicy,
    source_dsn: str,
    target_dsn: str,
    database_name: str,
) -> int:
    if args.no_verify:
        db_log(database_name, "Verification skipped (--no-verify).")
        return 0

    with psycopg.connect(source_dsn) as source_conn, psycopg.connect(target_dsn) as target_conn:
        source_conn.execute("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        target_conn.execute("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        return verify_database_after_restore_with_connections(
            args=args,
            policy=policy,
            source_conn=source_conn,
            target_conn=target_conn,
            database_name=database_name,
        )


def verify_database_after_restore_with_connections(
    args: argparse.Namespace,
    policy: MigrationPolicy,
    source_conn: psycopg.Connection,
    target_conn: psycopg.Connection,
    database_name: str,
) -> int:
    if args.no_verify:
        db_log(database_name, "Verification skipped (--no-verify).")
        return 0

    db_log(database_name, "Checking schema/object parity.")
    object_errors, object_warnings = verify_database_object_signatures(source_conn, target_conn)
    if object_warnings:
        db_log(database_name, f"Object parity warnings: {len(object_warnings)} issue(s).")
        for issue in object_warnings:
            db_log(database_name, f"  - {issue}")
    if object_errors:
        db_log(database_name, f"Object parity failed: {len(object_errors)} issue(s).")
        for issue in object_errors:
            db_log(database_name, f"  - {issue}")
        return 2

    source_tables = discover_source_tables(
        source_conn,
        args.include,
        args.exclude,
        supports_relispartition=policy.supports_relispartition,
    )
    if not source_tables:
        db_log(database_name, "No matching source tables found for verification.")
        return 0

    db_log(database_name, "Running post-restore verification.")
    verify_progress = ProgressBar(f"[db:{database_name}] Verify", len(source_tables))
    mismatches = verify_tables(source_conn, target_conn, source_tables, progress=verify_progress)
    verify_progress.finish("verify complete")
    if mismatches:
        db_log(database_name, f"Verification failed: {len(mismatches)} table(s) differ.")
        for detail in mismatches[:30]:
            db_log(database_name, f"  - {detail}")
        if len(mismatches) > 30:
            db_log(database_name, f"  - ... plus {len(mismatches) - 30} more mismatch(es)")
        return 2
    db_log(database_name, "Verification passed for all migrated tables.")
    return 0


def replicate_globals_with_pg_dumpall(source_admin_dsn: str, target_admin_dsn: str, temp_dir: Path) -> None:
    globals_sql = temp_dir / "globals.sql"
    run_command(
        [
            "pg_dumpall",
            "--globals-only",
            "--no-role-passwords",
            "--quote-all-identifiers",
            "--file",
            str(globals_sql),
            "--dbname",
            source_admin_dsn,
        ],
        "Exporting global objects",
    )
    log("Importing global objects (non-fatal conflicts like 'already exists' are tolerated).")
    completed = subprocess.run(
        [
            "psql",
            "--dbname",
            target_admin_dsn,
            "--file",
            str(globals_sql),
        ],
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        stdout = (completed.stdout or "").strip()
        detail = " | ".join(line for line in [stderr.splitlines()[-1] if stderr else "", stdout.splitlines()[-1] if stdout else ""] if line)
        raise RuntimeError(f"Importing global objects failed with exit code {completed.returncode}: {detail or 'no output captured'}")

    stderr_text = completed.stderr or ""
    if "already exists" in stderr_text:
        log("Global import completed with existing-object conflicts (continuing).")


def safe_dump_filename(database_name: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in database_name)


def replicate_database_with_pg_dump(
    args: argparse.Namespace,
    policy: MigrationPolicy,
    source_dsn: str,
    target_dsn: str,
    database_name: str,
    temp_dir: Path,
) -> int:
    dump_path = temp_dir / f"{safe_dump_filename(database_name)}.dump"
    with psycopg.connect(source_dsn) as source_conn:
        source_conn.execute("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        with source_conn.cursor() as cur:
            cur.execute("SELECT pg_export_snapshot()")
            snapshot_id = str(cur.fetchone()[0])

        db_log(database_name, f"Creating logical dump archive (snapshot: {snapshot_id}).")
        run_command(
            [
                "pg_dump",
                "--format=custom",
                "--file",
                str(dump_path),
                "--snapshot",
                snapshot_id,
                source_dsn,
            ],
            f"[db:{database_name}] pg_dump",
        )

        db_log(database_name, "Restoring dump to target.")
        run_command(
            [
                "pg_restore",
                "--clean",
                "--if-exists",
                "--dbname",
                target_dsn,
                str(dump_path),
            ],
            f"[db:{database_name}] pg_restore",
        )

        with psycopg.connect(target_dsn) as target_conn:
            target_conn.execute("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            return verify_database_after_restore_with_connections(
                args=args,
                policy=policy,
                source_conn=source_conn,
                target_conn=target_conn,
                database_name=database_name,
            )


def run_table_copy_workflow(
    args: argparse.Namespace,
    policy: MigrationPolicy,
    source_admin_conn: psycopg.Connection,
    target_admin_conn: psycopg.Connection,
) -> int:
    if args.scope == "database":
        source_dbname = dsn_database_name(args.source_dsn)
        target_dbname = dsn_database_name(args.target_dsn)
        if source_dbname != target_dbname:
            log(
                "Warning: source/target database names differ "
                f"({source_dbname} -> {target_dbname})."
            )
        return migrate_database(args, policy, args.source_dsn, args.target_dsn, source_dbname)

    source_databases = list_source_databases(source_admin_conn)
    if not source_databases:
        log("No source databases found.")
        return 0

    log(f"Server scope selected. Found {len(source_databases)} source database(s).")
    verification_failed = False
    result = 0
    db_progress = ProgressBar("[server] Databases", len(source_databases))

    # CREATE DATABASE cannot run inside a transaction block.
    source_admin_conn.rollback()
    target_admin_conn.rollback()
    source_admin_conn.autocommit = True
    target_admin_conn.autocommit = True

    for dbname in source_databases:
        if not target_database_exists(target_admin_conn, dbname):
            if args.dry_run:
                db_log(dbname, "Target database missing; would create.")
            else:
                db_log(dbname, "Target database missing. Creating.")
                create_target_database_from_source(source_admin_conn, target_admin_conn, dbname)

        db_source_dsn = dsn_with_database(args.source_dsn, dbname)
        db_target_dsn = dsn_with_database(args.target_dsn, dbname)
        db_result = migrate_database(args, policy, db_source_dsn, db_target_dsn, dbname)
        db_progress.advance(dbname)
        if db_result == 1:
            result = 1
            break
        if db_result == 2:
            verification_failed = True

    db_progress.finish("database pass complete")
    if result == 0 and verification_failed:
        result = 2
    return result


def run_pg_dump_workflow(
    args: argparse.Namespace,
    policy: MigrationPolicy,
    source_admin_conn: psycopg.Connection,
    target_admin_conn: psycopg.Connection,
) -> int:
    required = ["pg_dump", "pg_restore"]
    if args.scope == "server" and not args.skip_globals:
        required.extend(["pg_dumpall", "psql"])
    require_binaries(required)

    if args.scope == "database":
        dbname = dsn_database_name(args.source_dsn)
        target_dbname = dsn_database_name(args.target_dsn)
        if dbname != target_dbname:
            log(f"Warning: source/target database names differ ({dbname} -> {target_dbname}).")
        if args.dry_run:
            db_log(dbname, "Dry-run: would perform pg_dump/pg_restore replication.")
            return 0

        with tempfile.TemporaryDirectory(prefix="postgres_updater_") as tmp:
            temp_dir = Path(tmp)
            return replicate_database_with_pg_dump(
                args=args,
                policy=policy,
                source_dsn=args.source_dsn,
                target_dsn=args.target_dsn,
                database_name=dbname,
                temp_dir=temp_dir,
            )

    source_databases = list_source_databases(source_admin_conn)
    if not source_databases:
        log("No source databases found.")
        return 0

    log(f"Server scope selected. Found {len(source_databases)} source database(s).")
    if args.dry_run:
        if not args.skip_globals:
            log("Dry-run: would replicate global objects (roles/tablespaces).")
        for dbname in source_databases:
            db_log(dbname, "Dry-run: would replicate full database via pg_dump/pg_restore.")
        return 0

    source_admin_conn.rollback()
    target_admin_conn.rollback()
    source_admin_conn.autocommit = True
    target_admin_conn.autocommit = True

    with tempfile.TemporaryDirectory(prefix="postgres_updater_") as tmp:
        temp_dir = Path(tmp)
        if not args.skip_globals:
            replicate_globals_with_pg_dumpall(
                source_admin_dsn=maintenance_dsn(args.source_dsn),
                target_admin_dsn=maintenance_dsn(args.target_dsn),
                temp_dir=temp_dir,
            )
        else:
            log("Skipping global object replication (--skip-globals).")

        verification_failed = False
        result = 0
        db_progress = ProgressBar("[server] Databases", len(source_databases))
        for dbname in source_databases:
            if not target_database_exists(target_admin_conn, dbname):
                db_log(dbname, "Target database missing. Creating.")
                create_target_database_from_source(source_admin_conn, target_admin_conn, dbname)

            db_source_dsn = dsn_with_database(args.source_dsn, dbname)
            db_target_dsn = dsn_with_database(args.target_dsn, dbname)
            db_result = replicate_database_with_pg_dump(
                args=args,
                policy=policy,
                source_dsn=db_source_dsn,
                target_dsn=db_target_dsn,
                database_name=dbname,
                temp_dir=temp_dir,
            )
            db_progress.advance(dbname)
            if db_result == 1:
                result = 1
                break
            if db_result == 2:
                verification_failed = True
        db_progress.finish("database pass complete")
        if not args.skip_globals:
            global_errors, global_warnings = verify_global_signatures(source_admin_conn, target_admin_conn)
            if global_warnings:
                log(f"Global parity warnings: {len(global_warnings)} issue(s).")
                for issue in global_warnings:
                    log(f"  - {issue}")
            if global_errors:
                log(f"Global parity failed: {len(global_errors)} issue(s).")
                for issue in global_errors:
                    log(f"  - {issue}")
                verification_failed = True
            else:
                log("Global parity passed (roles/tablespaces).")
        if result == 0 and verification_failed:
            result = 2
        return result


def run_preflight(
    args: argparse.Namespace,
    policy: MigrationPolicy,
    source_admin_conn: psycopg.Connection,
    target_admin_conn: psycopg.Connection,
) -> int:
    ok = True
    warnings: list[str] = []

    log("Preflight: checking required tools and permissions.")
    required = ["pg_dump", "pg_restore"] if args.engine == "pg_dump" else []
    if args.engine == "pg_dump" and args.scope == "server" and not args.skip_globals:
        required.extend(["pg_dumpall", "psql"])
    if required:
        require_binaries(required)
        log(f"Preflight: required binaries found ({', '.join(required)}).")

    source_databases = [dsn_database_name(args.source_dsn)]
    target_databases = [dsn_database_name(args.target_dsn)]
    if args.scope == "server":
        source_databases = list_source_databases(source_admin_conn)
        target_databases = list_target_databases(target_admin_conn)
        log(f"Preflight: source has {len(source_databases)} non-template database(s).")
        missing = sorted(set(source_databases) - set(target_databases))
        can_create_db, can_create_role = fetch_role_capabilities(target_admin_conn)

        if missing and not can_create_db:
            ok = False
            log(
                "Preflight FAIL: target is missing database(s) and current user lacks CREATEDB: "
                + ", ".join(missing[:20])
            )
        elif missing:
            log(f"Preflight: target is missing {len(missing)} database(s); will create during run.")
        else:
            log("Preflight: all source databases already exist on target.")

        if args.engine == "pg_dump" and not args.skip_globals and not can_create_role:
            warnings.append(
                "Global replication enabled but target user lacks CREATEROLE; role restore may fail."
            )

    if args.scope == "database":
        source_db = source_databases[0]
        target_db = target_databases[0]
        if source_db != target_db:
            warnings.append(f"Source database '{source_db}' differs from target database '{target_db}'.")

    if policy.mode == "major-upgrade-copy":
        log(f"Preflight: major upgrade path detected ({policy.source.major} -> {policy.target.major}).")
    else:
        log(f"Preflight: same-major path detected ({policy.source.major}).")

    if warnings:
        for warning in warnings:
            log(f"Preflight WARN: {warning}")

    if not ok:
        return 1

    log("Preflight OK: checks passed.")
    return 0


def run_verify_only(
    args: argparse.Namespace,
    policy: MigrationPolicy,
    source_admin_conn: psycopg.Connection,
    target_admin_conn: psycopg.Connection,
) -> int:
    if args.scope == "database":
        dbname = dsn_database_name(args.source_dsn)
        target_dbname = dsn_database_name(args.target_dsn)
        if dbname != target_dbname:
            log(f"Warning: source/target database names differ ({dbname} -> {target_dbname}).")
        return verify_database_after_restore(args, policy, args.source_dsn, args.target_dsn, dbname)

    source_databases = list_source_databases(source_admin_conn)
    if not source_databases:
        log("No source databases found.")
        return 0

    global_errors, global_warnings = verify_global_signatures(source_admin_conn, target_admin_conn)
    if global_warnings:
        log(f"Global parity warnings: {len(global_warnings)} issue(s).")
        for issue in global_warnings:
            log(f"  - {issue}")
    if global_errors:
        log(f"Global parity failed: {len(global_errors)} issue(s).")
        for issue in global_errors:
            log(f"  - {issue}")
        return 2
    log("Global parity passed (roles/tablespaces).")

    target_databases = set(list_target_databases(target_admin_conn))
    log(f"Server scope selected. Found {len(source_databases)} source database(s).")

    verification_failed = False
    result = 0
    db_progress = ProgressBar("[server] Verify DBs", len(source_databases))

    for dbname in source_databases:
        if dbname not in target_databases:
            db_log(dbname, "Verification failed: target database is missing.")
            verification_failed = True
            db_progress.advance(dbname)
            continue

        db_source_dsn = dsn_with_database(args.source_dsn, dbname)
        db_target_dsn = dsn_with_database(args.target_dsn, dbname)
        db_result = verify_database_after_restore(args, policy, db_source_dsn, db_target_dsn, dbname)
        db_progress.advance(dbname)
        if db_result == 1:
            result = 1
            break
        if db_result == 2:
            verification_failed = True

    db_progress.finish("verification pass complete")
    if result == 0 and verification_failed:
        result = 2
    return result


def run(args: argparse.Namespace) -> int:
    args, config_exists = resolve_args_from_config(args)
    validate_args(args)

    start_time = time.time()
    with psycopg.connect(args.source_dsn) as source_admin_conn, psycopg.connect(args.target_dsn) as target_admin_conn:
        if config_exists:
            log(f"Loaded config file: {args.config}")
        log(f"Using replication scope: {args.scope}.")

        source_version = detect_server_version(source_admin_conn)
        target_version = detect_server_version(target_admin_conn)
        policy = build_policy(source_version, target_version)

        log(
            "Detected versions: "
            f"source={source_version.version_text} (major {source_version.major}), "
            f"target={target_version.version_text} (major {target_version.major})."
        )
        if policy.mode == "major-upgrade-copy":
            log(
                "Using cross-major copy mode. "
                f"Major upgrade path: {source_version.major} -> {target_version.major}."
            )
        else:
            log("Using same-major copy mode.")
        if source_version.major == target_version.major and source_version.version_num > target_version.version_num:
            log(
                "Warning: target patch/minor appears older than source within same major. "
                "Copy continues, but feature mismatches can fail at runtime."
            )

        if args.command == "preflight":
            result = run_preflight(args, policy, source_admin_conn, target_admin_conn)
            elapsed_total = time.time() - start_time
            log(f"Done in {elapsed_total:.2f}s.")
            return result
        if args.command == "verify":
            result = run_verify_only(args, policy, source_admin_conn, target_admin_conn)
            elapsed_total = time.time() - start_time
            log(f"Done in {elapsed_total:.2f}s.")
            return result

        log(f"Using replication engine: {args.engine}.")
        if args.engine == "table_copy":
            result = run_table_copy_workflow(args, policy, source_admin_conn, target_admin_conn)
        else:
            result = run_pg_dump_workflow(args, policy, source_admin_conn, target_admin_conn)

    elapsed_total = time.time() - start_time
    log(f"Done in {elapsed_total:.2f}s.")
    return result


def main() -> int:
    args = parse_args()
    try:
        return run(args)
    except Exception as exc:
        log(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
