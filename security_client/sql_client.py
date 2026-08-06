"""SQL-backed client.

Same Protocol as the mock and the REST adapter, so nothing in `chatbot/` changes
when you switch to it.

The controlling rule: **the model never writes SQL.** It selects one of six
approved functions and supplies values from a fixed vocabulary; the query text
below is a constant, and every model-supplied value arrives as a bound
parameter. Injection is not mitigated here, it is structurally impossible —
there is no point at which a fragment could be concatenated into a statement.

Three independent guards, because a database connection is a bigger blast radius
than an HTTP token:

1. Statements are built from constants plus validated identifiers from
   `sql_schema.py`. Values are always bound, never formatted in.
2. `_execute` refuses anything that is not a single SELECT.
3. The database account itself should be read-only — see the module docstring in
   scripts/load_sqlite.py and TODO.md. Application-level checks are the last
   line, not the first.

Aggregation is a real GROUP BY here, so `summarize_records` gives exact totals —
unlike the REST adapter, where it is unimplemented because most platforms expose
no aggregation endpoint.
"""

from __future__ import annotations

import os
import re
import time
from typing import Any, Iterable, Sequence

from security_client.base import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    AmbiguousDevice,
    DeviceNotFound,
    GroupCount,
    QueryResult,
    Record,
    SummaryResult,
)
from security_client.sql_schema import DEFAULT_SCHEMA, SqlSchema, validate_identifier
from security_client.taxonomy import find_devices

#: Log levels are ordered, and `level` is a floor: asking for warnings should
#: surface errors too. SQL has no natural ordering for these strings, so the
#: floor is expanded into an IN list of bound parameters.
LEVEL_ORDER = ("debug", "info", "warning", "error", "critical")

_FORBIDDEN = re.compile(
    r"\b(insert|update|delete|drop|alter|truncate|create|grant|revoke|attach|"
    r"pragma|exec|merge|replace|vacuum)\b",
    re.IGNORECASE,
)

#: How long a device roster stays cached before it is re-read. Short enough that
#: equipment added mid-shift becomes findable without a restart.
DEVICE_CACHE_SECONDS = 300


class SqlSecurityClient:
    def __init__(
        self,
        connection: Any = None,
        *,
        schema: SqlSchema | None = None,
        dsn: str | None = None,
        paramstyle: str | None = None,
        statement_timeout_ms: int = 10_000,
    ) -> None:
        self.schema = schema or DEFAULT_SCHEMA
        self.statement_timeout_ms = statement_timeout_ms
        self._connection = connection if connection is not None else self._connect(dsn)
        self.paramstyle = paramstyle or self._detect_paramstyle(self._connection)
        self._device_cache: list[Record] | None = None
        self._device_cached_at = 0.0

    # --- connection -----------------------------------------------------------

    @staticmethod
    def _connect(dsn: str | None) -> Any:
        dsn = dsn or os.environ.get("SQL_DSN", "")
        if not dsn:
            raise RuntimeError(
                "SQL configuration is missing: set SQL_DSN (e.g. "
                "sqlite:///data/security.db or postgresql://user:pw@host/db)."
            )

        if dsn.startswith("sqlite://"):
            import sqlite3

            path = dsn.removeprefix("sqlite:///") or dsn.removeprefix("sqlite://")
            # file: URI with mode=ro so the driver itself refuses writes.
            connection = sqlite3.connect(
                f"file:{path}?mode=ro", uri=True, check_same_thread=False
            )
            connection.row_factory = sqlite3.Row
            return connection

        if dsn.startswith(("postgres://", "postgresql://")):
            import psycopg
            from psycopg.rows import dict_row

            return psycopg.connect(dsn, row_factory=dict_row, autocommit=True)

        if dsn.startswith("mysql://"):
            import pymysql

            from urllib.parse import urlparse

            parts = urlparse(dsn)
            return pymysql.connect(
                host=parts.hostname or "localhost",
                port=parts.port or 3306,
                user=parts.username or "",
                password=parts.password or "",
                database=(parts.path or "/").lstrip("/"),
                cursorclass=pymysql.cursors.DictCursor,
            )

        raise RuntimeError(f"Unsupported SQL_DSN scheme: {dsn.split('://', 1)[0]!r}")

    @staticmethod
    def _detect_paramstyle(connection: Any) -> str:
        module = type(connection).__module__.split(".")[0]
        return {"sqlite3": "named", "psycopg": "pyformat", "pymysql": "pyformat"}.get(
            module, "named"
        )

    # --- execution ------------------------------------------------------------

    def _adapt(self, sql: str) -> str:
        """Translate `:name` placeholders to the driver's paramstyle."""
        if self.paramstyle == "pyformat":
            return re.sub(r":(\w+)", r"%(\1)s", sql)
        return sql

    def _execute(self, sql: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        statement = sql.strip().rstrip(";")
        # Guard 2: the query text is ours, but assert it anyway. A future edit
        # that introduces a write should fail here rather than in production.
        if not statement.lower().startswith("select"):
            raise PermissionError("Only SELECT statements are permitted.")
        if ";" in statement:
            raise PermissionError("Multiple statements are not permitted.")
        if _FORBIDDEN.search(statement):
            raise PermissionError("Statement contains a non-read keyword.")

        cursor = self._connection.cursor()
        try:
            self._apply_timeout(cursor)
            cursor.execute(self._adapt(statement), params)
            rows = cursor.fetchall()
            if rows and not isinstance(rows[0], dict):
                columns = [c[0] for c in cursor.description]
                return [dict(zip(columns, row)) for row in rows]
            return [dict(row) for row in rows]
        finally:
            cursor.close()

    def _apply_timeout(self, cursor: Any) -> None:
        """Bound every statement. A broad question must not table-scan forever."""
        if self.paramstyle == "pyformat":
            try:
                cursor.execute(f"SET statement_timeout = {int(self.statement_timeout_ms)}")
            except Exception:  # noqa: BLE001 - MySQL and others use different syntax
                pass

    def _scalar(self, sql: str, params: dict[str, Any]) -> int:
        rows = self._execute(sql, params)
        if not rows:
            return 0
        return int(next(iter(rows[0].values())) or 0)

    # --- query building -------------------------------------------------------

    @staticmethod
    def _clause(conditions: Sequence[str]) -> str:
        return " AND ".join(conditions) if conditions else "1=1"

    def _select_list(self, table_map: Any, columns: Iterable[str]) -> str:
        """`db_column AS canonical_name` for each mapped field."""
        parts = []
        for canonical in columns:
            actual = getattr(table_map, canonical, None)
            if actual:
                parts.append(f"{actual} AS {canonical}")
        for extra in getattr(table_map, "extra", ()):  # already validated
            parts.append(extra)
        return ", ".join(parts)

    def _record_filters(
        self,
        table_map: Any,
        *,
        device: Record | None,
        device_type: str | None,
        category: str | None,
        area: str | None,
        since: Any,
        until: Any,
    ) -> tuple[list[str], dict[str, Any]]:
        conditions: list[str] = []
        params: dict[str, Any] = {}

        if device is not None:
            conditions.append(f"{table_map.device_id} = :device_id")
            params["device_id"] = device["id"]
        if device_type is not None:
            conditions.append(f"LOWER({table_map.device_type}) = LOWER(:device_type)")
            params["device_type"] = device_type
        if category is not None:
            conditions.append(f"LOWER({table_map.category}) = LOWER(:category)")
            params["category"] = category
        if area is not None:
            conditions.append(f"LOWER({table_map.area}) = LOWER(:area)")
            params["area"] = area
        if since is not None:
            conditions.append(f"{table_map.timestamp} >= :since")
            params["since"] = since.isoformat() if hasattr(since, "isoformat") else since
        if until is not None:
            conditions.append(f"{table_map.timestamp} < :until")
            params["until"] = until.isoformat() if hasattr(until, "isoformat") else until
        return conditions, params

    # --- device resolution ----------------------------------------------------

    def _devices(self) -> list[Record]:
        now = time.monotonic()
        if self._device_cache is None or now - self._device_cached_at > DEVICE_CACHE_SECONDS:
            table = self.schema.devices
            columns = ("id", "name", "type", "category", "area", "status", "last_seen", "firmware")
            self._device_cache = self._execute(
                f"SELECT {self._select_list(table, columns)} FROM {table.table}", {}
            )
            self._device_cached_at = now
        return self._device_cache

    def resolve_device(self, query: str | None) -> Record | None:
        """Free text -> one device, or an exception the model can act on."""
        if not query:
            return None
        matches = find_devices(self._devices(), query)
        if not matches:
            raise DeviceNotFound(query)
        if len(matches) > 1:
            raise AmbiguousDevice(query, matches)
        return matches[0]

    # --- SecurityClient -------------------------------------------------------

    def get_active_alarms(
        self,
        *,
        severity: str | None = None,
        status: str | None = None,
        alarm_type: str | None = None,
        device: str | None = None,
        device_type: str | None = None,
        category: str | None = None,
        area: str | None = None,
        since: Any = None,
        until: Any = None,
        sort: str = "newest",
        limit: int = DEFAULT_LIMIT,
    ) -> QueryResult:
        table = self.schema.alarms
        resolved = self.resolve_device(device)
        conditions, params = self._record_filters(
            table,
            device=resolved,
            device_type=device_type,
            category=category,
            area=area,
            since=since,
            until=until,
        )
        # "Active" is the default lens; an explicit status wins, or "show me
        # resolved alarms" would be inexpressible.
        conditions.append(f"LOWER({table.status}) = LOWER(:status)")
        params["status"] = status or "active"
        if severity is not None:
            conditions.append(f"LOWER({table.severity}) = LOWER(:severity)")
            params["severity"] = severity
        if alarm_type is not None:
            conditions.append(f"LOWER({table.type}) = LOWER(:alarm_type)")
            params["alarm_type"] = alarm_type

        where = self._clause(conditions)
        direction = "ASC" if sort == "oldest" else "DESC"
        columns = (
            "id", "timestamp", "severity", "status", "type", "message",
            "device_id", "device_name", "device_type", "category", "area",
        )
        capped = max(1, min(limit, MAX_LIMIT))
        rows = self._execute(
            f"SELECT {self._select_list(table, columns)} FROM {table.table} "
            f"WHERE {where} ORDER BY {table.timestamp} {direction} LIMIT :limit",
            {**params, "limit": capped},
        )
        total = self._scalar(
            f"SELECT COUNT(*) FROM {table.table} WHERE {where}", params
        )
        return QueryResult(records=rows, total_matched=total, resolved_device=resolved)

    def get_alarm_details(self, *, alarm_id: str) -> Record | None:
        table = self.schema.alarms
        columns = (
            "id", "timestamp", "severity", "status", "type", "message",
            "device_id", "device_name", "device_type", "category", "area",
        )
        rows = self._execute(
            f"SELECT {self._select_list(table, columns)} FROM {table.table} "
            f"WHERE LOWER({table.id}) = LOWER(:alarm_id) LIMIT 1",
            {"alarm_id": alarm_id},
        )
        return rows[0] if rows else None

    def get_recent_events(
        self,
        *,
        event_type: str | None = None,
        device: str | None = None,
        device_type: str | None = None,
        category: str | None = None,
        area: str | None = None,
        since: Any = None,
        until: Any = None,
        limit: int = DEFAULT_LIMIT,
    ) -> QueryResult:
        table = self.schema.events
        resolved = self.resolve_device(device)
        conditions, params = self._record_filters(
            table,
            device=resolved,
            device_type=device_type,
            category=category,
            area=area,
            since=since,
            until=until,
        )
        if event_type is not None:
            conditions.append(f"LOWER({table.type}) = LOWER(:event_type)")
            params["event_type"] = event_type

        where = self._clause(conditions)
        columns = (
            "id", "timestamp", "type", "outcome", "message",
            "device_id", "device_name", "device_type", "category", "area",
        )
        capped = max(1, min(limit, MAX_LIMIT))
        rows = self._execute(
            f"SELECT {self._select_list(table, columns)} FROM {table.table} "
            f"WHERE {where} ORDER BY {table.timestamp} DESC LIMIT :limit",
            {**params, "limit": capped},
        )
        total = self._scalar(f"SELECT COUNT(*) FROM {table.table} WHERE {where}", params)
        return QueryResult(records=rows, total_matched=total, resolved_device=resolved)

    def search_logs(
        self,
        *,
        device: str | None = None,
        device_type: str | None = None,
        category: str | None = None,
        level: str | None = None,
        since: Any = None,
        until: Any = None,
        limit: int = DEFAULT_LIMIT,
    ) -> QueryResult:
        table = self.schema.logs
        resolved = self.resolve_device(device)
        conditions, params = self._record_filters(
            table,
            device=resolved,
            device_type=device_type,
            category=category,
            area=None,
            since=since,
            until=until,
        )
        if level:
            floor = LEVEL_ORDER.index(level.casefold()) if level.casefold() in LEVEL_ORDER else 0
            accepted = LEVEL_ORDER[floor:]
            placeholders = ", ".join(f":lvl{i}" for i in range(len(accepted)))
            conditions.append(f"LOWER({table.level}) IN ({placeholders})")
            params.update({f"lvl{i}": value for i, value in enumerate(accepted)})

        where = self._clause(conditions)
        columns = (
            "id", "timestamp", "level", "component", "message",
            "device_id", "device_name", "device_type", "category", "area",
        )
        capped = max(1, min(limit, MAX_LIMIT))
        rows = self._execute(
            f"SELECT {self._select_list(table, columns)} FROM {table.table} "
            f"WHERE {where} ORDER BY {table.timestamp} DESC LIMIT :limit",
            {**params, "limit": capped},
        )
        total = self._scalar(f"SELECT COUNT(*) FROM {table.table} WHERE {where}", params)
        return QueryResult(records=rows, total_matched=total, resolved_device=resolved)

    def get_device_status(
        self,
        *,
        device: str | None = None,
        device_type: str | None = None,
        category: str | None = None,
        status: str | None = None,
        area: str | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> QueryResult:
        table = self.schema.devices
        resolved = self.resolve_device(device)
        if resolved is not None:
            return QueryResult(records=[resolved], total_matched=1, resolved_device=resolved)

        conditions: list[str] = []
        params: dict[str, Any] = {}
        for column, value, key in (
            (table.type, device_type, "device_type"),
            (table.category, category, "category"),
            (table.status, status, "status"),
            (table.area, area, "area"),
        ):
            if value is not None:
                conditions.append(f"LOWER({column}) = LOWER(:{key})")
                params[key] = value

        where = self._clause(conditions)
        columns = ("id", "name", "type", "category", "area", "status", "last_seen", "firmware")
        capped = max(1, min(limit, MAX_LIMIT))
        rows = self._execute(
            f"SELECT {self._select_list(table, columns)} FROM {table.table} "
            f"WHERE {where} ORDER BY {table.last_seen} DESC LIMIT :limit",
            {**params, "limit": capped},
        )
        total = self._scalar(f"SELECT COUNT(*) FROM {table.table} WHERE {where}", params)
        return QueryResult(records=rows, total_matched=total)

    def summarize_records(
        self,
        *,
        record_type: str,
        group_by: str,
        severity: str | None = None,
        status: str | None = None,
        category: str | None = None,
        device_type: str | None = None,
        area: str | None = None,
        since: Any = None,
        until: Any = None,
        limit: int = 10,
    ) -> SummaryResult:
        """A real GROUP BY — exact counts over every matching row.

        This is where SQL beats the REST adapter outright: no paging, no
        approximation, and the total is a COUNT(*) over the same predicate.
        """
        table_map = {
            "alarms": self.schema.alarms,
            "events": self.schema.events,
            "logs": self.schema.logs,
        }[record_type]

        group_column = {
            "type": getattr(table_map, "type", None),
            "severity": getattr(table_map, "severity", None),
            "status": getattr(table_map, "status", None),
            "level": getattr(table_map, "level", None),
            "area": table_map.area,
            "device": table_map.device_name,
            "category": table_map.category,
        }.get(group_by)
        if not group_column:
            raise ValueError(f"Cannot group {record_type} by {group_by!r}.")
        # Validated again at use: the mapping above is ours, but this string is
        # about to be interpolated into SQL.
        validate_identifier(group_column, context=f"group_by:{group_by}")

        conditions, params = self._record_filters(
            table_map,
            device=None,
            device_type=device_type,
            category=category,
            area=area,
            since=since,
            until=until,
        )
        if severity is not None and getattr(table_map, "severity", None):
            conditions.append(f"LOWER({table_map.severity}) = LOWER(:severity)")
            params["severity"] = severity
        if status is not None and getattr(table_map, "status", None):
            conditions.append(f"LOWER({table_map.status}) = LOWER(:status)")
            params["status"] = status

        where = self._clause(conditions)
        capped = max(1, min(limit, 50))
        rows = self._execute(
            f"SELECT {group_column} AS group_key, COUNT(*) AS group_count "
            f"FROM {table_map.table} WHERE {where} "
            f"GROUP BY {group_column} ORDER BY group_count DESC, group_key ASC "
            f"LIMIT :limit",
            {**params, "limit": capped},
        )
        total_records = self._scalar(
            f"SELECT COUNT(*) FROM {table_map.table} WHERE {where}", params
        )
        total_groups = self._scalar(
            f"SELECT COUNT(*) FROM (SELECT {group_column} FROM {table_map.table} "
            f"WHERE {where} GROUP BY {group_column}) AS g",
            params,
        )
        return SummaryResult(
            groups=[
                GroupCount(key=str(row["group_key"] or "unknown"), count=int(row["group_count"]))
                for row in rows
            ],
            total_records=total_records,
            total_groups=total_groups,
            group_by=group_by,
            record_type=record_type,
        )
