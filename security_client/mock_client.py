"""In-memory client backed by the JSON fixtures in data/.

Implements the same Protocol as the real adapter, so the controller cannot tell
them apart. Every filter, cap, sort, and count applied here must also be applied
by RealSecurityApiClient — if the two disagree, the mock stops being a useful
test surface.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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
from security_client.taxonomy import find_devices

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

_LEVEL_ORDER = {"debug": 0, "info": 1, "warning": 2, "error": 3, "critical": 4}

#: Which record field each group_by key reads. `device` groups by display name,
#: because a ranked list of IDs is useless to an operator.
_GROUP_FIELD = {
    "type": "type",
    "severity": "severity",
    "status": "status",
    "area": "area",
    "device": "device_name",
    "category": "category",
    "level": "level",
}


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value).astimezone(UTC)


def _in_window(value: str | None, since: datetime | None, until: datetime | None) -> bool:
    if since is None and until is None:
        return True
    moment = _parse(value)
    if moment is None:
        return False
    if since is not None and moment < since:
        return False
    if until is not None and moment >= until:
        return False
    return True


def _eq(record: Record, key: str, wanted: Any) -> bool:
    """Case-insensitive equality for strings, exact for everything else."""
    if wanted is None:
        return True
    actual = record.get(key)
    if isinstance(actual, str) and isinstance(wanted, str):
        return actual.casefold() == wanted.casefold()
    return actual == wanted


class MockSecurityClient:
    def __init__(self, data_dir: Path | None = None) -> None:
        self.data_dir = data_dir or DATA_DIR
        self.alarms = self._load("alarms")
        self.events = self._load("events")
        self.logs = self._load("logs")
        self.devices = self._load("devices")

    def _load(self, name: str) -> list[Record]:
        path = self.data_dir / f"{name}.json"
        if not path.exists():
            raise FileNotFoundError(
                f"Missing fixture {path}. Run: python3 scripts/generate_fixtures.py"
            )
        return json.loads(path.read_text())

    # --- device resolution ----------------------------------------------------

    def resolve_device(self, query: str | None) -> Record | None:
        """Free text -> one device, or an exception the model can act on.

        Raising beats guessing: answering about Server 20 when the user asked
        about Server 2 is worse than admitting the reference was ambiguous.
        """
        if not query:
            return None
        matches = find_devices(self.devices, query)
        if not matches:
            raise DeviceNotFound(query)
        if len(matches) > 1:
            raise AmbiguousDevice(query, matches)
        return matches[0]

    # --- shared filtering -----------------------------------------------------

    def _filter(
        self,
        records: list[Record],
        *,
        device: Record | None = None,
        device_type: str | None = None,
        category: str | None = None,
        area: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        time_field: str = "timestamp",
    ) -> list[Record]:
        return [
            record
            for record in records
            if (device is None or record.get("device_id") == device["id"])
            and _eq(record, "device_type", device_type)
            and _eq(record, "category", category)
            and _eq(record, "area", area)
            and _in_window(record.get(time_field), since, until)
        ]

    @staticmethod
    def _finalize(
        matches: list[Record],
        limit: int,
        sort_key: str,
        *,
        newest_first: bool = True,
        resolved: Record | None = None,
    ) -> QueryResult:
        matches.sort(key=lambda r: r.get(sort_key) or "", reverse=newest_first)
        capped = max(1, min(limit, MAX_LIMIT))
        return QueryResult(
            records=matches[:capped],
            total_matched=len(matches),
            resolved_device=resolved,
        )

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
        since: datetime | None = None,
        until: datetime | None = None,
        sort: str = "newest",
        limit: int = DEFAULT_LIMIT,
    ) -> QueryResult:
        resolved = self.resolve_device(device)
        # "Active" is the default lens, but an explicit status wins — otherwise
        # "show me resolved alarms" would be silently impossible to express.
        wanted_status = status or "active"
        matches = [
            alarm
            for alarm in self._filter(
                self.alarms,
                device=resolved,
                device_type=device_type,
                category=category,
                area=area,
                since=since,
                until=until,
            )
            if _eq(alarm, "severity", severity)
            and _eq(alarm, "status", wanted_status)
            and _eq(alarm, "type", alarm_type)
        ]
        return self._finalize(
            matches, limit, "timestamp", newest_first=(sort != "oldest"), resolved=resolved
        )

    def get_alarm_details(self, *, alarm_id: str) -> Record | None:
        for alarm in self.alarms:
            if alarm["id"].casefold() == alarm_id.casefold():
                return alarm
        return None

    def get_recent_events(
        self,
        *,
        event_type: str | None = None,
        device: str | None = None,
        device_type: str | None = None,
        category: str | None = None,
        area: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> QueryResult:
        resolved = self.resolve_device(device)
        matches = [
            event
            for event in self._filter(
                self.events,
                device=resolved,
                device_type=device_type,
                category=category,
                area=area,
                since=since,
                until=until,
            )
            if _eq(event, "type", event_type)
        ]
        return self._finalize(matches, limit, "timestamp", resolved=resolved)

    def search_logs(
        self,
        *,
        device: str | None = None,
        device_type: str | None = None,
        category: str | None = None,
        level: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> QueryResult:
        resolved = self.resolve_device(device)
        # `level` is a floor, not an exact match: asking for warnings should
        # surface errors too, which is what an operator means.
        floor = _LEVEL_ORDER.get((level or "").casefold(), 0)
        matches = [
            entry
            for entry in self._filter(
                self.logs,
                device=resolved,
                device_type=device_type,
                category=category,
                since=since,
                until=until,
            )
            if _LEVEL_ORDER.get(entry.get("level", "info"), 0) >= floor
        ]
        return self._finalize(matches, limit, "timestamp", resolved=resolved)

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
        resolved = self.resolve_device(device)
        candidates = [resolved] if resolved else self.devices
        matches = [
            entry
            for entry in candidates
            if _eq(entry, "type", device_type)
            and _eq(entry, "category", category)
            and _eq(entry, "status", status)
            and _eq(entry, "area", area)
        ]
        return self._finalize(matches, limit, "last_seen", resolved=resolved)

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
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 10,
    ) -> SummaryResult:
        source = {"alarms": self.alarms, "events": self.events, "logs": self.logs}[record_type]
        field = _GROUP_FIELD[group_by]

        matches = [
            record
            for record in self._filter(
                source,
                device_type=device_type,
                category=category,
                area=area,
                since=since,
                until=until,
            )
            if _eq(record, "severity", severity) and _eq(record, "status", status)
        ]

        # Counted over every match, not a page — that is the whole point of this
        # method existing rather than the model tallying returned records.
        counts = Counter(record.get(field) or "unknown" for record in matches)
        ranked = counts.most_common()
        capped = max(1, min(limit, 50))
        return SummaryResult(
            groups=[GroupCount(key=key, count=count) for key, count in ranked[:capped]],
            total_records=len(matches),
            total_groups=len(ranked),
            group_by=group_by,
            record_type=record_type,
        )
