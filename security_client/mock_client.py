"""In-memory client backed by the JSON fixtures in data/.

Implements the same Protocol as the real adapter, so the controller cannot tell
them apart. Every filter, cap, and sort applied here must also be applied by
RealSecurityApiClient — if the two disagree, the mock stops being a useful test
surface.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_client.base import DEFAULT_LIMIT, MAX_LIMIT, QueryResult, Record

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

_LEVEL_ORDER = {"debug": 0, "info": 1, "warning": 2, "error": 3, "critical": 4}


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
    """Case-insensitive equality for the string filters, exact for the rest."""
    if wanted is None:
        return True
    actual = record.get(key)
    if isinstance(actual, str) and isinstance(wanted, str):
        return actual.casefold() == wanted.casefold()
    return actual == wanted


def _finalize(matches: list[Record], limit: int, sort_key: str) -> QueryResult:
    """Sort newest-first and cap.

    Deterministic ordering matters: if truncation is going to happen, which
    records survive must be predictable, or the same question gives different
    answers on different runs.
    """
    matches.sort(key=lambda r: r.get(sort_key) or "", reverse=True)
    capped = max(1, min(limit, MAX_LIMIT))
    return QueryResult(records=matches[:capped], total_matched=len(matches))


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
                f"Missing fixture {path}. Run: python scripts/generate_fixtures.py"
            )
        return json.loads(path.read_text())

    # --- SecurityClient -------------------------------------------------------

    def get_active_alarms(
        self,
        *,
        severity: str | None = None,
        status: str | None = None,
        site: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> QueryResult:
        # "Active" is the default lens, but an explicit status wins — otherwise
        # "show me resolved alarms" would be silently impossible to express.
        wanted_status = status or "active"
        matches = [
            alarm
            for alarm in self.alarms
            if _eq(alarm, "severity", severity)
            and _eq(alarm, "status", wanted_status)
            and _eq(alarm, "site", site)
            and _in_window(alarm.get("timestamp"), since, until)
        ]
        return _finalize(matches, limit, "timestamp")

    def get_alarm_details(self, *, alarm_id: str) -> Record | None:
        for alarm in self.alarms:
            if alarm["id"].casefold() == alarm_id.casefold():
                return alarm
        return None

    def get_recent_events(
        self,
        *,
        event_type: str | None = None,
        site: str | None = None,
        device_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> QueryResult:
        matches = [
            event
            for event in self.events
            if _eq(event, "type", event_type)
            and _eq(event, "site", site)
            and _eq(event, "device_id", device_id)
            and _in_window(event.get("timestamp"), since, until)
        ]
        return _finalize(matches, limit, "timestamp")

    def search_logs(
        self,
        *,
        device_id: str | None = None,
        level: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> QueryResult:
        # `level` is a floor, not an exact match: asking for warnings should
        # surface errors too, which is what an operator means by "show warnings".
        floor = _LEVEL_ORDER.get((level or "").casefold(), 0)
        matches = [
            entry
            for entry in self.logs
            if _eq(entry, "device_id", device_id)
            and _LEVEL_ORDER.get(entry.get("level", "info"), 0) >= floor
            and _in_window(entry.get("timestamp"), since, until)
        ]
        return _finalize(matches, limit, "timestamp")

    def get_device_status(
        self,
        *,
        device_id: str | None = None,
        status: str | None = None,
        site: str | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> QueryResult:
        matches = [
            device
            for device in self.devices
            if _eq(device, "id", device_id)
            and _eq(device, "status", status)
            and _eq(device, "site", site)
        ]
        return _finalize(matches, limit, "last_seen")
