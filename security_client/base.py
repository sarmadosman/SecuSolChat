"""The boundary between the chatbot and the security platform.

Everything above this interface is platform-agnostic. Swapping `MockSecurityClient`
for `RealSecurityApiClient` must require no change in `chatbot/`.

Parameters here are plain types on purpose: validation happens upstream in
`chatbot.schemas` before anything reaches a client. A client's job is retrieval,
not policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

Record = dict[str, Any]

# Hard ceiling on records returned by any single call, regardless of what was
# requested. Enforced by every implementation, not by the caller.
MAX_LIMIT = 100
DEFAULT_LIMIT = 20


class DeviceNotFound(LookupError):
    """No device matched the name the user gave."""

    def __init__(self, query: str) -> None:
        super().__init__(f"No device matches {query!r}.")
        self.query = query


class AmbiguousDevice(LookupError):
    """Several devices matched. Carries the candidates so the model can ask."""

    def __init__(self, query: str, candidates: list[Record]) -> None:
        names = ", ".join(d.get("name", d["id"]) for d in candidates[:8])
        super().__init__(f"{query!r} matches several devices: {names}.")
        self.query = query
        self.candidates = candidates


@dataclass(frozen=True)
class QueryResult:
    """A capped, sorted slice of matching records.

    `total_matched` is the count *before* the limit was applied. It exists so
    truncation can be disclosed to the user rather than hidden — see PLAN.md §6.
    """

    records: list[Record] = field(default_factory=list)
    total_matched: int = 0
    resolved_device: Record | None = None

    @property
    def truncated(self) -> bool:
        return self.total_matched > len(self.records)

    def to_tool_payload(self) -> dict[str, Any]:
        """The shape handed back to the model as a tool result."""
        payload: dict[str, Any] = {
            "records": self.records,
            "returned": len(self.records),
            "total_matched": self.total_matched,
            "truncated": self.truncated,
        }
        if self.resolved_device is not None:
            # Tell the model which device a free-text name resolved to, so its
            # answer names the same thing the user did and follow-up calls can
            # use the canonical ID.
            payload["resolved_device"] = {
                "id": self.resolved_device["id"],
                "name": self.resolved_device.get("name"),
            }
        return payload


@dataclass(frozen=True)
class GroupCount:
    key: str
    count: int


@dataclass(frozen=True)
class SummaryResult:
    """Counts over the entire matching set, never over a truncated page."""

    groups: list[GroupCount] = field(default_factory=list)
    total_records: int = 0
    total_groups: int = 0
    group_by: str = ""
    record_type: str = ""

    def to_tool_payload(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "group_by": self.group_by,
            "groups": [{"key": g.key, "count": g.count} for g in self.groups],
            "groups_returned": len(self.groups),
            "total_groups": self.total_groups,
            "total_records": self.total_records,
            "truncated": self.total_groups > len(self.groups),
        }


@runtime_checkable
class SecurityClient(Protocol):
    """Read-only access to a security monitoring platform.

    Six methods, all retrieval. There is deliberately no generic
    `call_endpoint(method, url, params)` — adding one would hand the model an
    arbitrary-request primitive and defeat every control above this line.

    `device` is free text ("Machine 14", "pc # 10", "MCH-014"); implementations
    resolve it and raise DeviceNotFound / AmbiguousDevice rather than guessing.
    """

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
    ) -> QueryResult: ...

    def get_alarm_details(self, *, alarm_id: str) -> Record | None: ...

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
    ) -> QueryResult: ...

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
    ) -> QueryResult: ...

    def get_device_status(
        self,
        *,
        device: str | None = None,
        device_type: str | None = None,
        category: str | None = None,
        status: str | None = None,
        area: str | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> QueryResult: ...

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
    ) -> SummaryResult: ...
