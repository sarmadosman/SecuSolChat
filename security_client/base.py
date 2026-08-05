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


@dataclass(frozen=True)
class QueryResult:
    """A capped, sorted slice of matching records.

    `total_matched` is the count *before* the limit was applied. It exists so
    truncation can be disclosed to the user rather than hidden — see PLAN.md §6.
    """

    records: list[Record] = field(default_factory=list)
    total_matched: int = 0

    @property
    def truncated(self) -> bool:
        return self.total_matched > len(self.records)

    def to_tool_payload(self) -> dict[str, Any]:
        """The shape handed back to the model as a tool result."""
        return {
            "records": self.records,
            "returned": len(self.records),
            "total_matched": self.total_matched,
            "truncated": self.truncated,
        }


@runtime_checkable
class SecurityClient(Protocol):
    """Read-only access to a security monitoring platform.

    Five methods, all retrieval. There is deliberately no generic
    `call_endpoint(method, url, params)` — adding one would hand the model an
    arbitrary-request primitive and defeat every control above this line.
    """

    def get_active_alarms(
        self,
        *,
        severity: str | None = None,
        status: str | None = None,
        site: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> QueryResult: ...

    def get_alarm_details(self, *, alarm_id: str) -> Record | None: ...

    def get_recent_events(
        self,
        *,
        event_type: str | None = None,
        site: str | None = None,
        device_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> QueryResult: ...

    def search_logs(
        self,
        *,
        device_id: str | None = None,
        level: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> QueryResult: ...

    def get_device_status(
        self,
        *,
        device_id: str | None = None,
        status: str | None = None,
        site: str | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> QueryResult: ...
