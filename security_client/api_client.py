"""Adapter for the real security platform API.

UNVERIFIED — written against the expected contract in PLAN.md §9 day 2. Endpoint
paths, parameter names, and response envelopes must be reconciled against the
vendor's actual documentation before this is switched on. The Protocol it
implements is stable; only the inside of these methods should need to change.

Design constraints, all deliberate:

* One explicit method per operation. There is no generic request helper that
  takes a method or a URL, because that is exactly the primitive that would let a
  compromised caller reach an unapproved endpoint.
* GET only. `_get` hardcodes the verb.
* Paths come from a frozen allowlist, never from an argument.
* Limits are re-capped here, independently of the schema layer. Two locks.
* The token lives in the client's headers and is never returned, logged, or
  placed anywhere the model can see.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from security_client.base import DEFAULT_LIMIT, MAX_LIMIT, QueryResult, Record

#: The complete set of paths this client may ever request.
_ALLOWED_PATHS = frozenset(
    {"/alarms", "/alarms/{alarm_id}", "/events", "/logs", "/devices"}
)

_TIMEOUT_SECONDS = 10.0


class RealSecurityApiClient:
    def __init__(self, base_url: str | None = None, token: str | None = None) -> None:
        import httpx  # lazy so the mock path needs no HTTP dependency

        base_url = base_url or os.environ.get("SECURITY_API_URL", "")
        token = token or os.environ.get("SECURITY_API_TOKEN", "")
        if not base_url or not token:
            raise RuntimeError(
                "Security API configuration is missing: set SECURITY_API_URL and "
                "SECURITY_API_TOKEN."
            )

        self._httpx = httpx
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=_TIMEOUT_SECONDS,
        )

    # --- internals ------------------------------------------------------------

    def _get(self, template: str, /, **params: Any) -> Any:
        """The only outbound call site. GET, allowlisted path, bounded params."""
        if template not in _ALLOWED_PATHS:
            raise PermissionError(f"Endpoint not on the allowlist: {template!r}")

        path = template
        path_args = {k: v for k, v in params.items() if "{" + k + "}" in template}
        for key, value in path_args.items():
            path = path.replace("{" + key + "}", str(value))
            params.pop(key)

        query = {k: v for k, v in params.items() if v is not None}
        if "limit" in query:
            query["limit"] = max(1, min(int(query["limit"]), MAX_LIMIT))

        response = self._client.get(path, params=query)
        response.raise_for_status()
        return response.json()

    @staticmethod
    def _iso(moment: datetime | None) -> str | None:
        return moment.isoformat() if moment else None

    @staticmethod
    def _unpack(body: Any, key: str, limit: int) -> QueryResult:
        """Normalize the vendor envelope into a QueryResult.

        Assumes `{"<key>": [...], "total": N}`. Reconcile with the real API before
        use; `total` is what makes truncation disclosable, so if the platform does
        not return a count, decide here what to do rather than silently reporting
        the page size as the total.
        """
        if isinstance(body, list):
            records: list[Record] = body
            total = len(records)
        else:
            records = body.get(key, []) or []
            total = int(body.get("total", len(records)))
        capped = max(1, min(limit, MAX_LIMIT))
        return QueryResult(records=records[:capped], total_matched=total)

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
        body = self._get(
            "/alarms",
            severity=severity,
            status=status or "active",
            site=site,
            since=self._iso(since),
            until=self._iso(until),
            limit=limit,
        )
        return self._unpack(body, "alarms", limit)

    def get_alarm_details(self, *, alarm_id: str) -> Record | None:
        try:
            return self._get("/alarms/{alarm_id}", alarm_id=alarm_id)
        except self._httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return None
            raise

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
        body = self._get(
            "/events",
            type=event_type,
            site=site,
            device_id=device_id,
            since=self._iso(since),
            until=self._iso(until),
            limit=limit,
        )
        return self._unpack(body, "events", limit)

    def search_logs(
        self,
        *,
        device_id: str | None = None,
        level: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> QueryResult:
        body = self._get(
            "/logs",
            device_id=device_id,
            level=level,
            since=self._iso(since),
            until=self._iso(until),
            limit=limit,
        )
        return self._unpack(body, "logs", limit)

    def get_device_status(
        self,
        *,
        device_id: str | None = None,
        status: str | None = None,
        site: str | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> QueryResult:
        body = self._get(
            "/devices", id=device_id, status=status, site=site, limit=limit
        )
        return self._unpack(body, "devices", limit)
