"""Field allowlists — deny by default.

Applied *before records reach the model*, not before display. Anything not named
here never enters the LLM's context: usernames, IP addresses, badge IDs, personal
names, physical access history, precise locations, credentials, internal network
addresses, tokens, biometrics.

Allowlist rather than blocklist on purpose: a new sensitive field added upstream
by the platform is excluded automatically instead of leaking until someone
notices.
"""

from __future__ import annotations

from typing import Any

Record = dict[str, Any]

ALLOWED_ALARM_FIELDS = frozenset(
    {"id", "timestamp", "severity", "status", "site", "device_id", "type", "message"}
)

ALLOWED_EVENT_FIELDS = frozenset(
    {"id", "timestamp", "type", "site", "device_id", "outcome", "message"}
)

ALLOWED_LOG_FIELDS = frozenset({"id", "timestamp", "level", "device_id", "component", "message"})

ALLOWED_DEVICE_FIELDS = frozenset(
    {"id", "name", "type", "status", "site", "last_seen", "firmware"}
)

ALLOWLISTS: dict[str, frozenset[str]] = {
    "alarm": ALLOWED_ALARM_FIELDS,
    "event": ALLOWED_EVENT_FIELDS,
    "log": ALLOWED_LOG_FIELDS,
    "device": ALLOWED_DEVICE_FIELDS,
}


def sanitize_record(record: Record, allowed: frozenset[str]) -> Record:
    return {key: value for key, value in record.items() if key in allowed}


def sanitize_records(records: list[Record], kind: str) -> list[Record]:
    """Strip every field not on the allowlist for `kind`.

    `kind` is one of: alarm, event, log, device. An unknown kind is a programming
    error and raises rather than passing data through unfiltered.
    """
    try:
        allowed = ALLOWLISTS[kind]
    except KeyError:
        raise ValueError(f"No field allowlist defined for record kind {kind!r}") from None
    return [sanitize_record(record, allowed) for record in records]
