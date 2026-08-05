"""Structured audit logging.

One JSON line per tool call. Never logs API keys, tokens, passwords, full record
bodies, or PII — the parameters are already validated and bounded by the schema
layer, so they are safe to record; the records themselves are not.

v1 has no authentication, so `user_id` is an explicit stub rather than a fiction.
When auth arrives, that is the only field that changes here.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_PATH = LOG_DIR / "audit.jsonl"

#: No auth in v1. See PLAN.md §6 — stubbed, not invented.
ANONYMOUS_USER = "local-dev"

_REDACTED_KEYS = {"token", "api_key", "apikey", "password", "secret", "authorization"}


def _safe_params(parameters: dict[str, Any] | None) -> dict[str, Any]:
    """Belt-and-braces: schema validation should make this a no-op."""
    if not parameters:
        return {}
    return {
        key: ("[REDACTED]" if key.casefold() in _REDACTED_KEYS else value)
        for key, value in parameters.items()
        if value is not None
    }


def log_tool_call(
    *,
    action: str,
    parameters: dict[str, Any] | None,
    result_count: int,
    total_matched: int,
    truncated: bool,
    duration_ms: int,
    status: str,
    error: str | None = None,
    user_id: str = ANONYMOUS_USER,
) -> dict[str, Any]:
    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "user_id": user_id,
        "auth": "none",
        "action": action,
        "parameters": _safe_params(parameters),
        "result_count": result_count,
        "total_matched": total_matched,
        "truncated": truncated,
        "duration_ms": duration_ms,
        "status": status,
    }
    if error:
        # The message only — never a traceback, never a URL, never a response body.
        entry["error"] = error[:200]

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")

    if os.getenv("AUDIT_ECHO"):
        print(json.dumps(entry))
    return entry
