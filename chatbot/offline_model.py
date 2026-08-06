"""A scripted stand-in for Claude, so the app runs with no API key.

⚠️ **This is not the chatbot.** It is a deterministic pattern-matcher that maps
a question to a tool call and renders the result from a template. It proves the
*plumbing* — routing reaches the client, records come back sanitized, truncation
is disclosed, refusals refuse, the UI renders evidence — and proves nothing at
all about language understanding.

Use it to demo the app, check the interface, and sanity-check the data. Do not
use it to judge whether the assistant answers well; only a real model can tell
you that, and the routing it produces here is hand-written, not inferred.

Enable with OFFLINE_MODEL=true.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from security_client.taxonomy import CATEGORY_SYNONYMS, normalize

# --- response objects, shaped like the SDK's -----------------------------------


@dataclass
class _Text:
    text: str
    type: str = "text"


@dataclass
class _ToolUse:
    name: str
    input: dict[str, Any]
    id: str = "toolu_offline"
    type: str = "tool_use"


@dataclass
class _Response:
    content: list[Any]
    stop_reason: str
    usage: Any = None


# --- routing -------------------------------------------------------------------

REFUSAL = (
    "I can't do that — this assistant is read-only. It cannot acknowledge or close "
    "alarms, change device configuration, restart systems, or delete logs. I can "
    "retrieve the current status, alarms, events, and logs for whatever you're "
    "looking at."
)

INJECTION_REFUSAL = (
    "I can't provide credentials, tokens, or internal configuration. I can retrieve "
    "alarms, events, logs, and device status."
)

_WRITE_VERBS = re.compile(
    r"\b(close|acknowledge|ack|restart|reboot|delete|remove|disable|enable|"
    r"change|modify|update|assign|silence|reset)\b",
    re.IGNORECASE,
)
_CREDENTIAL_PROBE = re.compile(
    r"\b(api[- ]?token|api[- ]?key|system prompt|credentials?|secret|"
    r"ignore (your |all |previous )?instructions)\b",
    re.IGNORECASE,
)
_DEVICE_REFERENCE = re.compile(
    r"\b((?:pc|machine|server|camera|sensor|switch|access controller)\s*#?\s*\d+"
    r"|building [ab] door \d+|north entrance door|data center door)\b",
    re.IGNORECASE,
)

_WINDOWS = [
    (re.compile(r"\blast hour|past hour\b", re.I), "last_hour"),
    (re.compile(r"\b(last|past) 24 hours?\b", re.I), "last_24_hours"),
    (re.compile(r"\btoday\b", re.I), "today"),
    (re.compile(r"\byesterday\b", re.I), "yesterday"),
    (re.compile(r"\b(last|past) (7 days?|week)\b", re.I), "last_7_days"),
    (re.compile(r"\b(last|past) (30 days?|month)\b", re.I), "last_30_days"),
]

_SEVERITIES = ["critical", "major", "warning", "info"]
_DEVICE_TYPES = {
    "server": "server", "servers": "server",
    "camera": "camera", "cameras": "camera",
    "sensor": "sensor", "sensors": "sensor",
    "door": "door", "doors": "door",
    "switch": "network", "switches": "network",
    "pc": "pc", "pcs": "pc", "workstation": "pc", "workstations": "pc",
    "machine": "machine", "machines": "machine",
    "access controller": "access_controller",
}
_ALARM_TYPES = {
    "tamper": "tamper", "power": "power_loss", "storage": "disk_full",
    "forced": "door_forced", "communication": "communication_failure",
}


def _window(text: str) -> str | None:
    for pattern, value in _WINDOWS:
        if pattern.search(text):
            return value
    return None


def _category(text: str) -> str | None:
    lowered = text.casefold()
    for phrase, category in CATEGORY_SYNONYMS.items():
        if re.search(rf"\b{re.escape(phrase)}\b", lowered):
            return category
    return None


def _device_type(text: str) -> str | None:
    lowered = text.casefold()
    for phrase, kind in _DEVICE_TYPES.items():
        if re.search(rf"\b{re.escape(phrase)}\b", lowered):
            return kind
    return None


def route(question: str) -> tuple[str, dict[str, Any]] | str:
    """Question -> (action, parameters), or a plain string to answer directly."""
    text = question.strip()
    lowered = text.casefold()

    if _CREDENTIAL_PROBE.search(lowered):
        return INJECTION_REFUSAL
    if _WRITE_VERBS.search(lowered) and not lowered.startswith(("show", "list", "give")):
        return REFUSAL

    window = _window(lowered)
    params: dict[str, Any] = {}

    # Aggregation first: "top N", "how many", "most", "which area".
    if re.search(r"\btop \d+|most frequent|how many|which (location|area|site)|busiest", lowered):
        if not re.search(r"\btop \d+\b.*\b(by|frequen)|frequen|how many|most|which", lowered):
            return "Ranked by what — severity, frequency, most recent, or duration?"
        group_by = "area" if re.search(r"location|area|site", lowered) else "type"
        record_type = "events" if "event" in lowered else "logs" if "log" in lowered else "alarms"
        match = re.search(r"\btop (\d+)", lowered)
        params = {"record_type": record_type, "group_by": group_by,
                  "limit": int(match.group(1)) if match else 10}
        if window:
            params["window"] = window
        if "resolved" in lowered:
            params["status"] = "resolved"
        return "summarize_records", params

    device_match = _DEVICE_REFERENCE.search(text)
    device = device_match.group(1) if device_match else None

    # Logs
    if re.search(r"\blogs?\b", lowered):
        if device:
            params["device"] = device
        if "error" in lowered:
            params["level"] = "error"
        elif "warning" in lowered:
            params["level"] = "warning"
        if window:
            params["window"] = window
        return "search_logs", params

    # Device status
    if re.search(r"\boffline|down|status|last seen|reachable|working normally\b", lowered) or (
        device and re.search(r"what happened to|what.s wrong with|why is", lowered)
    ):
        if device:
            params["device"] = device
        else:
            if re.search(r"\boffline|down\b", lowered):
                params["status"] = "offline"
            if category := _category(lowered):
                params["category"] = category
            elif kind := _device_type(lowered):
                params["device_type"] = kind
            params["limit"] = 50
        return "get_device_status", params

    # Events
    if re.search(r"\bevents?|access denied|access-denied|denials|login|authentication\b", lowered):
        if re.search(r"auth|login", lowered):
            params["event_type"] = "auth_failure"
        elif re.search(r"denied|denial", lowered):
            params["event_type"] = "access_denied"
        if device:
            params["device"] = device
        if window:
            params["window"] = window
        match = re.search(r"\b(?:last|latest|top)\s+(\d+)", lowered)
        params["limit"] = int(match.group(1)) if match else 20
        return "get_recent_events", params

    # Alarm by ID
    if match := re.search(r"\b(ALM-\d+)\b", text, re.I):
        return "get_alarm_details", {"alarm_id": match.group(1).upper()}

    # Alarms, and the catch-all
    if re.search(r"\bimportant ones|everything that happened|what happened earlier\b", lowered):
        return ("Which records, and over what period? I can look at alarms, events, "
                "logs, or device status.")
    if re.search(r"\bthis alarm|that one|this issue\b", lowered):
        return "Which alarm do you mean? An alarm ID or the affected device would let me check."

    for severity in _SEVERITIES:
        if severity in lowered:
            params["severity"] = severity
            break
    if category := _category(lowered):
        params["category"] = category
    elif kind := _device_type(lowered):
        params["device_type"] = kind
    if device:
        params["device"] = device
    for phrase, alarm_type in _ALARM_TYPES.items():
        if phrase in lowered:
            params["alarm_type"] = alarm_type
            break
    if window:
        params["window"] = window
    if "resolved" in lowered:
        params["status"] = "resolved"
    if re.search(r"\blongest|oldest\b", lowered):
        params["sort"] = "oldest"
    match = re.search(r"\b(?:last|latest|newest|top)\s+(\d+)", lowered)
    params["limit"] = int(match.group(1)) if match else 20
    return "get_active_alarms", params


# --- rendering -----------------------------------------------------------------


def _render(payload: dict[str, Any]) -> str:
    if "error" in payload:
        lines = [payload["error"]]
        for candidate in payload.get("candidates", [])[:8]:
            lines.append(f"- {candidate['name']} ({candidate['id']})")
        if payload.get("candidates"):
            lines.insert(1, "Which one did you mean?")
        return "\n".join(lines)

    if "groups" in payload:
        header = (
            f"{payload['total_records']} {payload['record_type']} across "
            f"{payload['total_groups']} {payload['group_by']} groups. Top "
            f"{len(payload['groups'])}:"
        )
        rows = [f"{i}. {g['key'].replace('_', ' ')} — {g['count']}"
                for i, g in enumerate(payload["groups"], 1)]
        return "\n".join([header, "", *rows])

    records = payload.get("records", [])
    if not records:
        return "No matching records were found."

    header = (
        f"Showing the {payload['returned']} most recent of {payload['total_matched']} "
        f"matching records:"
        if payload.get("truncated")
        else f"Found {payload['total_matched']} matching record(s):"
    )
    if resolved := payload.get("resolved_device"):
        header = f"{resolved['name']} ({resolved['id']}). {header}"

    rows = []
    for record in records[:10]:
        if "severity" in record:
            rows.append(
                f"- {record['id']} · {record['severity']} · {record.get('device_name', '?')}"
                f" — {record.get('message', '')}"
            )
        elif "level" in record:
            rows.append(
                f"- {record['level']} · {record.get('device_name', '?')} — {record.get('message', '')}"
            )
        elif "status" in record and "name" in record:
            rows.append(
                f"- {record['name']} ({record['id']}) · {record['status']}"
                f" · last seen {record.get('last_seen', 'unknown')}"
            )
        else:
            rows.append(
                f"- {record.get('type', '?')} · {record.get('device_name', '?')}"
                f" — {record.get('message', '')}"
            )
    return "\n".join([header, "", *rows])


NOTICE = (
    "\n\n_(Offline mode: this reply was assembled by a scripted stand-in, not by "
    "Claude. Routing is hand-written pattern matching.)_"
)


@dataclass
class ScriptedModel:
    """Mimics the slice of the SDK that Controller uses."""

    requests: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.messages = self

    def create(self, **kwargs: Any) -> _Response:
        self.requests.append(kwargs)
        messages = kwargs.get("messages", [])

        # A tool result present in the last message means we are on the second
        # pass and should render an answer.
        last = messages[-1] if messages else {}
        if isinstance(last.get("content"), list):
            results = [
                block
                for block in last["content"]
                if isinstance(block, dict) and block.get("type") == "tool_result"
            ]
            if results:
                import json

                rendered = []
                for result in results:
                    body = result["content"]
                    match = re.search(r"<records[^>]*>\s*(\{.*\})\s*</records>", body, re.S)
                    payload = json.loads(match.group(1)) if match else {"error": body}
                    rendered.append(_render(payload))
                return _Response([_Text("\n\n".join(rendered) + NOTICE)], "end_turn")

        question = next(
            (m["content"] for m in reversed(messages)
             if m.get("role") == "user" and isinstance(m.get("content"), str)),
            "",
        )
        decision = route(question)
        if isinstance(decision, str):
            return _Response([_Text(decision + NOTICE)], "end_turn")

        action, params = decision
        return _Response([_ToolUse(name=action, input=params)], "tool_use")
