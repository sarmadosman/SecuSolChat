"""Request schemas — the security boundary.

Every parameter the model can influence is typed here. `extra="forbid"` means an
invented parameter is a ValidationError at parse time, not a silent pass-through.

The tool definitions sent to Claude are *generated* from these models, so the
schema the model sees and the schema we enforce cannot drift apart.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

# --- Controlled vocabularies -------------------------------------------------
# These are the single source of truth. Fixtures and clients mirror them.

Severity = Literal["info", "warning", "major", "critical"]
AlarmStatus = Literal["active", "acknowledged", "resolved"]
DeviceStatus = Literal["online", "offline", "degraded", "maintenance"]
LogLevel = Literal["debug", "info", "warning", "error", "critical"]

# Devices group two ways: by what they are, and by which team owns them.
# "Is there anything wrong with the IT?" is a category question.
DeviceType = Literal[
    "pc", "server", "network", "camera", "access_controller", "sensor", "door", "machine"
]
DeviceCategory = Literal["it", "security", "operations"]

AlarmType = Literal[
    "communication_failure",
    "tamper",
    "unauthorized_access",
    "auth_failure",
    "door_forced",
    "door_held_open",
    "power_loss",
    "disk_full",
    "service_down",
]

EventType = Literal[
    "access_granted",
    "access_denied",
    "auth_failure",
    "door_forced",
    "motion_detected",
    "system_login",
    "config_change",
    "alarm_acknowledged",
]

# Relative time is an enum, never a free-form date. The model has no clock; asking
# it for ISO timestamps invites hallucinated dates. Python resolves these against
# a real `now` in chatbot.timeutil.
TimeWindow = Literal[
    "last_hour",
    "last_24_hours",
    "today",
    "yesterday",
    "last_7_days",
    "last_30_days",
]

GroupBy = Literal["type", "severity", "status", "area", "device", "category", "level"]
RecordType = Literal["alarms", "events", "logs"]
SortOrder = Literal["newest", "oldest"]

ACTIONS = (
    "get_active_alarms",
    "get_alarm_details",
    "get_recent_events",
    "search_logs",
    "get_device_status",
    "summarize_records",
)

#: The allowlist. Enforced in code, never in the prompt.
ALLOWED_ACTIONS = frozenset(ACTIONS)

MAX_LIMIT = 100
DEFAULT_LIMIT = 20

_AREA = Field(
    default=None,
    max_length=100,
    description="Area or location, e.g. 'Building A', 'Data Center', 'North Entrance'.",
)
_LIMIT = Field(
    default=DEFAULT_LIMIT,
    ge=1,
    le=MAX_LIMIT,
    description=f"Max records to return (1-{MAX_LIMIT}).",
)
_WINDOW = Field(default=None, description="Relative time range to filter by.")
# Free text, not an ID pattern: operators say "Machine 14" or "pc # 10", never
# "MCH-014". Resolution to a real device happens in Python, so an unrecognised
# name comes back as "not found" or a list of candidates rather than a
# validation error the user cannot act on.
_DEVICE = Field(
    default=None,
    max_length=80,
    description=(
        "Device by name or ID, as the user said it — e.g. 'Machine 14', 'pc # 10', "
        "'Server 2', 'Building A Door 3', or 'MCH-014'. Do not invent an ID."
    ),
)
_DEVICE_TYPE = Field(default=None, description="Filter by kind of device.")
_CATEGORY = Field(
    default=None,
    description=(
        "Filter by the group that owns the equipment: 'it' (PCs, servers, network), "
        "'security' (cameras, access controllers, sensors, doors), or 'operations' "
        "(machines)."
    ),
)


class Params(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --- Per-action parameter models ---------------------------------------------


class ActiveAlarmsParams(Params):
    severity: Severity | None = Field(default=None, description="Filter by severity.")
    status: AlarmStatus | None = Field(default=None, description="Filter by alarm status.")
    alarm_type: AlarmType | None = Field(default=None, description="Filter by alarm type.")
    device: str | None = _DEVICE
    device_type: DeviceType | None = _DEVICE_TYPE
    category: DeviceCategory | None = _CATEGORY
    area: str | None = _AREA
    window: TimeWindow | None = _WINDOW
    sort: SortOrder = Field(
        default="newest",
        description="'oldest' answers 'which alarm has been active the longest'.",
    )
    limit: int = _LIMIT


class AlarmDetailsParams(Params):
    alarm_id: str = Field(
        pattern=r"^ALM-\d{1,8}$", description="Alarm identifier, e.g. ALM-1842."
    )


class RecentEventsParams(Params):
    event_type: EventType | None = Field(default=None, description="Filter by event type.")
    device: str | None = _DEVICE
    device_type: DeviceType | None = _DEVICE_TYPE
    category: DeviceCategory | None = _CATEGORY
    area: str | None = _AREA
    window: TimeWindow | None = _WINDOW
    limit: int = _LIMIT


class SearchLogsParams(Params):
    device: str | None = _DEVICE
    device_type: DeviceType | None = _DEVICE_TYPE
    category: DeviceCategory | None = _CATEGORY
    level: LogLevel | None = Field(default=None, description="Minimum log level.")
    window: TimeWindow | None = _WINDOW
    limit: int = _LIMIT


class DeviceStatusParams(Params):
    device: str | None = _DEVICE
    device_type: DeviceType | None = _DEVICE_TYPE
    category: DeviceCategory | None = _CATEGORY
    status: DeviceStatus | None = Field(default=None, description="Filter by device state.")
    area: str | None = _AREA
    limit: int = _LIMIT


class SummarizeParams(Params):
    """Counts over the *whole* matching set, not over a truncated page.

    This exists so the assistant never has to do arithmetic on a capped list and
    then state a confident total — the failure mode behind "what are the top 10
    alarms?" answered from the 20 records that happened to come back.
    """

    record_type: RecordType = Field(description="Which collection to count.")
    group_by: GroupBy = Field(description="Field to group and rank by.")
    severity: Severity | None = Field(default=None, description="Filter by severity.")
    status: AlarmStatus | None = Field(default=None, description="Alarms only.")
    category: DeviceCategory | None = _CATEGORY
    device_type: DeviceType | None = _DEVICE_TYPE
    area: str | None = _AREA
    window: TimeWindow | None = _WINDOW
    limit: int = Field(default=10, ge=1, le=50, description="How many groups to return.")


# --- Discriminated union ------------------------------------------------------


class GetActiveAlarms(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["get_active_alarms"]
    parameters: ActiveAlarmsParams = Field(default_factory=ActiveAlarmsParams)


class GetAlarmDetails(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["get_alarm_details"]
    parameters: AlarmDetailsParams


class GetRecentEvents(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["get_recent_events"]
    parameters: RecentEventsParams = Field(default_factory=RecentEventsParams)


class SearchLogs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["search_logs"]
    parameters: SearchLogsParams = Field(default_factory=SearchLogsParams)


class GetDeviceStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["get_device_status"]
    parameters: DeviceStatusParams = Field(default_factory=DeviceStatusParams)


class SummarizeRecords(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["summarize_records"]
    parameters: SummarizeParams


ToolRequest = Annotated[
    GetActiveAlarms
    | GetAlarmDetails
    | GetRecentEvents
    | SearchLogs
    | GetDeviceStatus
    | SummarizeRecords,
    Field(discriminator="action"),
]

_ADAPTER: TypeAdapter[Any] = TypeAdapter(ToolRequest)

_PARAM_MODELS: dict[str, type[Params]] = {
    "get_active_alarms": ActiveAlarmsParams,
    "get_alarm_details": AlarmDetailsParams,
    "get_recent_events": RecentEventsParams,
    "search_logs": SearchLogsParams,
    "get_device_status": DeviceStatusParams,
    "summarize_records": SummarizeParams,
}

_DESCRIPTIONS: dict[str, str] = {
    "get_active_alarms": (
        "Retrieve alarms from the security platform. Use for questions about what is "
        "currently wrong, what alarms are active, or what alarmed recently. Returns a "
        "capped, newest-first list. Read-only."
    ),
    "get_alarm_details": (
        "Retrieve one alarm in full by its identifier. Use when the user names a specific "
        "alarm or asks to know more about one already listed. Read-only."
    ),
    "get_recent_events": (
        "Retrieve security events such as access grants and denials, door events, motion "
        "detections, and logins. Use for questions about what happened, rather than what "
        "is currently in an alarm state. Read-only."
    ),
    "search_logs": (
        "Search system log entries, optionally scoped to a device or minimum level. Use "
        "for diagnostic questions about a specific device or component. Read-only."
    ),
    "get_device_status": (
        "Retrieve device and system health: online, offline, degraded, or in maintenance. "
        "Use for questions about whether equipment is reachable or healthy — 'which "
        "cameras are offline', 'are any servers down', 'what happened to pc 10'. Pass the "
        "device name exactly as the user said it. Use `category` for questions about a "
        "whole group, such as 'is there anything wrong with the IT?'. Read-only."
    ),
    "summarize_records": (
        "Count and rank records by a field, across the whole matching set rather than a "
        "single page. Use whenever the question asks how many, which is most, top N, "
        "busiest, or a comparison between groups — 'what are the top 10 alarms', 'which "
        "area has the most alarms', 'how many alarms were resolved today'. Prefer this "
        "over counting records yourself: a retrieval call returns a capped page, so "
        "counting its records would understate the true total. Read-only."
    ),
}


def validate_action(action: str) -> None:
    """Reject anything not on the allowlist. Called before parsing, always."""
    if action not in ALLOWED_ACTIONS:
        raise PermissionError(f"Unsupported or prohibited action: {action!r}")


def parse_tool_request(action: str, parameters: dict[str, Any] | None = None) -> Any:
    """Validate a model-proposed tool call into a typed request.

    Raises PermissionError for an unknown action, ValidationError for bad params.
    """
    validate_action(action)
    return _ADAPTER.validate_python({"action": action, "parameters": parameters or {}})


def _strict_schema(model: type[BaseModel]) -> dict[str, Any]:
    """JSON Schema for Claude strict tool use.

    Strict mode requires `additionalProperties: false` and an explicit `required`
    list. Optional parameters are therefore emitted as required-but-nullable: the
    model must state a value or an explicit null, which is unambiguous in a way
    that an omitted key is not.
    """
    schema = model.model_json_schema()
    if "$defs" in schema:  # nothing here should nest; fail loudly if that changes
        raise AssertionError(f"unexpected $defs in {model.__name__} schema")
    schema.pop("title", None)
    properties = schema.get("properties", {})
    for prop in properties.values():
        prop.pop("title", None)
        prop.pop("default", None)
    schema["additionalProperties"] = False
    schema["required"] = sorted(properties)
    return schema


def tool_definitions() -> list[dict[str, Any]]:
    """Claude tool definitions, generated from the Pydantic models above.

    Generated rather than hand-written so the schema the model is shown and the
    schema we enforce can never disagree.
    """
    return [
        {
            "name": action,
            "description": _DESCRIPTIONS[action],
            "input_schema": _strict_schema(_PARAM_MODELS[action]),
            "strict": True,
        }
        for action in ACTIONS
    ]
