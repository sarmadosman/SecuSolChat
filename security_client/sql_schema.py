"""Where MTC's tables and columns are named.

The one file to edit when reconciling against the real database. Defaults match
the canonical record shape used everywhere else, so a database that happens to
use these names needs no configuration at all.

Identifiers are interpolated into SQL text (bound parameters cannot carry table
or column names), so every one is validated against a strict pattern first.
These values come from configuration, never from the model or the user — the
validation is defence in depth, not the primary control.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, fields

#: Deliberately strict: letters, digits, underscore. No dots, quotes, spaces,
#: semicolons, or comment markers can survive this.
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")


class InvalidIdentifier(ValueError):
    """A configured table or column name is not a plain SQL identifier."""


def validate_identifier(value: str, *, context: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.match(value):
        raise InvalidIdentifier(
            f"{context}: {value!r} is not a valid SQL identifier. Expected letters, "
            f"digits and underscores only."
        )
    return value


@dataclass(frozen=True)
class TableMap:
    """One table, and the columns the assistant reads from it.

    `extra` names columns to select and carry through under their own names —
    useful when a site has a field the standard shape lacks. Anything selected
    still has to survive the field allowlist in sanitization.py before it
    reaches the model.
    """

    table: str
    id: str = "id"
    timestamp: str = "timestamp"
    device_id: str = "device_id"
    device_name: str = "device_name"
    device_type: str = "device_type"
    category: str = "category"
    area: str = "area"
    message: str = "message"
    extra: tuple[str, ...] = ()


@dataclass(frozen=True)
class AlarmTable(TableMap):
    table: str = "alarms"
    severity: str = "severity"
    status: str = "status"
    type: str = "type"


@dataclass(frozen=True)
class EventTable(TableMap):
    table: str = "events"
    type: str = "type"
    outcome: str = "outcome"


@dataclass(frozen=True)
class LogTable(TableMap):
    table: str = "logs"
    level: str = "level"
    component: str = "component"


@dataclass(frozen=True)
class DeviceTable:
    table: str = "devices"
    id: str = "id"
    name: str = "name"
    type: str = "type"
    category: str = "category"
    area: str = "area"
    status: str = "status"
    last_seen: str = "last_seen"
    firmware: str = "firmware"
    extra: tuple[str, ...] = ()


@dataclass(frozen=True)
class SqlSchema:
    alarms: AlarmTable = field(default_factory=AlarmTable)
    events: EventTable = field(default_factory=EventTable)
    logs: LogTable = field(default_factory=LogTable)
    devices: DeviceTable = field(default_factory=DeviceTable)

    def __post_init__(self) -> None:
        for table_map in (self.alarms, self.events, self.logs, self.devices):
            name = type(table_map).__name__
            for spec in fields(table_map):
                value = getattr(table_map, spec.name)
                if spec.name == "extra":
                    for column in value:
                        validate_identifier(column, context=f"{name}.extra")
                else:
                    validate_identifier(value, context=f"{name}.{spec.name}")


DEFAULT_SCHEMA = SqlSchema()
