"""Relative-time resolution.

The model has no clock. It picks a `TimeWindow` from a fixed vocabulary; Python
turns that into a concrete UTC range. Nothing else in the system interprets a
relative date. See PLAN.md §5.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from chatbot.schemas import TimeWindow


def utc_now() -> datetime:
    return datetime.now(UTC)


def resolve_window(
    window: TimeWindow | None, *, now: datetime | None = None
) -> tuple[datetime | None, datetime | None]:
    """Return an inclusive-start, exclusive-end UTC range for `window`.

    `None` means unbounded on that side; a `None` window means no time filter.
    """
    if window is None:
        return None, None

    now = (now or utc_now()).astimezone(UTC)
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)

    match window:
        case "last_hour":
            return now - timedelta(hours=1), now
        case "last_24_hours":
            return now - timedelta(hours=24), now
        case "today":
            return midnight, now
        case "yesterday":
            return midnight - timedelta(days=1), midnight
        case "last_7_days":
            return now - timedelta(days=7), now
        case "last_30_days":
            return now - timedelta(days=30), now

    raise ValueError(f"Unknown time window: {window!r}")


def describe_window(window: TimeWindow | None) -> str:
    """Plain-English label, for disclosing to the user what was actually filtered."""
    if window is None:
        return "all time"
    return {
        "last_hour": "the last hour",
        "last_24_hours": "the last 24 hours",
        "today": "today (UTC)",
        "yesterday": "yesterday (UTC)",
        "last_7_days": "the last 7 days",
        "last_30_days": "the last 30 days",
    }[window]
