"""Device taxonomy and name resolution.

Operators say "Machine 14", "pc # 10", "Server 2" — not "MCH-014". Resolution
happens here, in Python, against a real device list. The model never guesses an
ID, and an unrecognised name comes back as "not found" or "did you mean" rather
than a validation error the user can't act on.

⚠️ ASSUMPTION TO CONFIRM WITH MTC: the three categories below, and what "Machine"
actually is. `operations` is a placeholder — if Machines are cameras, or are IT
endpoints, remap `CATEGORY_OF_TYPE` and regenerate the fixtures. Nothing else
depends on the choice.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

#: Device type -> category. The one place the grouping is defined.
CATEGORY_OF_TYPE: dict[str, str] = {
    "pc": "it",
    "server": "it",
    "network": "it",
    "camera": "security",
    "access_controller": "security",
    "sensor": "security",
    "door": "security",
    "machine": "operations",
}

CATEGORIES = ("it", "security", "operations")

#: Words operators use for a category, so "anything wrong with IT?" resolves.
CATEGORY_SYNONYMS: dict[str, str] = {
    "it": "it",
    "i t": "it",  # "I.T." normalizes to this
    "it systems": "it",
    "it equipment": "it",
    "computers": "it",
    "pcs": "it",
    "workstations": "it",
    "servers": "it",
    "security": "security",
    "access control": "security",
    "cctv": "security",
    "cameras": "security",
    "operations": "operations",
    "production": "operations",
    "machines": "operations",
}

_PUNCTUATION = re.compile(r"[#_/\\.,\-]+")
_WHITESPACE = re.compile(r"\s+")
_ID_PADDING = re.compile(r"^([a-z]+)-?0*(\d+)$")
#: Operators type "the IT", "our servers". Strip the filler.
_LEADING_FILLER = re.compile(r"^(the|our|any|all)\s+")


def normalize(value: str) -> str:
    """Fold the variations operators actually type.

    'pc # 10', 'PC-10', 'pc10', 'PC 010' all normalize to 'pc 10'.
    """
    text = _PUNCTUATION.sub(" ", (value or "").strip().casefold())
    text = _WHITESPACE.sub(" ", text).strip()
    text = _LEADING_FILLER.sub("", text)
    # split a trailing number off an unspaced token: "pc10" -> "pc 10"
    text = re.sub(r"^([a-z ]+?)\s*(\d+)$", r"\1 \2", text).strip()
    # drop leading zeros on the trailing number: "pc 010" -> "pc 10"
    match = re.match(r"^(.*?)\s*(\d+)$", text)
    if match:
        text = f"{match.group(1)} {int(match.group(2))}".strip()
    return text


def normalize_id(device_id: str) -> str:
    """'MCH-014' -> 'mch 14', so an ID and its name collapse to comparable forms."""
    text = (device_id or "").strip().casefold()
    match = _ID_PADDING.match(text.replace(" ", "-"))
    if match:
        return f"{match.group(1)} {int(match.group(2))}"
    return normalize(text)


def device_aliases(device: dict[str, Any]) -> set[str]:
    """Every string that should resolve to this device."""
    aliases = {normalize_id(device["id"]), normalize(device.get("name", ""))}
    name = device.get("name", "")
    # "Building A Door 3" should also answer to "door 3"
    tokens = normalize(name).split()
    if len(tokens) > 2 and tokens[-1].isdigit():
        aliases.add(f"{tokens[-2]} {tokens[-1]}")
    aliases.discard("")
    return aliases


def resolve_category(value: str | None) -> str | None:
    if not value:
        return None
    key = normalize(value)
    if key in CATEGORIES:
        return key
    return CATEGORY_SYNONYMS.get(key)


def find_devices(devices: Iterable[dict[str, Any]], query: str) -> list[dict[str, Any]]:
    """Resolve a free-text device reference.

    Returns every match. Exact alias matches win outright; only if there are none
    does it fall back to prefix/substring, so "Server 2" never drags in
    "Server 20" when "Server 2" exists.
    """
    wanted = normalize(query)
    if not wanted:
        return []

    devices = list(devices)
    exact = [d for d in devices if wanted in device_aliases(d)]
    if exact:
        return exact

    partial = [
        d
        for d in devices
        if any(alias.startswith(wanted) or wanted in alias for alias in device_aliases(d))
    ]
    return partial
