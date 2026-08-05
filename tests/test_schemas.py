"""The security boundary. These tests are the reason `extra="forbid"` is there."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from chatbot.schemas import (
    ACTIONS,
    ALLOWED_ACTIONS,
    MAX_LIMIT,
    parse_tool_request,
    tool_definitions,
    validate_action,
)


class TestActionAllowlist:
    @pytest.mark.parametrize("action", ACTIONS)
    def test_approved_actions_pass(self, action: str) -> None:
        validate_action(action)

    @pytest.mark.parametrize(
        "action",
        [
            "acknowledge_alarm",
            "close_alarm",
            "restart_device",
            "delete_logs",
            "execute_query",
            "call_any_endpoint",
            "get_active_alarms ",  # trailing space must not sneak through
            "GET_ACTIVE_ALARMS",  # nor a case variant
            "",
        ],
    )
    def test_everything_else_is_rejected(self, action: str) -> None:
        with pytest.raises(PermissionError):
            validate_action(action)

    def test_write_verbs_are_absent_from_the_allowlist(self) -> None:
        for verb in ("acknowledge", "close", "delete", "restart", "update", "create"):
            assert not any(verb in action for action in ALLOWED_ACTIONS)


class TestParameterValidation:
    def test_unknown_parameter_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            parse_tool_request("get_active_alarms", {"sql": "DROP TABLE alarms"})

    def test_invalid_enum_value_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            parse_tool_request("get_active_alarms", {"severity": "catastrophic"})

    @pytest.mark.parametrize("limit", [0, -1, MAX_LIMIT + 1, 10_000])
    def test_out_of_range_limit_is_rejected(self, limit: int) -> None:
        with pytest.raises(ValidationError):
            parse_tool_request("get_active_alarms", {"limit": limit})

    def test_limit_within_range_is_accepted(self) -> None:
        assert parse_tool_request("get_active_alarms", {"limit": MAX_LIMIT}).parameters.limit == MAX_LIMIT

    @pytest.mark.parametrize(
        "alarm_id", ["ALM-1842", "ALM-1", "ALM-99999999"]
    )
    def test_wellformed_alarm_ids_accepted(self, alarm_id: str) -> None:
        req = parse_tool_request("get_alarm_details", {"alarm_id": alarm_id})
        assert req.parameters.alarm_id == alarm_id

    @pytest.mark.parametrize(
        "alarm_id",
        [
            "ALM-1842; DROP TABLE alarms",
            "../../etc/passwd",
            "ALM-",
            "1842",
            "ALM-1842 OR 1=1",
            "",
        ],
    )
    def test_malformed_alarm_ids_rejected(self, alarm_id: str) -> None:
        with pytest.raises(ValidationError):
            parse_tool_request("get_alarm_details", {"alarm_id": alarm_id})

    @pytest.mark.parametrize(
        "device_id", ["CAM-014; rm -rf /", "cam-014", "DEVICE_014", "../CAM-014"]
    )
    def test_malformed_device_ids_rejected(self, device_id: str) -> None:
        with pytest.raises(ValidationError):
            parse_tool_request("get_device_status", {"device_id": device_id})

    def test_required_parameter_cannot_be_omitted(self) -> None:
        with pytest.raises(ValidationError):
            parse_tool_request("get_alarm_details", {})

    def test_oversized_site_rejected(self) -> None:
        with pytest.raises(ValidationError):
            parse_tool_request("get_active_alarms", {"site": "x" * 101})

    def test_unknown_action_raises_before_validation(self) -> None:
        with pytest.raises(PermissionError):
            parse_tool_request("delete_everything", {})


class TestToolDefinitions:
    def test_one_definition_per_approved_action(self) -> None:
        names = [d["name"] for d in tool_definitions()]
        assert names == list(ACTIONS)
        assert set(names) == ALLOWED_ACTIONS

    @pytest.mark.parametrize("definition", tool_definitions(), ids=lambda d: d["name"])
    def test_definitions_are_strict(self, definition: dict) -> None:
        schema = definition["input_schema"]
        assert definition["strict"] is True
        assert schema["additionalProperties"] is False
        # Strict mode needs an explicit `required`; every property is listed so an
        # omitted key can never be mistaken for an intentional null.
        assert set(schema["required"]) == set(schema["properties"])

    @pytest.mark.parametrize("definition", tool_definitions(), ids=lambda d: d["name"])
    def test_descriptions_state_read_only(self, definition: dict) -> None:
        assert "Read-only." in definition["description"]
        assert len(definition["description"]) > 100
