"""The tool-use loop, driven by a fake model.

`Controller.__init__` imports the Anthropic SDK, so these build the object with
`__new__` and inject a stub. That keeps the loop — budget enforcement, evidence
collection, error round-tripping — testable with no API key and no network.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from chatbot import prompts
from chatbot.controller import (
    MAX_TOOL_CALLS_PER_TURN,
    Controller,
    execute_tool_request,
)
from chatbot.schemas import tool_definitions
from security_client.mock_client import MockSecurityClient


# --- stubs -------------------------------------------------------------------


@dataclass
class TextBlock:
    text: str
    type: str = "text"


@dataclass
class ToolUseBlock:
    name: str
    input: dict[str, Any]
    id: str = "toolu_1"
    type: str = "tool_use"


@dataclass
class FakeResponse:
    content: list[Any]
    stop_reason: str


class FakeLLM:
    """Replays a scripted list of responses and records what it was sent."""

    def __init__(self, responses: list[FakeResponse]) -> None:
        self._responses = list(responses)
        self.requests: list[dict[str, Any]] = []
        self.messages = self

    def create(self, **kwargs: Any) -> FakeResponse:
        self.requests.append(kwargs)
        if not self._responses:
            return FakeResponse([TextBlock("done")], "end_turn")
        return self._responses.pop(0)


def make_controller(responses: list[FakeResponse]) -> Controller:
    import anthropic

    controller = Controller.__new__(Controller)
    controller.anthropic = anthropic
    controller.llm = FakeLLM(responses)
    controller.client = MockSecurityClient()
    controller.model = "claude-opus-5"
    controller.max_tool_calls = MAX_TOOL_CALLS_PER_TURN
    controller.tools = tool_definitions()
    return controller


@pytest.fixture(scope="module")
def client() -> MockSecurityClient:
    return MockSecurityClient()


# --- execution path ----------------------------------------------------------


class TestExecuteToolRequest:
    def test_payload_shape(self, client) -> None:
        outcome = execute_tool_request(client, "get_active_alarms", {"severity": "critical"})
        assert set(outcome.payload) >= {"records", "returned", "total_matched", "truncated"}
        assert outcome.payload["returned"] == len(outcome.payload["records"])

    def test_window_is_resolved_and_echoed(self, client) -> None:
        outcome = execute_tool_request(
            client, "search_logs", {"window": "last_hour", "limit": 5}
        )
        assert outcome.payload["window"] == "last_hour"
        # `window` is consumed into since/until, never forwarded to the client.
        assert "window" not in outcome.parameters

    def test_missing_alarm_reports_nothing_found(self, client) -> None:
        outcome = execute_tool_request(client, "get_alarm_details", {"alarm_id": "ALM-999999"})
        assert not outcome.is_error
        assert outcome.payload["records"] == []
        assert outcome.payload["total_matched"] == 0

    def test_client_failure_yields_a_generic_message(self) -> None:
        class Broken:
            def get_active_alarms(self, **_: Any):
                raise RuntimeError("token=sk-secret host=https://internal.mtc")

        outcome = execute_tool_request(Broken(), "get_active_alarms", {})
        assert outcome.is_error
        # The detail goes to the audit log; the model sees nothing sensitive.
        assert "sk-secret" not in str(outcome.payload)
        assert "internal.mtc" not in str(outcome.payload)


# --- the loop ----------------------------------------------------------------


class TestLoop:
    def test_plain_answer_makes_no_tool_call(self) -> None:
        controller = make_controller([FakeResponse([TextBlock("I am read-only.")], "end_turn")])
        turn, _ = controller.process_message("Restart camera 14")
        assert turn.answer == "I am read-only."
        assert turn.evidence == []

    def test_tool_call_then_answer(self) -> None:
        controller = make_controller(
            [
                FakeResponse(
                    [ToolUseBlock("get_active_alarms", {"severity": "critical", "limit": 5})],
                    "tool_use",
                ),
                FakeResponse([TextBlock("There are critical alarms.")], "end_turn"),
            ]
        )
        turn, history = controller.process_message("Any critical alarms?")
        assert turn.answer == "There are critical alarms."
        assert len(turn.evidence) == 1
        assert turn.evidence[0].action == "get_active_alarms"
        assert turn.evidence[0].payload["records"]
        assert any(m["role"] == "system" for m in history)

    def test_records_are_wrapped_as_untrusted(self) -> None:
        controller = make_controller(
            [
                FakeResponse([ToolUseBlock("get_active_alarms", {"limit": 2})], "tool_use"),
                FakeResponse([TextBlock("ok")], "end_turn"),
            ]
        )
        controller.process_message("alarms?")
        sent = controller.llm.requests[-1]["messages"]
        tool_results = [
            block
            for message in sent
            if isinstance(message["content"], list)
            for block in message["content"]
            if isinstance(block, dict) and block.get("type") == "tool_result"
        ]
        assert tool_results
        assert 'trust="untrusted"' in tool_results[0]["content"]

    def test_rejected_call_round_trips_as_an_error(self) -> None:
        controller = make_controller(
            [
                FakeResponse([ToolUseBlock("get_active_alarms", {"severity": "boom"})], "tool_use"),
                FakeResponse([TextBlock("Let me rephrase.")], "end_turn"),
            ]
        )
        turn, _ = controller.process_message("alarms?")
        assert turn.evidence[0].is_error
        assert turn.answer == "Let me rephrase."

    def test_tool_budget_is_enforced(self) -> None:
        """A loop that keeps calling tools is cut off, not allowed to run away."""
        responses = [
            FakeResponse([ToolUseBlock("get_active_alarms", {"limit": 1}, id=f"t{i}")], "tool_use")
            for i in range(MAX_TOOL_CALLS_PER_TURN + 3)
        ]
        responses.append(FakeResponse([TextBlock("stopping")], "end_turn"))
        controller = make_controller(responses)
        turn, _ = controller.process_message("keep going")
        assert len(turn.evidence) == MAX_TOOL_CALLS_PER_TURN

    def test_refusal_never_yields_an_empty_answer(self) -> None:
        controller = make_controller([FakeResponse([], "refusal")])
        turn, _ = controller.process_message("something disallowed")
        assert turn.answer
        assert turn.stop_reason == "refusal"


class TestRequestConstruction:
    def test_system_prompt_is_cached_and_tools_are_attached(self) -> None:
        controller = make_controller([FakeResponse([TextBlock("hi")], "end_turn")])
        controller.process_message("hello")
        request = controller.llm.requests[0]
        assert request["system"][0]["cache_control"] == {"type": "ephemeral"}
        assert request["system"][0]["text"] == prompts.SYSTEM_PROMPT
        assert len(request["tools"]) == 5

    def test_thinking_is_not_disabled(self) -> None:
        """Disabling thinking on Opus 5 can turn tool calls into plain text."""
        controller = make_controller([FakeResponse([TextBlock("hi")], "end_turn")])
        controller.process_message("hello")
        assert "thinking" not in controller.llm.requests[0]

    def test_clock_is_injected_per_turn_not_baked_into_the_prompt(self) -> None:
        controller = make_controller([FakeResponse([TextBlock("hi")], "end_turn")])
        controller.process_message("what happened today?")
        request = controller.llm.requests[0]
        assert "Current time" not in request["system"][0]["text"]
        system_messages = [m for m in request["messages"] if m["role"] == "system"]
        assert len(system_messages) == 1
        assert "Current time is" in system_messages[0]["content"]
