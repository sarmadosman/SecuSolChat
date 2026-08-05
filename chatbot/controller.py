"""The tool-use loop: validate -> execute -> sanitize -> summarize.

Split deliberately in two:

* `execute_tool_request` is pure — no network, no SDK. It is the security-critical
  path (allowlist, validation, capping, sanitization) and is unit-testable on its
  own, which is the point.
* `Controller` owns the Claude conversation and imports the SDK lazily, so the
  above stays testable without an API key or the `anthropic` package installed.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from chatbot import audit, prompts
from chatbot.schemas import parse_tool_request, tool_definitions
from chatbot.timeutil import resolve_window, utc_now
from security_client.base import QueryResult, SecurityClient
from security_client.sanitization import sanitize_records

MODEL = "claude-opus-5"
MAX_TOKENS = 16_000
#: Bounds a single user turn. Caps runaway loops and limits the blast radius of
#: anything injected via record content to a handful of logged reads.
MAX_TOOL_CALLS_PER_TURN = 4

class ConfigurationError(RuntimeError):
    """The deployment is misconfigured — distinct from the platform being unreachable.

    Worth its own type: a missing API key and a down security platform need
    completely different responses, and collapsing them into one generic error
    sends an operator chasing an outage that isn't happening.
    """


#: Which field allowlist applies to each action's records.
RECORD_KIND: dict[str, str] = {
    "get_active_alarms": "alarm",
    "get_alarm_details": "alarm",
    "get_recent_events": "event",
    "search_logs": "log",
    "get_device_status": "device",
}


@dataclass
class ToolOutcome:
    action: str
    parameters: dict[str, Any]
    payload: dict[str, Any]
    is_error: bool = False


@dataclass
class Turn:
    answer: str
    evidence: list[ToolOutcome] = field(default_factory=list)
    stop_reason: str | None = None


def execute_tool_request(
    client: SecurityClient, action: str, raw_parameters: dict[str, Any] | None
) -> ToolOutcome:
    """Validate a model-proposed call, run it, sanitize the result.

    Never raises for a bad request: an invalid action or parameter comes back as
    an error payload so the model can correct itself, while the illegal call is
    still never executed.
    """
    started = time.perf_counter()

    try:
        request = parse_tool_request(action, raw_parameters)
    except (PermissionError, ValidationError) as exc:
        detail = (
            str(exc)
            if isinstance(exc, PermissionError)
            else "; ".join(
                f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:5]
            )
        )
        audit.log_tool_call(
            action=action,
            parameters=raw_parameters,
            result_count=0,
            total_matched=0,
            truncated=False,
            duration_ms=int((time.perf_counter() - started) * 1000),
            status="rejected",
            error=detail,
        )
        return ToolOutcome(
            action=action,
            parameters=raw_parameters or {},
            payload={"error": f"Request rejected: {detail}"},
            is_error=True,
        )

    params = request.parameters.model_dump()
    window = params.pop("window", None)
    since, until = resolve_window(window)
    kind = RECORD_KIND[request.action]

    try:
        if request.action == "get_alarm_details":
            record = client.get_alarm_details(alarm_id=params["alarm_id"])
            result = QueryResult(records=[record] if record else [], total_matched=1 if record else 0)
        elif request.action == "get_active_alarms":
            result = client.get_active_alarms(since=since, until=until, **params)
        elif request.action == "get_recent_events":
            result = client.get_recent_events(since=since, until=until, **params)
        elif request.action == "search_logs":
            result = client.search_logs(since=since, until=until, **params)
        else:  # get_device_status — no time filter; device state is current, not historical
            result = client.get_device_status(**params)
    except Exception as exc:  # noqa: BLE001 - surface a generic failure, log the detail
        audit.log_tool_call(
            action=request.action,
            parameters=params,
            result_count=0,
            total_matched=0,
            truncated=False,
            duration_ms=int((time.perf_counter() - started) * 1000),
            status="error",
            error=f"{type(exc).__name__}: {exc}",
        )
        return ToolOutcome(
            action=request.action,
            parameters=params,
            payload={"error": "The security platform could not be reached."},
            is_error=True,
        )

    payload = result.to_tool_payload()
    payload["records"] = sanitize_records(payload["records"], kind)
    if window:
        payload["window"] = window

    audit.log_tool_call(
        action=request.action,
        parameters={**params, "window": window} if window else params,
        result_count=len(result.records),
        total_matched=result.total_matched,
        truncated=result.truncated,
        duration_ms=int((time.perf_counter() - started) * 1000),
        status="success",
    )
    return ToolOutcome(action=request.action, parameters=params, payload=payload)


def build_client() -> SecurityClient:
    """Pick an implementation from the environment. The controller never knows which."""
    choice = os.getenv("SECURITY_CLIENT", "mock").strip().lower()
    if choice == "mock":
        from security_client.mock_client import MockSecurityClient

        return MockSecurityClient()
    if choice == "real":
        from security_client.api_client import RealSecurityApiClient

        return RealSecurityApiClient()
    raise ValueError(f"SECURITY_CLIENT must be 'mock' or 'real', got {choice!r}")


class Controller:
    def __init__(
        self,
        client: SecurityClient | None = None,
        *,
        model: str = MODEL,
        max_tool_calls: int = MAX_TOOL_CALLS_PER_TURN,
    ) -> None:
        import anthropic  # lazy: keeps execute_tool_request testable without the SDK

        self.anthropic = anthropic
        self.llm = anthropic.Anthropic()
        self.client = client or build_client()
        self.model = model
        self.max_tool_calls = max_tool_calls
        self.tools = tool_definitions()

    def process_message(
        self, user_message: str, history: list[dict[str, Any]] | None = None
    ) -> tuple[Turn, list[dict[str, Any]]]:
        """Run one user turn. Returns the turn and the updated message history."""
        messages: list[dict[str, Any]] = list(history or [])
        messages.append({"role": "user", "content": user_message})
        # Message-level system note, not the top-level prompt: keeps the cached
        # prefix byte-stable while still giving the model a clock.
        messages.append(
            {"role": "system", "content": prompts.time_context(utc_now().isoformat())}
        )

        evidence: list[ToolOutcome] = []
        calls_made = 0
        stop_reason: str | None = None

        while True:
            response = self._create(messages)
            stop_reason = response.stop_reason
            messages.append({"role": "assistant", "content": response.content})

            if stop_reason != "tool_use":
                break

            tool_uses = [b for b in response.content if b.type == "tool_use"]
            results: list[dict[str, Any]] = []
            for block in tool_uses:
                if calls_made >= self.max_tool_calls:
                    results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": "Tool call budget for this turn is exhausted. "
                            "Answer with what you already have, or ask the user to narrow "
                            "the question.",
                            "is_error": True,
                        }
                    )
                    continue

                outcome = execute_tool_request(self.client, block.name, dict(block.input or {}))
                calls_made += 1
                evidence.append(outcome)
                results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": prompts.wrap_records(outcome.payload),
                        "is_error": outcome.is_error,
                    }
                )

            messages.append({"role": "user", "content": results})

        answer = "".join(b.text for b in response.content if b.type == "text").strip()
        if stop_reason == "refusal":
            answer = answer or "I can't help with that request."

        return Turn(answer=answer, evidence=evidence, stop_reason=stop_reason), messages

    def _create(self, messages: list[dict[str, Any]]) -> Any:
        try:
            return self._request(messages)
        except self.anthropic.AuthenticationError as exc:
            raise ConfigurationError(
                "Claude rejected the credentials. Check ANTHROPIC_API_KEY in .env."
            ) from exc
        except TypeError as exc:
            # The SDK resolves credentials at request time, not construction, and
            # raises a bare TypeError when it finds none. Translate it, or a
            # first-run setup mistake looks like a security-platform outage.
            if "authentication" in str(exc).lower():
                raise ConfigurationError(
                    "No Claude credentials found. Copy .env.example to .env and set "
                    "ANTHROPIC_API_KEY."
                ) from exc
            raise

    def _request(self, messages: list[dict[str, Any]]) -> Any:
        return self.llm.messages.create(
            model=self.model,
            max_tokens=MAX_TOKENS,
            system=[
                {
                    "type": "text",
                    "text": prompts.SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            tools=self.tools,
            # Routing and summarizing are not hard reasoning. Note we do NOT set
            # thinking={"type": "disabled"} — with thinking off, Opus 5 can write a
            # tool call into visible text instead of emitting a tool_use block, and
            # the call then silently never runs. Low effort is the right lever.
            output_config={"effort": "low"},
            messages=messages,
        )
