"""Audit logging.

A stated requirement of the project, so it gets tests rather than trust. The two
properties that matter: every tool call produces a record, and no record ever
contains a secret.
"""

from __future__ import annotations

import json

import pytest

from chatbot import audit
from chatbot.controller import execute_tool_request
from security_client.mock_client import MockSecurityClient


@pytest.fixture(scope="module")
def client() -> MockSecurityClient:
    return MockSecurityClient()


def read_log(path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


class TestEntryShape:
    def test_successful_call_is_recorded(self, client, isolate_audit_log) -> None:
        execute_tool_request(client, "get_active_alarms", {"severity": "critical", "limit": 5})
        entries = read_log(isolate_audit_log)
        assert len(entries) == 1
        entry = entries[0]
        assert entry["action"] == "get_active_alarms"
        assert entry["status"] == "success"
        assert entry["result_count"] == 5
        assert entry["total_matched"] >= 5
        assert entry["user_id"] == audit.ANONYMOUS_USER
        assert entry["auth"] == "none"
        assert "duration_ms" in entry

    def test_rejected_call_is_recorded_with_the_reason(self, client, isolate_audit_log) -> None:
        execute_tool_request(client, "delete_logs", {})
        entry = read_log(isolate_audit_log)[0]
        assert entry["status"] == "rejected"
        assert entry["result_count"] == 0
        assert "error" in entry

    def test_truncation_is_recorded(self, client, isolate_audit_log) -> None:
        execute_tool_request(client, "search_logs", {"limit": 5})
        entry = read_log(isolate_audit_log)[0]
        assert entry["truncated"] is True
        assert entry["total_matched"] > entry["result_count"]

    def test_every_call_produces_exactly_one_entry(self, client, isolate_audit_log) -> None:
        execute_tool_request(client, "get_active_alarms", {"limit": 1})
        execute_tool_request(client, "search_logs", {"limit": 1})
        execute_tool_request(client, "not_an_action", {})
        assert len(read_log(isolate_audit_log)) == 3


class TestSecretsAreNeverLogged:
    def test_credential_shaped_parameters_are_redacted(self, isolate_audit_log) -> None:
        audit.log_tool_call(
            action="get_active_alarms",
            parameters={"severity": "critical", "api_key": "sk-ant-secret", "token": "abc"},
            result_count=0,
            total_matched=0,
            truncated=False,
            duration_ms=1,
            status="success",
        )
        raw = isolate_audit_log.read_text()
        assert "sk-ant-secret" not in raw
        assert raw.count("[REDACTED]") == 2

    def test_record_bodies_are_never_written(self, client, isolate_audit_log) -> None:
        """Parameters are bounded and safe. The records themselves are not."""
        execute_tool_request(client, "get_recent_events", {"limit": 20})
        raw = isolate_audit_log.read_text()
        for leaky in ("badge_id", "person_name", "ip_address", "username", "records"):
            assert leaky not in raw

    def test_error_detail_is_truncated(self, isolate_audit_log) -> None:
        audit.log_tool_call(
            action="get_active_alarms",
            parameters={},
            result_count=0,
            total_matched=0,
            truncated=False,
            duration_ms=1,
            status="error",
            error="x" * 5000,
        )
        assert len(read_log(isolate_audit_log)[0]["error"]) <= 200

    def test_none_valued_parameters_are_dropped(self, isolate_audit_log) -> None:
        audit.log_tool_call(
            action="get_active_alarms",
            parameters={"severity": "critical", "site": None},
            result_count=0,
            total_matched=0,
            truncated=False,
            duration_ms=1,
            status="success",
        )
        assert read_log(isolate_audit_log)[0]["parameters"] == {"severity": "critical"}
