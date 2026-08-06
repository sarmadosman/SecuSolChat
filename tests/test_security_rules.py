"""Controls that must hold regardless of what the model asks for."""

from __future__ import annotations

import inspect

import pytest

from chatbot.controller import RECORD_KIND, execute_tool_request
from chatbot.schemas import ACTIONS, MAX_LIMIT
from security_client import api_client, mock_client
from security_client.base import MAX_LIMIT as CLIENT_MAX_LIMIT
from security_client.sanitization import ALLOWLISTS, sanitize_records

# Fields that must never reach the model, matched against the raw fixtures.
FORBIDDEN = [
    "username",
    "person_name",
    "badge_id",
    "ip_address",
    "mac_address",
    "operator_ip",
    "acknowledged_by",
    "internal_url",
    "raw_payload",
    "raw_line",
    "session_token",
]


@pytest.fixture(scope="module")
def client() -> mock_client.MockSecurityClient:
    return mock_client.MockSecurityClient()


class TestSanitization:
    @pytest.mark.parametrize(
        ("collection", "kind"),
        [("alarms", "alarm"), ("events", "event"), ("logs", "log"), ("devices", "device")],
    )
    def test_sensitive_fields_are_stripped(self, client, collection: str, kind: str) -> None:
        raw = getattr(client, collection)
        assert raw, f"fixture {collection} is empty"
        # The fixtures must actually contain something to strip, or this proves nothing.
        assert any(field in record for record in raw for field in FORBIDDEN)

        for record in sanitize_records(raw, kind):
            assert not (set(record) & set(FORBIDDEN))
            assert set(record) <= ALLOWLISTS[kind]

    def test_unknown_record_kind_raises_rather_than_passing_through(self) -> None:
        with pytest.raises(ValueError):
            sanitize_records([{"secret": "x"}], "not_a_kind")

    def test_every_record_returning_action_has_an_allowlist(self) -> None:
        # summarize_records returns counts, not records, so it has no allowlist.
        record_actions = set(ACTIONS) - {"summarize_records"}
        assert set(RECORD_KIND) == record_actions
        assert set(RECORD_KIND.values()) <= set(ALLOWLISTS)

    def test_summaries_carry_no_record_bodies(self) -> None:
        """Aggregation must not become a side channel around sanitization."""
        from security_client.mock_client import MockSecurityClient

        summary = MockSecurityClient().summarize_records(
            record_type="events", group_by="type", limit=50
        )
        payload = summary.to_tool_payload()
        assert "records" not in payload
        assert set(payload["groups"][0]) == {"key", "count"}


class TestResultCaps:
    def test_client_caps_beyond_requested_limit(self, client) -> None:
        result = client.search_logs(limit=MAX_LIMIT)
        assert len(result.records) <= CLIENT_MAX_LIMIT

    def test_truncation_is_disclosed_not_hidden(self, client) -> None:
        result = client.search_logs(limit=5)
        assert result.truncated is True
        payload = result.to_tool_payload()
        assert payload["returned"] == 5
        assert payload["total_matched"] > 5
        assert payload["truncated"] is True

    def test_ordering_is_deterministic_so_truncation_is_predictable(self, client) -> None:
        first = client.get_active_alarms(limit=10).records
        second = client.get_active_alarms(limit=10).records
        assert [r["id"] for r in first] == [r["id"] for r in second]
        timestamps = [r["timestamp"] for r in first]
        assert timestamps == sorted(timestamps, reverse=True)


class TestExecutionPath:
    def test_unapproved_action_is_never_executed(self, client) -> None:
        outcome = execute_tool_request(client, "delete_logs", {})
        assert outcome.is_error
        assert "rejected" in outcome.payload["error"].lower()
        assert "records" not in outcome.payload

    def test_injected_parameter_is_rejected(self, client) -> None:
        outcome = execute_tool_request(
            client, "get_active_alarms", {"severity": "critical", "callback_url": "http://evil"}
        )
        assert outcome.is_error

    def test_unknown_device_is_reported_not_substituted(self, client) -> None:
        outcome = execute_tool_request(client, "get_device_status", {"device": "Server 99"})
        assert outcome.is_error
        assert "No device matches" in outcome.payload["error"]
        assert "records" not in outcome.payload

    def test_ambiguous_device_returns_candidates_rather_than_picking(self, client) -> None:
        outcome = execute_tool_request(client, "get_device_status", {"device": "pc"})
        assert outcome.is_error
        assert len(outcome.payload["candidates"]) > 1
        assert set(outcome.payload["candidates"][0]) == {"id", "name"}

    def test_successful_call_returns_sanitized_records(self, client) -> None:
        outcome = execute_tool_request(
            client, "get_active_alarms", {"severity": "critical", "limit": 5}
        )
        assert not outcome.is_error
        for record in outcome.payload["records"]:
            assert not (set(record) & set(FORBIDDEN))

    def test_oversized_limit_never_reaches_the_client(self, client) -> None:
        outcome = execute_tool_request(client, "search_logs", {"limit": 5000})
        assert outcome.is_error  # schema rejects it before the client is touched


class TestNoArbitraryRequestPrimitive:
    """The one design property worth asserting mechanically."""

    def test_real_client_has_no_generic_request_helper(self) -> None:
        public = [
            name
            for name, _ in inspect.getmembers(
                api_client.RealSecurityApiClient, inspect.isfunction
            )
            if not name.startswith("_")
        ]
        assert set(public) == set(ACTIONS)

    def test_real_client_paths_are_allowlisted(self) -> None:
        assert api_client._ALLOWED_PATHS  # noqa: SLF001 - asserting on the control itself
        for path in api_client._ALLOWED_PATHS:  # noqa: SLF001
            assert path.startswith("/")

    def test_only_get_is_ever_issued(self) -> None:
        source = inspect.getsource(api_client)
        for verb in (".post(", ".put(", ".patch(", ".delete(", ".request("):
            assert verb not in source, f"non-GET call {verb} present in api_client"
