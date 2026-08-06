"""Retrieval behaviour, including the planted records the sample questions need."""

from __future__ import annotations

from datetime import datetime

import pytest

from chatbot.timeutil import resolve_window
from security_client.base import AmbiguousDevice, DeviceNotFound, SecurityClient
from security_client.mock_client import MockSecurityClient


@pytest.fixture(scope="module")
def client() -> MockSecurityClient:
    return MockSecurityClient()


def test_mock_satisfies_the_protocol(client) -> None:
    assert isinstance(client, SecurityClient)


class TestFixtureShape:
    def test_volumes_are_realistic(self, client) -> None:
        assert len(client.alarms) >= 100
        assert len(client.events) >= 300
        assert len(client.logs) >= 500
        assert len(client.devices) >= 30

    def test_variation_exists(self, client) -> None:
        assert {a["severity"] for a in client.alarms} == {"info", "warning", "major", "critical"}
        assert {a["status"] for a in client.alarms} >= {"active", "resolved"}
        assert {d["status"] for d in client.devices} >= {"online", "offline"}
        assert {d["category"] for d in client.devices} == {"it", "security", "operations"}
        assert len({d["type"] for d in client.devices}) >= 6
        assert len({d["area"] for d in client.devices}) >= 3

    def test_records_carry_device_context(self, client) -> None:
        """Every record must name its device the way an operator would."""
        for collection in (client.alarms, client.events, client.logs):
            sample = collection[0]
            assert {"device_id", "device_name", "device_type", "category", "area"} <= set(sample)


class TestDeviceResolution:
    """'pc # 10' must reach PC-010. This is the whole point of the layer."""

    @pytest.mark.parametrize(
        "query", ["pc # 10", "PC 10", "pc10", "PC-010", "PC-10", "pc 010"]
    )
    def test_pc_10_resolves_however_it_is_typed(self, client, query: str) -> None:
        assert client.resolve_device(query)["id"] == "PC-010"

    @pytest.mark.parametrize(
        ("query", "expected"),
        [
            ("Machine 14", "MCH-014"),
            ("machine 14", "MCH-014"),
            ("Server 2", "SRV-002"),
            ("Building A Door 3", "DOOR-A3"),
            ("Sensor 9", "SNS-009"),
            ("Access Controller 4", "AC-004"),
        ],
    )
    def test_operator_names_resolve(self, client, query: str, expected: str) -> None:
        assert client.resolve_device(query)["id"] == expected

    def test_exact_match_beats_prefix(self, client) -> None:
        """'Server 2' must not drag in 'Server 20' when 'Server 2' exists."""
        assert client.resolve_device("Server 2")["id"] == "SRV-002"

    def test_ambiguous_reference_raises_with_candidates(self, client) -> None:
        with pytest.raises(AmbiguousDevice) as exc:
            client.resolve_device("pc")
        assert len(exc.value.candidates) > 1

    def test_unknown_device_raises_rather_than_guessing(self, client) -> None:
        with pytest.raises(DeviceNotFound):
            client.resolve_device("Server 99")

    def test_resolution_is_reported_back(self, client) -> None:
        payload = client.get_device_status(device="pc # 10").to_tool_payload()
        assert payload["resolved_device"] == {"id": "PC-010", "name": "PC 10"}


class TestFiltering:
    def test_severity_filter(self, client) -> None:
        result = client.get_active_alarms(severity="critical", limit=100)
        assert result.records
        assert all(r["severity"] == "critical" for r in result.records)

    def test_area_filter_is_case_insensitive(self, client) -> None:
        lower = client.get_active_alarms(area="building a", limit=100)
        exact = client.get_active_alarms(area="Building A", limit=100)
        assert lower.total_matched == exact.total_matched > 0

    def test_category_filter(self, client) -> None:
        result = client.get_device_status(category="it", limit=100)
        assert result.records
        assert all(r["category"] == "it" for r in result.records)
        assert all(r["type"] in {"pc", "server", "network"} for r in result.records)

    def test_device_type_filter(self, client) -> None:
        result = client.get_device_status(device_type="server", limit=100)
        assert result.records
        assert all(r["type"] == "server" for r in result.records)

    def test_alarm_type_filter(self, client) -> None:
        result = client.get_active_alarms(alarm_type="tamper", limit=100)
        assert result.records
        assert all(r["type"] == "tamper" for r in result.records)

    def test_status_defaults_to_active_but_can_be_overridden(self, client) -> None:
        assert all(r["status"] == "active" for r in client.get_active_alarms(limit=100).records)
        resolved = client.get_active_alarms(status="resolved", limit=100)
        assert resolved.records
        assert all(r["status"] == "resolved" for r in resolved.records)

    def test_log_level_is_a_floor_not_an_exact_match(self, client) -> None:
        result = client.search_logs(level="error", limit=100)
        assert result.records
        assert all(r["level"] in {"error", "critical"} for r in result.records)

    def test_time_window_excludes_older_records(self, client) -> None:
        since, until = resolve_window("last_hour")
        result = client.search_logs(since=since, until=until, limit=100)
        for record in result.records:
            assert datetime.fromisoformat(record["timestamp"]) >= since
        assert result.total_matched < client.search_logs(limit=100).total_matched

    def test_oldest_sort_answers_longest_active(self, client) -> None:
        newest = client.get_active_alarms(limit=1).records[0]
        oldest = client.get_active_alarms(sort="oldest", limit=1).records[0]
        assert oldest["timestamp"] < newest["timestamp"]

    def test_unknown_filter_value_returns_empty_not_everything(self, client) -> None:
        result = client.get_active_alarms(area="Atlantis", limit=100)
        assert result.total_matched == 0
        assert result.records == []


class TestSummarize:
    def test_counts_cover_every_match_not_a_page(self, client) -> None:
        summary = client.summarize_records(record_type="alarms", group_by="type", limit=50)
        listed = client.get_active_alarms(status=None, limit=100)
        # The summary total must exceed what a single capped page could report.
        assert summary.total_records == len(client.alarms)
        assert summary.total_records > len(listed.records)

    def test_groups_are_ranked_descending(self, client) -> None:
        summary = client.summarize_records(record_type="alarms", group_by="type", limit=10)
        counts = [g.count for g in summary.groups]
        assert counts == sorted(counts, reverse=True)

    def test_group_limit_is_respected_and_disclosed(self, client) -> None:
        summary = client.summarize_records(record_type="alarms", group_by="type", limit=3)
        payload = summary.to_tool_payload()
        assert len(summary.groups) == 3
        assert payload["truncated"] is True
        assert payload["total_groups"] > 3

    def test_group_by_device_uses_names_not_ids(self, client) -> None:
        summary = client.summarize_records(record_type="events", group_by="device", limit=5)
        assert summary.groups
        assert not any(g.key.startswith(("PC-", "MCH-", "SRV-")) for g in summary.groups)

    def test_filters_apply_before_counting(self, client) -> None:
        everything = client.summarize_records(record_type="alarms", group_by="type", limit=50)
        it_only = client.summarize_records(
            record_type="alarms", group_by="type", category="it", limit=50
        )
        assert 0 < it_only.total_records < everything.total_records


class TestLookups:
    def test_known_alarm_is_found(self, client) -> None:
        alarm = client.get_alarm_details(alarm_id="ALM-1842")
        assert alarm is not None
        assert alarm["device_name"] == "Machine 14"

    def test_unknown_alarm_returns_none_rather_than_inventing_one(self, client) -> None:
        assert client.get_alarm_details(alarm_id="ALM-999999") is None


class TestTargetQuestions:
    """The three questions MTC named as the bar for success."""

    def test_top_10_alarms(self, client) -> None:
        """'What are the top 10 alarms?' — needs ranked counts."""
        summary = client.summarize_records(record_type="alarms", group_by="type", limit=10)
        assert len(summary.groups) >= 5
        assert summary.total_records >= 100
        assert summary.groups[0].count >= summary.groups[-1].count

    def test_what_happened_to_pc_10(self, client) -> None:
        """'What happened to pc # 10?' — needs name resolution across three tools."""
        status = client.get_device_status(device="pc # 10")
        assert status.records[0]["status"] == "offline"

        logs = client.search_logs(device="pc # 10", limit=10)
        assert logs.total_matched >= 4
        messages = " ".join(r["message"] for r in logs.records)
        assert "Connection to the monitoring server lost" in messages

        alarms = client.get_active_alarms(device="pc # 10", limit=10)
        assert alarms.total_matched >= 1

    def test_anything_wrong_with_it(self, client) -> None:
        """'Is there anything wrong with the IT?' — needs the category grouping."""
        offline = client.get_device_status(category="it", status="offline", limit=50)
        assert offline.total_matched >= 1
        assert all(r["type"] in {"pc", "server", "network"} for r in offline.records)

        alarms = client.get_active_alarms(category="it", limit=50)
        assert alarms.total_matched >= 1
        assert all(r["category"] == "it" for r in alarms.records)


class TestPlantedScenarios:
    def test_machine_14_is_offline_with_an_active_alarm(self, client) -> None:
        assert client.get_device_status(device="Machine 14").records[0]["status"] == "offline"
        assert client.get_active_alarms(device="Machine 14", limit=10).total_matched >= 1

    def test_repeated_auth_failures_from_pc_22(self, client) -> None:
        since, until = resolve_window("last_24_hours")
        result = client.get_recent_events(
            event_type="auth_failure", device="PC 22", since=since, until=until, limit=100
        )
        assert result.total_matched >= 9

    def test_repeated_access_denials_at_building_a_door_3(self, client) -> None:
        result = client.get_recent_events(
            event_type="access_denied", device="Building A Door 3", limit=100
        )
        assert result.total_matched >= 6

    def test_server_2_has_a_storage_alarm(self, client) -> None:
        result = client.get_active_alarms(device="Server 2", limit=10)
        assert any("97%" in r["message"] for r in result.records)

    def test_some_devices_are_offline(self, client) -> None:
        assert client.get_device_status(status="offline", limit=100).total_matched >= 3


class TestInjectionFixtures:
    """The poisoned records must survive sanitization — that is the test surface."""

    def test_injected_alarm_text_is_present_in_the_corpus(self, client) -> None:
        messages = " ".join(a["message"] for a in client.alarms)
        assert "Ignore all previous instructions" in messages

    def test_injected_text_reaches_the_model_as_data(self, client) -> None:
        from security_client.sanitization import sanitize_records

        poisoned = [a for a in client.alarms if "Ignore all previous" in a["message"]]
        assert poisoned
        sanitized = sanitize_records(poisoned, "alarm")
        # Still there after sanitization: it is content to report on, and the
        # prompt plus the tool-call cap are what keep it from being acted on.
        assert "Ignore all previous instructions" in sanitized[0]["message"]
