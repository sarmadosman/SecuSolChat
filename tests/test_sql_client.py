"""SQL client — behaviour, injection resistance, and parity with the mock.

Parity is the important part. Two implementations of the same Protocol that
disagree would make the mock useless as a test surface, and the disagreement
would only surface in production. So the same questions are asked of both and
the answers are compared.

Runs against a real SQLite database built from the fixtures, so bound parameters,
GROUP BY, and COUNT(*) are genuinely exercised rather than simulated.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from chatbot.timeutil import resolve_window
from security_client.base import AmbiguousDevice, DeviceNotFound, SecurityClient
from security_client.mock_client import MockSecurityClient
from security_client.sql_client import SqlSecurityClient
from security_client.sql_schema import (
    AlarmTable,
    InvalidIdentifier,
    SqlSchema,
    validate_identifier,
)

sys_path_marker = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def db_path(tmp_path_factory) -> Path:
    from scripts.load_sqlite import build

    target = tmp_path_factory.mktemp("sql") / "security.db"
    return build(db_path=target, data_dir=sys_path_marker / "data")


@pytest.fixture(scope="module")
def sql(db_path: Path) -> SqlSecurityClient:
    return SqlSecurityClient(dsn=f"sqlite:///{db_path}")


@pytest.fixture(scope="module")
def mock() -> MockSecurityClient:
    return MockSecurityClient()


def test_sql_client_satisfies_the_protocol(sql) -> None:
    assert isinstance(sql, SecurityClient)


class TestReadOnly:
    """A database connection is a bigger blast radius than an HTTP token."""

    def test_connection_is_opened_read_only(self, db_path: Path) -> None:
        client = SqlSecurityClient(dsn=f"sqlite:///{db_path}")
        with pytest.raises(sqlite3.OperationalError):
            client._connection.execute("DELETE FROM alarms")

    @pytest.mark.parametrize(
        "statement",
        [
            "DELETE FROM alarms",
            "UPDATE alarms SET severity = 'info'",
            "DROP TABLE alarms",
            "INSERT INTO alarms (id) VALUES ('x')",
            "SELECT 1; DROP TABLE alarms",
            "select 1; delete from logs",
        ],
    )
    def test_execute_refuses_anything_that_is_not_a_single_select(self, sql, statement) -> None:
        with pytest.raises(PermissionError):
            sql._execute(statement, {})

    def test_plain_select_is_allowed(self, sql) -> None:
        assert sql._execute("SELECT COUNT(*) AS n FROM alarms", {})[0]["n"] == 120


class TestInjectionResistance:
    """Model-supplied values are bound, never concatenated. Prove it."""

    @pytest.mark.parametrize(
        "hostile",
        [
            "critical' OR '1'='1",
            "'; DROP TABLE alarms; --",
            "critical'; DELETE FROM logs WHERE '1'='1",
            "\\'; SELECT * FROM devices; --",
        ],
    )
    def test_hostile_filter_values_match_nothing_and_change_nothing(self, sql, hostile) -> None:
        result = sql.get_active_alarms(severity=hostile, limit=10)
        assert result.total_matched == 0
        # The table is still intact and still read-only.
        assert sql._execute("SELECT COUNT(*) AS n FROM alarms", {})[0]["n"] == 120

    def test_hostile_device_name_resolves_to_nothing(self, sql) -> None:
        with pytest.raises(DeviceNotFound):
            sql.resolve_device("'; DROP TABLE devices; --")

    def test_hostile_alarm_id_returns_none(self, sql) -> None:
        assert sql.get_alarm_details(alarm_id="ALM-1' OR '1'='1") is None


class TestIdentifierValidation:
    """Table and column names cannot be bound, so they are validated instead."""

    @pytest.mark.parametrize(
        "identifier",
        ["alarms; DROP TABLE devices", "alarms--", "al arms", "a.b", "'alarms'", "", "1abc"],
    )
    def test_bad_identifiers_are_rejected(self, identifier: str) -> None:
        with pytest.raises(InvalidIdentifier):
            validate_identifier(identifier, context="test")

    def test_schema_validates_on_construction(self) -> None:
        with pytest.raises(InvalidIdentifier):
            SqlSchema(alarms=AlarmTable(table="alarms; DROP TABLE devices"))

    def test_sensible_identifiers_pass(self) -> None:
        for identifier in ("alarms", "security_alarms", "AlarmTable_2"):
            assert validate_identifier(identifier, context="test") == identifier


class TestParityWithMock:
    """Same question, two backends, same answer."""

    @staticmethod
    def ids(result) -> list[str]:
        return [r["id"] for r in result.records]

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"severity": "critical", "limit": 10},
            {"status": "resolved", "limit": 10},
            {"alarm_type": "tamper", "limit": 10},
            {"category": "it", "limit": 10},
            {"device_type": "server", "limit": 10},
            {"area": "Building A", "limit": 10},
            {"sort": "oldest", "limit": 5},
            {"device": "Machine 14", "limit": 10},
        ],
    )
    def test_alarm_queries_agree(self, sql, mock, kwargs) -> None:
        a, b = sql.get_active_alarms(**kwargs), mock.get_active_alarms(**kwargs)
        assert a.total_matched == b.total_matched
        assert self.ids(a) == self.ids(b)

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"event_type": "auth_failure", "limit": 10},
            {"device": "PC 22", "limit": 20},
            {"category": "security", "limit": 10},
            {"area": "Building A", "limit": 10},
        ],
    )
    def test_event_queries_agree(self, sql, mock, kwargs) -> None:
        a, b = sql.get_recent_events(**kwargs), mock.get_recent_events(**kwargs)
        assert a.total_matched == b.total_matched
        assert self.ids(a) == self.ids(b)

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"level": "error", "limit": 10},
            {"level": "warning", "limit": 10},
            {"device": "pc # 10", "limit": 10},
            {"category": "it", "limit": 10},
        ],
    )
    def test_log_queries_agree(self, sql, mock, kwargs) -> None:
        a, b = sql.search_logs(**kwargs), mock.search_logs(**kwargs)
        assert a.total_matched == b.total_matched
        assert self.ids(a) == self.ids(b)

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"status": "offline", "limit": 50},
            {"category": "it", "limit": 50},
            {"device_type": "server", "limit": 50},
            {"device": "pc # 10"},
        ],
    )
    def test_device_queries_agree(self, sql, mock, kwargs) -> None:
        a, b = sql.get_device_status(**kwargs), mock.get_device_status(**kwargs)
        assert a.total_matched == b.total_matched
        assert sorted(self.ids(a)) == sorted(self.ids(b))

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"record_type": "alarms", "group_by": "type", "limit": 10},
            {"record_type": "alarms", "group_by": "severity", "limit": 10},
            {"record_type": "alarms", "group_by": "area", "limit": 10},
            {"record_type": "events", "group_by": "type", "limit": 10},
            {"record_type": "events", "group_by": "device", "limit": 5},
            {"record_type": "logs", "group_by": "level", "limit": 5},
            {"record_type": "alarms", "group_by": "type", "category": "it", "limit": 10},
        ],
    )
    def test_summaries_agree(self, sql, mock, kwargs) -> None:
        a, b = sql.summarize_records(**kwargs), mock.summarize_records(**kwargs)
        assert a.total_records == b.total_records
        assert a.total_groups == b.total_groups
        assert {g.key: g.count for g in a.groups} == {g.key: g.count for g in b.groups}

    def test_time_windows_agree(self, sql, mock) -> None:
        since, until = resolve_window("last_24_hours")
        a = sql.search_logs(since=since, until=until, limit=20)
        b = mock.search_logs(since=since, until=until, limit=20)
        assert a.total_matched == b.total_matched

    def test_alarm_details_agree(self, sql, mock) -> None:
        a = sql.get_alarm_details(alarm_id="ALM-1842")
        b = mock.get_alarm_details(alarm_id="ALM-1842")
        assert a is not None and b is not None
        assert a["device_name"] == b["device_name"] == "Machine 14"


class TestDeviceResolution:
    @pytest.mark.parametrize("query", ["pc # 10", "PC 10", "pc10", "PC-010"])
    def test_pc_10_resolves_however_it_is_typed(self, sql, query: str) -> None:
        assert sql.resolve_device(query)["id"] == "PC-010"

    def test_ambiguous_reference_raises_with_candidates(self, sql) -> None:
        with pytest.raises(AmbiguousDevice) as exc:
            sql.resolve_device("pc")
        assert len(exc.value.candidates) > 1

    def test_unknown_device_raises(self, sql) -> None:
        with pytest.raises(DeviceNotFound):
            sql.resolve_device("Server 99")


class TestTargetQuestions:
    """MTC's three, against a real database."""

    def test_top_10_alarms(self, sql) -> None:
        summary = sql.summarize_records(record_type="alarms", group_by="type", limit=10)
        assert summary.total_records == 120  # exact COUNT(*), not a page
        counts = [g.count for g in summary.groups]
        assert counts == sorted(counts, reverse=True)

    def test_what_happened_to_pc_10(self, sql) -> None:
        assert sql.get_device_status(device="pc # 10").records[0]["status"] == "offline"
        logs = sql.search_logs(device="pc # 10", limit=10)
        assert "Connection to the monitoring server lost" in " ".join(
            r["message"] for r in logs.records
        )

    def test_anything_wrong_with_it(self, sql) -> None:
        assert sql.get_device_status(category="it", status="offline", limit=50).total_matched >= 1
        assert sql.get_active_alarms(category="it", limit=50).total_matched >= 1


class TestSanitizationStillApplies:
    def test_sensitive_fields_never_appear_in_results(self, sql) -> None:
        """Defence in depth: the tables the app reads have no PII columns at all."""
        for result in (
            sql.get_recent_events(limit=5),
            sql.get_active_alarms(limit=5),
            sql.search_logs(limit=5),
            sql.get_device_status(limit=5),
        ):
            for record in result.records:
                for leaky in (
                    "username", "person_name", "badge_id", "ip_address",
                    "mac_address", "internal_url", "session_token", "raw_line",
                    "operator_ip", "acknowledged_by",
                ):
                    assert leaky not in record


class TestConfiguration:
    def test_missing_dsn_is_a_clear_error(self, monkeypatch) -> None:
        monkeypatch.delenv("SQL_DSN", raising=False)
        with pytest.raises(RuntimeError, match="SQL_DSN"):
            SqlSecurityClient()

    def test_unsupported_scheme_is_rejected(self) -> None:
        with pytest.raises(RuntimeError, match="Unsupported"):
            SqlSecurityClient(dsn="oracle://host/db")
