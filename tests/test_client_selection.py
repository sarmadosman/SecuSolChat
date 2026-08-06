"""`build_client` — which backend the USE_SQL boolean selects.

Worth testing because a misconfiguration here is silent in the worst way: the
assistant answers confidently from the wrong data source.
"""

from __future__ import annotations

import pytest

from chatbot.controller import build_client
from security_client.mock_client import MockSecurityClient


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ("USE_SQL", "SECURITY_CLIENT", "SQL_DSN"):
        monkeypatch.delenv(name, raising=False)


class TestDefault:
    def test_defaults_to_the_mock(self) -> None:
        assert isinstance(build_client(), MockSecurityClient)


class TestUseSqlBoolean:
    @pytest.mark.parametrize("value", ["true", "True", "TRUE", "1", "yes", "on"])
    def test_truthy_values_select_sql(self, monkeypatch, value: str, tmp_path) -> None:
        from scripts.load_sqlite import build
        from security_client.sql_client import SqlSecurityClient

        db = build(db_path=tmp_path / "s.db")
        monkeypatch.setenv("USE_SQL", value)
        monkeypatch.setenv("SQL_DSN", f"sqlite:///{db}")
        assert isinstance(build_client(), SqlSecurityClient)

    @pytest.mark.parametrize("value", ["false", "False", "0", "no", "off", ""])
    def test_falsey_values_fall_through_to_security_client(self, monkeypatch, value: str) -> None:
        monkeypatch.setenv("USE_SQL", value)
        assert isinstance(build_client(), MockSecurityClient)

    @pytest.mark.parametrize("value", ["maybe", "sql", "yes please", "2"])
    def test_nonsense_is_rejected_rather_than_guessed(self, monkeypatch, value: str) -> None:
        """Silently treating 'sql' as false would point at the wrong data source."""
        monkeypatch.setenv("USE_SQL", value)
        with pytest.raises(ValueError, match="USE_SQL"):
            build_client()

    def test_sql_without_a_dsn_is_a_clear_error(self, monkeypatch) -> None:
        monkeypatch.setenv("USE_SQL", "true")
        with pytest.raises(RuntimeError, match="SQL_DSN"):
            build_client()

    def test_use_sql_overrides_security_client(self, monkeypatch, tmp_path) -> None:
        from scripts.load_sqlite import build
        from security_client.sql_client import SqlSecurityClient

        db = build(db_path=tmp_path / "s.db")
        monkeypatch.setenv("USE_SQL", "true")
        monkeypatch.setenv("SECURITY_CLIENT", "mock")
        monkeypatch.setenv("SQL_DSN", f"sqlite:///{db}")
        assert isinstance(build_client(), SqlSecurityClient)


class TestSecurityClientChoice:
    @pytest.mark.parametrize("value", ["mock", "MOCK", " mock "])
    def test_mock_is_accepted(self, monkeypatch, value: str) -> None:
        monkeypatch.setenv("SECURITY_CLIENT", value)
        assert isinstance(build_client(), MockSecurityClient)

    def test_api_without_configuration_is_a_clear_error(self, monkeypatch) -> None:
        monkeypatch.setenv("SECURITY_CLIENT", "api")
        monkeypatch.delenv("SECURITY_API_URL", raising=False)
        monkeypatch.delenv("SECURITY_API_TOKEN", raising=False)
        with pytest.raises(RuntimeError, match="SECURITY_API_URL"):
            build_client()

    def test_unknown_choice_points_at_use_sql(self, monkeypatch) -> None:
        monkeypatch.setenv("SECURITY_CLIENT", "postgres")
        with pytest.raises(ValueError, match="USE_SQL"):
            build_client()
