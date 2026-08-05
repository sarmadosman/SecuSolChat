"""Shared test setup.

The audit log is redirected per-test. Without this, running the suite appends
hundreds of synthetic entries to the real logs/audit.jsonl — which both pollutes
it and makes the log useless as evidence of what actually happened in the app.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from chatbot import audit  # noqa: E402


@pytest.fixture(autouse=True)
def isolate_audit_log(tmp_path, monkeypatch):
    log_dir = tmp_path / "logs"
    monkeypatch.setattr(audit, "LOG_DIR", log_dir)
    monkeypatch.setattr(audit, "LOG_PATH", log_dir / "audit.jsonl")
    return log_dir / "audit.jsonl"
