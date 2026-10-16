"""Unit tests for unattended session pruning and its periodic wiring.

The delete logic runs against a lightweight fake Session that records the
statement it is given and returns a rowcount, so no database is needed. The real
delete against PostgreSQL is left to the integration suite.
"""

import logging
from datetime import timedelta

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.services import maintenance
from app.workers import inline


class _FakeResult:
    def __init__(self, rowcount: int) -> None:
        self.rowcount = rowcount


class _FakeSession:
    def __init__(self, *, rowcount: int = 0, fail: bool = False) -> None:
        self.rowcount = rowcount
        self.fail = fail
        self.statements = []
        self.commits = 0
        self.rollbacks = 0
        self.closed = 0

    def execute(self, statement):
        self.statements.append(statement)
        if self.fail:
            raise SQLAlchemyError("database unavailable")
        return _FakeResult(self.rowcount)

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closed += 1


@pytest.fixture
def fake_session(monkeypatch):
    """Install a fake Session and return a factory for a fresh one."""
    holder = {"session": _FakeSession()}

    def build(*, rowcount: int = 0, fail: bool = False) -> _FakeSession:
        holder["session"] = _FakeSession(rowcount=rowcount, fail=fail)
        return holder["session"]

    monkeypatch.setattr(maintenance, "session_factory", lambda: (lambda: holder["session"]))
    return build


@pytest.fixture
def maintenance_log(caplog):
    """Capture the service log on its own logger, like the inline runner tests."""
    logger = logging.getLogger("privacyshield")
    logger.addHandler(caplog.handler)
    try:
        with caplog.at_level("WARNING", logger="privacyshield"):
            yield caplog
    finally:
        logger.removeHandler(caplog.handler)


def test_prune_deletes_the_matching_rows_and_commits(fake_session):
    session = fake_session(rowcount=3)
    assert maintenance.prune_expired_sessions() == 3
    assert session.commits == 1
    assert session.rollbacks == 0
    assert session.closed == 1
    assert len(session.statements) == 1
    statement = str(session.statements[0])
    assert "DELETE FROM user_sessions" in statement
    assert "expires_at" in statement
    assert "revoked_at" in statement


def test_prune_rolls_back_and_logs_without_raising(fake_session, maintenance_log):
    session = fake_session(fail=True)
    assert maintenance.prune_expired_sessions() == 0
    assert session.commits == 0
    assert session.rollbacks == 1
    assert session.closed == 1
    assert "Session pruning skipped (SQLAlchemyError)" in maintenance_log.text
    # The driver's text can quote statement values; only the type is logged.
    assert "database unavailable" not in maintenance_log.text


def test_prune_rejects_a_negative_grace(fake_session):
    session = fake_session()
    with pytest.raises(ValueError):
        maintenance.prune_expired_sessions(grace=timedelta(seconds=-1))
    assert session.statements == []


def test_prune_is_wired_into_the_inline_sweep():
    assert inline._prune_sessions in inline.SWEEPERS


def test_prune_is_wired_into_celery_beat():
    from app.workers.celery_app import celery_app

    entry = celery_app.conf.beat_schedule["prune-sessions"]
    assert entry["task"] == "privacyshield.prune_sessions"
    assert "privacyshield.prune_sessions" in celery_app.tasks
