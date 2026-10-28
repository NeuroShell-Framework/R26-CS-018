import pytest
import time
from unittest.mock import patch, MagicMock
from src.middleware.session_context import (
    SessionContextStore, Session, SessionTurn
)
from src.schemas.intent_schema import IREResponse, IntentType, Target, TargetType


@pytest.fixture
def store():
    return SessionContextStore()


@pytest.fixture
def store_disabled():
    with patch("src.middleware.session_context.get_feature_flags") as mock:
        mock.return_value.session_context = False
        mock.return_value.get_tuning = lambda k, d: d
        return SessionContextStore()


@pytest.fixture
def mock_success_response():
    resp = MagicMock(spec=IREResponse)
    resp.status = "success"
    resp.intent = IntentType.NETWORK_SCAN
    resp.target = Target(type=TargetType.SUBNET, value="192.168.1.0/24")
    resp.ports = [22, 80]
    resp.cve_ids = []
    resp.confidence = 0.92
    return resp


@pytest.fixture
def mock_error_response():
    resp = MagicMock(spec=IREResponse)
    resp.status = "error"
    resp.intent = None
    resp.target = None
    resp.ports = []
    resp.cve_ids = []
    resp.confidence = None
    return resp


class TestSessionTurn:

    def test_to_context_line_basic_format(self):
        """to_context_line produces correct basic format string."""
        turn = SessionTurn(
            turn_number=1, command="scan 10.0.0.1",
            intent="NETWORK_SCAN", target_type="IP",
            target_value="10.0.0.1", ports=[], cve_ids=[],
            confidence=0.9,
        )
        line = turn.to_context_line()
        assert "[Turn 1]" in line
        assert "NETWORK_SCAN" in line
        assert "10.0.0.1" in line

    def test_to_context_line_includes_ports(self):
        """to_context_line includes ports when present."""
        turn = SessionTurn(
            turn_number=2, command="scan host",
            intent="SERVICE_ENUMERATION", target_type="IP",
            target_value="10.0.0.1", ports=[22, 80, 443],
            cve_ids=[], confidence=0.85,
        )
        line = turn.to_context_line()
        assert "ports=[22, 80, 443]" in line

    def test_to_context_line_includes_cve_ids(self):
        """to_context_line includes cve_ids when present."""
        turn = SessionTurn(
            turn_number=1, command="exploit host",
            intent="EXPLOITATION", target_type="IP",
            target_value="10.0.0.1", ports=[445],
            cve_ids=["CVE-2017-0144"], confidence=0.78,
        )
        line = turn.to_context_line()
        assert "cves=['CVE-2017-0144']" in line

    def test_to_context_line_no_ports_or_cves(self):
        """to_context_line omits ports and cves when empty."""
        turn = SessionTurn(
            turn_number=1, command="recon target.com",
            intent="PASSIVE_RECON", target_type="DOMAIN",
            target_value="target.com", ports=[], cve_ids=[],
            confidence=0.95,
        )
        line = turn.to_context_line()
        assert "ports=" not in line
        assert "cves=" not in line


class TestSession:

    def test_add_turn_increments_turn_count(self):
        """add_turn increments the session turn_count."""
        session = Session(session_id="test-1")
        assert session.turn_count == 0
        turn = SessionTurn(
            turn_number=1, command="scan 10.0.0.1",
            intent="NETWORK_SCAN", target_type="IP",
            target_value="10.0.0.1", ports=[], cve_ids=[],
            confidence=0.9,
        )
        session.add_turn(turn)
        assert session.turn_count == 1

    def test_get_recent_turns_returns_last_n(self):
        """get_recent_turns returns only the most recent N turns."""
        session = Session(session_id="test-2")
        for i in range(5):
            session.add_turn(SessionTurn(
                turn_number=i + 1, command=f"cmd {i}",
                intent="NETWORK_SCAN", target_type="IP",
                target_value="10.0.0.1", ports=[], cve_ids=[],
                confidence=0.9,
            ))
        recent = session.get_recent_turns(3)
        assert len(recent) == 3
        assert recent[0].turn_number == 3
        assert recent[2].turn_number == 5

    def test_get_recent_turns_returns_all_when_less_than_max(self):
        """get_recent_turns returns all turns when fewer than max_turns."""
        session = Session(session_id="test-3")
        for i in range(2):
            session.add_turn(SessionTurn(
                turn_number=i + 1, command=f"cmd {i}",
                intent="NETWORK_SCAN", target_type="IP",
                target_value="10.0.0.1", ports=[], cve_ids=[],
                confidence=0.9,
            ))
        recent = session.get_recent_turns(10)
        assert len(recent) == 2

    def test_is_expired_returns_false_when_recent(self):
        """is_expired returns False when session was recently active."""
        session = Session(session_id="test-4")
        assert session.is_expired(3600) is False

    def test_is_expired_returns_true_when_stale(self):
        """is_expired returns True when session exceeded TTL."""
        session = Session(
            session_id="test-5",
            last_active=time.time() - 120,
        )
        assert session.is_expired(60) is True

    def test_get_last_target_returns_tuple(self):
        """get_last_target returns (target_type, target_value) tuple."""
        session = Session(session_id="test-6")
        session.add_turn(SessionTurn(
            turn_number=1, command="scan 10.0.0.1",
            intent="NETWORK_SCAN", target_type="IP",
            target_value="10.0.0.1", ports=[], cve_ids=[],
            confidence=0.9,
        ))
        result = session.get_last_target()
        assert result == ("IP", "10.0.0.1")

    def test_get_last_target_returns_none_when_no_turns(self):
        """get_last_target returns None when session has no turns."""
        session = Session(session_id="test-7")
        assert session.get_last_target() is None

    def test_get_last_target_skips_empty_value(self):
        """get_last_target skips turns with empty target_value."""
        session = Session(session_id="test-8")
        session.add_turn(SessionTurn(
            turn_number=1, command="recon",
            intent="PASSIVE_RECON", target_type="DOMAIN",
            target_value="", ports=[], cve_ids=[],
            confidence=0.9,
        ))
        session.add_turn(SessionTurn(
            turn_number=2, command="scan 10.0.0.5",
            intent="NETWORK_SCAN", target_type="IP",
            target_value="10.0.0.5", ports=[], cve_ids=[],
            confidence=0.9,
        ))
        result = session.get_last_target()
        assert result == ("IP", "10.0.0.5")


class TestSessionContextStoreInjectContext:

    def test_inject_context_returns_command_when_no_session_id(self, store):
        """inject_context returns command unchanged when session_id is None."""
        result = store.inject_context("scan 10.0.0.1", None)
        assert result == "scan 10.0.0.1"

    def test_inject_context_returns_command_when_disabled(self, store_disabled):
        """inject_context returns command unchanged when feature is disabled."""
        result = store_disabled.inject_context("scan 10.0.0.1", "sess-1")
        assert result == "scan 10.0.0.1"

    def test_inject_context_returns_command_on_first_turn(self, store):
        """inject_context returns command unchanged on first turn (no prior context)."""
        result = store.inject_context("scan 10.0.0.1", "first-turn")
        assert result == "scan 10.0.0.1"

    def test_inject_context_prepends_session_context(self, store):
        """inject_context prepends session context on subsequent turns."""
        resp = MagicMock(spec=IREResponse)
        resp.status = "success"
        resp.intent = IntentType.NETWORK_SCAN
        resp.target = Target(type=TargetType.IP, value="10.0.0.1")
        resp.ports = [22]
        resp.cve_ids = []
        resp.confidence = 0.9

        store.update("sess-ctx-1", "scan 10.0.0.1", resp)
        result = store.inject_context("scan ports 10.0.0.1", "sess-ctx-1")
        assert "Session context:" in result
        assert "[Turn 1]" in result
        assert "Current command: scan ports 10.0.0.1" in result

    def test_inject_context_respects_max_turns(self, store):
        """inject_context only injects up to max_turns recent turns."""
        resp = MagicMock(spec=IREResponse)
        resp.status = "success"
        resp.intent = IntentType.NETWORK_SCAN
        resp.target = Target(type=TargetType.IP, value="10.0.0.1")
        resp.ports = []
        resp.cve_ids = []
        resp.confidence = 0.9

        for i in range(12):
            store.update("sess-max", f"cmd {i}", resp)

        result = store.inject_context("new cmd", "sess-max")
        lines = result.split("\n")
        turn_lines = [l for l in lines if l.startswith("[Turn")]
        assert len(turn_lines) <= store._max_turns


class TestSessionContextStoreUpdate:

    def test_update_adds_turn_on_success(self, store):
        """update adds a turn when response status is success."""
        resp = MagicMock(spec=IREResponse)
        resp.status = "success"
        resp.intent = IntentType.NETWORK_SCAN
        resp.target = Target(type=TargetType.SUBNET, value="192.168.1.0/24")
        resp.ports = [80, 443]
        resp.cve_ids = []
        resp.confidence = 0.95

        store.update("sess-upd-1", "scan 192.168.1.0/24", resp)
        info = store.get_session_info("sess-upd-1")
        assert info is not None
        assert info["turn_count"] == 1

    def test_update_ignores_error_response(self, store, mock_error_response):
        """update does nothing when response status is error."""
        store.update("sess-err", "bad command", mock_error_response)
        info = store.get_session_info("sess-err")
        assert info is None

    def test_update_ignores_none_session_id(self, store, mock_success_response):
        """update does nothing when session_id is None."""
        store.update(None, "scan host", mock_success_response)
        stats = store.get_stats()
        assert stats["active_sessions"] == 0

    def test_update_ignores_when_disabled(self, store_disabled, mock_success_response):
        """update does nothing when session_context feature is disabled."""
        store_disabled.update("sess-disabled", "scan host", mock_success_response)
        stats = store_disabled.get_stats()
        assert stats["active_sessions"] == 0

    def test_update_increments_turn_count(self, store):
        """update increments turn_count for each successive call."""
        resp = MagicMock(spec=IREResponse)
        resp.status = "success"
        resp.intent = IntentType.NETWORK_SCAN
        resp.target = Target(type=TargetType.IP, value="10.0.0.1")
        resp.ports = []
        resp.cve_ids = []
        resp.confidence = 0.9

        store.update("sess-inc", "cmd 1", resp)
        store.update("sess-inc", "cmd 2", resp)
        store.update("sess-inc", "cmd 3", resp)
        info = store.get_session_info("sess-inc")
        assert info["turn_count"] == 3

    def test_update_with_no_target(self, store):
        """update handles response with no target gracefully."""
        resp = MagicMock(spec=IREResponse)
        resp.status = "success"
        resp.intent = IntentType.AMBIGUOUS
        resp.target = None
        resp.ports = []
        resp.cve_ids = []
        resp.confidence = 0.5

        store.update("sess-notarget", "vague command", resp)
        info = store.get_session_info("sess-notarget")
        assert info["turn_count"] == 1


class TestSessionContextStoreGetSessionInfo:

    def test_get_session_info_returns_metadata(self, store, mock_success_response):
        """get_session_info returns session_id, turn_count, last_target, age_seconds."""
        store.update("sess-info-1", "scan 10.0.0.1", mock_success_response)
        info = store.get_session_info("sess-info-1")
        assert info["session_id"] == "sess-info-1"
        assert info["turn_count"] == 1
        assert info["last_target"] is not None
        assert isinstance(info["age_seconds"], int)

    def test_get_session_info_returns_none_for_unknown(self, store):
        """get_session_info returns None for unknown session_id."""
        info = store.get_session_info("nonexistent-session")
        assert info is None

    def test_get_session_info_last_target_matches(self, store, mock_success_response):
        """get_session_info last_target matches the last response target."""
        store.update("sess-target", "scan 10.0.0.5", mock_success_response)
        info = store.get_session_info("sess-target")
        assert info["last_target"] == ("SUBNET", "192.168.1.0/24")


class TestSessionContextStoreClearSession:

    def test_clear_session_returns_true_when_exists(self, store, mock_success_response):
        """clear_session returns True when the session exists."""
        store.update("sess-clear-1", "scan 10.0.0.1", mock_success_response)
        assert store.clear_session("sess-clear-1") is True

    def test_clear_session_returns_false_when_missing(self, store):
        """clear_session returns False when the session does not exist."""
        assert store.clear_session("nonexistent") is False

    def test_clear_session_removes_from_store(self, store, mock_success_response):
        """clear_session removes the session so get_session_info returns None."""
        store.update("sess-clear-2", "scan 10.0.0.1", mock_success_response)
        store.clear_session("sess-clear-2")
        assert store.get_session_info("sess-clear-2") is None


class TestSessionContextStoreGetStats:

    def test_get_stats_returns_active_sessions_count(self, store, mock_success_response):
        """get_stats reports the correct number of active sessions."""
        store.update("sess-stats-1", "scan 10.0.0.1", mock_success_response)
        store.update("sess-stats-2", "scan 10.0.0.2", mock_success_response)
        stats = store.get_stats()
        assert stats["active_sessions"] == 2

    def test_get_stats_returns_max_sessions(self, store):
        """get_stats includes max_sessions configuration value."""
        stats = store.get_stats()
        assert stats["max_sessions"] == store._max_sessions

    def test_get_stats_returns_ttl_seconds(self, store):
        """get_stats includes ttl_seconds configuration value."""
        stats = store.get_stats()
        assert stats["ttl_seconds"] == store._ttl_seconds

    def test_get_stats_returns_feature_enabled(self, store):
        """get_stats includes feature_enabled boolean."""
        stats = store.get_stats()
        assert isinstance(stats["feature_enabled"], bool)


class TestSessionContextStoreEviction:

    def test_evict_expired_removes_stale_sessions(self, store):
        """_evict_expired removes sessions that exceed TTL."""
        store._ttl_seconds = 60
        store._sessions["stale-1"] = Session(
            session_id="stale-1", last_active=time.time() - 200
        )
        store._sessions["fresh-1"] = Session(session_id="fresh-1")
        evicted = store._evict_expired()
        assert evicted == 1
        assert "stale-1" not in store._sessions
        assert "fresh-1" in store._sessions

    def test_get_session_after_expired_ttl_returns_none(self, store):
        """get_session_info returns None after a session has expired and is evicted."""
        store._sessions["expire-check"] = Session(
            session_id="expire-check", last_active=time.time() - 200
        )
        store._ttl_seconds = 60
        store.get_stats()
        assert store.get_session_info("expire-check") is None
