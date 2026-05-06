import pytest
import httpx
from unittest.mock import patch, MagicMock
from src.api.main import app
from src.schemas.intent_schema import (
    IREResponseV2, IntentType, Target, TargetType, SubIntentType
)


@pytest.fixture
def mock_pipeline():
    with patch("src.api.main.pipeline") as mock:
        mock.parse.return_value = IREResponseV2(
            status="success",
            intent=IntentType.NETWORK_SCAN,
            target=Target(type=TargetType.IP, value="192.168.1.1"),
            ports=[22, 80],
            modifiers=["stealth"],
            cve_ids=[],
            tool_hint="nmap",
            schedule=None,
            confidence=0.92,
            rejection_reason=None,
            scope_warnings=[],
            latency_ms=1500,
            error=None,
            stage=None,
            field=None,
            detail=None,
            sub_intent=SubIntentType.NETWORK_SCAN_SYN_STEALTH,
            secondary_intents=[],
            clarification_request=None,
            uncertainty_band=None,
            calibration_method=None,
            cache_hit="none",
            rbac_role="analyst",
            session_turns=1,
            xai=None,
            schema_version=2,
        )
        mock.health_check.return_value = {
            "status": "healthy",
            "ollama": "connected",
            "model": "gemma4:latest",
            "pipeline_stages": 7,
            "middleware": {
                "rbac": True,
                "session_context": True,
                "adversarial_detection": True,
                "semantic_cache": True,
                "sub_intent": True,
            },
        }
        mock.metrics.get_summary.return_value = {
            "total_requests": 42,
            "success_count": 40,
            "error_count": 2,
            "intent_distribution": {"NETWORK_SCAN": 30, "REJECTED": 12},
            "latency_p50": 1200,
            "latency_p95": 3500,
            "latency_p99": 8000,
            "uptime_seconds": 3600,
        }
        mock.session_context.get_session_info.return_value = {
            "session_id": "int-test-1",
            "turn_count": 3,
            "last_target": ("IP", "192.168.1.1"),
            "age_seconds": 120,
        }
        mock.session_context.clear_session.return_value = True
        mock.rbac_guard.get_role_summary.return_value = {
            "role": "analyst",
            "permitted_intents": [
                "NETWORK_SCAN", "VULNERABILITY_AUDIT",
                "SERVICE_ENUMERATION", "PASSIVE_RECON",
            ],
            "rbac_enabled": True,
        }
        yield mock


@pytest.fixture
async def client(mock_pipeline):
    import src.api.main as main_module
    main_module.pipeline = mock_pipeline
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestRootV2:

    @pytest.mark.asyncio
    async def test_root_returns_version_2(self, client):
        """GET / returns version 2.0.0."""
        r = await client.get("/")
        data = r.json()
        assert data["version"] == "2.0.0"

    @pytest.mark.asyncio
    async def test_root_returns_schema_versions(self, client):
        """GET / returns schema_versions array [1, 2]."""
        r = await client.get("/")
        data = r.json()
        assert data["schema_versions"] == [1, 2]


class TestHealthV2:

    @pytest.mark.asyncio
    async def test_health_returns_middleware_status(self, client):
        """GET /health returns middleware dict."""
        r = await client.get("/health")
        data = r.json()
        assert "middleware" in data
        assert data["middleware"]["rbac"] is True

    @pytest.mark.asyncio
    async def test_health_returns_200_when_healthy(self, client):
        """GET /health returns 200 when pipeline is healthy."""
        r = await client.get("/health")
        assert r.status_code == 200


class TestParseV2Schema:

    @pytest.mark.asyncio
    async def test_parse_returns_v2_fields(self, client):
        """POST /parse returns v2 fields: sub_intent, schema_version, cache_hit."""
        r = await client.post("/parse", json={
            "command": "stealth scan 192.168.1.1",
            "session_id": "v2-test-1",
            "role": "analyst",
        })
        data = r.json()
        assert data["status"] == "success"
        assert "sub_intent" in data
        assert data["schema_version"] == 2
        assert "cache_hit" in data

    @pytest.mark.asyncio
    async def test_parse_v1_header_strips_v2_fields(self, client):
        """POST /parse with X-IRE-Schema-Version: 1 strips v2 fields."""
        r = await client.post("/parse",
            headers={"X-IRE-Schema-Version": "1"},
            json={"command": "scan 192.168.1.1", "role": "analyst"})
        data = r.json()
        assert "sub_intent" not in data
        assert "schema_version" not in data
        assert "intent" in data

    @pytest.mark.asyncio
    async def test_parse_v2_header_returns_all_fields(self, client):
        """POST /parse with X-IRE-Schema-Version: 2 returns all fields."""
        r = await client.post("/parse",
            headers={"X-IRE-Schema-Version": "2"},
            json={"command": "scan 192.168.1.1", "role": "analyst"})
        data = r.json()
        assert "sub_intent" in data
        assert data["schema_version"] == 2

    @pytest.mark.asyncio
    async def test_parse_invalid_schema_version_defaults_to_v2(self, client):
        """POST /parse with invalid schema version defaults to v2."""
        r = await client.post("/parse",
            headers={"X-IRE-Schema-Version": "99"},
            json={"command": "scan 192.168.1.1"})
        data = r.json()
        assert data["schema_version"] == 2

    @pytest.mark.asyncio
    async def test_parse_response_headers_present(self, client):
        """POST /parse response includes X-IRE observability headers."""
        r = await client.post("/parse", json={
            "command": "scan 192.168.1.1",
            "session_id": "hdr-test",
        })
        assert "x-ire-schema-version" in r.headers
        assert "x-ire-latency-ms" in r.headers
        assert "x-ire-intent" in r.headers
        assert "x-ire-cache-hit" in r.headers

    @pytest.mark.asyncio
    async def test_parse_response_header_values(self, client):
        """POST /parse response header values match response body."""
        r = await client.post("/parse", json={
            "command": "scan 192.168.1.1",
            "session_id": "hdr-val-test",
        })
        assert r.headers["x-ire-schema-version"] == "2"
        assert r.headers["x-ire-latency-ms"] == "1500"
        assert r.headers["x-ire-intent"] == "NETWORK_SCAN"
        assert r.headers["x-ire-cache-hit"] == "none"


class TestParseValidation:

    @pytest.mark.asyncio
    async def test_parse_empty_command_returns_400(self, client):
        """POST /parse with empty command returns 400."""
        r = await client.post("/parse", json={"command": "   "})
        assert r.status_code == 400

    @pytest.mark.asyncio
    async def test_parse_oversized_command_returns_413(self, client):
        """POST /parse with command > 2000 chars returns 413."""
        r = await client.post("/parse", json={"command": "A" * 2001})
        assert r.status_code == 413


class TestMetricsV2:

    @pytest.mark.asyncio
    async def test_metrics_returns_total_requests(self, client):
        """GET /metrics returns total_requests."""
        r = await client.get("/metrics")
        data = r.json()
        assert "total_requests" in data

    @pytest.mark.asyncio
    async def test_metrics_returns_latency_percentiles(self, client):
        """GET /metrics returns latency_p50, p95, p99."""
        r = await client.get("/metrics")
        data = r.json()
        assert "latency_p50" in data
        assert "latency_p95" in data
        assert "latency_p99" in data

    @pytest.mark.asyncio
    async def test_metrics_returns_intent_distribution(self, client):
        """GET /metrics returns intent_distribution."""
        r = await client.get("/metrics")
        data = r.json()
        assert "intent_distribution" in data


class TestSessionV2:

    @pytest.mark.asyncio
    async def test_get_session_returns_turn_count(self, client):
        """GET /session/{id} returns turn_count."""
        r = await client.get("/session/int-test-1")
        data = r.json()
        assert data["turn_count"] == 3

    @pytest.mark.asyncio
    async def test_get_session_returns_last_target(self, client):
        """GET /session/{id} returns last_target tuple."""
        r = await client.get("/session/int-test-1")
        data = r.json()
        assert data["last_target"] == ["IP", "192.168.1.1"]

    @pytest.mark.asyncio
    async def test_get_session_not_found_returns_404(self, client, mock_pipeline):
        """GET /session/{id} returns 404 for unknown session."""
        mock_pipeline.session_context.get_session_info.return_value = None
        r = await client.get("/session/nonexistent")
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_session_returns_cleared(self, client):
        """DELETE /session/{id} returns cleared=True."""
        r = await client.delete("/session/int-test-1")
        data = r.json()
        assert data["cleared"] is True

    @pytest.mark.asyncio
    async def test_delete_session_not_found_returns_404(self, client, mock_pipeline):
        """DELETE /session/{id} returns 404 for unknown session."""
        mock_pipeline.session_context.clear_session.return_value = False
        r = await client.delete("/session/nonexistent")
        assert r.status_code == 404


class TestAdminRBAC:

    @pytest.mark.asyncio
    async def test_rbac_returns_role(self, client):
        """GET /admin/rbac/{role} returns role field."""
        r = await client.get("/admin/rbac/analyst")
        data = r.json()
        assert data["role"] == "analyst"

    @pytest.mark.asyncio
    async def test_rbac_returns_permitted_intents(self, client):
        """GET /admin/rbac/{role} returns permitted_intents list."""
        r = await client.get("/admin/rbac/analyst")
        data = r.json()
        assert "permitted_intents" in data
        assert "NETWORK_SCAN" in data["permitted_intents"]

    @pytest.mark.asyncio
    async def test_rbac_returns_rbac_enabled_flag(self, client):
        """GET /admin/rbac/{role} returns rbac_enabled boolean."""
        r = await client.get("/admin/rbac/analyst")
        data = r.json()
        assert data["rbac_enabled"] is True


class TestAdminFeatures:

    @pytest.mark.asyncio
    async def test_features_returns_features_dict(self, client):
        """GET /admin/features returns features dict."""
        r = await client.get("/admin/features")
        data = r.json()
        assert "features" in data
        assert isinstance(data["features"], dict)

    @pytest.mark.asyncio
    async def test_features_returns_tuning_dict(self, client):
        """GET /admin/features returns tuning dict."""
        r = await client.get("/admin/features")
        data = r.json()
        assert "tuning" in data
        assert isinstance(data["tuning"], dict)

    @pytest.mark.asyncio
    async def test_features_returns_schema_v2_enabled(self, client):
        """GET /admin/features returns schema_v2_enabled boolean."""
        r = await client.get("/admin/features")
        data = r.json()
        assert "schema_v2_enabled" in data
        assert isinstance(data["schema_v2_enabled"], bool)

    @pytest.mark.asyncio
    async def test_features_reload_returns_reloaded_true(self, client):
        """POST /admin/features/reload returns reloaded=True."""
        r = await client.post("/admin/features/reload")
        data = r.json()
        assert data["reloaded"] is True

    @pytest.mark.asyncio
    async def test_features_reload_returns_features(self, client):
        """POST /admin/features/reload returns current features."""
        r = await client.post("/admin/features/reload")
        data = r.json()
        assert "features" in data


class TestDocs:

    @pytest.mark.asyncio
    async def test_docs_accessible(self, client):
        """GET /docs returns 200."""
        r = await client.get("/docs")
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_redoc_accessible(self, client):
        """GET /redoc returns 200."""
        r = await client.get("/redoc")
        assert r.status_code == 200
