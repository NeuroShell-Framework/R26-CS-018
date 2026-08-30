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
            "error_counts": {"inference": 2},
            "intent_distribution": {"NETWORK_SCAN": 30, "REJECTED": 12},
            "latency_p50_ms": 1200,
            "latency_p95_ms": 3500,
            "latency_p99_ms": 8000,
            "average_semantic_entropy": 0.1,
            "max_semantic_entropy": 0.4,
            "tier_counts": {1: 39, 2: 3},
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
    from src.pipeline.contract_builder import ContractBuilder
    from src.validation.contract_validator import ContractValidator
    app.state.contract_builder = ContractBuilder()
    app.state.contract_validator = ContractValidator()
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
    async def test_parse_triggers_both_schema_versions(self, client):
        """POST /parse triggers BOTH version1 and version2 structures."""
        r = await client.post("/parse", json={
            "command": "stealth scan 192.168.1.1",
            "session_id": "v2-test-1",
            "role": "analyst",
        })
        data = r.json()
        contract = data["version1"]["intent_contract"]
        assert contract["intent"] == "NETWORK_SCAN"
        assert data["version1"]["session_id"] == "v2-test-1"
        assert data["version2"]["status"] == "success"
        assert "sub_intent" in data["version2"]
        assert data["version2"]["schema_version"] == 2
        assert "cache_hit" in data["version2"]

    @pytest.mark.asyncio
    async def test_version1_omits_v2_fields(self, client):
        """version1 structure contains only the official v1 fields."""
        r = await client.post("/parse", json={
            "command": "scan 192.168.1.1",
            "role": "analyst"})
        data = r.json()
        v1 = data["version1"]
        contract = v1["intent_contract"]
        assert "sub_intent" not in contract
        assert "schema_version" not in v1
        assert "cache_hit" not in contract
        assert "intent" in contract
        assert "confidence" in contract
        assert set(v1.keys()) == {"intent_contract", "session_id"}

    @pytest.mark.asyncio
    async def test_version2_is_extended_version_of_v1(self, client):
        """version2 contains all intent_contract fields plus extended fields."""
        r = await client.post("/parse",
            json={"command": "scan 192.168.1.1", "role": "analyst"})
        data = r.json()
        contract = data["version1"]["intent_contract"]
        v2 = data["version2"]
        for field in contract.keys():
            assert field in v2
        assert "sub_intent" in v2
        assert v2["schema_version"] == 2

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
        assert r.headers["x-ire-schema-version"] == "1,2"
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


class TestParsePlanV2:

    @pytest.mark.asyncio
    async def test_parse_plan_returns_contract(self, client):
        """POST /parse/plan returns a valid PlannerContract for a successful parse."""
        r = await client.post("/parse/plan", json={
            "command": "stealth scan 192.168.1.1",
            "role": "analyst",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["intent"] == "NETWORK_SCAN"
        assert data["target"]["value"] == "192.168.1.1"
        assert data["confidence"] == 0.92
        assert data["tool_hint"] == "nmap"

    @pytest.mark.asyncio
    async def test_parse_plan_error_returns_422(self, client, mock_pipeline):
        """POST /parse/plan returns 422 CONTRACT_VALIDATION_FAILED on pipeline error."""
        mock_pipeline.parse.return_value = IREResponseV2(
            status="error",
            error="SCOPE_VIOLATION",
            stage="scope_guard",
            detail="Target out of scope",
            latency_ms=5,
            schema_version=2,
        )
        r = await client.post("/parse/plan", json={
            "command": "scan 192.168.1.1",
            "role": "analyst",
        })
        assert r.status_code == 422
        data = r.json()
        assert data["error"] == "SCOPE_VIOLATION"
        assert data["contract"] is None

    @pytest.mark.asyncio
    async def test_parse_plan_real_scope_rejection_returns_422(self, monkeypatch):
        """POST /parse/plan with real un-mocked pipeline under strict scope_mode returns 422 on public IP."""
        from unittest.mock import MagicMock
        from config.settings import get_settings
        from src.pipeline.ire_pipeline import IREPipeline
        import src.api.main as main_module

        settings = get_settings()
        monkeypatch.setattr(settings, "scope_mode", "strict")

        p = IREPipeline(settings=settings)
        import json
        monkeypatch.setattr(
            p.inference_engine,
            "_call_ollama",
            MagicMock(return_value=json.dumps({
                "intent": "NETWORK_SCAN",
                "target": {"type": "IP", "value": "8.8.8.8"},
                "ports": [],
                "modifiers": [],
                "cve_ids": [],
                "confidence": 0.9,
            }))
        )
        main_module.pipeline = p
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-API-Key": "test_api_key"}) as c:
            r = await c.post("/parse/plan", json={"command": "scan 8.8.8.8", "role": "analyst"})
        assert r.status_code == 422
        data = r.json()
        assert data["contract"] is None
        assert data["error"] == "SCOPE_VIOLATION"
        assert "detail" in data


class TestMetricsV2:

    @pytest.mark.asyncio
    async def test_metrics_returns_total_requests(self, client):
        """GET /metrics returns total_requests."""
        r = await client.get("/metrics")
        data = r.json()
        assert "total_requests" in data

    @pytest.mark.asyncio
    async def test_metrics_returns_latency_percentiles(self, client):
        """GET /metrics returns latency_p50_ms, p95_ms, p99_ms."""
        r = await client.get("/metrics")
        data = r.json()
        assert "latency_p50_ms" in data
        assert "latency_p95_ms" in data
        assert "latency_p99_ms" in data

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


class TestExecuteFlow:

    @pytest.mark.asyncio
    async def test_execute_returns_step_chain(self, client):
        """POST /execute returns user input + C1 + C2 in one response."""
        r = await client.post("/execute", json={
            "command": "scan host 192.168.1.1 for open ports 80 and 443 using nmap",
            "session_id": "web-01",
            "role": "admin",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        flow = data["flow"]
        assert flow["step_1_user_input"]["command"].startswith("scan")
        assert flow["step_1_user_input"]["session_id"] == "web-01"

        c1 = flow["step_2_component_1"]
        assert c1["status"] == "success"
        assert c1["output"]["version1"]["intent_contract"]["intent"] == "NETWORK_SCAN"
        assert c1["output"]["version1"]["session_id"] == "web-01"
        assert c1["output"]["version2"]["status"] == "success"
        assert c1["output"]["version2"]["latency_ms"] == 1500

        c2 = flow["step_3_component_2"]
        assert c2["status"] == "skipped"

    @pytest.mark.asyncio
    async def test_execute_with_planner_shows_c2_output(self, client):
        """POST /execute forwards version1 to C2 and surfaces its output."""
        from unittest.mock import AsyncMock
        import src.api.main as main_module

        planner = MagicMock()
        planner.push = AsyncMock(return_value={
            "status": "success",
            "command": "nmap -sS -p 80,443 192.168.1.1",
            "tool": "nmap",
            "push_latency_ms": 42,
        })
        main_module.app.state.planner = planner
        try:
            r = await client.post("/execute", json={
                "command": "scan host 192.168.1.1 for open ports 80 and 443 using nmap",
                "session_id": "web-01",
            })
        finally:
            del main_module.app.state.planner

        assert r.status_code == 200
        flow = r.json()["flow"]
        c2 = flow["step_3_component_2"]
        assert c2["status"] == "success"
        assert c2["latency_ms"] == 42
        assert c2["output"]["command"] == "nmap -sS -p 80,443 192.168.1.1"
        assert c2["output"]["tool"] == "nmap"

        called = planner.push.await_args[0][0]
        assert called["session_id"] == "web-01"
        assert called["intent_contract"]["intent"] == "NETWORK_SCAN"
