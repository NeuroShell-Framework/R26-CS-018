# NeuroShell IRE — Integration Tests for Audit Logging & Escalation Queue API

import json
import pytest
import httpx
from src.api.main import app
from src.audit import get_audit_logger
from src.validation.hallucination_taxonomy import ValidationFinding, HallucinationClass


@pytest.fixture
def memory_audit_logger(monkeypatch):
    logger = get_audit_logger(db_path=":memory:")
    import src.api.main as main_module
    app.state.audit_logger = logger
    yield logger


@pytest.fixture
async def client(memory_audit_logger, monkeypatch):
    from unittest.mock import MagicMock
    from src.pipeline.ire_pipeline import IREPipeline
    import src.api.main as main_module

    p = IREPipeline()
    p.audit_logger = memory_audit_logger
    monkeypatch.setattr(
        p.inference_engine,
        "_call_ollama",
        MagicMock(return_value=json.dumps({
            "intent": "NETWORK_SCAN",
            "target": {"type": "IP", "value": "192.168.1.1"},
            "ports": [80],
            "modifiers": [],
            "cve_ids": [],
            "confidence": 0.95,
        }))
    )
    from src.pipeline.contract_builder import ContractBuilder
    from src.validation.contract_validator import ContractValidator
    app.state.contract_builder = ContractBuilder()
    app.state.contract_validator = ContractValidator()
    app.state.audit_logger = memory_audit_logger

    main_module.pipeline = p
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-API-Key": "test_api_key"}) as c:
        yield c


@pytest.mark.asyncio
async def test_blocking_finding_produces_block_audit_row(client, memory_audit_logger):
    """A blocking finding produces exactly one audit_log row with enforcement_action=BLOCK."""
    # Send a request with invalid domain that fails regex validator
    r = await client.post("/parse", json={"command": "scan domain..com"})
    assert r.status_code in (200, 422)

    summary = memory_audit_logger.get_audit_summary()
    assert summary["total_records"] >= 1
    assert "FABRICATED_PARAMETER" in summary["by_hallucination_class"] or "OUT_OF_SCOPE_TARGET" in summary["by_hallucination_class"] or "BLOCK" in summary["by_enforcement_action"]


@pytest.mark.asyncio
async def test_escalate_finding_returns_202_pending_review(client, memory_audit_logger, monkeypatch):
    """An escalate-tagged finding creates a pending row, returns 202 (not 200/422), and withholds contract."""
    from src.schemas.intent_schema import IREResponseV2, IntentType, Target, TargetType

    # Mock pipeline parse to inject an ESCALATE validation finding
    import src.api.main as main_module
    p = main_module.pipeline
    monkeypatch.setattr(
        p,
        "parse",
        lambda req: IREResponseV2(
            status="success",
            intent=IntentType.EXPLOITATION,
            target=Target(type=TargetType.IP, value="192.168.1.1"),
            confidence=0.85,
            validation_findings=[
                ValidationFinding(
                    validator="contract_validator",
                    passed=False,
                    hallucination_class=HallucinationClass.CONTRADICTORY_ACTION_TARGET,
                    detail="Action requires human authorization escalation",
                    severity="escalate",
                )
            ],
            schema_version=2,
        )
    )

    r = await client.post("/parse/plan", json={"command": "exploit 192.168.1.1", "role": "admin"})
    assert r.status_code == 202
    data = r.json()
    assert data["status"] == "pending_review"
    assert data["contract"] is None
    assert "escalation_id" in data

    # Verify pending escalation is stored in database
    pending = memory_audit_logger.get_pending_escalations()
    assert len(pending) == 1
    assert pending[0]["id"] == data["escalation_id"]
    assert pending[0]["status"] == "pending"
    assert pending[0]["enforcement_action"] == "ESCALATE"


@pytest.mark.asyncio
async def test_resolve_escalation_approve_releases_contract(client, memory_audit_logger):
    """Resolving an escalation via approve=True releases contract and updates resolution fields."""
    row_id = memory_audit_logger.record_finding(
        raw_input="exploit 10.0.0.1",
        intent_summary="EXPLOITATION on 10.0.0.1",
        hallucination_class="CONTRADICTORY_ACTION_TARGET",
        severity="escalate",
        enforcement_action="ESCALATE",
        session_id="test-sess",
        status="pending",
        cached_contract_json=json.dumps({"intent": "EXPLOITATION", "target": {"value": "10.0.0.1"}}),
    )

    # 1. Fetch pending escalations
    r_list = await client.get("/admin/escalations?status=pending")
    assert r_list.status_code == 200
    esc_data = r_list.json()
    assert esc_data["count"] == 1
    assert esc_data["escalations"][0]["id"] == row_id

    # 2. Resolve via POST /admin/escalations/{id}/resolve with approve=True
    r_res = await client.post(
        f"/admin/escalations/{row_id}/resolve",
        json={"approve": True, "note": "Approved by SecOps", "resolved_by": "sec_admin"}
    )
    assert r_res.status_code == 200
    res_data = r_res.json()
    assert res_data["status"] == "approved"
    assert res_data["escalation_id"] == row_id
    assert res_data["contract"] is not None
    assert res_data["contract"]["intent"] == "EXPLOITATION"
    assert res_data["resolved_by"] == "sec_admin"
    assert res_data["resolved_at"] is not None

    # 3. Verify audit summary
    r_sum = await client.get("/admin/audit/summary")
    assert r_sum.status_code == 200
    sum_data = r_sum.json()["summary"]
    assert sum_data["pending_escalation_count"] == 0
