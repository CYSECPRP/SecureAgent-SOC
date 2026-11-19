import pytest
import httpx
from src.config import settings


@pytest.mark.asyncio
async def test_opa_tool_access():
    async with httpx.AsyncClient(base_url=settings.OPA_URL) as client:
        # Whitelisted tool for phishing_agent
        resp_allowed = await client.post(
            "/v1/data/secureagent/tool_access/allow",
            json={"input": {"agent_role": "phishing_agent", "tool_name": "whois_lookup"}},
        )
        assert resp_allowed.status_code == 200
        assert resp_allowed.json().get("result") is True

        # Unauthorized tool for phishing_agent
        resp_denied = await client.post(
            "/v1/data/secureagent/tool_access/allow",
            json={"input": {"agent_role": "phishing_agent", "tool_name": "isolate_host"}},
        )
        assert resp_denied.status_code == 200
        assert resp_denied.json().get("result") is False


@pytest.mark.asyncio
async def test_opa_taint_lineage():
    async with httpx.AsyncClient(base_url=settings.OPA_URL) as client:
        # Critical action with low taint -> allowed
        resp1 = await client.post(
            "/v1/data/secureagent/taint_lineage/allow_execution",
            json={"input": {"tool_name": "isolate_host", "taint_score": 0.20, "human_approved": False}},
        )
        assert resp1.status_code == 200
        assert resp1.json().get("result") is True

        # Critical action with high taint (> 0.40) without human approval -> BLOCKED
        resp2 = await client.post(
            "/v1/data/secureagent/taint_lineage/allow_execution",
            json={"input": {"tool_name": "isolate_host", "taint_score": 0.85, "human_approved": False}},
        )
        assert resp2.status_code == 200
        assert resp2.json().get("result") is False

        # Critical action with high taint WITH human approval -> ALLOWED
        resp3 = await client.post(
            "/v1/data/secureagent/taint_lineage/allow_execution",
            json={"input": {"tool_name": "isolate_host", "taint_score": 0.85, "human_approved": True}},
        )
        assert resp3.status_code == 200
        assert resp3.json().get("result") is True

