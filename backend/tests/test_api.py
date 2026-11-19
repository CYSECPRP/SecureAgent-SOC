import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_root_endpoint(client: AsyncClient):
    response = await client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["project"] == "SecureAgent-SOC"
    assert data["status"] == "online"
    assert "N1_Graph_Check" in data["background_methods"]
    assert "N2_Critique_Agent" in data["background_methods"]
    assert "N3_Agent_Watchdog" in data["background_methods"]
    assert "N4_Signed_Evidence_Ledger" in data["background_methods"]
    assert "N5_Auto_Rule_Generator" in data["background_methods"]


@pytest.mark.asyncio
async def test_health_check_endpoint(client: AsyncClient):
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "services" in data
    assert "version" in data
    assert "environment" in data

