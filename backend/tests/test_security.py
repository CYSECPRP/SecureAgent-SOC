import uuid

import pytest
from pydantic import ValidationError

from src.config import DEV_POSTGRES_PASSWORD, DEV_SECRET_KEY, Settings, settings
from src.security import rate_limit

API = "/api/v1"


def email_alert(text: str) -> dict:
    return {"source": "email", "raw_payload": {"email_text": text}, "severity": "low"}


@pytest.fixture
def api_key(monkeypatch) -> str:
    key = f"test-key-{uuid.uuid4().hex}"
    monkeypatch.setattr(settings, "API_KEYS", key)
    return key


async def test_protected_endpoints_need_a_key(client, api_key):
    for path in ("/alerts", "/alerts/count"):
        response = await client.get(API + path)
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "ApiKey"

    response = await client.post(f"{API}/ingest", json=email_alert("Team lunch at noon"))
    assert response.status_code == 401


async def test_wrong_key_is_rejected(client, api_key):
    response = await client.get(f"{API}/alerts", headers={"X-API-Key": "not-the-right-key"})
    assert response.status_code == 401


async def test_valid_key_is_accepted(client, api_key):
    headers = {"X-API-Key": api_key}
    response = await client.post(f"{API}/ingest", json=email_alert(f"Team lunch {uuid.uuid4().hex}"), headers=headers)
    assert response.status_code == 201

    response = await client.get(f"{API}/alerts/count", headers=headers)
    assert response.status_code == 200


async def test_health_stays_public(client, api_key):
    response = await client.get(f"{API}/health")
    assert response.status_code == 200


async def test_ingest_rate_limit(client, api_key, monkeypatch):
    window = uuid.uuid4().int
    monkeypatch.setattr(settings, "RATE_LIMIT_PER_MINUTE", 2)
    monkeypatch.setattr(rate_limit, "_current_window", lambda: window)
    headers = {"X-API-Key": api_key}
    payload = email_alert(f"Status update {uuid.uuid4().hex}")

    codes = []
    for _ in range(3):
        response = await client.post(f"{API}/ingest", json=payload, headers=headers)
        codes.append(response.status_code)

    assert codes == [201, 201, 429]
    assert "retry-after" in response.headers


def production_settings(**overrides) -> Settings:
    values = {
        "ENVIRONMENT": "production",
        "DEBUG": False,
        "SECRET_KEY": "s" * 40,
        "POSTGRES_PASSWORD": "a-strong-database-password",
        "API_KEYS": "k" * 32,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_production_accepts_real_secrets():
    assert production_settings().api_keys == ["k" * 32]


@pytest.mark.parametrize(
    "override",
    [
        {"SECRET_KEY": DEV_SECRET_KEY},
        {"SECRET_KEY": "too-short"},
        {"POSTGRES_PASSWORD": DEV_POSTGRES_PASSWORD},
        {"API_KEYS": ""},
        {"API_KEYS": "short-key"},
        {"DEBUG": True},
    ],
)
def test_production_refuses_unsafe_settings(override):
    with pytest.raises(ValidationError):
        production_settings(**override)
