import hmac
from typing import Optional

from fastapi import Header, HTTPException, status

from src.config import settings


async def require_api_key(x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")) -> Optional[str]:
    """Accept the request when no keys are configured or when X-API-Key matches a configured key."""
    keys = settings.api_keys
    if not keys:
        return None

    matched = False
    if x_api_key:
        # Compare against every key so the response time does not reveal which key matched.
        for key in keys:
            matched |= hmac.compare_digest(x_api_key.encode("utf-8"), key.encode("utf-8"))
    if matched:
        return x_api_key

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing or invalid API key",
        headers={"WWW-Authenticate": "ApiKey"},
    )
