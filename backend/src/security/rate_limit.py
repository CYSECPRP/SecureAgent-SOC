import logging
import time
from typing import Optional

import redis.asyncio as aioredis
from fastapi import Depends, HTTPException, Request, status

from src.api.deps import get_redis
from src.config import settings
from src.security.auth import require_api_key

logger = logging.getLogger("secureagent.ratelimit")


def _current_window() -> int:
    return int(time.time() // 60)


async def limit_ingest_rate(
    request: Request,
    api_key: Optional[str] = Depends(require_api_key),
    redis: aioredis.Redis = Depends(get_redis),
) -> None:
    """Fixed one-minute window per API key (or client address when keys are off), stored in Redis."""
    limit = settings.RATE_LIMIT_PER_MINUTE
    if limit <= 0:
        return

    if api_key:
        client_id = f"key-{settings.api_keys.index(api_key)}"
    else:
        client_id = request.client.host if request.client else "unknown"
    counter_key = f"ratelimit:ingest:{client_id}:{_current_window()}"

    try:
        async with redis.pipeline(transaction=True) as pipe:
            pipe.incr(counter_key)
            pipe.expire(counter_key, 120)
            count, _ = await pipe.execute()
    except Exception as exc:
        # Fail open: losing the limiter must not stop alert ingestion.
        logger.warning(f"Rate limit check skipped: {exc}")
        return

    if count > limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(60 - int(time.time()) % 60)},
        )
