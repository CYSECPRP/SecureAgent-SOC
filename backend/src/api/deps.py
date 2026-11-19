from typing import AsyncGenerator
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as aioredis
from qdrant_client import AsyncQdrantClient

from src.knowledge.db import get_db_session
from src.knowledge.cache import get_redis_client
from src.knowledge.vector import get_qdrant_client


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async for session in get_db_session():
        yield session


async def get_redis() -> aioredis.Redis:
    return await get_redis_client()


async def get_vector_db() -> AsyncQdrantClient:
    return await get_qdrant_client()

