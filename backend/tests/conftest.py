import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import NullPool
from sqlalchemy import text
import redis.asyncio as aioredis

from src.main import app
from src.config import settings
from src.api.deps import get_db, get_redis


@pytest_asyncio.fixture(scope="function")
async def client():
    # Dedicated test engine with NullPool to prevent event loop sharing issues across test functions
    test_engine = create_async_engine(settings.DATABASE_URL, poolclass=NullPool)
    test_session_maker = async_sessionmaker(bind=test_engine, class_=AsyncSession, expire_on_commit=False)

    test_redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)

    async def override_get_db():
        async with test_session_maker() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    async def override_get_redis():
        return test_redis

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_redis] = override_get_redis

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac

    app.dependency_overrides.clear()
    await test_redis.aclose()
    await test_engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session():
    test_engine = create_async_engine(settings.DATABASE_URL, poolclass=NullPool)
    session_maker = async_sessionmaker(bind=test_engine, class_=AsyncSession, expire_on_commit=False)
    
    async with session_maker() as session:
        yield session
        # Ensure zero residual test data remains in the database
        await session.execute(text("TRUNCATE TABLE alerts, incidents, evidence_nodes, ledger_entries, agent_metrics, generated_rules CASCADE;"))
        await session.commit()
    
    await test_engine.dispose()
