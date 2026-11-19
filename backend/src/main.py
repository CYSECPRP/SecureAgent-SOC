import sys
from pathlib import Path

# Add backend directory to sys.path so 'src' resolves when running directly
backend_dir = str(Path(__file__).resolve().parent.parent)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.config import settings
from src.knowledge.db import init_db
from src.knowledge.cache import get_redis_client, close_redis
from src.knowledge.vector import init_qdrant_collections, close_qdrant
from src.api.v1.router import api_v1_router

# Configure logging
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("secureagent.main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("Initializing SecureAgent-SOC services...")
    # Initialize DB tables
    try:
        await init_db()
    except Exception as e:
        logger.warning(f"Database initialization deferred (waiting for Postgres container): {e}")

    # Warm up Redis
    try:
        redis = await get_redis_client()
        await redis.ping()
        logger.info("Redis cache connection verified.")
    except Exception as e:
        logger.warning(f"Redis connection deferred: {e}")

    # Initialize Qdrant Collections
    try:
        await init_qdrant_collections()
    except Exception as e:
        logger.warning(f"Qdrant initialization deferred: {e}")

    logger.info("SecureAgent-SOC initialization sequence complete.")
    yield
    logger.info("Shutting down SecureAgent-SOC services...")
    await close_redis()
    await close_qdrant()
    logger.info("All background connections closed.")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Automated Multi-Agent SOC Framework with Background Verification Methods (N1–N5)",
    lifespan=lifespan,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(api_v1_router, prefix=settings.API_V1_PREFIX)


@app.get("/", tags=["System"])
async def root() -> JSONResponse:
    return JSONResponse(
        content={
            "project": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "status": "online",
            "docs_url": "/docs",
            "health_url": f"{settings.API_V1_PREFIX}/health",
            "background_methods": ["N1_Graph_Check", "N2_Critique_Agent", "N3_Agent_Watchdog", "N4_Signed_Evidence_Ledger", "N5_Auto_Rule_Generator"],
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.main:app", host="127.0.0.1", port=8000, reload=True)