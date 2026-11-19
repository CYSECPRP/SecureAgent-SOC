import logging
from typing import Optional
from qdrant_client import AsyncQdrantClient
from qdrant_client.http import models as qmodels
from src.config import settings

logger = logging.getLogger("secureagent.vector")

qdrant_client: Optional[AsyncQdrantClient] = None


async def get_qdrant_client() -> AsyncQdrantClient:
    global qdrant_client
    if qdrant_client is None:
        qdrant_client = AsyncQdrantClient(
            host=settings.QDRANT_HOST,
            port=settings.QDRANT_PORT,
            timeout=5.0,
            check_compatibility=False,
        )
    return qdrant_client


async def init_qdrant_collections() -> None:
    """Ensure vector collections exist in Qdrant"""
    try:
        client = await get_qdrant_client()
        collections = await client.get_collections()
        existing_names = [c.name for c in collections.collections]

        if settings.QDRANT_COLLECTION_ALERTS not in existing_names:
            await client.create_collection(
                collection_name=settings.QDRANT_COLLECTION_ALERTS,
                vectors_config=qmodels.VectorParams(
                    size=384,  # Standard all-MiniLM-L6-v2 size
                    distance=qmodels.Distance.COSINE,
                ),
            )
            logger.info(f"Created Qdrant collection: {settings.QDRANT_COLLECTION_ALERTS}")

        if settings.QDRANT_COLLECTION_RULES not in existing_names:
            await client.create_collection(
                collection_name=settings.QDRANT_COLLECTION_RULES,
                vectors_config=qmodels.VectorParams(
                    size=384,
                    distance=qmodels.Distance.COSINE,
                ),
            )
            logger.info(f"Created Qdrant collection: {settings.QDRANT_COLLECTION_RULES}")
    except Exception as e:
        logger.warning(f"Could not initialize Qdrant collections: {e}")


async def close_qdrant() -> None:
    global qdrant_client
    if qdrant_client is not None:
        await qdrant_client.close()
        qdrant_client = None
        logger.info("Qdrant client connection closed.")
