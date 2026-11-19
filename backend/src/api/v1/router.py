import hashlib
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import text, select, func
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as aioredis
from qdrant_client import AsyncQdrantClient

from src.config import settings
from src.api.deps import get_db, get_redis, get_vector_db
from src.models.database import AlertModel
from src.models.enums import AlertSeverity, AlertStatus, TelemetrySource
from src.models.schemas import (
    HealthCheckResponse,
    ServiceHealth,
    AlertCreate,
    AlertRead,
    AlertIngestResponse,
    AlertIngestBatch,
)
from src.security.sanitizer import InputSanitizer

logger = logging.getLogger("secureagent.api")
api_v1_router = APIRouter()


def compute_content_hash(source: str, payload: dict, src_ip: Optional[str], dst_ip: Optional[str]) -> str:
    hasher = hashlib.sha256()
    hasher.update(source.encode("utf-8"))
    if src_ip:
        hasher.update(src_ip.encode("utf-8"))
    if dst_ip:
        hasher.update(dst_ip.encode("utf-8"))
    hasher.update(json.dumps(payload, sort_keys=True).encode("utf-8"))
    return hasher.hexdigest()


@api_v1_router.get(
    "/health",
    response_model=HealthCheckResponse,
    status_code=status.HTTP_200_OK,
    tags=["System"],
)
async def health_check(
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
    vector_db: AsyncQdrantClient = Depends(get_vector_db),
) -> HealthCheckResponse:
    services = {}

    # Check PostgreSQL
    db_start = time.perf_counter()
    try:
        await db.execute(text("SELECT 1"))
        db_lat = (time.perf_counter() - db_start) * 1000
        services["postgresql"] = ServiceHealth(status="healthy", latency_ms=round(db_lat, 2))
    except Exception as e:
        services["postgresql"] = ServiceHealth(status="unhealthy", details=str(e))

    # Check Redis
    redis_start = time.perf_counter()
    try:
        await redis.ping()
        redis_lat = (time.perf_counter() - redis_start) * 1000
        services["redis"] = ServiceHealth(status="healthy", latency_ms=round(redis_lat, 2))
    except Exception as e:
        services["redis"] = ServiceHealth(status="unhealthy", details=str(e))

    # Check Qdrant
    qdrant_start = time.perf_counter()
    try:
        await vector_db.get_collections()
        qdrant_lat = (time.perf_counter() - qdrant_start) * 1000
        services["qdrant"] = ServiceHealth(status="healthy", latency_ms=round(qdrant_lat, 2))
    except Exception as e:
        services["qdrant"] = ServiceHealth(status="degraded", details=str(e))

    overall_status = "healthy"
    if any(s.status == "unhealthy" for s in services.values()):
        overall_status = "unhealthy"
    elif any(s.status == "degraded" for s in services.values()):
        overall_status = "degraded"

    return HealthCheckResponse(
        status=overall_status,
        timestamp=datetime.now(timezone.utc),
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
        services=services,
    )


@api_v1_router.post(
    "/ingest",
    response_model=AlertIngestResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Ingestion"],
)
async def ingest_alert(
    alert_in: AlertCreate,
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
) -> AlertIngestResponse:
    """
    Layer 1 Primary Ingestion Endpoint:
    1. Computes SHA-256 fingerprint and checks Redis deduplication (10-minute sliding window).
    2. Runs Security Control 1 (SC1): Delimiter Spotlighting and Continuous Taint Scoring (tau).
    3. Persists clean alert record into PostgreSQL `alerts` table.
    4. Pushes alert reference to Redis Priority Ingestion Queue for the Layer 2 Agent Swarm.
    """
    content_hash = compute_content_hash(
        source=alert_in.source.value,
        payload=alert_in.raw_payload,
        src_ip=alert_in.source_ip,
        dst_ip=alert_in.destination_ip,
    )

    # 1. Deduplication via Redis (TTL = 600 seconds)
    dedup_key = f"dedup:{content_hash}"
    is_duplicate = bool(await redis.get(dedup_key))

    if is_duplicate:
        # Increment duplicate counter in Redis
        await redis.incr(f"count:dup:{content_hash}")
        return AlertIngestResponse(
            id="deduplicated",
            status="DEDUPLICATED",
            taint_score=0.0,
            is_injection_detected=False,
            is_duplicate=True,
            content_hash=content_hash,
            queue_name=None,
        )

    # Set deduplication lock with 10-minute TTL
    await redis.set(dedup_key, "1", ex=600)

    # 2. Security Control 1: Sanitization & Taint Tracking
    alert_id = str(uuid.uuid4())
    sanitized_payload, taint_score, is_inj, _ = InputSanitizer.process_alert_payload(
        source=alert_in.source,
        raw_payload=alert_in.raw_payload,
        content_id=alert_id,
    )

    # 3. Persist to PostgreSQL
    normalized_data = alert_in.normalized_data or {
        "alert_type": alert_in.source.value,
        "is_sanitized": True,
        "has_injection": is_inj,
    }

    db_alert = AlertModel(
        id=alert_id,
        source=alert_in.source,
        raw_payload=sanitized_payload,
        normalized_data=normalized_data,
        severity=alert_in.severity or AlertSeverity.MEDIUM,
        status=AlertStatus.NEW,
        taint_score=taint_score,
        source_ip=alert_in.source_ip,
        destination_ip=alert_in.destination_ip,
        user_account=alert_in.user_account,
        hostname=alert_in.hostname,
        content_hash=content_hash,
    )
    db.add(db_alert)
    await db.commit()
    await db.refresh(db_alert)

    # 4. Push to Redis Priority Ingestion Queue
    queue_name = "queue:ingestion:priority" if (alert_in.severity == AlertSeverity.CRITICAL or taint_score >= 0.8) else "queue:ingestion:standard"
    await redis.rpush(queue_name, alert_id)

    return AlertIngestResponse(
        id=alert_id,
        status="INGESTED",
        taint_score=taint_score,
        is_injection_detected=is_inj,
        is_duplicate=False,
        content_hash=content_hash,
        queue_name=queue_name,
    )


@api_v1_router.get(
    "/alerts",
    response_model=List[AlertRead],
    tags=["Alerts"],
)
async def list_alerts(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    source: Optional[TelemetrySource] = None,
    db: AsyncSession = Depends(get_db),
) -> List[AlertRead]:
    """Retrieve ingested alerts from PostgreSQL."""
    query = select(AlertModel).order_by(AlertModel.created_at.desc()).offset(offset).limit(limit)
    if source:
        query = query.where(AlertModel.source == source)
    result = await db.execute(query)
    return list(result.scalars().all())


@api_v1_router.get(
    "/alerts/count",
    tags=["Alerts"],
)
async def get_alerts_count(db: AsyncSession = Depends(get_db)):
    """Count total ingested alerts in PostgreSQL."""
    result = await db.execute(select(func.count(AlertModel.id)))
    return {"total_alerts": result.scalar_one()}
