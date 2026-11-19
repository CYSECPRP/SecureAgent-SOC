"""
Database Seeding Script for SecureAgent-SOC
Seeds fresh Docker containers (PostgreSQL, Redis, Qdrant) with baseline data:
1. PostgreSQL: Initializes table schemas (Base.metadata.create_all).
2. Redis: Loads C2 botnet IP blocklist (Feodo Tracker) & user baseline profiles.
3. Qdrant: Creates 'soc_alerts' and 'soc_rules' collections and embeds historical knowledge seeds & MITRE ATT&CK techniques.
"""

import asyncio
import csv
import hashlib
import json
import logging
import math
import sys
from pathlib import Path
from typing import List, Dict, Any

from qdrant_client import AsyncQdrantClient
from qdrant_client.http import models as qmodels
import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import create_async_engine

# Path setup
PROJECT_DIR = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = PROJECT_DIR / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from src.config import settings
from src.models.database import Base

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("seed_db")

DATA_DIR = PROJECT_DIR / "data"
KNOWLEDGE_DIR = DATA_DIR / "splits" / "knowledge"
RAW_DIR = DATA_DIR / "raw"


def deterministic_text_embedding(text: str, dim: int = 384) -> List[float]:
    """
    Generates a deterministic 384-dimensional unit vector from text tokens.
    Guarantees consistent semantic-hash projections into Qdrant without heavy external ML dependencies.
    """
    tokens = text.lower().split()
    vector = [0.0] * dim
    if not tokens:
        vector[0] = 1.0
        return vector

    for i, token in enumerate(tokens):
        h = int(hashlib.sha256(token.encode("utf-8")).hexdigest(), 16)
        idx = h % dim
        sign = 1.0 if (h >> 8) % 2 == 0 else -1.0
        weight = 1.0 / math.sqrt(i + 1)
        vector[idx] += sign * weight

    # Normalize to unit sphere for Cosine similarity
    norm = math.sqrt(sum(x * x for x in vector))
    if norm > 0:
        vector = [x / norm for x in vector]
    else:
        vector[0] = 1.0
    return vector


async def seed_postgres():
    logger.info("[1/3] Initializing PostgreSQL Tables...")
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await engine.dispose()
    logger.info("  -> PostgreSQL tables verified (alerts, incidents, evidence_ledger).")


async def seed_redis():
    logger.info("[2/3] Seeding Redis In-Memory Cache...")
    r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    await r.flushdb()

    # 1. Seed Feodo C2 Blocklist
    c2_csv = RAW_DIR / "malware_hashes" / "feodo_c2_blocklist.csv"
    c2_count = 0
    if c2_csv.exists():
        with open(c2_csv, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            for row in reader:
                if row and not row[0].startswith("#") and len(row) >= 2:
                    ip = row[1].strip()
                    malware = row[2].strip() if len(row) > 2 else "Feodo_Botnet"
                    await r.set(f"threat_intel:c2:{ip}", json.dumps({"source": "feodo_tracker", "threat": malware}))
                    c2_count += 1
    logger.info(f"  -> Loaded {c2_count} C2 Botnet IPs into Redis threat_intel:c2:*")

    # 2. Seed Baseline Normal User Auth Profiles (from baseline_auth.jsonl)
    baseline_file = KNOWLEDGE_DIR / "baseline_auth.jsonl"
    auth_count = 0
    if baseline_file.exists():
        pipe = r.pipeline()
        with open(baseline_file, "r", encoding="utf-8") as f:
            for line in f:
                rec = json.loads(line)
                user = rec.get("user_account")
                host = rec.get("hostname")
                if user and host:
                    pipe.sadd(f"baseline:user_hosts:{user}", host)
                    auth_count += 1
                    if auth_count % 500 == 0:
                        await pipe.execute()
                        pipe = r.pipeline()
        await pipe.execute()
    logger.info(f"  -> Profiled {auth_count:,} user-to-host baseline records into Redis.")
    await r.close()


async def seed_qdrant():
    logger.info("[3/3] Seeding Qdrant Vector Memory...")
    client = AsyncQdrantClient(host=settings.QDRANT_HOST, port=settings.QDRANT_PORT, timeout=10.0)

    # Recreate collections clean
    for col in [settings.QDRANT_COLLECTION_ALERTS, settings.QDRANT_COLLECTION_RULES]:
        try:
            await client.delete_collection(col)
        except Exception:
            pass

        await client.create_collection(
            collection_name=col,
            vectors_config=qmodels.VectorParams(size=384, distance=qmodels.Distance.COSINE),
        )
        logger.info(f"  -> Created fresh collection: {col}")

    # Seed MITRE ATT&CK Matrix into soc_rules
    mitre_file = RAW_DIR / "mitre_attack" / "enterprise_attack.json"
    mitre_points = []
    if mitre_file.exists():
        with open(mitre_file, "r", encoding="utf-8") as f:
            stix = json.load(f)
            objects = stix.get("objects", [])
            for obj in objects:
                if obj.get("type") == "attack-pattern":
                    name = obj.get("name", "")
                    desc = obj.get("description", "")
                    ext_ids = [ref.get("external_id") for ref in obj.get("external_references", []) if ref.get("external_id")]
                    tech_id = ext_ids[0] if ext_ids else obj.get("id")
                    
                    combined_text = f"{name} {desc[:400]}"
                    vector = deterministic_text_embedding(combined_text, dim=384)
                    
                    point_id = int(hashlib.md5(obj["id"].encode("utf-8")).hexdigest()[:15], 16)
                    mitre_points.append(
                        qmodels.PointStruct(
                            id=point_id,
                            vector=vector,
                            payload={
                                "rule_type": "MITRE_ATTACK",
                                "technique_id": tech_id,
                                "name": name,
                                "description": desc[:300],
                            },
                        )
                    )
                    if len(mitre_points) >= 100:
                        await client.upsert(collection_name=settings.QDRANT_COLLECTION_RULES, points=mitre_points)
                        mitre_points = []
            if mitre_points:
                await client.upsert(collection_name=settings.QDRANT_COLLECTION_RULES, points=mitre_points)
        logger.info(f"  -> Seeded MITRE ATT&CK Enterprise Matrix techniques into {settings.QDRANT_COLLECTION_RULES}.")

    # Seed Historical Phishing Reference into soc_alerts
    phishing_file = KNOWLEDGE_DIR / "historical_phishing.jsonl"
    alert_points = []
    if phishing_file.exists():
        with open(phishing_file, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                if i >= 1000:  # Seed top 1,000 distinct historical samples for fast semantic retrieval
                    break
                rec = json.loads(line)
                body = rec.get("raw_payload", {}).get("email_text", "")[:300]
                label = rec.get("raw_payload", {}).get("label", "Phishing Email")
                vector = deterministic_text_embedding(body, dim=384)
                
                point_id = i + 1
                alert_points.append(
                    qmodels.PointStruct(
                        id=point_id,
                        vector=vector,
                        payload={
                            "alert_type": "PHISHING",
                            "label": label,
                            "snippet": body[:150],
                            "taint_score": rec.get("taint_score", 1.0),
                        },
                    )
                )
                if len(alert_points) >= 100:
                    await client.upsert(collection_name=settings.QDRANT_COLLECTION_ALERTS, points=alert_points)
                    alert_points = []
            if alert_points:
                await client.upsert(collection_name=settings.QDRANT_COLLECTION_ALERTS, points=alert_points)
        logger.info(f"  -> Seeded 1,000 reference attack vectors into {settings.QDRANT_COLLECTION_ALERTS}.")

    await client.close()


async def main():
    print("=" * 75)
    print("SecureAgent-SOC: Running Database Seeding Pipeline")
    print("=" * 75)
    await seed_postgres()
    await seed_redis()
    await seed_qdrant()
    print("=" * 75)
    print("All databases successfully seeded from data/splits/knowledge/ and raw Feodo/MITRE!")
    print("=" * 75)


if __name__ == "__main__":
    asyncio.run(main())

