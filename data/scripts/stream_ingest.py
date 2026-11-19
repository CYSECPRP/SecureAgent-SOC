"""
Operational Data Stream Ingestion Runner for SecureAgent-SOC
Streams alerts from data/splits/operational/ into FastAPI /api/v1/ingest.

Usage:
  # Ingest 100 test alerts immediately (batch mode)
  python data/scripts/stream_ingest.py --batch 100

  # Ingest specific stream
  python data/scripts/stream_ingest.py --stream email --batch 50
  python data/scripts/stream_ingest.py --stream auth --batch 50
  python data/scripts/stream_ingest.py --stream ids --batch 50

  # Continuous simulation (1 alert every N seconds)
  python data/scripts/stream_ingest.py --continuous --rate 0.5
"""

import argparse
import asyncio
import json
import logging
import sys
import time
from pathlib import Path
from typing import Optional

import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("stream_ingest")

DATA_DIR = Path(__file__).resolve().parent.parent
OPERATIONAL_DIR = DATA_DIR / "splits" / "operational"

STREAM_FILES = {
    "all": OPERATIONAL_DIR / "all_ingest.jsonl",
    "email": OPERATIONAL_DIR / "email_stream.jsonl",
    "auth": OPERATIONAL_DIR / "auth_stream.jsonl",
    "ids": OPERATIONAL_DIR / "ids_network_stream.jsonl",
    "wazuh": OPERATIONAL_DIR / "wazuh_host_stream.jsonl",
}


async def stream_alerts(
    stream_type: str = "all",
    batch_size: int = 100,
    continuous: bool = False,
    delay_sec: float = 0.5,
    api_url: str = "http://localhost:8000/api/v1/ingest",
):
    target_file = STREAM_FILES.get(stream_type)
    if not target_file or not target_file.exists():
        logger.error(f"Target stream file not found: {target_file}")
        return

    logger.info("=" * 70)
    logger.info(f"SecureAgent-SOC: Ingesting Operational Stream ({stream_type})")
    logger.info(f"Source: {target_file.name}")
    logger.info(f"Target: {api_url}")
    logger.info("=" * 70)

    # Check backend accessibility
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            health = await client.get("http://localhost:8000/api/v1/health")
            if health.status_code != 200:
                logger.error(f"Backend unhealthy: {health.text}")
                return
        except Exception as e:
            logger.error(f"Cannot reach backend at http://localhost:8000: {e}")
            logger.error("Make sure backend is running with: make dev")
            return

        ingested_count = 0
        dedup_count = 0
        injected_detected_count = 0
        start_time = time.perf_counter()

        with open(target_file, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                if not continuous and i >= batch_size:
                    break

                line = line.strip()
                if not line:
                    continue

                record = json.loads(line)
                
                # Map raw dictionary to API payload
                payload = {
                    "source": record.get("source", "manual").lower(),
                    "raw_payload": record.get("raw_payload", {}),
                    "normalized_data": record.get("normalized_data"),
                    "severity": record.get("severity", "medium").lower(),
                    "source_ip": record.get("source_ip"),
                    "destination_ip": record.get("destination_ip"),
                    "user_account": record.get("user_account"),
                    "hostname": record.get("hostname"),
                }

                try:
                    resp = await client.post(api_url, json=payload)
                    if resp.status_code == 201:
                        data = resp.json()
                        if data.get("is_duplicate"):
                            dedup_count += 1
                        else:
                            ingested_count += 1

                        if data.get("is_injection_detected"):
                            injected_detected_count += 1

                        if (ingested_count + dedup_count) % 25 == 0:
                            logger.info(
                                f"Progress: {ingested_count} ingested | {dedup_count} deduped | "
                                f"{injected_detected_count} injections flagged"
                            )
                    else:
                        logger.warning(f"Failed ingest [{resp.status_code}]: {resp.text}")
                except Exception as ex:
                    logger.error(f"Request error: {ex}")

                if continuous:
                    await asyncio.sleep(delay_sec)

        elapsed = time.perf_counter() - start_time
        logger.info("=" * 70)
        logger.info(f"Ingestion Run Complete in {elapsed:.2f}s:")
        logger.info(f"  - Successfully Ingested into PostgreSQL & Redis: {ingested_count}")
        logger.info(f"  - Deduplicated by Redis Cache:                 {dedup_count}")
        logger.info(f"  - Injections Intercepted by SC1:                {injected_detected_count}")
        logger.info("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="SecureAgent-SOC Stream Ingest")
    parser.add_argument("--stream", choices=["all", "email", "auth", "ids", "wazuh"], default="all")
    parser.add_argument("--batch", type=int, default=100, help="Number of records to ingest in batch mode")
    parser.add_argument("--continuous", action="store_true", help="Run in continuous simulation mode")
    parser.add_argument("--rate", type=float, default=0.5, help="Seconds delay between events in continuous mode")
    args = parser.parse_args()

    asyncio.run(
        stream_alerts(
            stream_type=args.stream,
            batch_size=args.batch,
            continuous=args.continuous,
            delay_sec=args.rate,
        )
    )


if __name__ == "__main__":
    main()

