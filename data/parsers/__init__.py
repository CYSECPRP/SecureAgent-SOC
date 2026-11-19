"""
Parsers Package for SecureAgent-SOC Datasets
Converts heterogeneous raw datasets into unified, normalized dictionary records
ready for ingestion and evaluation.
"""

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, Optional


def generate_content_hash(*parts: str) -> str:
    """Deterministic SHA-256 hash across salient fields for deduplication."""
    hasher = hashlib.sha256()
    for part in parts:
        hasher.update(str(part).strip().lower().encode("utf-8"))
    return hasher.hexdigest()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

