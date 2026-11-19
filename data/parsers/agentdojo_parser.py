"""
AgentDojo Adversarial Benchmark Parser for SecureAgent-SOC
Parses AgentDojo indirect prompt injections (NeurIPS 2024 Track) into NormalizedAlert records.
Calculates continuous taint score tau = 1.0 (untrusted external attack payload).
"""

import uuid
import yaml
from pathlib import Path
from typing import Dict, Any, Generator

from . import generate_content_hash, utc_now_iso


def parse_agentdojo_yaml(yaml_path: Path, suite_name: str) -> Generator[Dict[str, Any], None, None]:
    if not yaml_path.exists():
        return

    with open(yaml_path, "r", encoding="utf-8", errors="ignore") as f:
        try:
            data = yaml.safe_load(f)
        except Exception:
            return

    if not isinstance(data, dict):
        return

    for task_name, task_body in data.items():
        if not isinstance(task_body, dict):
            continue

        desc = task_body.get("description", "")
        payload = task_body.get("default", "")
        if not payload:
            continue

        content_hash = generate_content_hash("ADVERSARIAL_BENCHMARK", suite_name, task_name, payload[:100])

        record = {
            "id": str(uuid.uuid4()),
            "source": "ADVERSARIAL_BENCHMARK",
            "timestamp": utc_now_iso(),
            "severity": "CRITICAL",
            "status": "NEW",
            "taint_score": 1.0,  # Explicit adversarial prompt injection
            "source_ip": "198.51.100.99",
            "destination_ip": "10.0.1.50",
            "user_account": "adversary@untrusted.external",
            "hostname": f"agentdojo-{suite_name}",
            "content_hash": content_hash,
            "raw_payload": {
                "benchmark": "AgentDojo_NeurIPS_2024",
                "suite": suite_name,
                "task_name": task_name,
                "description": desc,
                "attack_payload": payload,
            },
            "normalized_data": {
                "alert_type": "PROMPT_INJECTION",
                "suite": suite_name,
                "vector": task_name,
                "payload_snippet": payload[:250],
            },
        }

        yield record

