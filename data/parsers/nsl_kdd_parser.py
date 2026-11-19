"""
NSL-KDD Network Flow Parser for SecureAgent-SOC
Parses NSL-KDD evaluation benchmark (evaluating machine learning / intrusion detection papers).
Calculates continuous taint score tau = 0.6 (network perimeter flow sensor).
"""

import csv
import uuid
import io
from pathlib import Path
from typing import Dict, Any, Generator

from . import generate_content_hash, utc_now_iso


def parse_nsl_kdd(csv_path: Path) -> Generator[Dict[str, Any], None, None]:
    if not csv_path.exists():
        return

    # Handle carriage-return lines (Mac/Classic line-endings in raw file)
    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read().replace("\r\n", "\n").replace("\r", "\n")

    reader = csv.reader(io.StringIO(content))
    for row in reader:
        if not row or len(row) < 42:
            continue

        proto = row[1].strip()
        service = row[2].strip()
        flag = row[3].strip()
        src_bytes = row[4].strip()
        dst_bytes = row[5].strip()
        attack_label = row[41].strip()

        is_attack = attack_label.lower() != "normal"
        severity = "HIGH" if is_attack else "LOW"

        content_hash = generate_content_hash("NSL_KDD", proto, service, flag, src_bytes, dst_bytes, attack_label)

        record = {
            "id": str(uuid.uuid4()),
            "source": "NETWORK_FLOW",
            "timestamp": utc_now_iso(),
            "severity": severity,
            "status": "NEW",
            "taint_score": 0.6,
            "source_ip": "10.0.10.100",
            "destination_ip": "10.0.20.200",
            "user_account": None,
            "hostname": f"net-sensor-{service}",
            "content_hash": content_hash,
            "raw_payload": {
                "protocol": proto,
                "service": service,
                "flag": flag,
                "src_bytes": src_bytes,
                "dst_bytes": dst_bytes,
                "attack_label": attack_label,
            },
            "normalized_data": {
                "alert_type": "FLOW_ANOMALY" if is_attack else "NORMAL_TRAFFIC",
                "attack_class": attack_label,
                "protocol": proto,
                "service": service,
                "is_intrusion": is_attack,
            },
        }
        yield record

