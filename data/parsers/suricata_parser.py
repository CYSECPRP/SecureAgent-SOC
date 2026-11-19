"""
Suricata EVE JSON Parser for SecureAgent-SOC
Parses Suricata IDS EVE alert logs into NormalizedAlert records.
Calculates continuous taint score tau = 0.6 (network perimeter sensor).
"""

import json
import uuid
from pathlib import Path
from typing import Dict, Any, Generator

from . import generate_content_hash, utc_now_iso


def parse_suricata_eve(file_path: Path, max_records: int = 5000) -> Generator[Dict[str, Any], None, None]:
    if not file_path.exists():
        return

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        count = 0
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue

            event_type = raw.get("event_type", "alert")
            alert_info = raw.get("alert", {})
            signature = alert_info.get("signature", "Suricata Network Anomaly")
            severity_num = alert_info.get("severity", 3)

            # Map Suricata severity (1 = high/critical, 2 = medium, 3 = low)
            if severity_num == 1:
                severity = "CRITICAL"
            elif severity_num == 2:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

            src_ip = raw.get("src_ip")
            dest_ip = raw.get("dest_ip")
            src_port = raw.get("src_port")
            dest_port = raw.get("dest_port")
            proto = raw.get("proto", "TCP")

            content_hash = generate_content_hash("SURICATA", str(src_ip), str(dest_ip), signature)

            record = {
                "id": str(uuid.uuid4()),
                "source": "SURICATA",
                "timestamp": raw.get("timestamp", utc_now_iso()),
                "severity": severity,
                "status": "NEW",
                "taint_score": 0.6,  # Network perimeter sensor
                "source_ip": src_ip,
                "destination_ip": dest_ip,
                "user_account": None,
                "hostname": raw.get("host", "sensor-gw-01"),
                "content_hash": content_hash,
                "raw_payload": raw,
                "normalized_data": {
                    "alert_type": "INTRUSION",
                    "signature": signature,
                    "category": alert_info.get("category", "Potentially Bad Traffic"),
                    "protocol": proto,
                    "source_port": src_port,
                    "destination_port": dest_port,
                    "gid_sid_rev": f"{alert_info.get('gid', 1)}:{alert_info.get('signature_id', 0)}:{alert_info.get('rev', 1)}",
                },
            }

            yield record
            count += 1
            if max_records and count >= max_records:
                break

