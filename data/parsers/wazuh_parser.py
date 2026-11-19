"""
Wazuh Ruleset Parser for SecureAgent-SOC
Parses Wazuh integration test .ini files into NormalizedAlert records.
Calculates continuous taint score tau = 0.1 (authenticated internal host sensor).
"""

import re
import uuid
from pathlib import Path
from typing import Dict, Any, Generator

from . import generate_content_hash, utc_now_iso


def parse_wazuh_ini_dir(ruleset_dir: Path) -> Generator[Dict[str, Any], None, None]:
    if not ruleset_dir.exists():
        return

    ini_files = list(ruleset_dir.glob("*.ini"))

    for ini_file in ini_files:
        service_name = ini_file.stem
        with open(ini_file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        sections = content.split("\n\n[")
        for sec in sections:
            if not sec.strip():
                continue

            lines = sec.strip().split("\n")
            title = lines[0].replace("[", "").replace("]", "").strip()

            rule_id = "100000"
            alert_level = 5
            log_messages = []

            for line in lines[1:]:
                line = line.strip()
                if line.startswith("rule ="):
                    rule_id = line.split("=", 1)[1].strip()
                elif line.startswith("alert ="):
                    try:
                        alert_level = int(line.split("=", 1)[1].strip())
                    except ValueError:
                        alert_level = 5
                elif "pass =" in line:
                    log_messages.append(line.split("pass =", 1)[1].strip())

            # Severity mapping from Wazuh 1-15 scale
            if alert_level >= 10:
                severity = "CRITICAL"
            elif alert_level >= 7:
                severity = "HIGH"
            elif alert_level >= 4:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            for msg in log_messages:
                # Extract potential IPs from log string
                ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", msg)
                src_ip = ip_matches[0] if ip_matches else None

                # Extract potential user account
                user_match = re.search(r"user\s+([a-zA-Z0-9_\-\.]+)", msg, re.IGNORECASE)
                user_account = user_match.group(1) if user_match else None

                content_hash = generate_content_hash("WAZUH", service_name, rule_id, msg[:100])

                record = {
                    "id": str(uuid.uuid4()),
                    "source": "WAZUH",
                    "timestamp": utc_now_iso(),
                    "severity": severity,
                    "status": "NEW",
                    "taint_score": 0.1,  # Internal host sensor
                    "source_ip": src_ip,
                    "destination_ip": None,
                    "user_account": user_account,
                    "hostname": f"srv-{service_name}-01",
                    "content_hash": content_hash,
                    "raw_payload": {
                        "service": service_name,
                        "rule_id": rule_id,
                        "alert_level": alert_level,
                        "section_title": title,
                        "raw_log": msg,
                    },
                    "normalized_data": {
                        "alert_type": "HOST_ANOMALY",
                        "rule_id": rule_id,
                        "description": title,
                        "wazuh_level": alert_level,
                        "log_snippet": msg[:200],
                    },
                }
                yield record

