"""
LANL Cyber-1 Parser for SecureAgent-SOC
Parses LANL authentication stream and flags confirmed red-team compromises.
Calculates continuous taint score tau = 0.1 (internal Kerberos authentication).
"""

import csv
import uuid
from pathlib import Path
from typing import Dict, Any, Generator, Set

from . import generate_content_hash, utc_now_iso


def load_redteam_labels(redteam_csv: Path) -> Set[str]:
    compromises = set()
    if not redteam_csv.exists():
        return compromises

    with open(redteam_csv, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        for row in reader:
            if row and len(row) >= 4:
                # time, user, src_comp, dst_comp
                key = f"{row[0].strip()}:{row[1].strip()}:{row[2].strip()}"
                compromises.add(key)
    return compromises


def parse_lanl_auth(
    auth_csv: Path, redteam_csv: Path, max_records: int = 0
) -> Generator[Dict[str, Any], None, None]:
    if not auth_csv.exists():
        return

    redteam_set = load_redteam_labels(redteam_csv)

    with open(auth_csv, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            return

        count = 0
        for row in reader:
            if not row or len(row) < 10:
                continue

            time_val = row[1].strip()
            src_user = row[2].strip()
            dst_user = row[3].strip()
            src_comp = row[4].strip()
            dst_comp = row[5].strip()
            auth_type = row[6].strip()
            logon_type = row[7].strip()
            status_val = row[9].strip()  # Success or Failure

            is_redteam = (f"{time_val}:{src_user}:{src_comp}" in redteam_set) or (
                len(row) > 10 and row[10].strip() == "1"
            )

            severity = "CRITICAL" if is_redteam else ("LOW" if status_val.lower() == "success" else "MEDIUM")
            taint_score = 0.1  # Authenticated internal domain controller

            content_hash = generate_content_hash("LANL", time_val, src_user, src_comp, dst_comp)

            record = {
                "id": str(uuid.uuid4()),
                "source": "LANL",
                "timestamp": utc_now_iso(),
                "severity": severity,
                "status": "NEW",
                "taint_score": taint_score,
                "source_ip": None,
                "destination_ip": None,
                "user_account": src_user,
                "hostname": src_comp,
                "content_hash": content_hash,
                "raw_payload": {
                    "time": time_val,
                    "src_user": src_user,
                    "dst_user": dst_user,
                    "src_comp": src_comp,
                    "dst_comp": dst_comp,
                    "auth_type": auth_type,
                    "logon_type": logon_type,
                    "status": status_val,
                    "is_redteam": is_redteam,
                },
                "normalized_data": {
                    "alert_type": "LATERAL_MOVEMENT" if is_redteam else "AUTHENTICATION",
                    "src_host": src_comp,
                    "dst_host": dst_comp,
                    "auth_orientation": row[8].strip() if len(row) > 8 else "LogOn",
                    "is_compromise": is_redteam,
                },
            }

            yield record
            count += 1
            if max_records and count >= max_records:
                break

