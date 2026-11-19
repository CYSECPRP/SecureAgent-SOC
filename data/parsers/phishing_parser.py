"""
Phishing Dataset Parser for SecureAgent-SOC
Parses Nazario/Enron/CEAS phishing benchmark into NormalizedAlert records.
Calculates initial continuous taint score tau = 1.0 (untrusted external email).
"""

import csv
import sys
import uuid
from pathlib import Path
from typing import Dict, Any, Generator

from . import generate_content_hash, utc_now_iso

# Support arbitrarily large email bodies
csv.field_size_limit(sys.maxsize)


def parse_phishing_csv(file_path: Path, max_records: int = 0) -> Generator[Dict[str, Any], None, None]:
    """
    Parses Phishing_Email.csv.
    Header: ['', 'Email Text', 'Email Type']
    """
    if not file_path.exists():
        return

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            return

        count = 0
        for row in reader:
            if not row or len(row) < 3:
                continue

            email_text = row[1].strip()
            email_type = row[2].strip()  # 'Phishing Email' or 'Safe Email'

            if not email_text:
                continue

            is_phishing = email_type.lower() == "phishing email"
            severity = "HIGH" if is_phishing else "LOW"
            taint_score = 1.0  # External untrusted source

            # Extract pseudo-subject from the first line or up to 80 chars
            first_line = email_text.split("\n")[0][:100]
            content_hash = generate_content_hash("EMAIL", first_line, email_text[:200])

            record = {
                "id": str(uuid.uuid4()),
                "source": "EMAIL",
                "timestamp": utc_now_iso(),
                "severity": severity,
                "status": "NEW",
                "taint_score": taint_score,
                "source_ip": None,
                "destination_ip": None,
                "user_account": "internal_recipient@enterprise.local",
                "hostname": "mail-gateway-01",
                "content_hash": content_hash,
                "raw_payload": {
                    "email_text": email_text,
                    "label": email_type,
                    "is_phishing": is_phishing,
                },
                "normalized_data": {
                    "alert_type": "PHISHING" if is_phishing else "CLEAN_EMAIL",
                    "subject_snippet": first_line,
                    "ground_truth_label": email_type,
                    "body_length": len(email_text),
                },
            }

            yield record
            count += 1
            if max_records and count >= max_records:
                break

