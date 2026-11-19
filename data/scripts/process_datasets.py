"""
Master Data Processing Pipeline for SecureAgent-SOC
Parses ALL authentic raw benchmark datasets completely (zero data skipped):
- 18,631 Phishing Emails (100% of Hugging Face corpus)
- 50,000 LANL Cyber-1 Authentication Logs (100% of event stream)
- All Suricata EVE Alert records
- All Wazuh Ruleset Integration Tests
- All AgentDojo Prompt Injection Benchmarks
- All NSL-KDD Evaluation Network Flow records

Saves everything in data/processed/ (.jsonl). Does NOT split.
"""

import json
import sys
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"

sys.path.insert(0, str(DATA_DIR))

from parsers.phishing_parser import parse_phishing_csv
from parsers.suricata_parser import parse_suricata_eve
from parsers.wazuh_parser import parse_wazuh_ini_dir
from parsers.lanl_parser import parse_lanl_auth
from parsers.agentdojo_parser import parse_agentdojo_yaml
from parsers.nsl_kdd_parser import parse_nsl_kdd


def process_all_datasets():
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 75)
    print("SecureAgent-SOC: Running Complete Dataset Processing (Zero Skipped)")
    print(f"Raw Input Directory:       {RAW_DIR}")
    print(f"Processed Directory:       {PROCESSED_DIR}")
    print("=" * 75)

    stats = {}

    # 1. Phishing Benchmark (ALL rows)
    phishing_raw = RAW_DIR / "phishing" / "Phishing_Email.csv"
    phishing_out = PROCESSED_DIR / "phishing_alerts.jsonl"
    print("\n[1/6] Processing 100% of Phishing Emails (Nazario/Enron/CEAS)...")
    count = 0
    with open(phishing_out, "w", encoding="utf-8") as out:
        for alert in parse_phishing_csv(phishing_raw, max_records=0):
            out.write(json.dumps(alert) + "\n")
            count += 1
    stats["phishing"] = count
    print(f"  -> Generated {count:,} normalized alerts in {phishing_out.name}")

    # 2. Suricata EVE Alerts (ALL rows)
    suri_raw = RAW_DIR / "siem_alerts" / "suricata_eve_alerts.jsonl"
    suri_out = PROCESSED_DIR / "suricata_alerts.jsonl"
    print("\n[2/6] Processing 100% of Suricata EVE Alert Captures...")
    count = 0
    with open(suri_out, "w", encoding="utf-8") as out:
        for alert in parse_suricata_eve(suri_raw, max_records=0):
            out.write(json.dumps(alert) + "\n")
            count += 1
    stats["suricata"] = count
    print(f"  -> Generated {count:,} normalized alerts in {suri_out.name}")

    # 3. Wazuh Host Test Cases (ALL suites)
    wazuh_raw = RAW_DIR / "siem_alerts" / "wazuh_ruleset"
    wazuh_out = PROCESSED_DIR / "wazuh_alerts.jsonl"
    print("\n[3/6] Processing 100% of Wazuh Host Telemetry (.ini test suites)...")
    count = 0
    with open(wazuh_out, "w", encoding="utf-8") as out:
        for alert in parse_wazuh_ini_dir(wazuh_raw):
            out.write(json.dumps(alert) + "\n")
            count += 1
    stats["wazuh"] = count
    print(f"  -> Generated {count:,} normalized alerts in {wazuh_out.name}")

    # 4. LANL Cyber-1 Authentication (ALL 50,000 rows)
    lanl_auth = RAW_DIR / "lanl" / "lanl_auth_50k.csv"
    lanl_redteam = RAW_DIR / "lanl" / "redteam_labels.csv"
    lanl_out = PROCESSED_DIR / "lanl_auth_alerts.jsonl"
    print("\n[4/6] Processing 100% of LANL Cyber-1 Authentication Stream...")
    count = 0
    with open(lanl_out, "w", encoding="utf-8") as out:
        for alert in parse_lanl_auth(lanl_auth, lanl_redteam, max_records=0):
            out.write(json.dumps(alert) + "\n")
            count += 1
    stats["lanl"] = count
    print(f"  -> Generated {count:,} normalized alerts in {lanl_out.name}")

    # 5. AgentDojo Adversarial Prompt Injections (ALL suites)
    agentdojo_out = PROCESSED_DIR / "agentdojo_injections.jsonl"
    print("\n[5/6] Processing 100% of AgentDojo Adversarial Prompt Injections...")
    count = 0
    with open(agentdojo_out, "w", encoding="utf-8") as out:
        for suite in ["workspace", "slack", "banking"]:
            yaml_path = RAW_DIR / "adversarial_eval" / f"agentdojo_{suite}_injections.yaml"
            for alert in parse_agentdojo_yaml(yaml_path, suite):
                out.write(json.dumps(alert) + "\n")
                count += 1
    stats["agentdojo"] = count
    print(f"  -> Generated {count:,} normalized alerts in {agentdojo_out.name}")

    # 6. NSL-KDD Network Flow Benchmark (ALL rows)
    nsl_raw = RAW_DIR / "network_flows" / "nsl_kdd_test.csv"
    nsl_out = PROCESSED_DIR / "nsl_kdd_alerts.jsonl"
    print("\n[6/6] Processing 100% of NSL-KDD Network Flow Telemetry...")
    count = 0
    with open(nsl_out, "w", encoding="utf-8") as out:
        for alert in parse_nsl_kdd(nsl_raw):
            out.write(json.dumps(alert) + "\n")
            count += 1
    stats["nsl_kdd"] = count
    print(f"  -> Generated {count:,} normalized alerts in {nsl_out.name}")

    # Combined master consolidated dataset
    master_out = PROCESSED_DIR / "master_alerts.jsonl"
    print("\nCompiling master consolidated dataset...")
    total_master = 0
    with open(master_out, "w", encoding="utf-8") as out:
        for out_file in [phishing_out, suri_out, wazuh_out, lanl_out, agentdojo_out, nsl_out]:
            with open(out_file, "r", encoding="utf-8") as f:
                for line in f:
                    out.write(line)
                    total_master += 1
    stats["master_total"] = total_master
    print(f"  -> Consolidated {total_master:,} total normalized records in {master_out.name}")

    print("\n" + "=" * 75)
    print("Full Processing Summary (100% of Raw Data Parsed):")
    for k, v in stats.items():
        print(f"  - {k:<20}: {v:>7,} records")
    print("=" * 75)
    print("All processed data is cleanly saved in data/processed/ (.jsonl).")
    print("Zero splitting has been applied yet.")


if __name__ == "__main__":
    process_all_datasets()
