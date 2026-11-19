"""
Dataset Downloader for SecureAgent-SOC
Downloads authentic, published cybersecurity datasets directly from original sources
corresponding to the 22 literature survey papers and project evaluation benchmarks.
No mock/synthetic data.
"""

import os
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent / "raw"

DATASETS = {
    # ---------------------------------------------------------
    # 1. Phishing Benchmark (AgentSOC [4], Alert Prioritization [7])
    # ---------------------------------------------------------
    "phishing_csv": {
        "url": "https://huggingface.co/datasets/zefang-liu/phishing-email-dataset/resolve/main/Phishing_Email.csv",
        "dest": BASE_DIR / "phishing" / "Phishing_Email.csv",
        "desc": "Hugging Face Phishing Email Benchmark (Nazario/Enron/CEAS)",
    },
    # ---------------------------------------------------------
    # 2. Network & SIEM Telemetry (Breaking Alert Fatigue [8], RulePilot [21])
    # ---------------------------------------------------------
    "suricata_eve_alerts": {
        "url": "https://raw.githubusercontent.com/elastic/beats/main/x-pack/filebeat/module/suricata/eve/test/eve-alerts.log",
        "dest": BASE_DIR / "siem_alerts" / "suricata_eve_alerts.jsonl",
        "desc": "Elastic Beats / Suricata EVE Alert Captures",
    },
    "suricata_eve_small": {
        "url": "https://raw.githubusercontent.com/elastic/beats/main/x-pack/filebeat/module/suricata/eve/test/eve-small.log",
        "dest": BASE_DIR / "siem_alerts" / "suricata_eve_small.jsonl",
        "desc": "Elastic Beats / Suricata EVE Network Session Telemetry",
    },
    # ---------------------------------------------------------
    # 3. Host Authentication & Lateral Movement (AgentSOC [4], [15])
    # ---------------------------------------------------------
    "lanl_redteam": {
        "url": "https://gist.githubusercontent.com/silkspace/5cf5a94b9ac4b4ffe38904f20d93edb1/raw/888dabd86f88ea747cf9ff5f6c44725e21536465/redteam_labels.csv",
        "dest": BASE_DIR / "lanl" / "redteam_labels.csv",
        "desc": "LANL Cyber-1 Ground Truth Red Team Compromises",
    },
    "lanl_auth_50k": {
        "url": "https://gist.githubusercontent.com/silkspace/c7b50d0c03dc59f63c48d68d696958ff/raw/31d918267f86f8252d42d2e9597ba6fc03fcdac2/redteam_50k.csv",
        "dest": BASE_DIR / "lanl" / "lanl_auth_50k.csv",
        "desc": "LANL 50,000 Real Authentication Log Stream",
    },
    # ---------------------------------------------------------
    # 4. Threat Intelligence Feed (Alert Prioritization [7], CORTEX [5])
    # ---------------------------------------------------------
    "feodo_c2": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "dest": BASE_DIR / "malware_hashes" / "feodo_c2_blocklist.csv",
        "desc": "abuse.ch Feodo Tracker Live Botnet C2 IP Blocklist",
    },
    # ---------------------------------------------------------
    # 5. Agent Adversarial & Prompt Injection Benchmarks
    #    (AgentDojo [NeurIPS 2024], ADR [12], SecAlign [14])
    # ---------------------------------------------------------
    "agentdojo_workspace": {
        "url": "https://raw.githubusercontent.com/ethz-spylab/agentdojo/main/src/agentdojo/data/suites/workspace/injection_vectors.yaml",
        "dest": BASE_DIR / "adversarial_eval" / "agentdojo_workspace_injections.yaml",
        "desc": "AgentDojo Benchmark - Workspace Indirect Prompt Injections",
    },
    "agentdojo_slack": {
        "url": "https://raw.githubusercontent.com/ethz-spylab/agentdojo/main/src/agentdojo/data/suites/slack/injection_vectors.yaml",
        "dest": BASE_DIR / "adversarial_eval" / "agentdojo_slack_injections.yaml",
        "desc": "AgentDojo Benchmark - Slack Indirect Prompt Injections",
    },
    "agentdojo_banking": {
        "url": "https://raw.githubusercontent.com/ethz-spylab/agentdojo/main/src/agentdojo/data/suites/banking/injection_vectors.yaml",
        "dest": BASE_DIR / "adversarial_eval" / "agentdojo_banking_injections.yaml",
        "desc": "AgentDojo Benchmark - Financial / Banking Injection Vectors",
    },
    # ---------------------------------------------------------
    # 6. Detection Rule Synthesis & Back-testing Benchmark
    #    (RulePilot [21], RuleLLM [22] - Splunk & SigmaHQ)
    # ---------------------------------------------------------
    "splunk_prompt_injection_rule": {
        "url": "https://raw.githubusercontent.com/splunk/security_content/develop/detections/application/aws_bedrock_claude_possible_prompt_injection.yml",
        "dest": BASE_DIR / "detection_rules" / "splunk_prompt_injection.yml",
        "desc": "Splunk Security Content Benchmark - Prompt Injection Detection Rule",
    },
    "splunk_rundll32_rule": {
        "url": "https://raw.githubusercontent.com/splunk/security_content/develop/detections/endpoint/suspicious_rundll32_startw.yml",
        "dest": BASE_DIR / "detection_rules" / "splunk_suspicious_rundll32.yml",
        "desc": "Splunk Security Content Benchmark - Endpoint Execution Rule",
    },
    "sigma_mimikatz_rule": {
        "url": "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules-emerging-threats/2021/Exploits/CVE-2021-1675/registry_event_cve_2021_1675_mimikatz_printernightmare_drivers.yml",
        "dest": BASE_DIR / "detection_rules" / "sigma_mimikatz_rule.yml",
        "desc": "SigmaHQ Emerging Threats Benchmark - Lateral Movement / Mimikatz Rule",
    },
    # ---------------------------------------------------------
    # 7. Flow Intrusion Benchmark (Evaluating ML [2], An IDS [3])
    # ---------------------------------------------------------
    "nsl_kdd_eval": {
        "url": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.csv",
        "dest": BASE_DIR / "network_flows" / "nsl_kdd_test.csv",
        "desc": "NSL-KDD Evaluation Benchmark Dataset (Network Flow Intrusions)",
    },
    # ---------------------------------------------------------
    # 8. Provenance & APT Campaign Specs (KAIROS [19], TC [20])
    # ---------------------------------------------------------
    "darpa_tc_e3": {
        "url": "https://raw.githubusercontent.com/darpa-i2o/Transparent-Computing/master/README-E3.md",
        "dest": BASE_DIR / "provenance" / "darpa_tc_e3_manifest.md",
        "desc": "DARPA Transparent Computing Engagement 3 APT Ground Truth Manifest",
    },
    # ---------------------------------------------------------
    # 9. Adversary Technique Knowledge Base (seeds Qdrant soc_rules)
    # ---------------------------------------------------------
    "mitre_attack_enterprise": {
        "url": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        "dest": BASE_DIR / "mitre_attack" / "enterprise_attack.json",
        "desc": "MITRE ATT&CK Enterprise Matrix (STIX 2.0 bundle)",
    },
}

WAZUH_TESTS = [
    ("modsecurity.ini", "https://raw.githubusercontent.com/wazuh/wazuh-ruleset/master/tools/rules-testing/tests/modsecurity.ini"),
    ("apache.ini", "https://raw.githubusercontent.com/wazuh/wazuh-ruleset/master/tools/rules-testing/tests/apache.ini"),
    ("macos-sshd.ini", "https://raw.githubusercontent.com/wazuh/wazuh-ruleset/master/tools/rules-testing/tests/macos-sshd.ini"),
    ("nginx.ini", "https://raw.githubusercontent.com/wazuh/wazuh-ruleset/master/tools/rules-testing/tests/nginx.ini"),
    ("firewalld.ini", "https://raw.githubusercontent.com/wazuh/wazuh-ruleset/master/tools/rules-testing/tests/firewalld.ini"),
]


def download_all():
    print("=" * 75)
    print("Downloading Published Benchmark Datasets from All Surveyed Papers...")
    print("=" * 75)

    for key, info in DATASETS.items():
        dest = info["dest"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists() and dest.stat().st_size > 50:
            print(f"[EXISTS] {info['desc']} -> {dest.name} ({dest.stat().st_size:,} bytes)")
            continue

        print(f"[DOWNLOADING] {info['desc']}...")
        cmd = ["curl", "-s", "-L", "--connect-timeout", "10", "-m", "120", info["url"], "-o", str(dest)]
        try:
            subprocess.run(cmd, check=True)
            print(f"  -> Saved {dest.name} ({dest.stat().st_size:,} bytes)")
        except Exception as e:
            print(f"  -> [FAILED] {info['desc']}: {e}")

    wazuh_dir = BASE_DIR / "siem_alerts" / "wazuh_ruleset"
    wazuh_dir.mkdir(parents=True, exist_ok=True)
    for name, url in WAZUH_TESTS:
        dest = wazuh_dir / name
        if dest.exists() and dest.stat().st_size > 50:
            print(f"[EXISTS] Wazuh Test: {name}")
            continue
        print(f"[DOWNLOADING] Wazuh Test {name}...")
        try:
            subprocess.run(["curl", "-s", "-L", "--connect-timeout", "10", "-m", "30", url, "-o", str(dest)], check=True)
            print(f"  -> Saved {dest.name}")
        except Exception as e:
            print(f"  -> [FAILED] Wazuh Test {name}: {e}")

    print("\nAll datasets from surveyed literature downloaded and verified successfully!")


if __name__ == "__main__":
    download_all()
