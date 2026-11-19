# SecureAgent-SOC Dataset Repository & Pipeline

> **Directory:** `SecureAgent-SOC/data/`  
> **Status:** 100% Authentic Published Cybersecurity Benchmarks (Zero synthetic data)  
> **Standard:** Standard Unix / Data Science Repository Layout

---

## 1. Directory Layout

```text
SecureAgent-SOC/data/
├── README.md                      # Architecture, provenance, and data manual (this file)
├── LICENSES/                      # Licence texts of the bundled third-party datasets
│
├── raw/                           # Raw, untouched benchmark files from original sources
│   ├── adversarial_eval/          # AgentDojo YAML suites (workspace, slack, banking)
│   ├── detection_rules/           # Splunk & SigmaHQ YAML detection rules
│   ├── lanl/                      # LANL Cyber-1 authentication CSV & red team labels
│   ├── malware_hashes/            # abuse.ch Feodo Tracker C2 blocklist
│   ├── mitre_attack/              # MITRE ATT&CK STIX 2.0 Enterprise Matrix
│   ├── network_flows/             # NSL-KDD intrusion test benchmark
│   ├── phishing/                  # Nazario / Enron / CEAS raw email corpus
│   ├── provenance/                # DARPA TC Engagement 3 APT manifests
│   └── siem_alerts/               # Suricata EVE captures & Wazuh ruleset .ini tests
│
├── parsers/                       # Dedicated ingestion normalization engines
│   ├── __init__.py                # SHA-256 deduplication hashing & timestamp utils
│   ├── phishing_parser.py         # Parses email headers/bodies (tau = 1.0)
│   ├── suricata_parser.py         # Parses network packet alerts (tau = 0.6)
│   ├── wazuh_parser.py            # Parses host OS & daemon telemetry (tau = 0.1)
│   ├── lanl_parser.py             # Parses authentication & red team hops (tau = 0.1)
│   ├── agentdojo_parser.py        # Parses indirect prompt injection vectors (tau = 1.0)
│   └── nsl_kdd_parser.py          # Parses network flow features (tau = 0.6)
│
├── processed/                     # 100% parsed, validated JSON Lines (.jsonl)
│   ├── phishing_alerts.jsonl      # 18,631 records
│   ├── lanl_auth_alerts.jsonl     # 50,000 records
│   ├── suricata_alerts.jsonl      # 22 records
│   ├── wazuh_alerts.jsonl         # 51 records
│   ├── agentdojo_injections.jsonl # 16 records
│   ├── nsl_kdd_alerts.jsonl       # 22,543 records
│   └── master_alerts.jsonl        # 91,263 total records (111 MB)
│
├── splits/                        # Deterministic 70 / 15 / 15 Partitioning (seed=42)
│   ├── operational/               # 70% (63,871 records) -> Redis Queue & PostgreSQL
│   │   ├── all_ingest.jsonl       # Master stream for full-scale load testing
│   │   ├── email_stream.jsonl     # Phishing Agent stream
│   │   ├── auth_stream.jsonl      # LANL auth & lateral movement stream
│   │   ├── ids_network_stream.jsonl # Suricata + NSL-KDD network IDS stream
│   │   └── wazuh_host_stream.jsonl# Wazuh endpoint host stream
│   │
│   ├── knowledge/                 # 15% (13,685 records) -> Qdrant Vector Memory
│   │   ├── all_knowledge_seed.jsonl # Master knowledge base
│   │   ├── historical_phishing.jsonl# Past phishing samples for vector similarity RAG
│   │   ├── baseline_auth.jsonl    # Normal auth behavior for user profiling (UBA)
│   │   ├── network_attack_signatures.jsonl # Reference attack patterns
│   │   └── wazuh_rule_baselines.jsonl # Wazuh rule reference definitions
│   │
│   └── evaluation/                # 15% (13,707 records) -> Strictly Held-Out Test
│       ├── all_evaluation_test.jsonl # Held-out benchmark for publication metrics
│       ├── agentdojo_adversarial_injections.jsonl # 100% AgentDojo tests for Attack Simulator (:8501)
│       ├── lateral_hop_attacks.jsonl # Held-out red-team lateral movement hops (Tests N1 SSE)
│       ├── phishing_test_set.jsonl# Held-out email classification test set
│       ├── network_intrusion_test.jsonl # Held-out flow intrusion test set
│       └── wazuh_host_test.jsonl  # Held-out host test cases
│
└── scripts/                       # Executable data lifecycle pipeline tools
    ├── download_datasets.py       # Retrieves raw datasets from authenticated sources
    ├── process_datasets.py        # Normalizes raw data into processed/ .jsonl
    ├── split_datasets.py          # Deterministically creates splits/ (seed=42)
    ├── seed_database.py           # Seeds PostgreSQL, Redis and Qdrant from splits/knowledge/ and raw/
    └── stream_ingest.py           # Streams splits/operational/ into POST /api/v1/ingest
```

---

## 2. Pipeline Execution Commands

All scripts can be executed directly from the workspace root or via Python:

```bash
# 1. Download raw datasets
python3 data/scripts/download_datasets.py

# 2. Process and normalize all raw records (generates data/processed/)
python3 data/scripts/process_datasets.py

# 3. Split into operational, knowledge, and evaluation partitions (generates data/splits/)
python3 data/scripts/split_datasets.py

# 4. Seed the running Docker services (PostgreSQL, Redis, Qdrant)
python3 data/scripts/seed_database.py

# 5. Stream operational alerts into the running API (port 8000)
python3 data/scripts/stream_ingest.py --batch 100
```

---

## 3. Getting the Data (Git LFS)

Everything in `raw/`, `processed/` and `splits/` (44 files, about 535 MB) is stored with [Git LFS](https://git-lfs.com). Install Git LFS once, then clone as usual:

```bash
git lfs install
git clone https://github.com/CYSECPRP/SecureAgent-SOC.git
```

If you only need the code, skip the data download and fetch single files later:

```bash
GIT_LFS_SKIP_SMUDGE=1 git clone https://github.com/CYSECPRP/SecureAgent-SOC.git   # PowerShell: $env:GIT_LFS_SKIP_SMUDGE = "1"
cd SecureAgent-SOC
git lfs pull --include "data/splits/evaluation/*"
```

The GitHub free plan includes 10 GiB of LFS bandwidth per month, and every full clone downloads about 535 MB, so please skip the data when you do not need it.

---

## 4. Sources, Licences and Citations

The project code is MIT licensed. The datasets are **not**: each one keeps the licence of its publisher. Licence texts are in [`LICENSES/`](LICENSES/).

| Data                                      | Files in `raw/`                                     | Publisher                                                                                                                                                                     | Licence / terms                                                                           |
| :---------------------------------------- | :-------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------- |
| Phishing emails                           | `phishing/Phishing_Email.csv`                       | Hugging Face [`zefang-liu/phishing-email-dataset`](https://huggingface.co/datasets/zefang-liu/phishing-email-dataset) (copy of the Kaggle "Phishing Email Detection" dataset) | LGPL-3.0 ([`LGPL-3.0.txt`](LICENSES/LGPL-3.0.txt), [`GPL-3.0.txt`](LICENSES/GPL-3.0.txt)) |
| Authentication events and red-team labels | `lanl/lanl_auth_50k.csv`, `lanl/redteam_labels.csv` | Los Alamos National Laboratory, [Cyber1](https://csr.lanl.gov/data/cyber1/)                                                                                                   | CC0 1.0 (please cite, see below)                                                          |
| Network intrusion flows                   | `network_flows/nsl_kdd_test.csv`                    | Canadian Institute for Cybersecurity, [NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html)                                                                                     | Free to redistribute with the citation below                                              |
| Prompt-injection tasks                    | `adversarial_eval/*.yaml`                           | ETH Zurich SPY Lab, [AgentDojo](https://github.com/ethz-spylab/agentdojo)                                                                                                     | MIT ([`MIT-AgentDojo.txt`](LICENSES/MIT-AgentDojo.txt))                                   |
| Suricata EVE alerts                       | `siem_alerts/suricata_eve_*.jsonl`                  | Elastic, [Beats](https://github.com/elastic/beats) Suricata module test logs                                                                                                  | Elastic License 2.0 ([`Elastic-License-2.0.txt`](LICENSES/Elastic-License-2.0.txt))       |
| Suricata rules                            | `siem_alerts/emerging_exploit.rules`                | Proofpoint, [Emerging Threats Open](https://rules.emergingthreats.net/)                                                                                                       | BSD / GPLv2, see file header ([`GPL-2.0.txt`](LICENSES/GPL-2.0.txt))                      |
| Wazuh rule tests                          | `siem_alerts/wazuh_ruleset/*.ini`                   | Wazuh, [`wazuh-ruleset`](https://github.com/wazuh/wazuh-ruleset)                                                                                                              | GPLv2 ([`GPL-2.0.txt`](LICENSES/GPL-2.0.txt))                                             |
| Splunk detections                         | `detection_rules/splunk_*.yml`                      | Splunk, [`security_content`](https://github.com/splunk/security_content)                                                                                                      | Apache-2.0 ([`Apache-2.0.txt`](LICENSES/Apache-2.0.txt))                                  |
| Sigma rule                                | `detection_rules/sigma_mimikatz_rule.yml`           | [SigmaHQ](https://github.com/SigmaHQ/sigma)                                                                                                                                   | Detection Rule License 1.1 ([`DRL-1.1.txt`](LICENSES/DRL-1.1.txt))                        |
| C2 IP blocklist                           | `malware_hashes/feodo_c2_blocklist.csv`             | abuse.ch, [Feodo Tracker](https://feodotracker.abuse.ch/)                                                                                                                     | CC0                                                                                       |
| ATT&CK Enterprise                         | `mitre_attack/enterprise_attack.json`               | The MITRE Corporation, [`mitre/cti`](https://github.com/mitre/cti)                                                                                                            | ATT&CK Terms of Use ([`MITRE-ATTACK.txt`](LICENSES/MITRE-ATTACK.txt))                     |
| APT ground-truth manifest                 | `provenance/darpa_tc_e3_manifest.md`                | DARPA, [Transparent Computing](https://github.com/darpa-i2o/Transparent-Computing)                                                                                            | Public domain                                                                             |

The files in `processed/` and `splits/` are derived from these sources: `process_datasets.py` normalises each record to the project alert schema and `split_datasets.py` partitions them. Each record keeps the licence of the source it came from.

**Citations**

- A. D. Kent, "Comprehensive, Multi-Source Cyber-Security Events," Los Alamos National Laboratory, 2015. doi:[10.17021/1179829](https://doi.org/10.17021/1179829)
- M. Tavallaee, E. Bagheri, W. Lu and A. A. Ghorbani, "A Detailed Analysis of the KDD CUP 99 Data Set," _IEEE Symposium on Computational Intelligence for Security and Defense Applications (CISDA)_, 2009.
- E. Debenedetti, J. Zhang, M. Balunović, L. Beurer-Kellner, M. Fischer and F. Tramèr, "AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents," _NeurIPS Datasets and Benchmarks Track_, 2024.
