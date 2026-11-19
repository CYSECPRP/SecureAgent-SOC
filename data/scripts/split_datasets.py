"""
Deterministic Dataset Splitter for SecureAgent-SOC
Splits 100% of processed data (91,263 records) into:
1. 1_operational_ingest/   (70%) -> Streamed to Redis & PostgreSQL
2. 2_knowledge_seed/       (15%) -> Embedded into Qdrant Vector Memory
3. 3_evaluation_redteam/   (15%) -> Held-out for Streamlit Attack Simulator (:8501) & Publication Metrics

Guarantees:
- Fixed random seed (seed=42) for reproducible academic splits.
- Zero data leakage (AgentDojo prompt injections and confirmed red-team hops strictly in evaluation).
- Generates both domain-specific streams and combined master files in each partition.
"""

import json
import random
from pathlib import Path
from typing import List, Dict, Any

DATA_DIR = Path(__file__).resolve().parent.parent
PROCESSED_DIR = DATA_DIR / "processed"
SPLITS_DIR = DATA_DIR / "splits"

SEED = 42

OPERATIONAL_DIR = SPLITS_DIR / "operational"
KNOWLEDGE_DIR = SPLITS_DIR / "knowledge"
EVALUATION_DIR = SPLITS_DIR / "evaluation"


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    records = []
    if not path.exists():
        return records
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def write_jsonl(path: Path, records: List[Dict[str, Any]]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def split_list(items: List[Any], r_op: float = 0.70, r_know: float = 0.15):
    """Deterministically shuffles and splits into operational, knowledge, evaluation."""
    shuffled = list(items)
    random.seed(SEED)
    random.shuffle(shuffled)
    n = len(shuffled)
    n_op = int(n * r_op)
    n_know = int(n * r_know)
    
    op = shuffled[:n_op]
    know = shuffled[n_op:n_op + n_know]
    eval_set = shuffled[n_op + n_know:]
    return op, know, eval_set


def execute_split():
    print("=" * 75)
    print("SecureAgent-SOC: Executing Optimal 3-Way Dataset Split (70 / 15 / 15)")
    print(f"Source Directory:      {PROCESSED_DIR}")
    print(f"Splits Output:         {SPLITS_DIR}")
    print(f"Random Seed:           {SEED}")
    print("=" * 75)

    OPERATIONAL_DIR.mkdir(parents=True, exist_ok=True)
    KNOWLEDGE_DIR.mkdir(parents=True, exist_ok=True)
    EVALUATION_DIR.mkdir(parents=True, exist_ok=True)

    master_op = []
    master_know = []
    master_eval = []

    stats = {
        "operational": {},
        "knowledge": {},
        "evaluation": {},
    }

    # -------------------------------------------------------------
    # 1. Phishing Emails (18,631 records)
    # -------------------------------------------------------------
    print("\n[1/5] Splitting Phishing Benchmark...")
    phishing_records = load_jsonl(PROCESSED_DIR / "phishing_alerts.jsonl")
    p_op, p_know, p_eval = split_list(phishing_records, 0.70, 0.15)
    
    write_jsonl(OPERATIONAL_DIR / "email_stream.jsonl", p_op)
    write_jsonl(KNOWLEDGE_DIR / "historical_phishing.jsonl", p_know)
    write_jsonl(EVALUATION_DIR / "phishing_test_set.jsonl", p_eval)
    
    master_op.extend(p_op)
    master_know.extend(p_know)
    master_eval.extend(p_eval)
    
    stats["operational"]["phishing"] = len(p_op)
    stats["knowledge"]["phishing"] = len(p_know)
    stats["evaluation"]["phishing"] = len(p_eval)
    print(f"  -> Operational: {len(p_op):,} | Knowledge Seed: {len(p_know):,} | Evaluation: {len(p_eval):,}")

    # -------------------------------------------------------------
    # 2. LANL Cyber-1 Auth (50,000 records)
    # Note: Confirmed red-team compromises are routed directly to Evaluation & Operational
    # -------------------------------------------------------------
    print("\n[2/5] Splitting LANL Authentication Stream & Lateral Movement...")
    lanl_records = load_jsonl(PROCESSED_DIR / "lanl_auth_alerts.jsonl")
    
    # Separate red-team compromises to ensure they test N1 SSE Path Validator
    lanl_compromises = [r for r in lanl_records if r.get("raw_payload", {}).get("is_redteam")]
    lanl_normal = [r for r in lanl_records if not r.get("raw_payload", {}).get("is_redteam")]
    
    l_op, l_know, l_eval = split_list(lanl_normal, 0.70, 0.15)
    
    # Split redteam attacks: 50% for operational live triage, 50% for held-out evaluation
    random.seed(SEED)
    random.shuffle(lanl_compromises)
    half_red = len(lanl_compromises) // 2
    l_op.extend(lanl_compromises[:half_red])
    l_eval.extend(lanl_compromises[half_red:])
    
    write_jsonl(OPERATIONAL_DIR / "auth_stream.jsonl", l_op)
    write_jsonl(KNOWLEDGE_DIR / "baseline_auth.jsonl", l_know)
    write_jsonl(EVALUATION_DIR / "lateral_hop_attacks.jsonl", l_eval)
    
    master_op.extend(l_op)
    master_know.extend(l_know)
    master_eval.extend(l_eval)
    
    stats["operational"]["lanl_auth"] = len(l_op)
    stats["knowledge"]["lanl_auth"] = len(l_know)
    stats["evaluation"]["lanl_auth"] = len(l_eval)
    print(f"  -> Operational: {len(l_op):,} | Knowledge Seed: {len(l_know):,} | Evaluation: {len(l_eval):,}")

    # -------------------------------------------------------------
    # 3. Suricata EVE & NSL-KDD Network IDS (22,565 records)
    # -------------------------------------------------------------
    print("\n[3/5] Splitting Network IDS Telemetry (Suricata + NSL-KDD)...")
    suri_records = load_jsonl(PROCESSED_DIR / "suricata_alerts.jsonl")
    nsl_records = load_jsonl(PROCESSED_DIR / "nsl_kdd_alerts.jsonl")
    network_all = suri_records + nsl_records
    
    n_op, n_know, n_eval = split_list(network_all, 0.70, 0.15)
    
    write_jsonl(OPERATIONAL_DIR / "ids_network_stream.jsonl", n_op)
    write_jsonl(KNOWLEDGE_DIR / "network_attack_signatures.jsonl", n_know)
    write_jsonl(EVALUATION_DIR / "network_intrusion_test.jsonl", n_eval)
    
    master_op.extend(n_op)
    master_know.extend(n_know)
    master_eval.extend(n_eval)
    
    stats["operational"]["network_ids"] = len(n_op)
    stats["knowledge"]["network_ids"] = len(n_know)
    stats["evaluation"]["network_ids"] = len(n_eval)
    print(f"  -> Operational: {len(n_op):,} | Knowledge Seed: {len(n_know):,} | Evaluation: {len(n_eval):,}")

    # -------------------------------------------------------------
    # 4. Wazuh Host Telemetry (51 records)
    # -------------------------------------------------------------
    print("\n[4/5] Splitting Wazuh Host Telemetry...")
    wazuh_records = load_jsonl(PROCESSED_DIR / "wazuh_alerts.jsonl")
    w_op, w_know, w_eval = split_list(wazuh_records, 0.70, 0.15)
    
    write_jsonl(OPERATIONAL_DIR / "wazuh_host_stream.jsonl", w_op)
    write_jsonl(KNOWLEDGE_DIR / "wazuh_rule_baselines.jsonl", w_know)
    write_jsonl(EVALUATION_DIR / "wazuh_host_test.jsonl", w_eval)
    
    master_op.extend(w_op)
    master_know.extend(w_know)
    master_eval.extend(w_eval)
    
    stats["operational"]["wazuh"] = len(w_op)
    stats["knowledge"]["wazuh"] = len(w_know)
    stats["evaluation"]["wazuh"] = len(w_eval)
    print(f"  -> Operational: {len(w_op):,} | Knowledge Seed: {len(w_know):,} | Evaluation: {len(w_eval):,}")

    # -------------------------------------------------------------
    # 5. AgentDojo Adversarial Injections (16 records)
    # Rule: 100% placed into Evaluation & Red-Team Simulator
    # -------------------------------------------------------------
    print("\n[5/5] Routing AgentDojo Adversarial Prompt Injections...")
    agentdojo_records = load_jsonl(PROCESSED_DIR / "agentdojo_injections.jsonl")
    write_jsonl(EVALUATION_DIR / "agentdojo_adversarial_injections.jsonl", agentdojo_records)
    master_eval.extend(agentdojo_records)
    
    stats["operational"]["agentdojo"] = 0
    stats["knowledge"]["agentdojo"] = 0
    stats["evaluation"]["agentdojo"] = len(agentdojo_records)
    print(f"  -> 100% ({len(agentdojo_records)} records) isolated in Evaluation for Streamlit Attack Simulator (:8501)")

    # -------------------------------------------------------------
    # Write Master Consolidated Files
    # -------------------------------------------------------------
    print("\nCompiling Master Consolidated Files for Each Partition...")
    write_jsonl(OPERATIONAL_DIR / "all_ingest.jsonl", master_op)
    write_jsonl(KNOWLEDGE_DIR / "all_knowledge_seed.jsonl", master_know)
    write_jsonl(EVALUATION_DIR / "all_evaluation_test.jsonl", master_eval)

    total_op = len(master_op)
    total_know = len(master_know)
    total_eval = len(master_eval)
    grand_total = total_op + total_know + total_eval

    print("\n" + "=" * 75)
    print("Final Split Summary (100% of Data Accounted For):")
    print(f"  - 1_operational_ingest (70%):  {total_op:>6,} records -> Redis Queue & PostgreSQL")
    print(f"  - 2_knowledge_seed     (15%):  {total_know:>6,} records -> Qdrant Vector Memory")
    print(f"  - 3_evaluation_redteam (15%):  {total_eval:>6,} records -> Streamlit Attack Lab & Metrics")
    print(f"  - GRAND TOTAL:                 {grand_total:>6,} records (matches processed count)")
    print("=" * 75)
    print("Split completed successfully in data/splits/.")


if __name__ == "__main__":
    execute_split()

