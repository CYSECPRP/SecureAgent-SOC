#!/usr/bin/env bash
# Runs once when the codespace is created.
set -euo pipefail

python -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r backend/requirements.txt -r attack_simulator/requirements.txt

# The Red-Team Lab only needs two small evaluation files, not the full 535 MB of data.
git lfs pull --include "data/splits/evaluation/agentdojo_adversarial_injections.jsonl,data/splits/evaluation/phishing_test_set.jsonl" \
  || echo "Could not download the evaluation data; lab scenarios 1 and 2 will show no samples."
