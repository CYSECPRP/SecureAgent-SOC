# Evaluation (planned)

The benchmark suite is planned for **Stage 6** of the [roadmap](../docs/STAGE_BY_STAGE_MASTER_PLAN.md). This folder holds a placeholder until then.

Planned scripts:

| Script                          | Purpose                                                                     |
| :------------------------------ | :-------------------------------------------------------------------------- |
| `scripts/run_baselines.py`      | Baseline: single-agent, prompt-only triage without security controls        |
| `scripts/run_ablation.py`       | Turn off N1 to N5 one at a time and measure the effect                      |
| `scripts/red_team_injection.py` | Batch of 50 automated prompt-injection and log-poisoning attacks (TCR, ASR) |
| `scripts/compute_metrics.py`    | Compute the seven core metrics and the publication charts                   |

The held-out test data is already in [`data/splits/evaluation/`](../data/splits/evaluation/).
