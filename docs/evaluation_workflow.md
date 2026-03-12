# Evaluation Workflow & Paper Artifact Map

This guide describes how CPSForge's experiment pipeline produces the
artifacts needed for the evaluation section of the paper.
It covers the end-to-end flow from running experiments to generating
publication-ready tables.

---

## 1. Pipeline Overview

```
  Experiment Run (PLC + Factory I/O)
          │
          ▼
  data/raw/<experiment>/<run_id>/
  ├── trace.parquet          (plant timeseries)
  ├── attacks.json           (proposed attack actions)
  ├── detections.json        (detector events)
  ├── shield_events.json     (shield decisions)
  ├── hard_cases.json        (missed/late detections)
  ├── metrics.json           (per-run EvalMetrics)
  └── metadata.json          (config snapshot)
          │
          ▼
  cpsforge report summarize  (aggregate across runs)
          │
          ▼
  data/processed/<experiment>/
  ├── run_index.csv
  ├── aggregate_metrics.csv
  └── summary.json
          │
          ▼
  cpsforge report export-all  (paper-ready tables)
          │
          ▼
  data/processed/<experiment>/paper/
  ├── table1_attack_results.csv
  ├── table2_shield_results.csv
  ├── table3_defender_results.csv
  ├── table4_adaptation_results.csv
  ├── attack_type_breakdown.csv
  ├── latency_distribution.json
  └── paper_export_manifest.json
```

---

## 2. Running Experiments

### Stage 1: Baseline Validation

```bash
cpsforge run baseline --scene tank_control --max-steps 200 --dry-run
cpsforge run attack --scene tank_control --attacker scripted --eval-run
cpsforge run attack --scene tank_control --attacker random --eval-run
```

### Stage 2: LLM Attacker

```bash
cpsforge run attack --scene tank_control --attacker llm --eval-run
```

### Stage 3: Closed-Loop Adaptation

```bash
cpsforge run closed-loop --scene tank_control --rounds 3 --eval-run
```

---

## 3. Analysis Commands

| Command | Paper Reference | Output |
|---------|----------------|--------|
| `cpsforge report cross-attacker -e <exp>` | Table 1 (`tab:attack-results`) | Attacker × {Validity, Exec Success, ASR, Impact} |
| `cpsforge report shield-analysis -e <exp>` | Table 2 (`tab:shield-results`) | Approval/rejection rates + per-rule breakdown |
| `cpsforge report cross-detector -e <exp>` | Table 3 (`tab:defender-results`) | Detector × {Precision, Recall, F1, Latency} |
| `cpsforge report adaptation -e <exp>` | Table 4 (`tab:adaptation-results`) | Round × {Detection Rate, Missed Cases, F1} |
| `cpsforge report attack-types -e <exp>` | Supplemental | Per-attack-type success analysis |
| `cpsforge report export-all -e <exp>` | All tables | Batch export with manifest |

All commands accept `--output / -o` for CSV file, `--eval-only/--all-runs`,
and `--data-dir` to override the default `data/` root.

---

## 4. Artifact-to-Paper Mapping

### Table 1: Attack Results (`tab:attack-results`)

**File:** `paper/table1_attack_results.csv`

| Column | Source | Description |
|--------|--------|-------------|
| `attacker` | `metrics.json → attacker_name` | Attacker type (scripted, random, llm) |
| `validity_mean` | `metrics.json → action_validity_rate` | Fraction of structurally valid actions |
| `exec_success_mean` | `metrics.json → execution_success_rate` | Fraction successfully executed |
| `attack_success_mean` | `metrics.json → attack_success_rate` | Fraction causing process deviation |
| `impact_mean` | `metrics.json → process_impact_score` | Mean physical deviation |

**LaTeX label:** `\ref{tab:attack-results}`

### Table 2: Shield Results (`tab:shield-results`)

**File:** `paper/table2_shield_results.csv`

| Column | Source | Description |
|--------|--------|-------------|
| `approval_rate` | `metrics.json → shield_approval_rate` | Fraction of actions approved |
| `rejection_rate` | `metrics.json → shield_rejection_rate` | Fraction rejected |
| `unsafe_block_rate` | `metrics.json → unsafe_block_rate` | Rejected due to safety rules |
| Rule breakdown | `shield_events.json → violated_rules` | Per-rule-type rejection counts |
| `normalization_count` | `shield_events.json → normalized_value` | Actions with value normalization |
| `rollback_count` | `shield_events.json → rollback_plan` | Decisions with rollback plans |

**LaTeX label:** `\ref{tab:shield-results}`

### Table 3: Defender Results (`tab:defender-results`)

**File:** `paper/table3_defender_results.csv`

| Column | Source | Description |
|--------|--------|-------------|
| `detector` | `detections.json → detector_name` | Individual detector name |
| `per_detector_precision` | Computed from TP/FP vs `trace.parquet → attack_active` | Per-detector precision |
| `per_detector_recall` | Computed from TP/FN | Per-detector recall |
| `per_detector_f1` | Harmonic mean | F1 score |
| `latency_p50`, `latency_p90` | From attack-start-step to first detection step | Latency percentiles |

**LaTeX label:** `\ref{tab:defender-results}`

### Table 4: Adaptation Results (`tab:adaptation-results`)

**File:** `paper/table4_adaptation_results.csv`

| Column | Source | Description |
|--------|--------|-------------|
| `round` | `round_metrics.csv` or `metrics.json → adaptation_round` | Adaptation round index |
| `detector_f1` | Aggregated per round | F1 per round |
| `detector_recall` | Aggregated per round | Detection rate per round |
| `false_negatives` | Summed per round | Missed cases |
| `f1_delta` | Computed | Improvement from previous round |

**LaTeX label:** `\ref{tab:adaptation-results}`

### Supplemental: Latency Distribution

**File:** `paper/latency_distribution.json`

Contains global and per-detector percentiles (p50, p90, p95, p99),
useful for latency CDF figures.

### Supplemental: Attack Type Breakdown

**File:** `paper/attack_type_breakdown.csv`

Disaggregates success by attack type (sensor_spoof, actuator_override,
setpoint_shift, etc.) for ablation analysis.

---

## 5. Programmatic API

All functions are importable from `cpsforge.analysis`:

```python
from cpsforge.analysis import (
    cross_attacker_table,
    cross_detector_table,
    shield_analysis_table,
    adaptation_round_table,
    attack_type_breakdown,
    latency_distribution,
    full_paper_export,
    hard_case_generalization,
)

# Example: generate Table 1
from pathlib import Path
df = cross_attacker_table(Path("data"), "my_experiment")
print(df.to_latex())  # paste into paper

# Example: full export
out = full_paper_export(Path("data"), "my_experiment")
# → data/processed/my_experiment/paper/
```

---

## 6. Replay-Based Analysis

For closed-loop evaluation (RQ5), use `hard_case_generalization` to measure
how many previously-missed attacks a retrained detector now catches:

```python
from cpsforge.adaptation.bank import HardCaseBank
from cpsforge.adaptation.replay import RunReplayLoader
from cpsforge.analysis import hard_case_generalization

bank = HardCaseBank(experiment_dir=Path("data/raw/experiment"))
bank.load_from_experiment(failure_modes=["miss", "late_detection"])

result = hard_case_generalization(bank, old_detectors, new_detectors)
print(result.summary())
# {'total_hard_cases': 12, 'caught_before': 3, 'caught_after': 9,
#  'still_missed': 3, 'generalization_rate': 0.75, ...}
```

---

## 7. Checklist Before Paper Submission

- [ ] All eval runs have `eval_run: true` in their config
- [ ] `cpsforge report summarize` run for each experiment
- [ ] `cpsforge report export-all` produces all 6 paper files
- [ ] `paper_export_manifest.json` shows correct row counts
- [ ] LaTeX tables populated from CSV exports
- [ ] Latency distribution plotted from JSON export
- [ ] Adaptation round deltas (Column `f1_delta`) show improvement
- [ ] Hard case generalization results documented
