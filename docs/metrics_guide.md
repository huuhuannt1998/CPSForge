# Metrics Collection and Reporting Guide

CPSForge collects structured metrics during every experiment run. This guide covers what is measured, where it is stored, and how to produce publication-quality reports.

---

## 1. EvalMetrics Fields

Each completed run produces a `metrics.json` containing:

| Metric | Type | Definition |
|--------|------|-----------|
| `run_id` | string | Unique run identifier |
| `scene_name` | string | Scene used in the experiment |
| `attacker_name` | string | Attacker type (`scripted`, `random`, `llm`) |
| `detector_names` | list[str] | Active detectors |
| `action_validity_rate` | float | Fraction of LLM/random actions that parsed successfully |
| `execution_success_rate` | float | Fraction of approved actions that executed without error |
| `attack_success_rate` | float | Fraction of attacks that achieved the intended process effect |
| `process_impact_score` | float | Normalized deviation from nominal plant behavior |
| `shield_approval_rate` | float | Fraction of proposed actions approved by shield |
| `shield_rejection_rate` | float | Fraction of proposed actions rejected |
| `unsafe_block_rate` | float | Fraction of truly unsafe actions correctly blocked |
| `detector_precision` | float | TP / (TP + FP) across all detectors |
| `detector_recall` | float | TP / (TP + FN) across all detectors |
| `detector_f1` | float | Harmonic mean of precision and recall |
| `detection_latency_ms` | float | Median time from attack start to first detection |
| `hard_case_flag` | bool | Whether this run produced hard cases |
| `adaptation_round` | int | Closed-loop adaptation round number |

---

## 2. Per-Run Artifacts

Every run writes to `data/raw/<experiment_name>/<run_id>/`:

```
trace.parquet          # Full plant snapshot timeline
metadata.json          # Run config, timestamps, software version
attacks.json           # All proposed attack actions with outcomes
detections.json        # All detector events
shield_events.json     # All shield decisions
metrics.json           # Computed EvalMetrics
```

### Eval Run Flag

Set `eval_run: true` in the experiment config to enable full metrics computation:

```yaml
# configs/experiments/eval_example.yaml
experiment_name: eval_tank_scripted
eval_run: true
scene: tank_control
attacker: scripted
live_writes: false
```

Non-eval runs still produce trace and event files but may skip aggregate metric computation.

---

## 3. Experiment-Level Aggregation

After collecting multiple runs, aggregate results are stored in `data/processed/<experiment_name>/`:

```
run_index.csv            # Index of all runs with key metadata
aggregate_metrics.csv    # Per-run metrics in tabular form
summary.json             # Experiment-level statistics
```

Generate aggregates via:

```bash
cpsforge report summarize --experiment eval_tank_scripted
```

---

## 4. CLI Report Commands

### Per-Run Reports

```bash
# Show metrics for a specific run
cpsforge report metrics --experiment eval_tank_scripted --run-id run_001

# Show the run index
cpsforge report run-index --experiment eval_tank_scripted
```

### Paper-Ready Tables

```bash
# Cross-attacker comparison table
cpsforge report cross-attacker --experiment eval_tank_scripted

# Cross-detector comparison table
cpsforge report cross-detector --experiment eval_tank_scripted

# Shield effectiveness table
cpsforge report shield-table --experiment eval_tank_scripted

# Adaptation round progression table
cpsforge report adaptation-table --experiment eval_tank_scripted
```

Each table command writes a CSV to `data/processed/<experiment_name>/` and prints a formatted version to the terminal.

### Summarize All Runs

```bash
cpsforge report summarize --experiment eval_tank_scripted
```

Produces `summary.json` with mean, std, min, max for every numeric metric.

---

## 5. Programmatic API

Use the analysis module directly:

```python
from cpsforge.analysis.tables import (
    build_cross_attacker_table,
    build_cross_detector_table,
    build_shield_table,
    build_adaptation_table,
)
from cpsforge.analysis.replay_analysis import (
    replay_analysis,
    compare_rounds,
)

# Build a cross-attacker comparison DataFrame
df = build_cross_attacker_table("data/processed/eval_tank_scripted")

# Compare adaptation rounds
comparison = compare_rounds(
    "data/processed/eval_tank_scripted",
    rounds=[0, 1, 2],
)
```

---

## 6. Metric Computation Details

### Attack Success Rate

An attack is considered successful if the `process_impact_score` exceeds a configurable threshold (default: 0.1). This measures actual physical deviation, not whether the write was accepted.

### Process Impact Score

Computed as the normalized root-mean-square deviation of sensor readings from their nominal (pre-attack) baseline during the attack window.

### Detection Latency

Measured from the timestamp of the first attack action to the timestamp of the first detection event with severity ≥ `warning`. Runs with no detection contribute ∞ latency (capped at run duration for averaging).

### Hard Case Classification

A run is flagged as a hard case if:
- An attack succeeded (`attack_success_rate > 0`) **and**
- No detector raised an alert (`detector_recall == 0`) **or**
- Detection latency exceeded the configured threshold

---

## 7. Workflow Example

```bash
# 1. Run a batch of experiments
for attacker in scripted random llm; do
  cpsforge run attack \
    --scene tank_control \
    --attacker $attacker \
    --experiment eval_tank_all \
    --eval-run \
    --steps 200
done

# 2. Aggregate results
cpsforge report summarize --experiment eval_tank_all

# 3. Generate paper tables
cpsforge report cross-attacker --experiment eval_tank_all
cpsforge report cross-detector --experiment eval_tank_all
cpsforge report shield-table --experiment eval_tank_all

# 4. Review hard cases
cpsforge adapt list-hard-cases --experiment eval_tank_all
```
