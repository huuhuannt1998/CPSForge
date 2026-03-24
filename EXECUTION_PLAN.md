# CPSForge — Execution Plan

**Date:** 2026-03-24
**Target:** Computers & Security (Elsevier)
**Hardware:** Siemens S7-1200 @ 192.168.0.1, Factory I/O, LM Studio (Qwen2-7B-Instruct)

This document defines every experiment, the exact command to run it, the script
that processes its output, and the paper element (table/figure/subsection) that
consumes the result. Nothing here is fabricated — slots without data are marked
`PENDING`.

---

## 0. Prerequisites

```bash
# Install CPSForge
pip install -e .

# Verify PLC connectivity
python -m cpsforge plc probe

# Verify LM Studio (for LLM/campaign/agent phases)
curl http://127.0.0.1:1234/v1/models
```

---

## 1. Experiment Registry

### 1.1 Completed Experiments (data exists in data/raw/)

| ID | Experiment Folder | Scene | Attacker | Runs | Status | Paper Target |
|----|-------------------|-------|----------|------|--------|--------------|
| E01 | `live_scripted_from_a_to_b` | S1 | Scripted | 5 | ✅ DONE | Tab 1, 2, 3 |
| E02 | `live_random_from_a_to_b` | S1 | Random | 3 | ✅ DONE | Tab 1, 2, 3 |
| E03 | `live_llm_from_a_to_b` | S1 | LLM batch | 1 | ⚠️ NEED 2 MORE | Tab 1, 2, 3 |
| E04 | `live_scripted_filling_tank` | S3 | Scripted | 2 | ✅ DONE (≥2) | Tab 1, 2, 3 |
| E05 | `live_random_filling_tank` | S3 | Random | 1 | ⚠️ NEED 2 MORE | Tab 1, 2, 3 |
| E06 | `live_llm_filling_tank` | S3 | LLM batch | 1 | ⚠️ NEED 2 MORE | Tab 1, 2, 3 |
| E07 | `live_scripted_level_control` | S12 | Scripted | 2 | ✅ DONE (≥2) | Tab 1, 2, 3 |
| E08 | `live_random_level_control` | S12 | Random | 2 | ✅ DONE (≥2) | Tab 1, 2, 3 |
| E09 | `live_llm_level_control` | S12 | LLM batch | 1 | ⚠️ NEED 2 MORE | Tab 1, 2, 3 |
| E10 | `live_scripted_sorting_height_basic` | S19 | Scripted | 4 | ✅ DONE | Tab 1, 2, 3 |
| E11 | `live_random_sorting_height_basic` | S19 | Random | 2 | ✅ DONE (≥2) | Tab 1, 2, 3 |
| E12 | `live_llm_sorting_height_basic` | S19 | LLM batch | 1 | ⚠️ NEED 2 MORE | Tab 1, 2, 3 |
| E13 | `live_scripted_sorting_weight` | S20 | Scripted | 1 | ⚠️ NEED 2 MORE | Tab 1, 2, 3 |
| E14 | `live_random_sorting_weight` | S20 | Random | 1 | ⚠️ NEED 2 MORE | Tab 1, 2, 3 |
| E15 | `live_llm_sorting_weight` | S20 | LLM batch | 1 | ⚠️ NEED 2 MORE | Tab 1, 2, 3 |
| E16 | `agent_from_a_to_b_eval` | S1 | Agent | 1 | ✅ DONE | Tab 4 |
| E17 | `agent_filling_tank` | S3 | Agent | 1 | ✅ DONE | Tab 4 |
| E18 | `agent_level_control_eval` | S12 | Agent | 1 | ✅ DONE | Tab 4 |
| E19 | `agent_sorting_height_basic` | S19 | Agent | 1 | ✅ DONE | Tab 4 |
| E20 | `agent_sorting_weight` | S20 | Agent | 1 | ✅ DONE | Tab 4 |
| E21 | `campaign_level_control_attack` | S12 | Campaign | 1 | ⚠️ NEED 2 MORE | Tab 5 |
| E22 | `campaign_sorting_weight_attack` | S20 | Campaign | 2 | ⚠️ NEED 1 MORE | Tab 5 |
| E23 | `adapt_level_control` | S12 | Closed-loop | 3 rounds | ✅ DONE | Tab 5 |
| E24 | `adapt_sorting_weight` | S20 | Closed-loop | 3 rounds | ✅ DONE | Tab 5 |
| E25 | `closed_loop_level_control` | S12 | Closed-loop (campaign) | 3 rounds | ✅ DONE | Tab 5 |
| E26 | `closed_loop_sorting_weight` | S20 | Closed-loop (campaign) | 3 rounds | ✅ DONE | Tab 5 |
| E27 | `baseline_*` (7 scenes) | Various | None | 7 | ✅ DONE | Benign FP, ML training |

### 1.2 Pending Experiments (no data yet)

| ID | Experiment Folder | Scene | Attacker | Runs Needed | Tier | Paper Target |
|----|-------------------|-------|----------|-------------|------|--------------|
| E28 | `ablation_threshold_only_level_control` | S12 | Scripted | 1 | REQUIRED | Tab 7 |
| E29 | `ablation_invariant_only_level_control` | S12 | Scripted | 1 | REQUIRED | Tab 7 |
| E30 | `ablation_ml_only_level_control` | S12 | Scripted | 1 | REQUIRED | Tab 7 |
| E31 | `ablation_full_ensemble_level_control` | S12 | Scripted | 1 | REQUIRED | Tab 7 |
| E32 | `ablation_threshold_only_sorting_weight` | S20 | Scripted | 1 | REQUIRED | Tab 7 |
| E33 | `ablation_invariant_only_sorting_weight` | S20 | Scripted | 1 | REQUIRED | Tab 7 |
| E34 | `ablation_ml_only_sorting_weight` | S20 | Scripted | 1 | REQUIRED | Tab 7 |
| E35 | `ablation_full_ensemble_sorting_weight` | S20 | Scripted | 1 | REQUIRED | Tab 7 |

---

## 2. Exact PLC Commands (Execution Sequence)

### Phase A — No PLC Required (run now)

These are offline analysis steps. All data already exists.

```bash
# Step A1: Run full post-processing pipeline
python scripts/run_pipeline.py

# Step A2: Verify all outputs
python scripts/run_pipeline.py --validate

# Step A3: Check which pairs need additional trials
python scripts/compute_variance.py
# → Look at "Pairs with only 1 run" warnings
```

### Phase B — PLC Required: Repeated Trials

**Factory I/O setup:** Load each scene, press Play, then run command.

```bash
# ── S1: From A to B ──────────────────────────────────────────
# Load Factory I/O scene "From A to B", press Play
python -m cpsforge run attack --scene from_a_to_b --attacker llm --experiment live_llm_from_a_to_b --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene from_a_to_b --attacker llm --experiment live_llm_from_a_to_b --no-dry-run --eval-run --yes

# ── S3: Filling Tank ─────────────────────────────────────────
# Load Factory I/O scene "Filling Tank", press Play
python -m cpsforge run attack --scene filling_tank --attacker llm --experiment live_llm_filling_tank --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene filling_tank --attacker llm --experiment live_llm_filling_tank --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene filling_tank --attacker random --experiment live_random_filling_tank --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene filling_tank --attacker random --experiment live_random_filling_tank --no-dry-run --eval-run --yes

# ── S12: Level Control ───────────────────────────────────────
# Load Factory I/O scene "Level Control", press Play
python -m cpsforge run attack --scene level_control --attacker llm --experiment live_llm_level_control --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene level_control --attacker llm --experiment live_llm_level_control --no-dry-run --eval-run --yes

# ── S19: Sorting by Height ───────────────────────────────────
# Load Factory I/O scene "Sorting by Height", press Play
python -m cpsforge run attack --scene sorting_height_basic --attacker llm --experiment live_llm_sorting_height_basic --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene sorting_height_basic --attacker llm --experiment live_llm_sorting_height_basic --no-dry-run --eval-run --yes

# ── S20: Sorting by Weight ───────────────────────────────────
# Load Factory I/O scene "Sorting by Weight", press Play
python -m cpsforge run attack --scene sorting_weight --attacker llm --experiment live_llm_sorting_weight --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene sorting_weight --attacker llm --experiment live_llm_sorting_weight --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene sorting_weight --attacker random --experiment live_random_sorting_weight --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene sorting_weight --attacker random --experiment live_random_sorting_weight --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene sorting_weight --attacker scripted --experiment live_scripted_sorting_weight --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene sorting_weight --attacker scripted --experiment live_scripted_sorting_weight --no-dry-run --eval-run --yes
```

**Estimated PLC time:** ~80 min (16 runs × ~5 min each)

### Phase C — PLC Required: Campaign Repeated Trials

```bash
# ── S12: Level Control (need 2 more runs) ────────────────────
# Load "Level Control" in Factory I/O, press Play
python -m cpsforge run attack --scene level_control --attacker campaign --experiment campaign_level_control_attack --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene level_control --attacker campaign --experiment campaign_level_control_attack --no-dry-run --eval-run --yes

# ── S20: Sorting by Weight (need 1 more run) ─────────────────
# Load "Sorting by Weight" in Factory I/O, press Play
python -m cpsforge run attack --scene sorting_weight --attacker campaign --experiment campaign_sorting_weight_attack --no-dry-run --eval-run --yes
```

**Estimated PLC time:** ~24 min (3 runs × ~8 min each)

### Phase D — PLC Required: Defense Ablation

```bash
# ── S12: Level Control (4 ablation configs) ───────────────────
# Load "Level Control" in Factory I/O, press Play
python -m cpsforge run attack --scene level_control --attacker scripted --experiment ablation_threshold_only_level_control --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene level_control --attacker scripted --experiment ablation_invariant_only_level_control --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene level_control --attacker scripted --experiment ablation_ml_only_level_control --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene level_control --attacker scripted --experiment ablation_full_ensemble_level_control --no-dry-run --eval-run --yes

# ── S20: Sorting by Weight (4 ablation configs) ──────────────
# Load "Sorting by Weight" in Factory I/O, press Play
python -m cpsforge run attack --scene sorting_weight --attacker scripted --experiment ablation_threshold_only_sorting_weight --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene sorting_weight --attacker scripted --experiment ablation_invariant_only_sorting_weight --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene sorting_weight --attacker scripted --experiment ablation_ml_only_sorting_weight --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene sorting_weight --attacker scripted --experiment ablation_full_ensemble_sorting_weight --no-dry-run --eval-run --yes
```

**Estimated PLC time:** ~24 min (8 runs × ~3 min each)

### Phase E — Post-Experiment Processing

After all PLC phases complete, regenerate everything:

```bash
# Regenerate all processed data
python scripts/run_pipeline.py

# Validate all outputs
python scripts/run_pipeline.py --validate

# Check variance analysis (should show all pairs ≥3 runs)
python scripts/compute_variance.py
```

### One-Command Alternative

If you prefer an interactive guided session:

```bash
# Run all PLC experiments with scene-switch prompts
python scripts/run_journal_experiments.py --phase all

# Or phase by phase:
python scripts/run_journal_experiments.py --phase 1   # LLM repeated trials
python scripts/run_journal_experiments.py --phase 2   # Campaign repeated trials
python scripts/run_journal_experiments.py --phase 3   # Ablation study
python scripts/run_journal_experiments.py --phase P   # Post-processing
```

---

## 3. Metrics Computation Pipeline

### 3.1 Per-Run Metrics (computed by orchestrator at runtime)

| Metric | Field in metrics.json | Formula | Source |
|--------|----------------------|---------|--------|
| Action Validity Rate | `action_validity_rate` | valid_actions / total_proposed | Shield decisions |
| Execution Success Rate | `execution_success_rate` | executed / approved | PLC write outcomes |
| Attack Success Rate | `attack_success_rate` | successful / executed | Process deviation > ε |
| Process Impact Score | `process_impact_score` | mean normalized deviation | Tag traces |
| Shield Approval Rate | `shield_approval_rate` | approved / total_proposed | Shield events |
| Shield Rejection Rate | `shield_rejection_rate` | rejected / total_proposed | Shield events |
| Unsafe Block Rate | `unsafe_block_rate` | unsafe_blocked / total_proposed | Shield events |
| Detector Precision | `detector_precision` | TP / (TP + FP) | Detection × ground truth |
| Detector Recall | `detector_recall` | TP / (TP + FN) | Detection × ground truth |
| Detector F1 | `detector_f1` | 2·P·R / (P+R) | Derived |
| Detection Latency | `detection_latency_ms` | time from attack start to first detection | Timestamps |
| False Positives | `false_positives` | count of FP steps | Detection × ground truth |
| False Negatives | `false_negatives` | count of FN steps | Detection × ground truth |
| Stealth Score | `stealth_score` | 1 - recall | Derived |
| Mean Deviation | `mean_deviation` | mean |tag - baseline| / range | Tag traces |

### 3.2 Aggregation Pipeline (offline scripts)

```
Raw artifacts (data/raw/<exp>/<run>/)
    │
    ├─► aggregate_results.py ──► all_metrics.csv, per_scene_attacker_summary.csv
    │
    ├─► compute_variance.py ───► variance_summary.csv, confidence_intervals.tex
    │
    ├─► generate_tables.py ────► table1-6.tex (paper-ready LaTeX)
    │
    ├─► generate_ablation_table.py ─► table7_ablation.tex
    │
    ├─► generate_figures.py ───► fig_asr_comparison.png, fig_f1_comparison.png, ...
    │
    ├─► analyze_attack_types.py ─► type_distribution.csv, per_type_metrics.csv
    │
    ├─► evaluate_benign_fp.py ─► per_detector_fp.csv, summary.json
    │
    ├─► measure_overhead.py ───► per_step_timing.csv, summary.json
    │
    └─► compute_variance.py ───► variance_summary.csv, confidence_intervals.tex
```

### 3.3 Script → Output → Paper Target Mapping

| Script | Output File | Paper Element |
|--------|-------------|---------------|
| `aggregate_results.py` | `all_metrics.csv` | Source for all tables |
| `aggregate_results.py` | `per_scene_attacker_summary.csv` | Tables 1-3 averages |
| `aggregate_results.py` | `experiment_manifest.json` | Methodology §Evaluation Environment |
| `compute_variance.py` | `variance_summary.csv` | Tables 1-3 (mean±SD columns) |
| `compute_variance.py` | `confidence_intervals.tex` | Table 8 (variance/CI) |
| `generate_tables.py` | `table1_attack_results.tex` | Table 1 in §Evaluation |
| `generate_tables.py` | `table2_shield_results.tex` | Table 2 in §Evaluation |
| `generate_tables.py` | `table3_defender_results.tex` | Table 3 in §Evaluation |
| `generate_tables.py` | `table4_agent_results.tex` | Table 4 in §Evaluation (RQ5) |
| `generate_tables.py` | `table5_adapt_results.tex` | Table 5 in §Evaluation (RQ6) |
| `generate_tables.py` | `table6_detector_comparison.tex` | Table 6 in §Cross-Detector |
| `generate_ablation_table.py` | `table7_ablation.tex` | Table 7 in §Ablation (NEW) |
| `generate_figures.py` | `fig_asr_comparison.png` | Fig: ASR bar chart |
| `generate_figures.py` | `fig_f1_comparison.png` | Fig: F1 bar chart |
| `generate_figures.py` | `fig_dataset_composition.png` | Fig: Dataset composition |
| `analyze_attack_types.py` | `type_distribution.csv` | Appendix §Attack Types |
| `generate_timeline_figure.py` | `timeline_*.png` | Fig: Case study timeline |
| `evaluate_benign_fp.py` | `summary.json` | §Benign FP paragraph |
| `measure_overhead.py` | `summary.json` | Table: Overhead (§Framework Overhead) |

---

## 4. Experiment Tier Classification

### REQUIRED (must complete before submission)

| Experiment | Runs Needed | PLC Time | Paper Element |
|------------|-------------|----------|---------------|
| LLM batch repeated trials (5 scenes × 2 new) | 10 | ~50 min | Tab 1-3 with CIs |
| Campaign repeated trials (S12 ×2, S20 ×1) | 3 | ~24 min | Tab 5 with CIs |
| Ablation study (2 scenes × 4 configs) | 8 | ~24 min | Tab 7 (NEW) |
| Additional scripted/random for S20, S3 | 6 | ~18 min | Tab 1-3 variance |
| **Total PLC time** | **27 runs** | **~2 hours** | |

### HIGH-VALUE (strongly recommended)

| Experiment | Runs Needed | PLC Time | Paper Element |
|------------|-------------|----------|---------------|
| ML detector training on S1, S3, S19 | 3 (training) | ~15 min | Tab 6 extended |
| Detector comparison on S1, S3, S19 | 3 (replay) | ~10 min | Tab 6 extended |
| **Total PLC time** | **6 runs** | **~25 min** | |

### STRETCH (if time permits)

| Experiment | Runs Needed | PLC Time | Paper Element |
|------------|-------------|----------|---------------|
| Campaign on S1, S3, S19 | 3 | ~24 min | Tab 5 extended |
| Second LLM model | Blocked | — | Discussion only |

---

## 5. Paper Element → Data Source Mapping

Every table, figure, and quantitative claim maps to a specific data artifact:

### Tables

| Paper Label | LaTeX `\label{}` | Generated By | Data Source | Status |
|-------------|-------------------|--------------|-------------|--------|
| Table 1 | `tab:attack-results` | `generate_tables.py` | `live_scripted_*`, `live_random_*`, `live_llm_*` | ✅ HAS DATA (some pairs n=1) |
| Table 2 | `tab:shield-results` | `generate_tables.py` | Same as Table 1 | ✅ HAS DATA |
| Table 3 | `tab:defender-results` | `generate_tables.py` | Same as Table 1 | ✅ HAS DATA |
| Table 4 | `tab:agent-results` | `generate_tables.py` | `agent_*` | ✅ HAS DATA |
| Table 5 | `tab:adapt-results` | `generate_tables.py` | `adapt_*`, `closed_loop_*`, `campaign_*` | ✅ HAS DATA |
| Table 6 | `tab:detector-comparison` | `run_detector_comparison.py` | `data/processed/detector_comparison/` | ✅ HAS DATA (2 scenes) |
| Table 7 | `tab:ablation` | `generate_ablation_table.py` | `ablation_*` | ❌ PENDING (needs PLC Phase D) |
| Table 8 | `tab:variance` | `compute_variance.py` | All `live_*` and `campaign_*` | ⚠️ PARTIAL (8/17 pairs have ≥2 runs) |
| Table 9 | `tab:overhead` | `measure_overhead.py` | `data/processed/overhead/summary.json` | ✅ HAS DATA |
| Comp. table | `tab:comparison` | Manual | Literature | ✅ DONE |

### Figures

| Paper Label | LaTeX `\label{}` | Generated By | Data Source | Status |
|-------------|-------------------|--------------|-------------|--------|
| Dataset composition | `fig:dataset` | TikZ in eval.tex | `experiment_manifest.json` | ✅ DONE |
| ASR comparison | `fig:asr-comparison` | `generate_figures.py` or TikZ | `per_scene_attacker_summary.csv` | ✅ DONE |
| F1 comparison | `fig:detector-f1` | `generate_figures.py` or TikZ | Same | ✅ DONE |
| Cross-detector | `fig:detector-comparison` | TikZ in eval.tex | `detector_comparison/` | ✅ DONE (2 scenes) |
| Adaptation line | `fig:adaptation` | `generate_figures.py` | `adapt_*` metrics | ✅ DONE |
| Timeline case study | `fig:timeline` | `generate_timeline_figure.py` | Best `live_scripted_level_control` run | ✅ DONE |
| Ablation bar | `fig:ablation` | `generate_figures.py` (after data) | `ablation_*` metrics | ❌ PENDING |
| Overhead boxplot | `fig:overhead` | `measure_overhead.py` | `overhead/per_step_timing.csv` | ✅ DONE |

### Quantitative Claims in Text

| Claim | Paper Location | Data Source | Script |
|-------|---------------|-------------|--------|
| "88 runs, 10,794 steps, 171 attacks" | Abstract, §Evaluation Env | `experiment_manifest.json` | `aggregate_results.py` |
| "FP rate = 0.0001" | §Benign FP | `benign_fp/summary.json` | `evaluate_benign_fp.py` |
| "1.9ms mean overhead" | §Framework Overhead | `overhead/summary.json` | `measure_overhead.py` |
| "actuator_override 119, setpoint_shift 31, seq_perturb 21" | §Evaluation Env | `attack_analysis/summary.json` | `analyze_attack_types.py` |
| "F1 improved from 0.65 to 0.78" | §RQ6 Adaptation | `adapt_*` metrics.json | Direct from runs |
| "95-98% shield approval in agent mode" | §RQ5 Agent Mode | `agent_*` metrics.json | Direct from runs |

---

## 6. Config Files Created for Pending Experiments

### Ablation Configs (8 files)

| Config File | Scene | Defenders |
|-------------|-------|-----------|
| `configs/experiments/ablation_threshold_only_level_control.yaml` | S12 | threshold |
| `configs/experiments/ablation_invariant_only_level_control.yaml` | S12 | invariant |
| `configs/experiments/ablation_ml_only_level_control.yaml` | S12 | ocsvm + iforest |
| `configs/experiments/ablation_full_ensemble_level_control.yaml` | S12 | threshold + invariant + ocsvm + iforest + cusum |
| `configs/experiments/ablation_threshold_only_sorting_weight.yaml` | S20 | threshold |
| `configs/experiments/ablation_invariant_only_sorting_weight.yaml` | S20 | invariant |
| `configs/experiments/ablation_ml_only_sorting_weight.yaml` | S20 | ocsvm + iforest |
| `configs/experiments/ablation_full_ensemble_sorting_weight.yaml` | S20 | threshold + invariant + ocsvm + iforest + cusum |

All configs use `scripted` attacker, `live_writes_enabled: true`, `eval_run: true`, `max_steps: 150`.

---

## 7. New Scripts Created

| Script | Purpose | Input | Output |
|--------|---------|-------|--------|
| `scripts/run_journal_experiments.py` | Master PLC experiment runner with phases | Interactive + configs | Run artifacts + manifest |
| `scripts/run_pipeline.py` | Offline post-processing pipeline | `data/raw/` | `data/processed/` |
| `scripts/generate_ablation_table.py` | Table 7: ablation results | `ablation_*/metrics.json` | `table7_ablation.tex` |
| `scripts/compute_variance.py` | Table 8: variance/CIs | All `live_*/metrics.json` | `variance_summary.csv`, `confidence_intervals.tex` |

---

## 8. Execution Sequence Summary

```
┌─────────────────────────────────────────────────────────────────┐
│ Phase A: Offline (no PLC)                                       │
│   python scripts/run_pipeline.py                                │
│   python scripts/run_pipeline.py --validate                     │
│   python scripts/compute_variance.py                            │
│   → Identifies which experiments need additional runs            │
├─────────────────────────────────────────────────────────────────┤
│ Phase B: Repeated LLM/batch trials       (~80 min PLC)          │
│   python scripts/run_journal_experiments.py --phase 1            │
│   → Fills Tables 1-3 variance columns                           │
├─────────────────────────────────────────────────────────────────┤
│ Phase C: Campaign repeated trials        (~24 min PLC)          │
│   python scripts/run_journal_experiments.py --phase 2            │
│   → Fills Table 5 variance                                      │
├─────────────────────────────────────────────────────────────────┤
│ Phase D: Defense ablation                (~24 min PLC)          │
│   python scripts/run_journal_experiments.py --phase 3            │
│   → Populates Table 7                                           │
├─────────────────────────────────────────────────────────────────┤
│ Phase E: Regenerate everything                                   │
│   python scripts/run_pipeline.py                                │
│   python scripts/compute_variance.py                            │
│   → All tables/figures updated with new data                    │
├─────────────────────────────────────────────────────────────────┤
│ Phase F: Update paper                                           │
│   Replace hand-typed table values with \input{} generated .tex  │
│   Add Table 7 (ablation) subsection                             │
│   Add Table 8 (variance) or integrate CIs into Tables 1-3      │
│   Verify all \ref{} and \cite{} resolve                         │
└─────────────────────────────────────────────────────────────────┘
```

---

## 9. Validation Checklist

After all experiments and processing, verify:

```bash
# 1. All pipeline outputs exist
python scripts/run_pipeline.py --validate

# 2. All experiment pairs have ≥3 runs
python scripts/compute_variance.py
# Check: "Pairs with only 1 run" should be empty

# 3. Ablation table populated
cat data/processed/paper_tables/table7_ablation.tex
# Check: no "---" placeholder values

# 4. Total run count updated
python -c "import json; m=json.load(open('data/processed/aggregate_results/experiment_manifest.json')); print(f'Total runs: {m[\"total_runs\"]}, Total steps: {m[\"total_steps\"]}')"

# 5. All LaTeX tables generated
ls data/processed/paper_tables/*.tex
# Expect: table1 through table7, plus confidence_intervals.tex
```
