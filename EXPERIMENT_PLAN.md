# CPSForge — Experiment Plan for Computers & Security Submission

**Date:** 2026-03-24
**Hardware:** Siemens S7-1200 PLC @ 192.168.0.1 + Factory I/O + LM Studio (Qwen2-7B-Instruct)

---

## Prerequisites

- PLC powered on and reachable: `python -m cpsforge plc probe`
- LM Studio running with Qwen2-7B-Instruct loaded at http://127.0.0.1:1234/v1
- Factory I/O installed with all 5 scenes available
- Python 3.11+ with `pip install -e .` completed

---

## Experiment Structure

All results stored under:
```
data/raw/<experiment_name>/<run_id>/
    trace.parquet
    attacks.json
    detections.json
    shield_events.json
    hard_cases.json
    metrics.json
    metadata.json
```

---

## Tier 1: Required Experiments (Must-Do)

### 1.1 Repeated Trials for LLM Batch Attacker (5 scenes × 3 runs = 15 runs)

**Purpose:** Establish statistical reliability for LLM attacker results.

**Scenes:** S1 (from_a_to_b), S3 (filling_tank), S12 (level_control), S19 (sorting_height_basic), S20 (sorting_weight)

**Commands (per scene, repeat 3 times):**
```bash
# Factory I/O: load scene S12, start simulation
python -m cpsforge run attack --scene level_control --attacker llm --experiment live_llm_level_control --no-dry-run --eval-run --yes

# Repeat for S1, S3, S19, S20 (switch Factory I/O scene between groups)
python -m cpsforge run attack --scene from_a_to_b --attacker llm --experiment live_llm_from_a_to_b --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene filling_tank --attacker llm --experiment live_llm_filling_tank --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene sorting_height_basic --attacker llm --experiment live_llm_sorting_height_basic --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene sorting_weight --attacker llm --experiment live_llm_sorting_weight --no-dry-run --eval-run --yes
```

**Expected runtime:** ~5 min per run × 15 runs = ~75 min + scene switching time

**Metrics:** ASR, impact, precision, recall, F1, FP, FN, detection latency
**Variance analysis:** Mean ± SD across 3 runs per scene

---

### 1.2 Repeated Trials for Campaign Attacker (2 scenes × 2 additional runs = 4 runs)

**Purpose:** Get ≥3 runs for campaign results on both scenes.

**Commands:**
```bash
# S12 (need 2 more runs to have ≥3 total)
python -m cpsforge run attack --scene level_control --attacker campaign --experiment campaign_level_control_attack --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene level_control --attacker campaign --experiment campaign_level_control_attack --no-dry-run --eval-run --yes

# S20 (need 1 more run to have ≥3 total)
python -m cpsforge run attack --scene sorting_weight --attacker campaign --experiment campaign_sorting_weight_attack --no-dry-run --eval-run --yes
```

**Expected runtime:** ~8 min per run × 4 runs = ~32 min

---

### 1.3 Benign-Only False Positive Evaluation (5 scenes × 1 long run = 5 runs)

**Purpose:** Measure detector false positive rate during normal (no-attack) operation.

**Method:** Run baseline (no attacker) for 200+ steps, then replay through all detectors.

**Commands:**
```bash
# Collect extended baselines (200 steps each)
python -m cpsforge run baseline --scene level_control --max-steps 200 --experiment benign_fp_level_control --eval-run --yes
python -m cpsforge run baseline --scene sorting_weight --max-steps 200 --experiment benign_fp_sorting_weight --eval-run --yes
python -m cpsforge run baseline --scene from_a_to_b --max-steps 200 --experiment benign_fp_from_a_to_b --eval-run --yes
python -m cpsforge run baseline --scene filling_tank --max-steps 200 --experiment benign_fp_filling_tank --eval-run --yes
python -m cpsforge run baseline --scene sorting_height_basic --max-steps 200 --experiment benign_fp_sorting_height_basic --eval-run --yes

# Then run detector evaluation on baselines (offline replay)
python scripts/evaluate_benign_fp.py --scene level_control
python scripts/evaluate_benign_fp.py --scene sorting_weight
# ... etc.
```

**Expected runtime:** ~3 min per scene × 5 = ~15 min collection + ~5 min replay

**Metrics:** FP count, FP rate, per-detector breakdown during benign operation

---

### 1.4 Defense Ablation Study (2 scenes × 4 configs × 1 run = 8 runs)

**Purpose:** Quantify contribution of each defense component.

**Configurations:**
1. **No defense** — attacker runs, no shield, no detectors (measure raw attack success)
2. **Shield only** — shield active, no detectors (measure how many attacks are blocked before execution)
3. **Detector only** — no shield, detectors active (measure detection without prevention)
4. **Combined** — shield + detectors (current full configuration)

**Scenes:** Level Control (S12), Sorting Weight (S20)
**Attacker:** Scripted (deterministic, reproducible)

**Commands:**
```bash
# Config variants needed: ablation_no_defense_*.yaml, ablation_shield_only_*.yaml, etc.
python -m cpsforge run attack --scene level_control --attacker scripted --experiment ablation_no_defense_level_control --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene level_control --attacker scripted --experiment ablation_shield_only_level_control --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene level_control --attacker scripted --experiment ablation_detector_only_level_control --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene level_control --attacker scripted --experiment ablation_combined_level_control --no-dry-run --eval-run --yes
# Repeat for sorting_weight
```

**Expected runtime:** ~3 min per run × 8 = ~24 min

**Metrics:** ASR comparison across configs, shield block rate, detector recall, combined effectiveness

---

### 1.5 Overhead / Latency Measurements (5 scenes × 1 run each)

**Purpose:** Characterize system overhead — shield decision time, detector inference time, PLC polling cycle stability.

**Method:** Instrument the orchestrator to record per-step timing:
- `t_poll`: time to read all tags from PLC
- `t_shield`: time for shield.evaluate() call
- `t_detect`: time for all detectors to process one snapshot
- `t_write`: time to execute approved PLC write
- `t_cycle`: total step time

**Commands:**
```bash
# Run instrumented experiments
python scripts/measure_overhead.py --scene level_control
python scripts/measure_overhead.py --scene sorting_weight
python scripts/measure_overhead.py --scene from_a_to_b
python scripts/measure_overhead.py --scene filling_tank
python scripts/measure_overhead.py --scene sorting_height_basic
```

**Expected runtime:** ~3 min per scene × 5 = ~15 min

**Metrics:** Mean, median, P95, P99 for each timing component; total cycle time distribution

---

## Tier 2: High-Value Extensions

### 2.1 Per-Attack-Type Breakdown (offline analysis)

**Purpose:** Analyze which attack types (sensor_spoof, actuator_override, setpoint_shift, etc.) succeed vs fail.

**Method:** Post-processing of existing attacks.json from all completed runs.

**Command:**
```bash
python scripts/analyze_attack_types.py
```

**No PLC needed** — pure data analysis.

---

### 2.2 Case Study Timeline Figure (offline analysis)

**Purpose:** Create a publication-quality timeline showing sensor values, attack injection, detection events, and shield decisions for one representative run.

**Method:** Select a run with clear attack signature (e.g., `live_scripted_level_control` run).

**Command:**
```bash
python scripts/generate_timeline_figure.py --run data/raw/live_scripted_level_control/<latest_run_id>
```

**No PLC needed.**

---

### 2.3 Extended Detector Comparison to Additional Scenes

**Purpose:** Expand cross-detector comparison from 2 scenes to 3–5 scenes.

**Requires:** Trained ML models for additional scenes (need baseline traces).

**Commands:**
```bash
# Train ML detectors on additional scenes
python scripts/train_ml_detectors.py --scene filling_tank
python scripts/train_ml_detectors.py --scene from_a_to_b

# Run detector comparison
python scripts/run_detector_comparison.py --scene filling_tank
python scripts/run_detector_comparison.py --scene from_a_to_b
```

---

## Tier 3: Stretch Experiments

### 3.1 Cross-Model LLM Comparison

**Blocked by:** Need a second model available in LM Studio or via API.
**If available:** Run LLM batch attacker with second model on 2–3 scenes.

### 3.2 Campaign Attacker on Additional Scenes

**Commands (if time permits):**
```bash
python -m cpsforge run attack --scene from_a_to_b --attacker campaign --experiment campaign_from_a_to_b_attack --no-dry-run --eval-run --yes
python -m cpsforge run attack --scene sorting_height_basic --attacker campaign --experiment campaign_sorting_height_basic_attack --no-dry-run --eval-run --yes
```

---

## Execution Order

**Phase A (no PLC needed — can do immediately):**
1. Create aggregate results script
2. Create table/figure generation scripts
3. Create overhead measurement instrumentation script
4. Create benign FP evaluation script
5. Create ablation config files
6. Create per-attack-type analysis script
7. Create timeline figure script
8. Run per-attack-type breakdown on existing data
9. Generate timeline figure from existing data
10. Create experiment manifest

**Phase B (needs PLC + Factory I/O):**
1. Run benign-only FP evaluation (5 scenes, ~15 min)
2. Run overhead measurements (5 scenes, ~15 min)
3. Run defense ablation (2 scenes × 4 configs, ~24 min)
4. Run LLM batch repeated trials (5 scenes × 2 new runs, ~50 min)
5. Run campaign repeated trials (3 new runs, ~24 min)

**Phase C (post-experiment):**
1. Aggregate all results
2. Generate all tables and figures from scripts
3. Compute standard deviations and confidence intervals
4. Update paper with new results
5. Create RESULTS_SUMMARY.md
6. Migrate paper to elsarticle format

**Total estimated PLC time:** ~2–3 hours of lab access
**Total analysis/scripting time:** Substantial but no hardware dependency

---

## Storage Layout for New Results

```
data/raw/
    benign_fp_level_control/<run_id>/          # Tier 1.3
    benign_fp_sorting_weight/<run_id>/
    benign_fp_from_a_to_b/<run_id>/
    benign_fp_filling_tank/<run_id>/
    benign_fp_sorting_height_basic/<run_id>/
    ablation_no_defense_level_control/<run_id>/ # Tier 1.4
    ablation_shield_only_level_control/<run_id>/
    ablation_detector_only_level_control/<run_id>/
    ablation_combined_level_control/<run_id>/
    ablation_*_sorting_weight/<run_id>/
    overhead_level_control/<run_id>/            # Tier 1.5
    overhead_sorting_weight/<run_id>/
    overhead_from_a_to_b/<run_id>/
    overhead_filling_tank/<run_id>/
    overhead_sorting_height_basic/<run_id>/
    live_llm_*/<additional_run_ids>/            # Tier 1.1 repeated
    campaign_*/<additional_run_ids>/            # Tier 1.2 repeated

data/processed/
    aggregate_results/
        all_metrics.csv                         # Every run's metrics in one table
        per_scene_summary.csv                   # Mean ± SD per scene × attacker
        per_attacker_summary.csv
        attack_type_breakdown.csv
        benign_fp_summary.csv
        ablation_summary.csv
        overhead_summary.csv
        detector_comparison_extended.csv
    figures/
        fig_asr_comparison.pdf
        fig_detector_f1.pdf
        fig_timeline_case_study.pdf
        fig_overhead_distribution.pdf
        fig_ablation_comparison.pdf
    tables/
        tab_attack_results.tex                  # LaTeX table source
        tab_shield_results.tex
        tab_defender_results.tex
        tab_agent_results.tex
        tab_adapt_results.tex
        tab_detector_comparison.tex
        tab_overhead.tex
        tab_ablation.tex
        tab_benign_fp.tex
```
