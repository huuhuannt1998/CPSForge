# CPSForge — Repository and Manuscript Audit

**Date:** 2026-03-24 (last updated)
**Target venue:** Computers & Security (Elsevier)
**Current paper format:** `elsarticle` (migrated from IEEEtran)

---

## 1. Current Implemented Capabilities

| Capability | Status | Evidence |
|------------|--------|----------|
| Real PLC communication (Siemens S7-1200, 192.168.0.1) | ✅ Complete | `cpsforge/plc/client.py`, probe logs in `data/probe_s*.txt` |
| Scene abstraction (22 Factory I/O scenes configured) | ✅ Complete | `configs/scenes/*.yaml`, 6 scene implementations |
| 5 scenes evaluated on live PLC | ✅ Complete | S1, S3, S12, S19, S20 — all with artifacts |
| Scripted attacker | ✅ Complete | `cpsforge/attacks/scripted.py`, 5-scene runs |
| Random attacker | ✅ Complete | `cpsforge/attacks/random_attacker.py`, 5-scene runs |
| LLM batch attacker (Qwen2-7B-Instruct) | ✅ Complete | `cpsforge/attacks/llm/`, 5-scene runs |
| Campaign attacker (4-phase LLM) | ✅ Complete | `cpsforge/attacks/campaign_attacker.py`, 2-scene runs |
| LLM agent mode (multi-process) | ✅ Complete | `cpsforge/agents/`, 5-scene runs |
| Safety shield | ✅ Complete | `cpsforge/shield/engine.py`, decisions logged per run |
| Threshold detector | ✅ Complete | `cpsforge/defenders/threshold.py` |
| Invariant detector | ✅ Complete | `cpsforge/defenders/invariant.py` |
| CUSUM detector | ✅ Complete | `cpsforge/defenders/cusum_detector.py` |
| OCSVM detector | ✅ Complete | `cpsforge/defenders/ocsvm_detector.py` |
| Isolation Forest detector | ✅ Complete | `cpsforge/defenders/iforest_detector.py` |
| LSTM autoencoder detector | ✅ Complete | `cpsforge/defenders/lstm_ad_detector.py` |
| Sequence model (IsolationForest rolling-window) | ✅ Complete | `cpsforge/defenders/sequence_model.py` |
| Hard-case extraction & bank | ✅ Complete | `cpsforge/adaptation/bank.py` |
| Closed-loop adaptation | ✅ Complete | 2 scenes × 3 rounds with campaign attacker |
| Cross-detector comparison | ✅ Complete | `scripts/run_detector_comparison.py`, results in `data/processed/detector_comparison/` |
| Trace logging (Parquet + JSON) | ✅ Complete | Every run folder has full artifacts |
| CLI | ✅ Complete | `cpsforge/cli/` — run, scene, plc, report commands |
| Analysis pipeline | ✅ Complete | `cpsforge/analysis/tables.py`, `scripts/aggregate_results.py`, `scripts/generate_tables.py`, `scripts/generate_figures.py` |

---

## 2. Experiment Data Inventory (Updated)

**Totals:** 88 runs, 46 experiment configurations, 10,794 time-series steps, 171 attack actions, 60 eval-flagged runs.

### 2.1 Primary Evaluation Runs (Batch Mode)

| Scene | Scripted | Random | LLM Batch | Campaign | Runs |
|-------|----------|--------|-----------|----------|------|
| From A to B (S1) | 5 runs | 3 runs | 1 run | — | 9 |
| Filling Tank (S3) | 2 runs | 1 run | 1 run | — | 4 |
| Level Control (S12) | 2 runs | 2 runs | 1 run | 1 run | 6 |
| Sorting Height (S19) | 4 runs | 2 runs | 1 run | — | 7 |
| Sorting Weight (S20) | 1 run | 1 run | 1 run | 2 runs | 5 |

### 2.2 Agent Mode Runs

| Scene | Runs | Notes |
|-------|------|-------|
| From A to B | 1+ | eval subfolder |
| Filling Tank | 1 | |
| Level Control | 8 | eval subfolder with 8 sub-runs |
| Sorting Height | 1 | eval subfolder |
| Sorting Weight | 1 | |

### 2.3 Adaptation Runs

| Scene | Attacker | Rounds | Notes |
|-------|----------|--------|-------|
| Level Control | Scripted/Random | 3 | No retraining needed (stable F1) |
| Sorting Weight | Scripted/Random | 3 | No retraining needed (stable F1) |
| Level Control | Campaign | 3 | 2 retraining cycles, F1: 0.65→0.78 |
| Sorting Weight | Campaign | 3 | Stable, no retraining triggered |

### 2.4 Benign Baselines

| Scene | Baseline Runs |
|-------|---------------|
| Level Control | 2 |
| Filling Tank | 1 |
| From A to B | 3 |
| Sorting Height | 2 |
| Sorting Weight | 1 (sorting_weight_baseline) |
| Assembler | 1 |
| Queue Items | 1 |

### 2.5 Trained ML Models

- `data/models/level_control/` — OCSVM, IForest, LSTM-AD, sequence model
- `data/models/sorting_weight/` — OCSVM, IForest, LSTM-AD, sequence model
- `data/models/closed_loop_level_control/` — Round 1 and 2 retrained models

---

## 3. Gaps and Weak Spots

### 3.1 CRITICAL — Must Fix for Submission

| # | Gap | Impact | Effort |
|---|-----|--------|--------|
| G1 | ~~Paper format is `IEEEtran`~~ | ✅ RESOLVED — migrated to `elsarticle` | — |
| G2 | **No repeated trials for most LLM/campaign runs** — single run per scene for LLM batch, single run for campaign | Reviewers will question statistical reliability | High (needs PLC + LM Studio) |
| G3 | ~~No benign-only FP evaluation~~ | ✅ RESOLVED — `scripts/evaluate_benign_fp.py` run: FP rate = 0.0001 across 6 scenes, 87 evaluations | — |
| G4 | ~~No overhead/latency characterization~~ | ✅ RESOLVED — `scripts/measure_overhead.py` run: mean total 1.9ms/step (P50: 0.3ms) across 1100 steps | — |
| G5 | **No ablation study** — no systematic comparison of defense-off / shield-only / detector-only / combined | Weak contribution evidence | High (needs PLC) |
| G6 | ~~appendix.tex is from the wrong paper~~ | ✅ RESOLVED — replaced with CPSForge-specific appendix (tag specs, shield rules, attack types, detector configs, prompts, artifacts) | — |
| G7 | ~~No aggregate metrics script~~ | ✅ RESOLVED — `scripts/aggregate_results.py`, `scripts/generate_tables.py`, `scripts/generate_figures.py` all tested and producing outputs | — |
| G8 | ~~No RESULTS_SUMMARY.md~~ | ✅ RESOLVED — created with full traceable metrics from 88 runs | — |
| G9 | **No confidence intervals or standard deviations reported** | Statistical rigor concern | Medium (needs repeated trials) |
| G10 | **RQ2 still says "four attacker types" in description** but body mentions 5 | Minor inconsistency | Low |

### 3.2 IMPORTANT — Strongly Should Do

| # | Gap | Impact | Effort |
|---|-----|--------|--------|
| G11 | **Only 1 LLM model tested (Qwen2-7B)** — no cross-model comparison | Generalizability concern (acknowledged in discussion) | High (needs models) |
| G12 | **Campaign attacker only on 2 scenes** | Limited coverage | Medium (needs PLC) |
| G13 | ~~No per-attack-type breakdown~~ | ✅ RESOLVED — `scripts/analyze_attack_types.py`: 171 actions, 3 types (actuator_override 69.6%, setpoint_shift 18.1%, sequence_perturbation 12.3%) | — |
| G14 | **Detector comparison only on 2 scenes** (Level Control, Sorting Weight) | Limited cross-scene insight | High (needs training + PLC) |
| G15 | ~~No case study or timeline figure~~ | ✅ RESOLVED — `scripts/generate_timeline_figure.py`: 5 timeline figures generated (all scenes) | — |
| G16 | ~~No experiment manifest~~ | ✅ RESOLVED — `data/processed/aggregate_results/experiment_manifest.json` maps all 88 runs | — |

### 3.3 OPTIONAL — Nice to Have

| # | Gap | Impact | Effort |
|---|-----|--------|--------|
| G17 | Cross-model comparison (GPT-4, Claude, Llama, etc.) | Stronger generalizability | Very High |
| G18 | Additional Factory I/O scenes beyond 5 | Broader evaluation | High |
| G19 | Formal safety proof or model checking of shield rules | Theoretical depth | Very High |
| G20 | Online adaptation (adapt during a run, not between rounds) | Advanced feature | High |

---

## 4. Paper–Code Mismatches

| Section | Claim | Reality |
|---------|-------|---------|
| Abstract | "five attacker variants" | ✅ Correct (scripted, random, LLM batch, campaign, agent) |
| Abstract | "88 runs, 10,794 steps" | ✅ Verified — 88 runs from 46 experiments, 60 eval-flagged |
| Evaluation | Tables use manually entered numbers | ✅ Script-generated tables available (`scripts/generate_tables.py`) |
| Evaluation RQ2 | "four attacker types" in description text | ❌ Should say "five" (campaign added to variants list but not to RQ2 text) |
| Appendix | Entire appendix is from wrong paper | ✅ Replaced with CPSForge appendix |
| Document class | `elsarticle` preprint | ✅ Migrated with CRediT, keywords, line numbers |

---

## 5. Blockers

| Blocker | Impact | Resolution |
|---------|--------|------------|
| PLC hardware availability | Cannot run new experiments without live PLC + Factory I/O | Schedule lab access |
| LM Studio availability | Cannot run new LLM-based experiments | Ensure local server running |
| Factory I/O scene switching | Manual process — must switch scene in Factory I/O UI between experiment groups | Plan scene batching |
| No second LLM model configured | Cannot do cross-model comparison | Install additional model in LM Studio or use API |

---

## 6. Prioritized Task List

### Tier 1: Must-Do for Submission

1. ~~**Migrate paper to `elsarticle` format**~~ ✅ Done
2. ~~**Create aggregate results script**~~ ✅ Done (`scripts/aggregate_results.py`)
3. ~~**Create experiment manifest**~~ ✅ Done (`data/processed/aggregate_results/experiment_manifest.json`)
4. ~~**Write proper CPSForge appendix**~~ ✅ Done (tag specs, shield rules, attack types, detector configs, LLM prompt, artifacts)
5. ~~**Run benign-only false positive evaluation**~~ ✅ Done (FP rate = 0.0001, 87 evaluations)
6. ~~**Add overhead/latency measurements**~~ ✅ Done (mean 1.9ms/step, 1100 steps measured)
7. **Run repeated trials** for LLM batch and campaign attackers (min 3 runs each) — NEEDS PLC
8. **Compute and report standard deviations** across repeated trials — NEEDS repeated runs
9. ~~**Generate all tables from scripts**~~ ✅ Done (`scripts/generate_tables.py`, 6 tables + `scripts/generate_figures.py`, 6 figures)
10. **Fix RQ2 description** ("five attacker types") — TODO
11. ~~**Create RESULTS_SUMMARY.md and EXPERIMENT_PLAN.md**~~ ✅ Done
12. **Add defense ablation experiment** (no defense / shield-only / detector-only / combined) — NEEDS PLC
13. ~~**Add per-attack-type breakdown analysis**~~ ✅ Done (`scripts/analyze_attack_types.py`)
14. **Create reproducibility section** in paper — TODO

### Tier 2: Strongly Should Do

15. ~~Create a real-run timeline figure~~ ✅ Done (5 scenes, `scripts/generate_timeline_figure.py`)
16. Extend detector comparison to all 5 scenes (or at least 3) — NEEDS PLC
17. Add campaign attacks to remaining scenes (S1, S3, S19) — NEEDS PLC
18. Strengthen limitations section with honest scope assessment — TODO
19. ~~Add a system overhead table to the paper~~ ✅ Data ready (need to add to evaluation.tex)

### Tier 3: Optional Extras

20. Cross-model comparison with a second LLM
21. Formal safety analysis of shield rules
22. Interactive dashboard screenshots
