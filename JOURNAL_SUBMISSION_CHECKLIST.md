# CPSForge — Journal Submission Checklist (Computers & Security)

**Target:** Computers & Security (Elsevier)
**Date:** 2026-03-24

Legend: ✅ Done | 🔧 In Progress | ❌ Not Started | 🚫 Blocked

---

## A. Manuscript Format and Structure

| # | Item | Status | Notes |
|---|------|--------|-------|
| A1 | Migrate to `elsarticle` document class | ✅ | `elsarticle[preprint,12pt]` with frontmatter |
| A2 | Update page layout, margins, font per Elsevier template | ✅ | Handled by elsarticle class |
| A3 | Add Elsevier author metadata (email, ORCID, CRediT) | ✅ | `\author[uncc]`, `\ead{}`, `\cortext`, CRediT section |
| A4 | Add keywords (Elsevier format) | ✅ | `\begin{keyword}...\sep...\end{keyword}` |
| A5 | Add highlights (3–5 bullet points, required by C&S) | ✅ | 5 highlights in `\begin{highlights}` block |
| A6 | Add graphical abstract (optional but recommended) | ❌ | Optional — deprioritized |
| A7 | Check reference format (Elsevier numbered style) | ✅ | `elsarticle-num` bibliography style |
| A8 | Remove `\balance` (IEEE-specific) | ✅ | Removed along with `\usepackage{times}` |
| A9 | Replace wrong-paper appendix with CPSForge appendix | ✅ | 7-section appendix (tags, shield rules, attacks, etc.) |
| A10 | Add data availability statement | ✅ | In main.tex before bibliography |
| A11 | Add declaration of competing interests | ✅ | In main.tex before bibliography |
| A12 | Verify all figures render in single-column (C&S is single-col) | 🔧 Partial | TikZ figures use `\columnwidth`; needs manual check |

---

## B. Experimental Evidence — Core Results

| # | Item | Status | Data Source |
|---|------|--------|-------------|
| B1 | Scripted attacker × 5 scenes | ✅ | `data/raw/live_scripted_*` |
| B2 | Random attacker × 5 scenes | ✅ | `data/raw/live_random_*` |
| B3 | LLM batch attacker × 5 scenes | ✅ | `data/raw/live_llm_*` |
| B4 | Campaign attacker × 2 scenes | ✅ | `data/raw/campaign_*` |
| B5 | Agent mode × 5 scenes | ✅ | `data/raw/agent_*` |
| B6 | Closed-loop adaptation (campaign) × 2 scenes | ✅ | `data/raw/closed_loop_*` |
| B7 | Closed-loop adaptation (scripted/random) × 2 scenes | ✅ | `data/raw/adapt_*` |
| B8 | Cross-detector comparison × 2 scenes | ✅ | `data/processed/detector_comparison/` |
| B9 | Benign baselines × 5 scenes | ✅ | `data/raw/baseline_*` |

---

## C. Statistical Rigor

| # | Item | Status | Notes |
|---|------|--------|-------|
| C1 | Repeated trials (≥3) for scripted attacks | 🔧 Partial | S1: 5 runs, S19: 4, S12: 2, S3: 2, S20: 1 |
| C2 | Repeated trials (≥3) for random attacks | 🔧 Partial | S1: 3 runs, S12: 2, S19: 2, others: 1 |
| C3 | Repeated trials (≥3) for LLM batch attacks | ❌ | All scenes: 1 run each |
| C4 | Repeated trials (≥3) for campaign attacks | ❌ | S20: 2 runs, S12: 1 run |
| C5 | Standard deviations / confidence intervals reported | ❌ | No variance analysis in paper |
| C6 | Per-scene sample sizes documented | 🔧 Partial | Run counts known but not in paper |
| C7 | Aggregate metrics with variance from repeated trials | ❌ | Paper reports single-run numbers |

---

## D. Missing Evaluations

| # | Item | Status | Priority |
|---|------|--------|----------|
| D1 | Benign-only false positive evaluation (detectors on baseline traces) | ✅ | 87 evaluations, 6 scenes, FP=0.0001 |
| D2 | Defense ablation (no-defense / shield-only / detector-only / combined) | ❌ | Configs created but need PLC runs |
| D3 | Overhead/latency characterization (shield time, detector time, cycle impact) | ✅ | 1100 steps, 8 scenes, 1.9ms mean |
| D4 | Per-attack-type breakdown (sensor_spoof, actuator_override, setpoint_shift) | ✅ | 171 actions: actuator_override 119, setpoint_shift 31, seq_perturb 21 |
| D5 | Cross-detector comparison extended to ≥3 scenes | ❌ | Should-do |
| D6 | Campaign attacker on additional scenes (S1, S3, S19) | ❌ | Should-do |
| D7 | Second LLM model comparison | ❌ | Optional |

---

## E. Reproducibility Artifacts

| # | Item | Status | Notes |
|---|------|--------|-------|
| E1 | All configs versioned in `configs/` | ✅ | |
| E2 | Aggregate results script | ✅ | `scripts/aggregate_results.py` — 88 runs aggregated |
| E3 | Table/figure generation scripts | ✅ | `generate_tables.py` (6 tables), `generate_figures.py` (6 figs + 5 timelines) |
| E4 | Experiment manifest (run IDs → paper tables) | ✅ | `data/processed/aggregate_results/experiment_manifest.json` |
| E5 | RESULTS_SUMMARY.md | ✅ | Full dataset overview, 6 tables, gaps |
| E6 | EXPERIMENT_PLAN.md | ✅ | 3-tier plan (Tier 1 done, Tier 2/3 PLC-dependent) |
| E7 | Raw logs preserved | ✅ | All in `data/raw/` |
| E8 | README with reproduction instructions | ✅ | Exists but needs journal-specific update |
| E9 | Data availability statement in paper | ✅ | In main.tex |

---

## F. Paper Content Quality

| # | Item | Status | Notes |
|---|------|--------|-------|
| F1 | Abstract updated with final numbers | ✅ | 88 runs, 10,794 steps, 171 attacks |
| F2 | Introduction contributions match evaluation | ✅ | |
| F3 | Threat model precise and complete | ✅ | |
| F4 | System design covers all components | ✅ | Campaign attacker added |
| F5 | Implementation covers all components | ✅ | Campaign attacker subsection added |
| F6 | Methodology lists all variants | ✅ | 5 attackers, 4 defender configs |
| F7 | Evaluation RQ2 description consistency | ✅ | Fixed to list all 5 variants including campaign |
| F8 | All tables traceable to scripts | ❌ | Currently manually typed |
| F9 | Discussion updated with campaign findings | ✅ | |
| F10 | Limitations section honest and complete | ✅ | Added single-PLC, ML portability, overhead/FP strengths |
| F11 | Related work table accurate | ✅ | |
| F12 | Conclusion matches evaluation | ✅ | |
| F13 | Case study or representative timeline figure | ❌ | Missing |
| F14 | System overhead table | ✅ | Table in evaluation.tex (1.9ms mean, 5 components) |
| F15 | Defense ablation table | ❌ | Needs PLC runs with ablation configs |
| F16 | Benign FP paragraph | ✅ | In evaluation.tex (FP rate = 0.0001) |
| F17 | Journal-quality writing tone throughout | 🔧 Partial | Conference-style; needs expansion |
| F18 | Proper Elsevier section numbering | ✅ | Handled by elsarticle class |
| F19 | Expand paper length to journal standard (15–25 pages) | ❌ | Currently ~12 pages IEEE format |

---

## G. Figures and Tables

| # | Item | Status | Notes |
|---|------|--------|-------|
| G1 | Fig 1: System architecture | ✅ | TikZ diagram |
| G2 | Fig 2: Adaptation loop | ✅ | TikZ diagram |
| G3 | Fig 3: Agent mode sequence | ✅ | TikZ diagram |
| G4 | Fig 4: Shield decision flow | ✅ | TikZ diagram |
| G5 | Fig 5: Experiment pipeline | ✅ | TikZ diagram |
| G6 | Fig 6: ASR comparison bar chart | ✅ | pgfplots |
| G7 | Fig 7: Detector F1 comparison | ✅ | pgfplots |
| G8 | Fig 8: Cross-detector F1 comparison | ✅ | pgfplots |
| G9 | Fig: Dataset composition stacked bar | ✅ | pgfplots |
| G10 | Table 1: Attack results | ✅ | Manually typed — needs script |
| G11 | Table 2: Shield results | ✅ | Manually typed — needs script |
| G12 | Table 3: Defender results | ✅ | Manually typed — needs script |
| G13 | Table 4: Agent results | ✅ | Manually typed — needs script |
| G14 | Table 5: Adaptation results | ✅ | Manually typed — needs script |
| G15 | Table 6: Cross-detector comparison | ✅ | Manually typed — needs script |
| G16 | Table: Related work comparison | ✅ | |
| G17 | **NEW: Table: System overhead** | ✅ | Table~\ref{tab:overhead} in evaluation.tex |
| G18 | **NEW: Table: Defense ablation** | ❌ | Needs PLC runs |
| G19 | **NEW: Benign FP rates paragraph** | ✅ | Section~\ref{sec:benign-fp} in evaluation.tex |
| G20 | **NEW: Fig: Timeline case study** | ❌ | Should-do |
| G21 | **NEW: Table: Per-attack-type breakdown** | ❌ | Should-do |
| G22 | Resize all TikZ figures for single-column (Elsevier) | ❌ | |

---

## H. Final Pre-Submission

| # | Item | Status |
|---|------|--------|
| H1 | All `\cite{}` resolve | ❌ (not checked) |
| H2 | All `\ref{}` resolve | ❌ (not checked) |
| H3 | No TODO/FIXME in paper | ❌ (not checked) |
| H4 | Spell check | ❌ |
| H5 | Grammar check | ❌ |
| H6 | Page count within C&S limits | ❌ |
| H7 | Supplementary materials prepared | ❌ |
| H8 | Cover letter drafted | ❌ |
| H9 | Suggested reviewers identified | ❌ |

---

## Summary

**Completion estimate:**
- Core experiments: ~85% complete (main gap: repeated trials, ablation PLC runs)
- Paper content: ~90% complete (main gap: ablation table, expanded writing, timeline case study)
- Reproducibility: ~95% complete (all scripts, manifest, RESULTS_SUMMARY.md done)
- Format/submission: ~85% complete (elsarticle done, highlights done; need graphical abstract, final checks)

**Critical path:** Ablation PLC runs → Repeated trials → Ablation table → Timeline figure → Writing polish → Final review
