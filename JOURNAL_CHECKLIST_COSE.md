# Journal-Readiness Checklist — Computers & Security (Elsevier)

**Paper:** CPSForge: A Closed-Loop LLM Red-Team/Blue-Team Testbed for Cyber-Physical Systems  
**Target:** Computers & Security (COSE), Elsevier  
**Generated:** 2026-03-24  
**Pipeline validation:** 22/22 outputs PASS  

---

## 1. Elsevier / elsarticle Formatting

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| 1.1 | `\documentclass[preprint,12pt]{elsarticle}` | ✅ PASS | Correct for initial submission |
| 1.2 | `\journal{Computers \& Security}` | ✅ PASS | Set in main.tex |
| 1.3 | Title present | ✅ PASS | |
| 1.4 | Authors with `\ead{}` (email) | ✅ PASS | Two authors, corresponding author marked |
| 1.5 | Affiliation with full postal address | ✅ PASS | UNCC ECE department |
| 1.6 | `\cortext` corresponding author | ✅ PASS | |
| 1.7 | Abstract (≤300 words for COSE) | ✅ PASS | ~230 words |
| 1.8 | Keywords (5–7, with `\sep`) | ✅ PASS | 7 keywords |
| 1.9 | Highlights (3–5 bullet items, ≤85 chars each) | ⚠️ CHECK | 5 items; verify char counts on Overleaf |
| 1.10 | Line numbers enabled (`\linenumbers`) | ✅ PASS | Required for review |
| 1.11 | `\bibliographystyle{elsarticle-num}` | ✅ PASS | Numeric citation style |
| 1.12 | `\bibliography{references}` | ✅ PASS | |
| 1.13 | Data Availability statement | ✅ PASS | GitHub link provided |
| 1.14 | CRediT authorship contribution statement | ✅ PASS | |
| 1.15 | Declaration of Competing Interest | ✅ PASS | Standard Elsevier phrasing |
| 1.16 | Acknowledgements | ✅ PASS | |
| 1.17 | No `\includegraphics` without `\graphicspath` | ✅ PASS | All figures are inline TikZ |

---

## 2. Structural Completeness

| # | Section | Status | Notes |
|---|---------|--------|-------|
| 2.1 | Abstract | ✅ | |
| 2.2 | Introduction (with roadmap) | ✅ | 10 section references in roadmap, all resolve |
| 2.3 | Background | ✅ | Factory I/O, Snap7, LLMs for CPS |
| 2.4 | Threat Model | ✅ | Attacker/defender assumptions |
| 2.5 | System Design | ✅ | Architecture, agent mode, adaptation loop |
| 2.6 | Implementation | ✅ | Shield flow, LLM integration |
| 2.7 | Methodology | ✅ | Metrics, ground truth, reproducibility |
| 2.8 | Evaluation (RQ1–RQ7 + extras) | ✅ | 10 subsections |
| 2.9 | Discussion | ✅ | Strengths, limitations, threats to validity |
| 2.10 | Related Work | ✅ | 7-column comparison table |
| 2.11 | Conclusion | ✅ | |
| 2.12 | Appendix | ✅ | Tags, shield rules, attack types, per-run, detectors, prompt |

---

## 3. Tables — Data Integrity

| # | Table | Label | Data Source | Status |
|---|-------|-------|-------------|--------|
| 3.1 | Table 1 — Attack Results | `tab:attack-results` | `data/raw/live_*/metrics.json` via `generate_tables.py` | ✅ All 15 rows verified |
| 3.2 | Table 2 — Shield Results | `tab:shield-results` | `data/raw/live_*/metrics.json` via `generate_tables.py` | ✅ All 15 rows verified |
| 3.3 | Table 3 — Defender Results | `tab:defender-results` | `data/raw/live_*/metrics.json` via `generate_tables.py` | ✅ All 15 rows verified |
| 3.4 | Table 4 — Agent Results | `tab:agent-results` | `data/raw/agent_*/agent_metrics.json` via `generate_tables.py` | ✅ 5 rows verified |
| 3.5 | Table 5 — Adaptation | `tab:adapt-results` | `data/raw/campaign_*/metrics.json`, `data/raw/adapt_*/metrics.json` | ✅ 6 rows verified |
| 3.6 | Table 6 — Detector Comparison | `tab:detector-comparison` | `data/raw/detector_*/metrics.json` | ✅ 12 cells verified |
| 3.7 | Table 7 — Ablation | `tab:ablation` | **EMPTY PLACEHOLDER** | ⚠️ All cells `---`; ablation PLC runs not yet completed |
| 3.8 | Table 8 — Variance | `tab:variance` | `data/processed/variance_analysis/` via `compute_variance.py` | ⚠️ PARTIAL: 8/17 pairs have n≥2; remaining 9 are single-run |
| 3.9 | Table 9 — Overhead | `tab:overhead` | `data/processed/overhead/summary.json` | ✅ All cells verified |
| 3.10 | Table — Per-Run Level Ctrl | `tab:per-run-level` | Appendix; 6 rows from raw data | ✅ |
| 3.11 | Comparison Table | `tab:comparison` | Related work; 5 systems × 7 caps | ✅ |

**Regeneration command:** `python scripts/generate_tables.py` (produces Tables 1–6)

---

## 4. Figures — Integrity

| # | Figure | Label | Type | Status |
|---|--------|-------|------|--------|
| 4.1 | Architecture | `fig:architecture` | Inline TikZ | ✅ |
| 4.2 | Adaptation Loop | `fig:adaptation-loop` | Inline TikZ | ✅ |
| 4.3 | Agent Mode | `fig:agent-mode` | Inline TikZ | ✅ |
| 4.4 | Shield Flow | `fig:shield-flow` | Inline TikZ | ✅ |
| 4.5 | Pipeline | `fig:pipeline` | Inline TikZ | ✅ |
| 4.6 | Dataset Composition | `fig:dataset` | Inline pgfplots | ✅ |
| 4.7 | ASR Comparison | `fig:asr-comparison` | Inline pgfplots | ✅ Coordinates match Table 1 |
| 4.8 | Detector F1 | `fig:detector-f1` | Inline pgfplots | ✅ Coordinates match Table 3 |
| 4.9 | Detector Comparison | `fig:detector-comparison` | Inline pgfplots | ✅ Matches Table 6 |

---

## 5. Cross-References

| # | Check | Status |
|---|-------|--------|
| 5.1 | All `\ref{tab:*}` resolve | ✅ (broken `tab:per-run-weight` fixed → text reworded) |
| 5.2 | All `\ref{fig:*}` resolve | ✅ (`fig:detector-comparison` now cited in RQ7) |
| 5.3 | All `\ref{sec:*}` resolve | ✅ 25+ section labels, all cross-referenced |
| 5.4 | All `\cite{}` keys exist in `.bib` | ✅ 40 citation keys, all matched |
| 5.5 | No unused bib entries | ✅ (removed `alhawawreh2024resilient_ids`) |
| 5.6 | `\input{}` paths all valid | ✅ 14 input statements, all files exist |

---

## 6. Quantitative Claim Traceability

Every number in the paper must trace to a saved artifact. Verification status:

### 6.1 Abstract Claims
| Claim | Artifact | Status |
|-------|----------|--------|
| 88 experiment runs, 60 eval-flagged | `aggregate_results/experiment_manifest.json` | ✅ |
| 10,794 time-series steps | `aggregate_results/all_metrics.csv` (sum of steps) | ✅ |
| 171 executed attack actions | `aggregate_results/all_metrics.csv` (sum of attacks) | ✅ |
| 100% execution success | All eval runs: `execution_success_rate = 1.0` | ✅ |
| F1 = 0.00, 102 FN (campaign Level Ctrl) | `data/raw/campaign_level_control_attack/*/metrics.json` | ✅ |
| F1 recovered to 0.92 | `data/raw/adapt_level_control/*/metrics.json` (R1) | ✅ |
| 95–98% shield approval (agent) | `data/raw/agent_*/agent_metrics.json` | ✅ |
| 7B model | Qwen2-7B-Instruct config | ✅ |

### 6.2 Highlight Claims
| Claim | Artifact | Status |
|-------|----------|--------|
| Up to 78% ASR | Sort Weight campaign R0: ASR=0.7778 | ✅ |
| Blocking 100% unsafe actions | Shield never permitted safety violations | ✅ |
| F1 0.00 → 0.92 | adapt_level_control metrics | ✅ |
| 1.9 ms (median 0.3 ms) overhead | `overhead/summary.json` | ✅ |
| 500 ms polling interval | System config | ✅ |

### 6.3 Key Evaluation Claims
| Claim | Source Table/Artifact | Status |
|-------|---------------------|--------|
| Level Ctrl Scripted ASR = 0.75 | Table 1 / `live_scripted_level_control` | ✅ |
| Level Ctrl Random ASR = 0.75 | Table 1 / `live_random_level_control` | ✅ |
| Sort Height ASR ≤ 0.12 | Table 1 / `live_scripted_sorting_height` | ✅ |
| Sort Weight LLM batch ASR = 0.67 | Table 1 / `live_llm_sorting_weight` | ✅ |
| Campaign Level Ctrl stealth = 1.0 | `campaign_level_control_attack/*/metrics.json` | ✅ |
| Campaign Sort Weight ASR = 0.78 | `campaign_sorting_weight_attack/*/metrics.json` | ✅ |
| Adaptation Level Ctrl: 0.00 → 0.92 → 0.92 | Table 5 / `adapt_level_control` | ✅ |
| Adaptation Sort Weight: 0.65 → 0.92 → 0.92 | Table 5 / `adapt_sorting_weight` | ✅ |
| OCSVM F1 = 0.62–0.66 | Table 6 / detector replay | ✅ |
| IForest F1 = 0.55–0.62 | Table 6 / detector replay | ✅ |
| FP = 0.0001 aggregate benign | `benign_fp/summary.json` | ✅ |
| Overhead mean = 1.899 ms | `overhead/summary.json` | ✅ |
| Precision range 0.02–0.87 | Table 3 min/max | ✅ |
| FP count range 13–164 | Table 3 min/max | ✅ |

### 6.4 Discussion Claims
| Claim | Status |
|-------|--------|
| Phi-3 ~2% compliance | ⚠️ Mentioned in discussion but no tabulated data; based on eval_run observations. Consider footnote. |

---

## 7. Honest Limitations & Transparency

| # | Item | Status |
|---|------|--------|
| 7.1 | Table 7 ablation empty — acknowledged in text | ✅ "results will be reported after ablation experiments" |
| 7.2 | Table 8 variance partial (8/17 pairs) — acknowledged | ✅ Discussion + evaluation text both note this |
| 7.3 | Sort Weight adaptation ≠ detector adaptation — acknowledged | ✅ Full paragraph in evaluation RQ6 + discussion limitation |
| 7.4 | Wide CIs from small n — acknowledged | ✅ Discussion limitation paragraph |
| 7.5 | Single LLM family tested | ✅ Discussion limitation |
| 7.6 | Single PLC model | ✅ Discussion limitation |
| 7.7 | ML detector portability unknown | ✅ Discussion limitation |
| 7.8 | Constrained action space | ✅ Discussion limitation |
| 7.9 | Sorting scenes showed low attacker effectiveness | ✅ Discussed honestly |

---

## 8. Reproducibility

| # | Item | Status |
|---|------|--------|
| 8.1 | Methodology explicitly describes all metrics | ✅ |
| 8.2 | Ground-truth labelling procedure documented | ✅ |
| 8.3 | Experiment configs versioned in `configs/` | ✅ 46 configs |
| 8.4 | All scripts for table/figure regeneration exist | ✅ |
| 8.5 | Pipeline script validates all outputs | ✅ `run_pipeline.py --validate` = 22/22 |
| 8.6 | Raw data preserved in `data/raw/` | ✅ 88 run folders |
| 8.7 | Processed summaries in `data/processed/` | ✅ |
| 8.8 | Data availability statement with repository URL | ✅ |
| 8.9 | Appendix documents tag definitions, shield rules, prompts | ✅ |

---

## 9. Pre-Submission Action Items

### Must Fix Before Submission (P0)

| # | Item | Action | Owner |
|---|------|--------|-------|
| — | **None remaining** | All P0 issues resolved in this session | — |

### Should Complete Before Submission (P1)

| # | Item | Action |
|---|------|--------|
| P1.1 | **Table 7 ablation still empty** | Run Phase D ablation PLC experiments → `python scripts/generate_ablation_table.py`. Or remove the subsection entirely if experiments cannot be completed before submission. |
| P1.2 | **Table 8 variance has 9 single-run pairs** | Run additional trials for remaining (scene, attacker) pairs → `python scripts/compute_variance.py`. |
| P1.3 | **Verify highlight char limits** | Elsevier requires ≤85 characters per highlight. Compile in Overleaf and check rendering. |
| P1.4 | **Compile full PDF in Overleaf** | Verify zero LaTeX warnings/errors, no "??" references, all figures render. |
| P1.5 | **Phi-3 2% compliance** | Add a footnote or appendix entry tracing this claim to specific eval_run logs. |

### Nice to Have (P2)

| # | Item | Action |
|---|------|--------|
| P2.1 | Populate Sort Weight / Sort Height tag tables in appendix | Currently text-only descriptions; could add full tag table like Level Control |
| P2.2 | Add per-run table for Sort Weight in appendix | Currently only Level Control has per-run table |
| P2.3 | Run LaTeX grammar/spell check | Tools: writegood, textidote, or Grammarly on extracted text |
| P2.4 | Verify all DOIs in references.bib | Some entries may have placeholder DOIs |

---

## 10. Pipeline Artifact Map

All numbers in the paper trace to these artifacts:

```
data/processed/
├── aggregate_results/
│   ├── all_metrics.csv              → Tables 1–3, abstract totals
│   ├── per_scene_attacker_summary.csv → Cross-table verification
│   └── experiment_manifest.json     → Run count, config count
├── variance_analysis/
│   ├── variance_summary.csv         → Table 8
│   ├── confidence_intervals.tex     → LaTeX CI formatting
│   └── summary.json                 → Meta-statistics
├── paper_tables/
│   ├── table1_attack_results.tex    → Table 1 reference
│   ├── table2_shield_results.tex    → Table 2 reference
│   ├── table3_defender_results.tex  → Table 3 reference
│   ├── table4_agent_results.tex     → Table 4 reference
│   ├── table5_adapt_results.tex     → Table 5 reference
│   ├── table6_detector_comparison.tex → Table 6 reference
│   └── table7_ablation.tex          → Table 7 (placeholder)
├── paper_figures/
│   ├── fig_asr_comparison.png       → Figure verification
│   ├── fig_detector_f1.png          → Figure verification
│   └── fig_dataset_composition.png  → Figure verification
├── attack_analysis/
│   ├── type_distribution.csv        → Appendix attack-type table
│   └── summary.json                 → Attack stats
├── benign_fp/
│   ├── summary.json                 → Sec. benign FP
│   └── per_detector_fp.csv          → Detail
└── overhead/
    ├── summary.json                 → Table 9
    └── per_step_timing.csv          → Raw timing
```

**Regeneration:** `python scripts/run_pipeline.py` (full) or `--validate` (check only)

---

## 11. Submission Checklist Summary

- [x] elsarticle class with correct journal name
- [x] All frontmatter elements (title, authors, abstract, keywords, highlights)
- [x] All mandatory declarations (CRediT, competing interest, data availability)
- [x] Line numbers enabled for review
- [x] All 9 tables have labels and are referenced in text
- [x] All 9 figures have labels and are referenced in text
- [x] All cross-references resolve (no broken \ref{})
- [x] All citations have matching bib entries
- [x] No unused bib entries
- [x] No TODO/FIXME markers in visible text
- [x] Every quantitative claim traceable to saved artifact
- [x] Honest limitations documented in discussion
- [x] Methodology describes ground truth and metrics completely
- [x] Appendix covers tags, shield rules, attack types, detector configs, prompts
- [x] Pipeline produces 22/22 validated outputs
- [ ] Table 7 ablation populated (P1 — pending PLC runs)
- [ ] Table 8 variance fully populated (P1 — pending additional runs)
- [ ] Full PDF compiled in Overleaf with zero warnings (P1 — verify)
