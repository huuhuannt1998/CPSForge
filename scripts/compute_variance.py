#!/usr/bin/env python3
"""
Compute variance analysis and confidence intervals from repeated experiment runs.

For each (scene, attacker) pair with ≥2 runs, computes mean, SD, 95% CI,
and min/max for all key metrics. Produces a CSV and a LaTeX table snippet
suitable for inclusion in the paper.

Output:
  data/processed/variance_analysis/
    variance_summary.csv
    confidence_intervals.tex
    summary.json

Usage:
    python scripts/compute_variance.py
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

RAW_DIR = Path("data/raw")
OUTPUT_DIR = Path("data/processed/variance_analysis")

METRICS = [
    "attack_success_rate",
    "process_impact_score",
    "shield_approval_rate",
    "detector_precision",
    "detector_recall",
    "detector_f1",
    "detection_latency_ms",
    "false_positives",
]

EXPERIMENT_MAP = {
    "live_scripted_from_a_to_b":           ("From A to B",  "Scripted"),
    "live_random_from_a_to_b":             ("From A to B",  "Random"),
    "live_llm_from_a_to_b":                ("From A to B",  "LLM batch"),
    "live_scripted_filling_tank":          ("Filling Tank",  "Scripted"),
    "live_random_filling_tank":            ("Filling Tank",  "Random"),
    "live_llm_filling_tank":               ("Filling Tank",  "LLM batch"),
    "live_scripted_level_control":         ("Level Ctrl",    "Scripted"),
    "live_random_level_control":           ("Level Ctrl",    "Random"),
    "live_llm_level_control":              ("Level Ctrl",    "LLM batch"),
    "live_scripted_sorting_height_basic":  ("Sort Height",   "Scripted"),
    "live_random_sorting_height_basic":    ("Sort Height",   "Random"),
    "live_llm_sorting_height_basic":       ("Sort Height",   "LLM batch"),
    "live_scripted_sorting_weight":        ("Sort Weight",   "Scripted"),
    "live_random_sorting_weight":          ("Sort Weight",   "Random"),
    "live_llm_sorting_weight":             ("Sort Weight",   "LLM batch"),
    "campaign_level_control_attack":       ("Level Ctrl",    "Campaign"),
    "campaign_sorting_weight_attack":      ("Sort Weight",   "Campaign"),
}


def load_all_metrics() -> pd.DataFrame:
    """Load metrics from all mapped experiments."""
    rows = []
    for exp_folder, (scene, attacker) in EXPERIMENT_MAP.items():
        exp_dir = RAW_DIR / exp_folder
        if not exp_dir.exists():
            continue
        for run_dir in sorted(exp_dir.iterdir()):
            if not run_dir.is_dir():
                continue
            mp = run_dir / "metrics.json"
            if not mp.exists():
                continue
            with mp.open() as f:
                m = json.load(f)
            m["scene_display"] = scene
            m["attacker_display"] = attacker
            m["experiment"] = exp_folder
            m["run_dir"] = str(run_dir.name)
            rows.append(m)
    return pd.DataFrame(rows) if rows else pd.DataFrame()


def compute_variance(df: pd.DataFrame) -> pd.DataFrame:
    """Compute per-(scene, attacker) variance statistics."""
    results = []
    for (scene, attacker), group in df.groupby(["scene_display", "attacker_display"]):
        n = len(group)
        row = {"scene": scene, "attacker": attacker, "n_runs": n}
        # Metrics bounded to [0, 1] — clamp CI bounds for these only
        rate_metrics = {
            "attack_success_rate", "process_impact_score", "shield_approval_rate",
            "detector_precision", "detector_recall", "detector_f1",
        }
        for metric in METRICS:
            vals = group[metric].dropna().values
            if len(vals) == 0:
                continue
            row[f"{metric}_mean"] = float(np.mean(vals))
            row[f"{metric}_std"] = float(np.std(vals, ddof=1)) if len(vals) >= 2 else 0.0
            row[f"{metric}_min"] = float(np.min(vals))
            row[f"{metric}_max"] = float(np.max(vals))
            if len(vals) >= 2:
                se = stats.sem(vals)
                if se > 0:
                    ci = stats.t.interval(0.95, df=len(vals) - 1, loc=np.mean(vals), scale=se)
                    lo, hi = float(ci[0]), float(ci[1])
                    if metric in rate_metrics:
                        lo, hi = max(0.0, lo), min(1.0, hi)
                    row[f"{metric}_ci_lo"] = lo
                    row[f"{metric}_ci_hi"] = hi
                else:
                    row[f"{metric}_ci_lo"] = float(np.mean(vals))
                    row[f"{metric}_ci_hi"] = float(np.mean(vals))
            else:
                row[f"{metric}_ci_lo"] = float(np.mean(vals))
                row[f"{metric}_ci_hi"] = float(np.mean(vals))
        results.append(row)
    return pd.DataFrame(results)


def generate_ci_table(var_df: pd.DataFrame) -> str:
    """Generate a LaTeX table showing ASR and F1 with 95% CIs."""
    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Attack success rate and detector F1 with 95\% confidence intervals "
        r"from repeated trials. $n$ = number of runs.}",
        r"\label{tab:variance}",
        r"\small",
        r"\begin{tabular}{llccc}",
        r"\toprule",
        r"\textbf{Scene} & \textbf{Attacker} & $n$ & \textbf{ASR (95\% CI)} & \textbf{F1 (95\% CI)} \\",
        r"\midrule",
    ]

    for _, row in var_df.sort_values(["scene", "attacker"]).iterrows():
        n = int(row["n_runs"])
        # ASR
        asr_mean = row.get("attack_success_rate_mean", None)
        asr_ci_lo = row.get("attack_success_rate_ci_lo", None)
        asr_ci_hi = row.get("attack_success_rate_ci_hi", None)
        if asr_mean is not None and n >= 2:
            asr_str = f"{asr_mean:.2f} [{asr_ci_lo:.2f}, {asr_ci_hi:.2f}]"
        elif asr_mean is not None:
            asr_str = f"{asr_mean:.2f}"
        else:
            asr_str = "---"

        # F1
        f1_mean = row.get("detector_f1_mean", None)
        f1_ci_lo = row.get("detector_f1_ci_lo", None)
        f1_ci_hi = row.get("detector_f1_ci_hi", None)
        if f1_mean is not None and n >= 2:
            f1_str = f"{f1_mean:.2f} [{f1_ci_lo:.2f}, {f1_ci_hi:.2f}]"
        elif f1_mean is not None:
            f1_str = f"{f1_mean:.2f}"
        else:
            f1_str = "---"

        lines.append(f"{row['scene']} & {row['attacker']} & {n} & {asr_str} & {f1_str} \\\\")

    lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ])
    return "\n".join(lines)


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    df = load_all_metrics()
    if df.empty:
        logger.error("No metrics found in %s", RAW_DIR)
        return

    logger.info("Loaded %d runs from %d experiments", len(df), df["experiment"].nunique())

    var_df = compute_variance(df)
    var_df.to_csv(OUTPUT_DIR / "variance_summary.csv", index=False)
    logger.info("Variance summary: %s", OUTPUT_DIR / "variance_summary.csv")

    # Pairs with ≥2 runs
    multi_run = var_df[var_df["n_runs"] >= 2]
    logger.info("Pairs with ≥2 runs: %d / %d", len(multi_run), len(var_df))

    single_run = var_df[var_df["n_runs"] < 2]
    if not single_run.empty:
        logger.warning("Pairs with only 1 run (need more trials):")
        for _, row in single_run.iterrows():
            logger.warning("  %s × %s  (n=%d)", row["scene"], row["attacker"], int(row["n_runs"]))

    # LaTeX table
    ci_tex = generate_ci_table(var_df)
    (OUTPUT_DIR / "confidence_intervals.tex").write_text(ci_tex)
    logger.info("CI table: %s", OUTPUT_DIR / "confidence_intervals.tex")

    # Summary JSON
    summary = {
        "total_runs": len(df),
        "total_pairs": len(var_df),
        "pairs_with_ci": len(multi_run),
        "pairs_single_run": len(single_run),
        "needs_more_trials": [
            {"scene": r["scene"], "attacker": r["attacker"], "n": int(r["n_runs"])}
            for _, r in single_run.iterrows()
        ],
    }
    (OUTPUT_DIR / "summary.json").write_text(json.dumps(summary, indent=2))
    logger.info("Summary: %s", OUTPUT_DIR / "summary.json")


if __name__ == "__main__":
    main()
