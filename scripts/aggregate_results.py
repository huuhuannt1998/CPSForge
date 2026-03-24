#!/usr/bin/env python
"""
Aggregate all experiment results into a single summary dataset.

Reads every metrics.json from data/raw/*/* and produces:
  - data/processed/aggregate_results/all_metrics.csv
  - data/processed/aggregate_results/per_scene_attacker_summary.csv
  - data/processed/aggregate_results/experiment_manifest.json
  - data/processed/aggregate_results/variance_report.csv

Usage:
    python scripts/aggregate_results.py
    python scripts/aggregate_results.py --data-dir data --output-dir data/processed/aggregate_results
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import numpy as np
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Canonical mapping from experiment folder prefixes to attacker types
ATTACKER_MAP = {
    "live_scripted_": "scripted",
    "live_random_": "random",
    "live_llm_": "llm_batch",
    "campaign_": "campaign",
    "agent_": "agent",
    "adapt_": "adaptation",
    "closed_loop_": "adaptation",
    "baseline_": "baseline",
    "benign_fp_": "benign_fp",
    "ablation_": "ablation",
    "scripted_": "scripted",
    "random_": "random",
    "llm_": "llm_batch",
    "overhead_": "overhead",
}

SCENE_MAP = {
    "level_control": "Level Control",
    "sorting_weight": "Sorting by Weight",
    "from_a_to_b": "From A to B",
    "filling_tank": "Filling Tank",
    "sorting_height_basic": "Sorting by Height",
    "sorting_height": "Sorting by Height",
    "tank_control": "Tank Control",
}

# Metrics columns for the summary
METRIC_COLS = [
    "action_validity_rate",
    "execution_success_rate",
    "attack_success_rate",
    "process_impact_score",
    "shield_approval_rate",
    "shield_rejection_rate",
    "unsafe_block_rate",
    "detector_precision",
    "detector_recall",
    "detector_f1",
    "detection_latency_ms",
    "false_positives",
    "false_negatives",
    "total_steps",
    "total_attacks",
]


def classify_experiment(folder_name: str) -> tuple[str, str]:
    """Return (attacker_type, scene_name) from an experiment folder name."""
    for prefix, attacker in ATTACKER_MAP.items():
        if folder_name.startswith(prefix):
            scene_part = folder_name[len(prefix):]
            # Remove trailing _attack, _eval, etc.
            for suffix in ("_attack", "_eval", "_debug"):
                if scene_part.endswith(suffix):
                    scene_part = scene_part[:-len(suffix)]
            return attacker, scene_part
    return "unknown", folder_name


def load_all_metrics(raw_dir: Path) -> list[dict]:
    """Load every metrics.json from all runs."""
    rows = []
    if not raw_dir.exists():
        logger.warning("raw_dir does not exist: %s", raw_dir)
        return rows

    for exp_dir in sorted(raw_dir.iterdir()):
        if not exp_dir.is_dir():
            continue
        attacker_type, scene_part = classify_experiment(exp_dir.name)
        for run_dir in sorted(exp_dir.iterdir()):
            if not run_dir.is_dir():
                continue
            mpath = run_dir / "metrics.json"
            if not mpath.exists():
                continue
            try:
                with mpath.open() as fh:
                    m = json.load(fh)
                m["experiment_folder"] = exp_dir.name
                m["run_folder"] = run_dir.name
                m["attacker_type"] = attacker_type
                m["scene_canonical"] = SCENE_MAP.get(
                    m.get("scene_name", scene_part), scene_part
                )
                m["data_path"] = str(run_dir.relative_to(raw_dir.parent))
                rows.append(m)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Failed to load %s: %s", mpath, e)
    return rows


def compute_variance_report(df: pd.DataFrame) -> pd.DataFrame:
    """Compute mean ± SD for each scene × attacker combination with ≥2 runs."""
    groups = df.groupby(["scene_canonical", "attacker_type"])
    summary_rows = []
    for (scene, attacker), group in groups:
        n = len(group)
        row = {"scene": scene, "attacker": attacker, "n_runs": n}
        for col in METRIC_COLS:
            if col in group.columns:
                vals = group[col].dropna()
                row[f"{col}_mean"] = vals.mean() if len(vals) > 0 else np.nan
                row[f"{col}_std"] = vals.std() if len(vals) > 1 else np.nan
                row[f"{col}_min"] = vals.min() if len(vals) > 0 else np.nan
                row[f"{col}_max"] = vals.max() if len(vals) > 0 else np.nan
        summary_rows.append(row)
    return pd.DataFrame(summary_rows)


def build_manifest(df: pd.DataFrame) -> dict:
    """Build an experiment manifest linking run IDs to experiment types."""
    manifest = {
        "generated_at": pd.Timestamp.utcnow().isoformat() + "Z",
        "total_runs": len(df),
        "total_steps": int(df["total_steps"].sum()) if "total_steps" in df.columns else 0,
        "scenes": sorted(df["scene_canonical"].unique().tolist()),
        "attacker_types": sorted(df["attacker_type"].unique().tolist()),
        "runs": [],
    }
    for _, row in df.iterrows():
        manifest["runs"].append({
            "run_id": row.get("run_id", row.get("run_folder", "")),
            "experiment": row.get("experiment_folder", ""),
            "scene": row.get("scene_canonical", ""),
            "attacker": row.get("attacker_type", ""),
            "steps": int(row.get("total_steps", 0)),
            "eval_run": bool(row.get("eval_run", False)),
            "data_path": row.get("data_path", ""),
        })
    return manifest


def main():
    parser = argparse.ArgumentParser(description="Aggregate CPSForge experiment results")
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args()

    raw_dir = args.data_dir / "raw"
    out_dir = args.output_dir or (args.data_dir / "processed" / "aggregate_results")
    out_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Loading metrics from %s", raw_dir)
    rows = load_all_metrics(raw_dir)
    if not rows:
        logger.error("No metrics found. Exiting.")
        sys.exit(1)

    df = pd.DataFrame(rows)
    logger.info("Loaded %d runs from %d experiments", len(df), df["experiment_folder"].nunique())

    # Save full metrics table
    csv_path = out_dir / "all_metrics.csv"
    df.to_csv(csv_path, index=False)
    logger.info("Saved all_metrics.csv (%d rows)", len(df))

    # Per-scene × attacker summary with variance
    variance_df = compute_variance_report(df)
    variance_path = out_dir / "per_scene_attacker_summary.csv"
    variance_df.to_csv(variance_path, index=False)
    logger.info("Saved per_scene_attacker_summary.csv (%d rows)", len(variance_df))

    # Filter to eval runs only for the paper-facing summary
    eval_df = df[df.get("eval_run", pd.Series(dtype=bool)) == True]
    if len(eval_df) > 0:
        eval_variance = compute_variance_report(eval_df)
        eval_variance.to_csv(out_dir / "eval_summary.csv", index=False)
        logger.info("Saved eval_summary.csv (%d rows, eval_run=True only)", len(eval_variance))

    # Experiment manifest
    manifest = build_manifest(df)
    manifest_path = out_dir / "experiment_manifest.json"
    with manifest_path.open("w") as fh:
        json.dump(manifest, fh, indent=2, default=str)
    logger.info("Saved experiment_manifest.json (%d runs, %d total steps)",
                manifest["total_runs"], manifest["total_steps"])

    # Print quick summary
    print("\n" + "=" * 60)
    print("AGGREGATE RESULTS SUMMARY")
    print("=" * 60)
    print(f"Total runs:       {len(df)}")
    print(f"Eval runs:        {len(eval_df)}")
    print(f"Total steps:      {manifest['total_steps']}")
    print(f"Scenes:           {', '.join(manifest['scenes'])}")
    print(f"Attacker types:   {', '.join(manifest['attacker_types'])}")
    print()

    # Per-scene × attacker run counts
    pivot = df.groupby(["scene_canonical", "attacker_type"]).size().unstack(fill_value=0)
    print("Run counts (scene × attacker):")
    print(pivot.to_string())
    print()

    # Variance report for key metrics
    if len(variance_df) > 0:
        print("Variance report (mean ± std where n ≥ 2):")
        for _, row in variance_df.iterrows():
            if row["n_runs"] >= 2:
                asr_m = row.get("attack_success_rate_mean", np.nan)
                asr_s = row.get("attack_success_rate_std", np.nan)
                f1_m = row.get("detector_f1_mean", np.nan)
                f1_s = row.get("detector_f1_std", np.nan)
                print(f"  {row['scene']:20s} {row['attacker']:10s}  "
                      f"n={row['n_runs']:2.0f}  "
                      f"ASR={asr_m:.3f}±{asr_s:.3f}  "
                      f"F1={f1_m:.3f}±{f1_s:.3f}")

    print(f"\nOutputs written to: {out_dir}")


if __name__ == "__main__":
    main()
