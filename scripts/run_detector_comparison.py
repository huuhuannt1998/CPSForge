#!/usr/bin/env python
"""
Run all detectors on all live attack traces and produce comparison results.

This produces the main detector comparison data for the paper (Table 3).

Usage:
    python scripts/run_detector_comparison.py
    python scripts/run_detector_comparison.py --scene level_control
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Attack experiments to evaluate (live PLC traces with actual attacks)
ATTACK_EXPERIMENTS = {
    "level_control": [
        "live_scripted_level_control",
        "live_random_level_control",
        "live_llm_level_control",
        "agent_level_control_eval",
    ],
    "sorting_weight": [
        "live_scripted_sorting_weight",
        "live_random_sorting_weight",
        "live_llm_sorting_weight",
        "agent_sorting_weight",
    ],
}

# All detector configs to test per scene
DETECTORS_PER_SCENE = {
    "level_control": [
        "threshold_level_control",
        "invariant_level_control",
        "cusum_level_control",
        "ocsvm_level_control",
        "iforest_level_control",
        "lstm_ad_level_control",
        "sequence_model_level_control",
    ],
    "sorting_weight": [
        "threshold_sorting_weight",
        "invariant_sorting_weight",
        "cusum_sorting_weight",
        "ocsvm_sorting_weight",
        "iforest_sorting_weight",
        "lstm_ad_sorting_weight",
        "sequence_model_sorting_weight",
    ],
}


def run_comparison_for_scene(scene: str, data_dir: Path = Path("data")) -> pd.DataFrame:
    """Run all detectors on all attack experiments for one scene."""
    from cpsforge.analysis.detector_comparison import (
        DetectorComparison,
        compare_detectors_across_runs,
    )
    from cpsforge.core.config import ConfigLoader

    loader = ConfigLoader()
    raw_dir = data_dir / "raw"

    all_dfs = []
    experiments = ATTACK_EXPERIMENTS.get(scene, [])
    detectors = DETECTORS_PER_SCENE.get(scene, [])

    # Filter to existing detector configs
    valid_detectors = []
    for det in detectors:
        try:
            loader.load_defender(det)
            valid_detectors.append(det)
        except FileNotFoundError:
            logger.warning("Detector config not found: %s -- skipping", det)

    logger.info("Scene %s: %d detectors, %d experiments", scene, len(valid_detectors), len(experiments))

    for exp_name in experiments:
        exp_dir = raw_dir / exp_name
        if not exp_dir.exists():
            logger.warning("Experiment dir not found: %s -- skipping", exp_dir)
            continue

        run_dirs = sorted(
            d for d in exp_dir.iterdir()
            if d.is_dir() and (d / "trace.parquet").exists()
        )

        if not run_dirs:
            logger.warning("No trace files in %s -- skipping", exp_dir)
            continue

        logger.info("  Experiment %s: %d runs", exp_name, len(run_dirs))

        for run_dir in run_dirs:
            logger.info("    Run: %s", run_dir.name)
            comp = DetectorComparison(run_dir, valid_detectors, loader)
            try:
                results = comp.run()
                if results:
                    df = comp.to_dataframe()
                    df["experiment"] = exp_name
                    # Determine attacker type from experiment name
                    if "scripted" in exp_name:
                        df["attacker"] = "scripted"
                    elif "random" in exp_name:
                        df["attacker"] = "random"
                    elif "llm" in exp_name:
                        df["attacker"] = "llm"
                    elif "agent" in exp_name:
                        df["attacker"] = "agent"
                    else:
                        df["attacker"] = "unknown"
                    all_dfs.append(df)
            except Exception as exc:
                logger.error("    Failed: %s", exc)

    if all_dfs:
        return pd.concat(all_dfs, ignore_index=True)
    return pd.DataFrame()


def main():
    parser = argparse.ArgumentParser(description="Run detector comparison on live attack traces")
    parser.add_argument("--scene", default="all", help="Scene name or 'all'")
    parser.add_argument("--data-dir", default="data", help="Data directory")
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    scenes = list(ATTACK_EXPERIMENTS.keys()) if args.scene == "all" else [args.scene]

    all_results = []
    for scene in scenes:
        logger.info("=" * 60)
        logger.info("Running detector comparison for: %s", scene)
        logger.info("=" * 60)
        df = run_comparison_for_scene(scene, data_dir)
        if not df.empty:
            all_results.append(df)
            logger.info("  %d result rows for %s", len(df), scene)

    if all_results:
        combined = pd.concat(all_results, ignore_index=True)

        # Save detailed results
        output_dir = data_dir / "processed" / "detector_comparison"
        output_dir.mkdir(parents=True, exist_ok=True)

        combined.to_csv(output_dir / "all_results.csv", index=False)
        logger.info("Full results saved: %s", output_dir / "all_results.csv")

        # Create summary table (mean ± std per detector per scene)
        numeric_cols = [c for c in combined.columns if combined[c].dtype in ('float64', 'int64', 'float32')]
        group_cols = ["detector_name", "detector_type", "scene_name"]
        valid_group = [c for c in group_cols if c in combined.columns]
        valid_numeric = [c for c in numeric_cols if c not in group_cols]

        if valid_group and valid_numeric:
            summary = combined.groupby(valid_group)[valid_numeric].agg(["mean", "std"]).round(4)
            summary.columns = [f"{c}_{s}" for c, s in summary.columns]
            summary = summary.reset_index()
            summary.to_csv(output_dir / "summary.csv", index=False)
            logger.info("Summary saved: %s", output_dir / "summary.csv")

            # Print summary table
            print("\n" + "=" * 80)
            print("DETECTOR COMPARISON SUMMARY")
            print("=" * 80)
            key_cols = ["detector_name"]
            metric_cols = [c for c in summary.columns if any(m in c for m in ["precision", "recall", "f1", "latency"])]
            if metric_cols:
                display_cols = key_cols + [c for c in metric_cols if "mean" in c]
                valid_display = [c for c in display_cols if c in summary.columns]
                print(summary[valid_display].to_string(index=False))
    else:
        logger.warning("No results produced.")


if __name__ == "__main__":
    main()
