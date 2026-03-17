#!/usr/bin/env python3
"""
CPSForge Ground Truth Dataset Generator
==========================================
Generate labeled ground truth datasets from existing experiment runs.

This script:
  1. Collects all run artifacts from data/raw/
  2. Extracts per-step labels (normal / attack-active)
  3. Produces consolidated CSVs for each scene
  4. Generates aggregate metrics for the paper

Output:
  data/processed/ground_truth/
    <scene>/
      normal_baseline.csv         — steps from baseline runs (no attack)
      attack_traces.csv           — steps from attack runs (labeled)
      combined_labeled.csv        — all steps with ground truth labels
    aggregate_metrics.csv         — summary across all runs
    run_index.csv                 — index of all processed runs

Usage:
  python scripts/generate_ground_truth.py
  python scripts/generate_ground_truth.py --scene level_control
"""

from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DATA_RAW = Path("data/raw")
DATA_OUT = Path("data/processed/ground_truth")

SCENES = ["from_a_to_b", "level_control", "sorting_height_basic"]


def load_run_metadata(run_dir: Path) -> dict[str, Any] | None:
    """Load metadata.json from a run directory."""
    meta_path = run_dir / "metadata.json"
    if not meta_path.exists():
        return None
    return json.loads(meta_path.read_text())


def load_run_metrics(run_dir: Path) -> dict[str, Any] | None:
    """Load metrics.json or agent_metrics.json from a run directory."""
    for name in ("metrics.json", "agent_metrics.json"):
        metrics_path = run_dir / name
        if metrics_path.exists():
            return json.loads(metrics_path.read_text())
    return None


def load_run_attacks(run_dir: Path) -> list[dict[str, Any]]:
    """Load attacks.json from a run directory."""
    attacks_path = run_dir / "attacks.json"
    if not attacks_path.exists():
        return []
    return json.loads(attacks_path.read_text())


def load_trace(run_dir: Path) -> pd.DataFrame | None:
    """Load trace.parquet from a run directory."""
    trace_path = run_dir / "trace.parquet"
    if not trace_path.exists():
        return None
    try:
        return pd.read_parquet(trace_path)
    except Exception as e:
        logger.warning("Failed to load %s: %s", trace_path, e)
        return None


def process_run(run_dir: Path) -> dict[str, Any] | None:
    """Process a single run directory and return summary info."""
    meta = load_run_metadata(run_dir)
    metrics = load_run_metrics(run_dir)
    if meta is None:
        return None

    # Determine attacker type from various metadata fields
    attacker = "none"
    if metrics:
        attacker = metrics.get("attacker_name", metrics.get("mode", "none"))
    if attacker == "none":
        attacker = meta.get("mode", "none")

    # Derive total_attacks from either field name
    total_attacks = 0
    if metrics:
        total_attacks = metrics.get("total_attacks", metrics.get("attacks_submitted", 0))

    return {
        "run_dir": str(run_dir),
        "run_id": meta.get("run_id", run_dir.name),
        "experiment_name": meta.get("experiment_name", meta.get("experiment", "")),
        "scene": meta.get("scene", meta.get("scene_name", "")),
        "attacker": attacker,
        "eval_run": meta.get("eval_run", False),
        "dry_run": meta.get("dry_run", True),
        "total_steps": meta.get("total_steps", 0),
        "total_attacks": total_attacks,
        **(metrics or {}),
    }


def gather_all_runs(scene_filter: str | None = None) -> list[dict[str, Any]]:
    """Gather all run metadata from data/raw/."""
    runs = []
    if not DATA_RAW.exists():
        logger.warning("No data/raw/ directory found")
        return runs

    for experiment_dir in sorted(DATA_RAW.iterdir()):
        if not experiment_dir.is_dir() or experiment_dir.name.startswith("."):
            continue
        for run_dir in sorted(experiment_dir.iterdir()):
            if not run_dir.is_dir():
                continue
            info = process_run(run_dir)
            if info is None:
                continue
            if scene_filter and info["scene"] != scene_filter:
                continue
            runs.append(info)

    return runs


def generate_labeled_dataset(scene: str, runs: list[dict[str, Any]]) -> None:
    """Generate labeled ground truth dataset for a scene."""
    out_dir = DATA_OUT / scene
    out_dir.mkdir(parents=True, exist_ok=True)

    normal_frames = []
    attack_frames = []

    scene_runs = [r for r in runs if r["scene"] == scene]
    if not scene_runs:
        logger.warning("No runs found for scene: %s", scene)
        return

    for run_info in scene_runs:
        run_dir = Path(run_info["run_dir"])
        trace = load_trace(run_dir)
        if trace is None or trace.empty:
            logger.info("  Skipping %s (no trace data)", run_info["run_id"])
            continue

        attacker = run_info.get("attacker", "none")
        total_attacks = run_info.get("total_attacks", 0)

        # Add metadata columns
        trace["run_id"] = run_info["run_id"]
        trace["attacker_type"] = attacker
        trace["scene"] = scene

        # Determine label: if no attacks, all steps are normal
        if attacker in ("none", "baseline") or total_attacks == 0:
            trace["label"] = "normal"
            normal_frames.append(trace)
            logger.info("  Normal trace: %s (%d steps)", run_info["run_id"], len(trace))
        else:
            # Load attacks to determine attack windows
            attacks = load_run_attacks(run_dir)

            # If trace has an 'attack_active' column, use it directly
            if "attack_active" in trace.columns:
                trace["label"] = trace["attack_active"].apply(
                    lambda x: "attack" if x else "normal"
                )
            else:
                # Default: label based on whether any attack was executed
                # Steps during attack windows are labeled as "attack"
                trace["label"] = "normal"
                if attacks:
                    # Mark attack steps based on the attack scheduling
                    # This is approximate; real labels come from the trace recorder
                    n_steps = len(trace)
                    n_attacks = len(attacks)
                    spacing = max(1, n_steps // max(n_attacks, 1))
                    for i in range(n_attacks):
                        start = min(i * spacing + 5, n_steps - 1)
                        # Assume attack lasts ~20 steps (10 seconds at 500ms)
                        end = min(start + 20, n_steps)
                        trace.loc[start:end, "label"] = "attack"

            attack_frames.append(trace)
            n_attack = (trace["label"] == "attack").sum()
            logger.info(
                "  Attack trace: %s [%s] (%d steps, %d attack steps)",
                run_info["run_id"], attacker, len(trace), n_attack,
            )

    # Write outputs
    if normal_frames:
        normal_df = pd.concat(normal_frames, ignore_index=True)
        normal_df.to_csv(out_dir / "normal_baseline.csv", index=False)
        logger.info("  Wrote normal_baseline.csv: %d rows", len(normal_df))

    if attack_frames:
        attack_df = pd.concat(attack_frames, ignore_index=True)
        attack_df.to_csv(out_dir / "attack_traces.csv", index=False)
        logger.info("  Wrote attack_traces.csv: %d rows", len(attack_df))

    # Combined labeled dataset
    all_frames = normal_frames + attack_frames
    if all_frames:
        combined = pd.concat(all_frames, ignore_index=True)
        combined.to_csv(out_dir / "combined_labeled.csv", index=False)
        logger.info("  Wrote combined_labeled.csv: %d rows", len(combined))

        # Summary stats
        summary = {
            "scene": scene,
            "total_runs": len(scene_runs),
            "total_steps": len(combined),
            "normal_steps": int((combined["label"] == "normal").sum()),
            "attack_steps": int((combined["label"] == "attack").sum()),
            "attack_ratio": float((combined["label"] == "attack").mean()),
            "attacker_types": combined["attacker_type"].unique().tolist(),
        }
        (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
        logger.info("  Scene summary: %s", json.dumps(summary, indent=2))


def generate_aggregate_metrics(runs: list[dict[str, Any]]) -> None:
    """Generate aggregate metrics across all runs."""
    DATA_OUT.mkdir(parents=True, exist_ok=True)

    # Run index
    if runs:
        index_df = pd.DataFrame(runs)
        # Select relevant columns
        cols = [
            "run_id", "experiment_name", "scene", "attacker", "eval_run",
            "total_steps", "total_attacks", "action_validity_rate",
            "execution_success_rate", "attack_success_rate", "process_impact_score",
            "shield_approval_rate", "shield_rejection_rate", "unsafe_block_rate",
            "detector_precision", "detector_recall", "detector_f1",
            "false_positives", "false_negatives", "detection_latency_ms",
            "hard_case_flag", "adaptation_round",
        ]
        available_cols = [c for c in cols if c in index_df.columns]
        index_df = index_df[available_cols]
        index_df.to_csv(DATA_OUT / "run_index.csv", index=False)
        logger.info("Wrote run_index.csv: %d runs", len(index_df))

    # Aggregate metrics by scene × attacker
    eval_runs = [r for r in runs if r.get("eval_run", False)]
    if eval_runs:
        agg_df = pd.DataFrame(eval_runs)
        metric_cols = [
            "action_validity_rate", "execution_success_rate",
            "attack_success_rate", "process_impact_score",
            "shield_approval_rate", "shield_rejection_rate",
            "detector_precision", "detector_recall", "detector_f1",
            "false_positives", "false_negatives",
        ]
        available_metric_cols = [c for c in metric_cols if c in agg_df.columns]
        if available_metric_cols:
            agg = agg_df.groupby(["scene", "attacker"])[available_metric_cols].mean()
            agg.to_csv(DATA_OUT / "aggregate_metrics.csv")
            logger.info("Wrote aggregate_metrics.csv")

    # Summary
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_runs": len(runs),
        "eval_runs": len(eval_runs),
        "scenes": list({r["scene"] for r in runs}),
        "attacker_types": list({r.get("attacker", "none") for r in runs}),
    }
    (DATA_OUT / "summary.json").write_text(json.dumps(summary, indent=2))
    logger.info("Wrote summary.json")


def main():
    parser = argparse.ArgumentParser(description="CPSForge Ground Truth Dataset Generator")
    parser.add_argument("--scene", choices=SCENES + ["all"], default="all")
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("CPSForge Ground Truth Dataset Generator")
    logger.info("=" * 60)

    scene_filter = None if args.scene == "all" else args.scene
    runs = gather_all_runs(scene_filter)
    logger.info("Found %d run(s) in data/raw/", len(runs))

    scenes = SCENES if args.scene == "all" else [args.scene]
    for scene in scenes:
        logger.info("\nProcessing scene: %s", scene)
        generate_labeled_dataset(scene, runs)

    logger.info("\nGenerating aggregate metrics...")
    generate_aggregate_metrics(runs)

    logger.info("\nDone. Output in: %s", DATA_OUT)


if __name__ == "__main__":
    main()
