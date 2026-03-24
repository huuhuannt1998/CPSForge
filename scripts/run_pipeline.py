#!/usr/bin/env python3
"""
CPSForge Post-Processing Pipeline
====================================
Runs all offline analysis scripts in the correct order and validates outputs.

This is the single command to regenerate all processed data, tables, figures,
and analysis artifacts from the raw experiment data.

Order:
  1. aggregate_results.py      → data/processed/aggregate_results/
  2. compute_variance.py       → data/processed/variance_analysis/
  3. generate_tables.py        → data/processed/paper_tables/table1-6
  4. generate_ablation_table.py→ data/processed/paper_tables/table7
  5. generate_figures.py       → data/processed/paper_figures/
  6. analyze_attack_types.py   → data/processed/attack_analysis/
  7. generate_timeline_figure.py→data/processed/paper_figures/
  8. evaluate_benign_fp.py     → data/processed/benign_fp/
  9. measure_overhead.py       → data/processed/overhead/

Usage:
    python scripts/run_pipeline.py
    python scripts/run_pipeline.py --step 1 2 3    # Run specific steps
    python scripts/run_pipeline.py --validate       # Only check outputs
"""
from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent
PROCESSED = ROOT / "data" / "processed"

PIPELINE_STEPS = [
    {
        "step": 1,
        "name": "Aggregate results",
        "script": "scripts/aggregate_results.py",
        "outputs": [
            "aggregate_results/all_metrics.csv",
            "aggregate_results/per_scene_attacker_summary.csv",
            "aggregate_results/experiment_manifest.json",
        ],
    },
    {
        "step": 2,
        "name": "Compute variance & CIs",
        "script": "scripts/compute_variance.py",
        "outputs": [
            "variance_analysis/variance_summary.csv",
            "variance_analysis/confidence_intervals.tex",
            "variance_analysis/summary.json",
        ],
    },
    {
        "step": 3,
        "name": "Generate LaTeX tables (1-6)",
        "script": "scripts/generate_tables.py",
        "outputs": [
            "paper_tables/table1_attack_results.tex",
            "paper_tables/table2_shield_results.tex",
            "paper_tables/table3_defender_results.tex",
            "paper_tables/table4_agent_results.tex",
            "paper_tables/table5_adapt_results.tex",
            "paper_tables/table6_detector_comparison.tex",
        ],
    },
    {
        "step": 4,
        "name": "Generate ablation table (7)",
        "script": "scripts/generate_ablation_table.py",
        "outputs": [
            "paper_tables/table7_ablation.tex",
        ],
    },
    {
        "step": 5,
        "name": "Generate figures",
        "script": "scripts/generate_figures.py",
        "outputs": [
            "paper_figures/fig_asr_comparison.png",
            "paper_figures/fig_detector_f1.png",
            "paper_figures/fig_dataset_composition.png",
        ],
    },
    {
        "step": 6,
        "name": "Analyze attack types",
        "script": "scripts/analyze_attack_types.py",
        "outputs": [
            "attack_analysis/type_distribution.csv",
            "attack_analysis/summary.json",
        ],
    },
    {
        "step": 7,
        "name": "Generate timeline figures",
        "script": "scripts/generate_timeline_figure.py",
        "outputs": [],  # dynamic outputs
    },
    {
        "step": 8,
        "name": "Evaluate benign false positives",
        "script": "scripts/evaluate_benign_fp.py",
        "outputs": [
            "benign_fp/summary.json",
            "benign_fp/per_detector_fp.csv",
        ],
    },
    {
        "step": 9,
        "name": "Measure overhead",
        "script": "scripts/measure_overhead.py",
        "outputs": [
            "overhead/summary.json",
            "overhead/per_step_timing.csv",
        ],
    },
]


def run_step(step_info: dict) -> bool:
    script = ROOT / step_info["script"]
    if not script.exists():
        logger.error("Script not found: %s", script)
        return False

    logger.info("=" * 60)
    logger.info("Step %d: %s", step_info["step"], step_info["name"])
    logger.info("  Script: %s", step_info["script"])

    result = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, cwd=str(ROOT),
    )

    if result.returncode != 0:
        logger.error("  FAILED (exit %d)", result.returncode)
        if result.stderr:
            for line in result.stderr.strip().split("\n")[-5:]:
                logger.error("    %s", line)
        return False

    logger.info("  OK")
    return True


def validate_outputs() -> dict:
    """Check which expected outputs exist."""
    results = {}
    for step_info in PIPELINE_STEPS:
        step_key = f"step_{step_info['step']}"
        results[step_key] = {
            "name": step_info["name"],
            "outputs": {},
        }
        for out in step_info["outputs"]:
            full_path = PROCESSED / out
            exists = full_path.exists()
            size = full_path.stat().st_size if exists else 0
            results[step_key]["outputs"][out] = {
                "exists": exists,
                "size_bytes": size,
            }
            status = "OK" if exists else "MISSING"
            logger.info("  [%s] %s (%d bytes)", status, out, size)
    return results


def main():
    parser = argparse.ArgumentParser(description="CPSForge Post-Processing Pipeline")
    parser.add_argument("--step", type=int, nargs="+", help="Run specific steps (1-9)")
    parser.add_argument("--validate", action="store_true", help="Only validate outputs")
    args = parser.parse_args()

    if args.validate:
        logger.info("Validating pipeline outputs...")
        results = validate_outputs()
        all_ok = all(
            all(o["exists"] for o in step["outputs"].values())
            for step in results.values()
            if step["outputs"]
        )
        if all_ok:
            logger.info("All outputs present.")
        else:
            logger.warning("Some outputs are missing. Run the pipeline to generate them.")
        return

    steps_to_run = args.step if args.step else [s["step"] for s in PIPELINE_STEPS]

    logger.info("CPSForge Post-Processing Pipeline")
    logger.info("Steps: %s", steps_to_run)

    success = 0
    failed = 0
    for step_info in PIPELINE_STEPS:
        if step_info["step"] not in steps_to_run:
            continue
        ok = run_step(step_info)
        if ok:
            success += 1
        else:
            failed += 1

    logger.info("=" * 60)
    logger.info("Pipeline complete: %d succeeded, %d failed", success, failed)

    # Save pipeline run record
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "steps_run": steps_to_run,
        "success": success,
        "failed": failed,
    }
    manifest_path = PROCESSED / "pipeline_manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(record, indent=2))
    logger.info("Manifest: %s", manifest_path)

    # Validate
    logger.info("")
    logger.info("Output validation:")
    validate_outputs()


if __name__ == "__main__":
    main()
