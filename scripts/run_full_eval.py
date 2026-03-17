#!/usr/bin/env python3
"""
CPSForge Evaluation Runner
============================
Run all evaluation experiments and generate ground-truth datasets.

This script orchestrates:
  1. Baseline (normal operation) traces for each scene — ground truth
  2. Scripted attacker runs — batch mode
  3. Random attacker runs — batch mode
  4. LLM attacker runs — batch mode
  5. Agent mode runs — live multi-agent

Prerequisites:
  - Siemens S7 PLC reachable at 192.168.0.1
  - Factory I/O in PLAY mode with the correct scene loaded
  - LM Studio running at http://127.0.0.1:1234/v1 (for LLM/agent runs)
  - CPSForge installed: pip install -e .

Usage:
  python scripts/run_full_eval.py --phase all
  python scripts/run_full_eval.py --phase baseline
  python scripts/run_full_eval.py --phase scripted
  python scripts/run_full_eval.py --phase random
  python scripts/run_full_eval.py --phase llm
  python scripts/run_full_eval.py --phase agent
  python scripts/run_full_eval.py --scene level_control --phase all
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

SCENES = ["from_a_to_b", "level_control", "sorting_height_basic"]
ATTACKERS_BATCH = ["scripted", "random", "llm"]


def run_command(cmd: list[str], description: str) -> int:
    """Run a CLI command and return the exit code."""
    logger.info("--- %s ---", description)
    logger.info("Command: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=False)
    if result.returncode != 0:
        logger.error("FAILED: %s (exit code %d)", description, result.returncode)
    else:
        logger.info("OK: %s", description)
    return result.returncode


def run_baseline(scene: str) -> int:
    """Run a baseline (no-attack) trace for ground truth."""
    return run_command(
        [
            sys.executable, "-m", "cpsforge", "run", "baseline",
            "--scene", scene,
            "--no-dry-run",
            "--eval-run",
            "--max-steps", "200",
            "--yes",
        ],
        f"Baseline normal trace: {scene}",
    )


def run_batch_attack(scene: str, attacker: str) -> int:
    """Run a batch-mode attack experiment."""
    experiment = f"live_{attacker}_{scene}"
    return run_command(
        [
            sys.executable, "-m", "cpsforge", "run", "attack",
            "--scene", scene,
            "--attacker", attacker,
            "--experiment", experiment,
            "--no-dry-run",
            "--eval-run",
            "--yes",
        ],
        f"Batch attack: {attacker} on {scene}",
    )


def run_agent_mode(scene: str) -> int:
    """Run an agent-mode experiment."""
    experiment = f"agent_{scene}"
    return run_command(
        [
            sys.executable, "-m", "cpsforge", "run", "agent",
            "--scene", scene,
            "--experiment", experiment,
            "--no-dry-run",
            "--eval-run",
            "--max-steps", "200",
            "--yes",
        ],
        f"Agent mode: {scene}",
    )


def run_phase(phase: str, scenes: list[str]) -> dict:
    """Run experiments for a given phase across specified scenes."""
    results = {}

    for scene in scenes:
        if phase in ("baseline", "all"):
            logger.info("\n{'=' * 60}")
            logger.info("SCENE: %s  |  PHASE: baseline (ground truth)", scene)
            logger.info("Load the '%s' scene in Factory I/O and press Enter...", scene)
            input(f"  >>> Press Enter to run baseline for {scene}...")
            rc = run_baseline(scene)
            results[f"baseline_{scene}"] = rc
            time.sleep(2)

        if phase in ("scripted", "batch", "all"):
            input(f"  >>> Press Enter to run scripted attacks on {scene}...")
            rc = run_batch_attack(scene, "scripted")
            results[f"scripted_{scene}"] = rc
            time.sleep(2)

        if phase in ("random", "batch", "all"):
            input(f"  >>> Press Enter to run random attacks on {scene}...")
            rc = run_batch_attack(scene, "random")
            results[f"random_{scene}"] = rc
            time.sleep(2)

        if phase in ("llm", "batch_llm", "all"):
            input(f"  >>> Press Enter to run LLM batch attacks on {scene}...")
            rc = run_batch_attack(scene, "llm")
            results[f"llm_{scene}"] = rc
            time.sleep(2)

        if phase in ("agent", "all"):
            input(f"  >>> Press Enter to run agent mode on {scene}...")
            rc = run_agent_mode(scene)
            results[f"agent_{scene}"] = rc
            time.sleep(2)

    return results


def main():
    parser = argparse.ArgumentParser(description="CPSForge Full Evaluation Runner")
    parser.add_argument(
        "--phase",
        choices=["all", "baseline", "scripted", "random", "llm", "batch", "batch_llm", "agent"],
        default="all",
        help="Which evaluation phase to run",
    )
    parser.add_argument(
        "--scene",
        choices=SCENES + ["all"],
        default="all",
        help="Which scene to evaluate (default: all)",
    )
    args = parser.parse_args()

    scenes = SCENES if args.scene == "all" else [args.scene]

    logger.info("=" * 60)
    logger.info("CPSForge Evaluation Runner")
    logger.info("Phase: %s  |  Scenes: %s", args.phase, ", ".join(scenes))
    logger.info("=" * 60)
    logger.info("")
    logger.info("Prerequisites:")
    logger.info("  1. PLC reachable at 192.168.0.1")
    logger.info("  2. Factory I/O in PLAY mode")
    logger.info("  3. LM Studio at http://127.0.0.1:1234/v1 (for LLM/agent)")
    logger.info("")

    results = run_phase(args.phase, scenes)

    logger.info("")
    logger.info("=" * 60)
    logger.info("EVALUATION SUMMARY")
    logger.info("=" * 60)
    for name, rc in results.items():
        status = "PASS" if rc == 0 else "FAIL"
        logger.info("  %-40s %s", name, status)

    # Save summary
    summary_path = Path("data/processed/eval_summary.json")
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "phase": args.phase,
        "scenes": scenes,
        "results": {k: ("pass" if v == 0 else "fail") for k, v in results.items()},
    }
    summary_path.write_text(json.dumps(summary, indent=2))
    logger.info("\nSummary saved to %s", summary_path)


if __name__ == "__main__":
    main()
