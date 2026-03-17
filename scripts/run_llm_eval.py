"""
CPSForge LLM Batch Evaluation Runner
=====================================
Runs LLM batch attacks on all 3 scenes and saves results.
Must be run as a standalone script (not via CLI) to avoid SIGINT issues.

Usage:
  python scripts/run_llm_eval.py
"""

import json
import signal
import sys
from pathlib import Path

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cpsforge.core.config import ConfigLoader, ExperimentConfig
from cpsforge.core.orchestrator import ExperimentOrchestrator
from cpsforge.logging.logger import setup_logging

setup_logging()

# Ignore SIGINT during experiment (allow graceful completion)
original_sigint = signal.getsignal(signal.SIGINT)
interrupted = False


def _sigint_handler(signum, frame):
    global interrupted
    if interrupted:
        # Second Ctrl+C: abort immediately
        print("\nForced abort.")
        sys.exit(1)
    interrupted = True
    print("\nInterrupt received. Will finish current experiment and exit.")


signal.signal(signal.SIGINT, _sigint_handler)

EXPERIMENTS = [
    {
        "name": "llm_level_control_eval",
        "scene": "level_control",
        "attacker": "llm_level_control",
        "defenders": ["threshold_level_control", "invariant_level_control"],
        "max_steps": 150,
    },
    {
        "name": "llm_from_a_to_b_eval",
        "scene": "from_a_to_b",
        "attacker": "llm_from_a_to_b",
        "defenders": ["threshold_from_a_to_b", "invariant_from_a_to_b"],
        "max_steps": 150,
    },
    {
        "name": "llm_sorting_height_eval",
        "scene": "sorting_height_basic",
        "attacker": "llm_sorting_height_basic",
        "defenders": ["threshold_sorting_height_basic", "invariant_sorting_height_basic"],
        "max_steps": 200,
    },
]


def run_experiment(exp_def: dict) -> dict:
    """Run a single LLM batch experiment."""
    loader = ConfigLoader()
    exp_cfg = ExperimentConfig(
        name=exp_def["name"],
        scene_config=f"scenes/{exp_def['scene']}.yaml",
        attackers=[exp_def["attacker"]],
        defenders=exp_def["defenders"],
        dry_run=False,
        live_writes_enabled=True,
        eval_run=True,
        max_steps=exp_def["max_steps"],
    )

    print(f"\n{'='*60}")
    print(f"  Running: {exp_def['name']}")
    print(f"  Scene: {exp_def['scene']} | Steps: {exp_def['max_steps']}")
    print(f"{'='*60}")

    orchestrator = ExperimentOrchestrator(exp_cfg, loader)
    run_id = orchestrator.run()

    metrics_path = Path(f"data/raw/{exp_def['name']}/{run_id}/metrics.json")
    if metrics_path.exists():
        with open(metrics_path) as f:
            metrics = json.load(f)
        print(f"\n  Run ID: {run_id}")
        print(f"  Total steps: {metrics.get('total_steps', '?')}")
        print(f"  Attacks: {metrics.get('total_attacks', '?')}")
        print(f"  ASR: {metrics.get('attack_success_rate', '?')}")
        print(f"  Impact: {metrics.get('process_impact_score', '?')}")
        print(f"  Shield approval: {metrics.get('shield_approval_rate', '?')}")
        print(f"  Precision: {metrics.get('detector_precision', '?')}")
        print(f"  Recall: {metrics.get('detector_recall', '?')}")
        print(f"  F1: {metrics.get('detector_f1', '?')}")
        return metrics
    else:
        print(f"  WARNING: Metrics file not found at {metrics_path}")
        return {}


def main():
    results = {}
    for exp_def in EXPERIMENTS:
        if interrupted:
            print(f"\nSkipping {exp_def['name']} (interrupted)")
            continue
        try:
            metrics = run_experiment(exp_def)
            results[exp_def["name"]] = metrics
        except Exception as e:
            print(f"\n  ERROR in {exp_def['name']}: {e}")
            results[exp_def["name"]] = {"error": str(e)}

    # Write summary
    summary_path = Path("data/processed/llm_eval_summary.json")
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with open(summary_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n{'='*60}")
    print(f"  All LLM eval experiments complete.")
    print(f"  Summary: {summary_path}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
