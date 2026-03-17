"""
CPSForge Baseline + Normal Trace Runner
=========================================
Runs baseline (no-attack) traces for scenes that need normal data.
Also runs scripted/random baselines if needed.

Usage:
  python scripts/run_baselines.py
"""

import json
import signal
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cpsforge.core.config import ConfigLoader, ExperimentConfig
from cpsforge.core.orchestrator import ExperimentOrchestrator
from cpsforge.logging.logger import setup_logging

setup_logging()

interrupted = False


def _sigint_handler(signum, frame):
    global interrupted
    if interrupted:
        sys.exit(1)
    interrupted = True
    print("\nInterrupt received. Will finish current experiment and exit.")


signal.signal(signal.SIGINT, _sigint_handler)

EXPERIMENTS = [
    # Normal baselines (no attacks) for scenes missing normal data
    {
        "name": "baseline_level_control",
        "scene": "level_control",
        "attackers": [],
        "defenders": [],
        "max_steps": 100,
    },
    {
        "name": "baseline_sorting_height_basic",
        "scene": "sorting_height_basic",
        "attackers": [],
        "defenders": [],
        "max_steps": 100,
    },
    {
        "name": "baseline_from_a_to_b",
        "scene": "from_a_to_b",
        "attackers": [],
        "defenders": [],
        "max_steps": 100,
    },
]


def run_experiment(exp_def: dict) -> dict:
    loader = ConfigLoader()
    exp_cfg = ExperimentConfig(
        name=exp_def["name"],
        scene_config=f"scenes/{exp_def['scene']}.yaml",
        attackers=exp_def["attackers"],
        defenders=exp_def["defenders"],
        dry_run=False,
        live_writes_enabled=True,  # needed for dry_run=False; no writes will happen (no attackers)
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
        print(f"  Run ID: {run_id}")
        print(f"  Total steps: {metrics.get('total_steps', '?')}")
        return metrics
    else:
        print(f"  Run ID: {run_id} (baseline, no metrics)")
        return {"run_id": run_id, "total_steps": exp_def["max_steps"]}


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

    summary_path = Path("data/processed/baseline_summary.json")
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with open(summary_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n{'='*60}")
    print(f"  All baseline experiments complete.")
    print(f"  Summary: {summary_path}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
