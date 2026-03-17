"""
CPSForge Agent Mode Evaluation Runner
=======================================
Runs live attacker/defender agent experiments on all 3 scenes.
Must be run as a standalone script to avoid SIGINT issues.

Usage:
  python scripts/run_agent_eval.py
"""

import json
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cpsforge.agents.runtime import AgentRuntime
from cpsforge.core.config import ConfigLoader, ExperimentConfig
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
    {
        "name": "agent_level_control_eval",
        "scene": "level_control",
        "defenders": ["threshold_level_control", "invariant_level_control"],
        "max_steps": 100,
    },
    {
        "name": "agent_from_a_to_b_eval",
        "scene": "from_a_to_b",
        "defenders": ["threshold_from_a_to_b", "invariant_from_a_to_b"],
        "max_steps": 100,
    },
    {
        "name": "agent_sorting_height_eval",
        "scene": "sorting_height_basic",
        "defenders": ["threshold_sorting_height_basic", "invariant_sorting_height_basic"],
        "max_steps": 100,
    },
]


def run_experiment(exp_def: dict) -> dict:
    loader = ConfigLoader()
    exp_cfg = ExperimentConfig(
        name=exp_def["name"],
        mode="agent",
        scene_config=f"scenes/{exp_def['scene']}.yaml",
        attackers=[],
        defenders=exp_def["defenders"],
        attacker_agent="attacker_agent",
        defender_agent="defender_agent",
        dry_run=False,
        live_writes_enabled=True,
        eval_run=True,
        max_steps=exp_def["max_steps"],
    )

    attacker_cfg = loader.load_agent("attacker_agent")
    defender_cfg = loader.load_agent("defender_agent")
    attacker_cfg.scene_name = exp_def["scene"]
    defender_cfg.scene_name = exp_def["scene"]

    run_id = f"agent-{exp_def['scene']}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

    print(f"\n{'='*60}")
    print(f"  Running: {exp_def['name']}")
    print(f"  Scene: {exp_def['scene']} | Steps: {exp_def['max_steps']}")
    print(f"  Run ID: {run_id}")
    print(f"{'='*60}")

    runtime = AgentRuntime(
        run_id=run_id,
        loader=loader,
        exp_config=exp_cfg,
        attacker_cfg=attacker_cfg,
        defender_cfg=defender_cfg,
    )
    result = runtime.run()

    metrics_path = result.artifact_dir / "agent_metrics.json" if result.artifact_dir else None
    if metrics_path and metrics_path.exists():
        with open(metrics_path) as f:
            metrics = json.load(f)
        print(f"\n  Run ID: {result.run_id}")
        print(f"  Snapshots: {len(result.snapshots)}")
        print(f"  Events: {len(result.events)}")
        print(f"  Write requests: {result.processed_requests}")
        for key in ("attacker_actions", "defender_actions", "attack_success_rate",
                     "shield_approval_rate", "corrective_success_rate"):
            if key in metrics:
                print(f"  {key}: {metrics[key]}")
        return metrics
    else:
        return {
            "run_id": result.run_id,
            "snapshots": len(result.snapshots),
            "events": len(result.events),
            "processed_requests": result.processed_requests,
        }


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
            import traceback
            traceback.print_exc()
            results[exp_def["name"]] = {"error": str(e)}

    summary_path = Path("data/processed/agent_eval_summary.json")
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with open(summary_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n{'='*60}")
    print(f"  All agent eval experiments complete.")
    print(f"  Summary: {summary_path}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
