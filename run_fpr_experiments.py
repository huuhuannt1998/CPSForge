"""
run_fpr_experiments.py — Execute FPR (False Positive Rate) experiments.

Measures how often the LLM defender incorrectly blocks legitimate writes.
Uses the FPR probe attacker that generates controller-consistent writes,
routes them through the defense chain, and logs block/allow decisions.

Experiment matrix:
  2 models (base, finetuned) × 2 defenses (llm_defender, llm_combined)
  × 3 scenes × 3 repeats = 36 cells

Each run: 60 steps, ~3 minutes wall clock with LLM inference.
Total: ~108 minutes.

Requirements:
  - PLC (Siemens S7-1200) connected and running
  - Factory I/O running with the correct scene loaded
  - No live_writes_enabled needed (reads only, probes are synthetic)

Usage:
  py -3 run_fpr_experiments.py --scenes level_control sorting_weight sorting_height_basic
  py -3 run_fpr_experiments.py --scenes level_control --models base --repeats 1  # quick test
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)-30s %(levelname)-7s %(message)s",
)
logger = logging.getLogger("fpr_runner")


def main():
    parser = argparse.ArgumentParser(description="Run FPR experiments")
    parser.add_argument(
        "--scenes",
        nargs="+",
        default=["level_control", "sorting_weight", "sorting_height_basic"],
        help="Scenes to test",
    )
    parser.add_argument(
        "--models",
        nargs="+",
        default=["base", "finetuned"],
        help="Model variants to test",
    )
    parser.add_argument(
        "--defenses",
        nargs="+",
        default=["llm_defender", "llm_combined"],
        help="Defense variants to test",
    )
    parser.add_argument("--repeats", type=int, default=3, help="Repeats per cell")
    parser.add_argument("--max-steps", type=int, default=60, help="Steps per run")
    parser.add_argument("--dry-run", action="store_true", help="No PLC connection")
    args = parser.parse_args()

    from cpsforge.core.config import ConfigLoader
    from cpsforge.runner.online_runner import OnlineExperimentRunner

    loader = ConfigLoader(Path("configs"))

    # Build FPR cells
    cells = []
    for mv in args.models:
        for dv in args.defenses:
            for scene in args.scenes:
                for r in range(1, args.repeats + 1):
                    cells.append({
                        "cell_id": f"FPR_{mv}_{dv}_{scene}_r{r}",
                        "scene": scene,
                        "model_variant": mv,
                        "defense_variant": dv,
                        "repeat": r,
                    })

    total = len(cells)
    logger.info("FPR experiment: %d cells total", total)

    # Group by scene for scene-switching prompts
    current_scene = None
    results = []

    for i, cell in enumerate(cells):
        scene = cell["scene"]

        if scene != current_scene:
            current_scene = scene
            print(f"\n{'='*60}")
            print(f"  SWITCH FACTORY I/O SCENE TO:")
            print(f"  >>> {scene} <<<")
            print(f"")
            print(f"  1. File > Open Scene > {scene}")
            print(f"  2. Press Play (F5)")
            print(f"  3. Verify PLC is running")
            print(f"{'='*60}")
            if not args.dry_run:
                input("  Press ENTER when ready...")

        logger.info(
            "[%d/%d] Running %s (model=%s, defense=%s, repeat=%d)",
            i + 1, total,
            cell["cell_id"],
            cell["model_variant"],
            cell["defense_variant"],
            cell["repeat"],
        )

        try:
            cfg_name = f"v2_online"
            config = loader.load_experiment(cfg_name)
            config.name = f"v2_FPR_{scene}"
            config.scene_config = f"scenes/{scene}.yaml"
            config.dry_run = args.dry_run
            config.max_steps = args.max_steps
            config.run_duration_s = 600
            config.live_writes_enabled = False  # FPR never writes to PLC

            extra = {
                "context_level": "full",
                "model_variant": cell["model_variant"],
                "finetune_status": "finetuned" if cell["model_variant"] == "finetuned" else "base",
                "defense_variant": cell["defense_variant"],
                "attack_budget": 999,  # Unlimited probes
                "decision_interval_steps": 3,
                "attacker_type": "fpr_probe",
            }

            runner = OnlineExperimentRunner(
                config=config,
                loader=loader,
                output_base=Path("data/raw") / f"v2_FPR_{scene}",
                extra=extra,
            )
            run_id = runner.run()

            cell["run_id"] = run_id
            cell["status"] = "done"
            logger.info("  -> run_id=%s (done)", run_id)

        except Exception as exc:
            logger.error("  -> FAILED: %s", exc, exc_info=True)
            cell["status"] = "failed"
            cell["error"] = str(exc)

        results.append(cell)

        # Save checkpoint after each run
        ckpt_path = Path("data/processed/fpr_checkpoint.json")
        ckpt_path.parent.mkdir(parents=True, exist_ok=True)
        with open(ckpt_path, "w") as f:
            json.dump(results, f, indent=2)

        # Brief pause between runs
        if i < total - 1:
            time.sleep(3)

    # Final summary
    done = sum(1 for r in results if r.get("status") == "done")
    failed = sum(1 for r in results if r.get("status") == "failed")
    logger.info("FPR experiments complete: %d done, %d failed out of %d total", done, failed, total)

    print(f"\nResults saved to data/processed/fpr_checkpoint.json")
    print(f"Run analysis: py -3 -m cpsforge.analysis.fpr_analysis")


if __name__ == "__main__":
    main()
