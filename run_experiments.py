"""
run_experiments.py -- CPSForge v2 Experiment Launcher

Run this from PowerShell/CMD (NOT Git Bash) to avoid CUDA segfault.
cd to the CPSForge directory, then:

  python run_experiments.py --rqs RQ1 --scenes level_control --repeats 1 --live
  python run_experiments.py --rqs RQ1 RQ2 RQ3 RQ4 --live
  python run_experiments.py --rqs RQ1 --scenes level_control --repeats 1 --dry-run

IMPORTANT:
  --live enables live PLC writes. Factory I/O must be running with the
  correct scene loaded before launching.

  The script prints a scene-switch prompt before each new scene and waits
  for your confirmation (press Enter) unless --yes is set.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("experiment_run.log", mode="a"),
    ],
)
logger = logging.getLogger("cpsforge.launcher")

# Scene display names for user prompts
# Factory I/O scene numbers verified from TIA Portal DB list:
#   From A to B           → Factory I/O Scene 1,  DB3
#   Filling Tank          → Factory I/O Scene 3,  DB5
#   Level Control         → Factory I/O Scene 12, DB14
#   Sorting by Height     → Factory I/O Scene 19, DB21
#   Sorting by Weight     → Factory I/O Scene 20, DB22
_SCENE_DISPLAY = {
    "level_control":        "Level Control       (Factory I/O Scene 12 — DB14, 15 tags)",
    "sorting_weight":       "Sorting by Weight   (Factory I/O Scene 20 — DB22, 35 tags)",
    "filling_tank":         "Filling Tank        (Factory I/O Scene 3  — DB5,  9 tags)",
    "from_a_to_b":          "From A to B         (Factory I/O Scene 1  — DB3,  3 tags)",
    "sorting_height_basic": "Sorting by Height   (Factory I/O Scene 19 — DB21, 30 tags)",
    # OpenPLC scenes (Modbus backend + Python simulator)
    "level_control_openplc":   "Level Control    (OpenPLC — Modbus TCP, TankSimulator)",
    "sorting_weight_openplc":  "Sorting by Weight(OpenPLC — Modbus TCP, WeightSorterSimulator)",
    "sorting_height_openplc":  "Sorting by Height(OpenPLC — Modbus TCP, HeightSorterSimulator)",
}

# Scenes that use OpenPLC (no Factory I/O scene switch needed)
_OPENPLC_SCENES = {
    "level_control_openplc",
    "sorting_weight_openplc",
    "sorting_height_openplc",
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="CPSForge v2 experiment runner")
    p.add_argument(
        "--rqs",
        nargs="+",
        default=["RQ1"],
        choices=["RQ1", "RQ2", "RQ3", "RQ4", "RQ5", "FPR", "TIER2", "FRONTIER"],
        help="Research questions to run (default: RQ1)",
    )
    p.add_argument(
        "--scenes",
        nargs="+",
        default=None,
        help="Scenes to include (default: all 5 scenes)",
    )
    p.add_argument(
        "--repeats",
        type=int,
        default=3,
        help="Repeats per cell (default: 3)",
    )
    p.add_argument(
        "--live",
        action="store_true",
        help="Enable live PLC writes (default: dry-run)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Dry-run mode: poll PLC but no writes, no LLM",
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/raw"),
        help="Base directory for run artifacts (default: data/raw)",
    )
    p.add_argument(
        "--checkpoint-file",
        type=Path,
        default=Path("data/checkpoint.json"),
        help="Checkpoint file for resuming interrupted runs",
    )
    p.add_argument(
        "--yes",
        action="store_true",
        help="Skip scene-switch confirmation prompts (use with care)",
    )
    return p.parse_args()


def prompt_scene_switch(scene_name: str, auto_yes: bool) -> None:
    """Print a scene-switch prompt and wait for user confirmation."""
    display = _SCENE_DISPLAY.get(scene_name, scene_name)
    print()
    print("=" * 70)

    if scene_name in _OPENPLC_SCENES:
        print(f"  OPENPLC SCENE:")
        print(f"  >>> {display} <<<")
        print()
        print("  Steps:")
        print("  1. Ensure OpenPLC Docker container is running:")
        print("     docker compose -f docker/docker-compose.openplc.yml up -d")
        print("  2. Ensure the correct ST program is uploaded and compiled")
        print("  3. Process simulator will start automatically")
    else:
        print(f"  SWITCH FACTORY I/O SCENE TO:")
        print(f"  >>> {display} <<<")
        print()
        print("  Steps:")
        print("  1. In Factory I/O: File > Open Scene > select the correct scene")
        print("  2. Press Play (F5) to start simulation")
        print("  3. Verify PLC is running (green LED on S7-1200)")

    print("=" * 70)
    if not auto_yes:
        input("  Press ENTER when ready... ")
    else:
        print("  (--yes flag set: skipping confirmation)")
        time.sleep(2)


def load_checkpoint(path: Path) -> dict:
    import json
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def save_checkpoint(path: Path, checkpoint: dict) -> None:
    import json
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(checkpoint, f, indent=2)


def run_cell(cell, loader, args) -> str:
    """Execute one experiment cell and return run_id."""
    import gc
    from cpsforge.runner.online_runner import OnlineExperimentRunner

    exp_cfg = loader.load_experiment("v2_online")
    exp_cfg.live_writes_enabled = args.live
    exp_cfg.dry_run = args.dry_run

    # Override scene from cell
    exp_cfg.scene_config = f"scenes/{cell.scene}.yaml"

    extra = {
        "context_level":          cell.context_level,
        "model_variant":          cell.model_variant,
        "finetune_status":        cell.finetune_status,
        "defense_variant":        cell.defense_variant,
        "attack_budget":          cell.attack_budget,
        "decision_interval_steps": cell.decision_interval_steps,
        "attacker_type":          cell.attacker_type,
    }

    runner = OnlineExperimentRunner(
        config=exp_cfg,
        loader=loader,
        output_base=args.output_dir,
        extra=extra,
    )
    run_id = runner.run()

    # Explicitly release GPU memory before next cell to prevent bitsandbytes
    # deadlock when loading the same model a second time in the same process.
    del runner
    gc.collect()
    try:
        import torch
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
    except Exception:
        pass

    return run_id


def main() -> None:
    args = parse_args()

    if not args.live and not args.dry_run:
        # Default: poll PLC but don't write
        logger.warning(
            "Neither --live nor --dry-run specified. Running in observation-only mode "
            "(PLC reads, no writes). Use --live for live attack writes."
        )

    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))

    from cpsforge.core.config import ConfigLoader
    from cpsforge.runner.experiment_matrix import build_matrix

    loader = ConfigLoader(configs_dir=Path("configs"))

    # Build cell list
    cells = build_matrix(
        scenes=args.scenes,
        repeats=args.repeats,
        include_rqs=args.rqs,
    )

    logger.info("Experiment matrix: %d cells across RQs %s", len(cells), args.rqs)

    # Load checkpoint to skip completed cells
    checkpoint = load_checkpoint(args.checkpoint_file)
    completed = set(checkpoint.get("completed", []))
    logger.info("Checkpoint: %d cells already completed", len(completed))

    # Group cells by scene for scene-switch prompts
    from collections import OrderedDict
    scene_groups: OrderedDict = OrderedDict()
    for cell in cells:
        if cell.cell_id not in completed:
            scene_groups.setdefault(cell.scene, []).append(cell)

    if not scene_groups:
        logger.info("All cells already completed. Nothing to do.")
        return

    total_remaining = sum(len(g) for g in scene_groups.values())
    logger.info("Remaining: %d cells across %d scenes", total_remaining, len(scene_groups))

    done = 0
    errors = 0

    for scene_name, scene_cells in scene_groups.items():
        # Prompt to switch scene in Factory I/O
        prompt_scene_switch(scene_name, args.yes)

        for cell in scene_cells:
            logger.info(
                "[%d/%d] %s  scene=%-25s ctx=%-8s model=%-12s att=%-12s def=%-12s repeat=%d",
                done + 1, total_remaining,
                cell.rq, cell.scene, cell.context_level,
                cell.model_variant, cell.attacker_type, cell.defense_variant,
                cell.repeat,
            )
            t0 = time.monotonic()
            try:
                run_id = run_cell(cell, loader, args)
                elapsed = time.monotonic() - t0
                logger.info("  Done: run_id=%s  elapsed=%.1fs", run_id, elapsed)
                completed.add(cell.cell_id)
                checkpoint["completed"] = list(completed)
                save_checkpoint(args.checkpoint_file, checkpoint)
                done += 1
            except Exception as exc:
                elapsed = time.monotonic() - t0
                logger.error("  FAILED: %s (%.1fs): %s", cell.cell_id, elapsed, exc, exc_info=True)
                errors += 1
                # Continue with next cell

    logger.info(
        "Experiment run complete: %d succeeded, %d failed out of %d attempted.",
        done, errors, done + errors,
    )


if __name__ == "__main__":
    main()
