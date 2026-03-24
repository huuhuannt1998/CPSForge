#!/usr/bin/env python3
"""
CPSForge Journal Experiment Runner
====================================
Single entry point for all Computers & Security experiments.

Organizes experiments into phases that can be run independently.
Each phase prints exact commands, waits for Factory I/O scene confirmation,
and logs results to a structured manifest.

Phases:
  Phase 1 — Repeated LLM batch trials          (PLC required, LM Studio required)
  Phase 2 — Repeated campaign trials            (PLC required, LM Studio required)
  Phase 3 — Defense ablation study              (PLC required)
  Phase 4 — Extended detector comparison        (PLC required for training)
  Phase 5 — Campaign on additional scenes       (PLC required, LM Studio required)

Post-processing (no PLC):
  Phase P — Run all offline analysis scripts

Prerequisites:
  - PLC at 192.168.0.1
  - Factory I/O with correct scene in PLAY mode
  - LM Studio at http://127.0.0.1:1234/v1 (for LLM/campaign phases)
  - pip install -e .

Usage:
  python scripts/run_journal_experiments.py --phase 1
  python scripts/run_journal_experiments.py --phase 3 --scene level_control
  python scripts/run_journal_experiments.py --phase P
  python scripts/run_journal_experiments.py --phase all
  python scripts/run_journal_experiments.py --list
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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent
DATA_RAW = ROOT / "data" / "raw"
DATA_PROCESSED = ROOT / "data" / "processed"
MANIFEST_PATH = ROOT / "data" / "processed" / "journal_experiment_manifest.json"

# ── Scene definitions ───────────────────────────────────────────────────

FIVE_SCENES = [
    "from_a_to_b",
    "filling_tank",
    "level_control",
    "sorting_height_basic",
    "sorting_weight",
]

SCENE_DISPLAY = {
    "from_a_to_b": "From A to B (S1)",
    "filling_tank": "Filling Tank (S3)",
    "level_control": "Level Control (S12)",
    "sorting_height_basic": "Sorting Height (S19)",
    "sorting_weight": "Sorting Weight (S20)",
}

# ── Experiment registry ─────────────────────────────────────────────────

EXPERIMENTS: dict[str, dict] = {}


def _reg(exp_id: str, phase: int, tier: str, scene: str, description: str,
         cmd: list[str], paper_target: str, repeats: int = 1):
    """Register an experiment in the global registry."""
    EXPERIMENTS[exp_id] = {
        "phase": phase,
        "tier": tier,
        "scene": scene,
        "description": description,
        "cmd": cmd,
        "paper_target": paper_target,
        "repeats": repeats,
    }


def _attack_cmd(scene: str, attacker: str, experiment: str,
                max_steps: int = 150) -> list[str]:
    return [
        sys.executable, "-m", "cpsforge", "run", "attack",
        "--scene", scene, "--attacker", attacker,
        "--experiment", experiment,
        "--no-dry-run", "--eval-run", "--max-steps", str(max_steps), "--yes",
    ]


def _agent_cmd(scene: str, experiment: str, max_steps: int = 200) -> list[str]:
    return [
        sys.executable, "-m", "cpsforge", "run", "agent",
        "--scene", scene, "--experiment", experiment,
        "--no-dry-run", "--eval-run", "--max-steps", str(max_steps), "--yes",
    ]


def _closed_loop_cmd(scene: str, experiment: str, attacker: str = "campaign",
                     rounds: int = 3, max_steps: int = 150) -> list[str]:
    return [
        sys.executable, "-m", "cpsforge", "run", "closed-loop",
        "--scene", scene, "--experiment", experiment,
        "--attacker", attacker, "--rounds", str(rounds),
        "--no-dry-run", "--max-steps", str(max_steps), "--yes",
    ]


# ── Phase 1: Repeated LLM batch trials ─────────────────────────────────

for sc in FIVE_SCENES:
    exp_name = f"live_llm_{sc}"
    _reg(
        exp_id=f"p1_llm_{sc}",
        phase=1, tier="REQUIRED", scene=sc,
        description=f"LLM batch attack on {SCENE_DISPLAY[sc]} (need ≥3 total runs)",
        cmd=_attack_cmd(sc, "llm", exp_name),
        paper_target="Table 1 (attack), Table 2 (shield), Table 3 (defender), Fig ASR",
        repeats=2,  # need 2 more per scene to reach ≥3 total
    )

# ── Phase 2: Repeated campaign trials ──────────────────────────────────

_reg(
    exp_id="p2_campaign_level_control",
    phase=2, tier="REQUIRED", scene="level_control",
    description="Campaign attack on Level Control (need 2 more for ≥3 total)",
    cmd=_attack_cmd("level_control", "campaign", "campaign_level_control_attack", 200),
    paper_target="Table 5 (adaptation), Fig adaptation-line",
    repeats=2,
)
_reg(
    exp_id="p2_campaign_sorting_weight",
    phase=2, tier="REQUIRED", scene="sorting_weight",
    description="Campaign attack on Sorting Weight (need 1 more for ≥3 total)",
    cmd=_attack_cmd("sorting_weight", "campaign", "campaign_sorting_weight_attack", 200),
    paper_target="Table 5 (adaptation)",
    repeats=1,
)

# ── Phase 3: Defense ablation study ─────────────────────────────────────

ABLATION_CONFIGS = [
    "ablation_threshold_only",
    "ablation_invariant_only",
    "ablation_ml_only",
    "ablation_full_ensemble",
]

for sc in ["level_control", "sorting_weight"]:
    for cfg in ABLATION_CONFIGS:
        exp_name = f"{cfg}_{sc}"
        short = cfg.replace("ablation_", "")
        _reg(
            exp_id=f"p3_{exp_name}",
            phase=3, tier="REQUIRED", scene=sc,
            description=f"Ablation ({short}) on {SCENE_DISPLAY[sc]}",
            cmd=_attack_cmd(sc, "scripted", exp_name),
            paper_target="Table 7 (ablation), Fig ablation-bar",
            repeats=1,
        )

# ── Phase 4: Extended detector comparison ───────────────────────────────

for sc in ["filling_tank", "from_a_to_b", "sorting_height_basic"]:
    _reg(
        exp_id=f"p4_train_ml_{sc}",
        phase=4, tier="HIGH-VALUE", scene=sc,
        description=f"Train ML detectors on {SCENE_DISPLAY[sc]} baseline",
        cmd=[sys.executable, "scripts/train_ml_detectors.py", "--scene", sc],
        paper_target="Table 6 (cross-detector)",
    )
    _reg(
        exp_id=f"p4_compare_{sc}",
        phase=4, tier="HIGH-VALUE", scene=sc,
        description=f"Run detector comparison on {SCENE_DISPLAY[sc]}",
        cmd=[sys.executable, "scripts/run_detector_comparison.py", "--scene", sc],
        paper_target="Table 6 (cross-detector), Fig detector-comparison",
    )

# ── Phase 5: Campaign on additional scenes ──────────────────────────────

for sc in ["from_a_to_b", "filling_tank", "sorting_height_basic"]:
    _reg(
        exp_id=f"p5_campaign_{sc}",
        phase=5, tier="STRETCH", scene=sc,
        description=f"Campaign attack on {SCENE_DISPLAY[sc]}",
        cmd=_attack_cmd(sc, "campaign", f"campaign_{sc}_attack", 200),
        paper_target="Table 5 extension",
        repeats=1,
    )


# ── Execution engine ───────────────────────────────────────────────────

def load_manifest() -> dict:
    if MANIFEST_PATH.exists():
        return json.loads(MANIFEST_PATH.read_text())
    return {"created": datetime.now(timezone.utc).isoformat(), "runs": []}


def save_manifest(manifest: dict):
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    manifest["updated"] = datetime.now(timezone.utc).isoformat()
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2))


def run_experiment(exp_id: str, exp: dict, manifest: dict) -> int:
    """Run a single experiment and record it in the manifest."""
    logger.info("=" * 60)
    logger.info("EXPERIMENT: %s", exp_id)
    logger.info("  Scene:  %s", exp["scene"])
    logger.info("  Tier:   %s", exp["tier"])
    logger.info("  Target: %s", exp["paper_target"])
    logger.info("  Cmd:    %s", " ".join(exp["cmd"]))
    logger.info("=" * 60)

    t0 = time.time()
    result = subprocess.run(exp["cmd"], capture_output=False)
    elapsed = time.time() - t0

    record = {
        "exp_id": exp_id,
        "phase": exp["phase"],
        "tier": exp["tier"],
        "scene": exp["scene"],
        "exit_code": result.returncode,
        "elapsed_s": round(elapsed, 1),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "paper_target": exp["paper_target"],
    }
    manifest["runs"].append(record)
    save_manifest(manifest)

    if result.returncode != 0:
        logger.error("FAILED: %s (exit %d, %.1fs)", exp_id, result.returncode, elapsed)
    else:
        logger.info("OK: %s (%.1fs)", exp_id, elapsed)
    return result.returncode


def run_phase(phase: int, scene_filter: str | None, manifest: dict):
    """Run all experiments in a phase, prompting for scene changes."""
    phase_exps = {k: v for k, v in EXPERIMENTS.items() if v["phase"] == phase}
    if scene_filter:
        phase_exps = {k: v for k, v in phase_exps.items()
                      if v["scene"] == scene_filter}

    if not phase_exps:
        logger.warning("No experiments found for phase %d (scene=%s)", phase, scene_filter)
        return

    # Group by scene for efficient Factory I/O switching
    by_scene: dict[str, list[tuple[str, dict]]] = {}
    for eid, exp in phase_exps.items():
        by_scene.setdefault(exp["scene"], []).append((eid, exp))

    for sc, exps in by_scene.items():
        print(f"\n{'=' * 60}")
        print(f"  Load Factory I/O scene: {SCENE_DISPLAY.get(sc, sc)}")
        print(f"  Experiments to run: {len(exps)}")
        print(f"{'=' * 60}")
        input(f"  >>> Press Enter when {sc} is loaded and running...")

        for eid, exp in exps:
            for rep in range(exp.get("repeats", 1)):
                if exp.get("repeats", 1) > 1:
                    logger.info("  Repeat %d/%d", rep + 1, exp["repeats"])
                rc = run_experiment(eid, exp, manifest)
                if rc != 0:
                    retry = input(f"  Experiment failed. Retry? [y/N] ").strip().lower()
                    if retry == "y":
                        run_experiment(eid, exp, manifest)
                time.sleep(3)


def run_postprocessing():
    """Run all offline analysis scripts."""
    scripts = [
        ("Aggregate results", [sys.executable, "scripts/aggregate_results.py"]),
        ("Generate tables", [sys.executable, "scripts/generate_tables.py"]),
        ("Generate figures", [sys.executable, "scripts/generate_figures.py"]),
        ("Analyze attack types", [sys.executable, "scripts/analyze_attack_types.py"]),
        ("Generate timelines", [sys.executable, "scripts/generate_timeline_figure.py"]),
        ("Evaluate benign FP", [sys.executable, "scripts/evaluate_benign_fp.py"]),
        ("Measure overhead", [sys.executable, "scripts/measure_overhead.py"]),
        ("Generate ablation table", [sys.executable, "scripts/generate_ablation_table.py"]),
    ]
    for desc, cmd in scripts:
        logger.info("--- %s ---", desc)
        logger.info("  %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=False)
        if result.returncode != 0:
            logger.error("  FAILED: %s", desc)
        else:
            logger.info("  OK: %s", desc)
        time.sleep(1)


def list_experiments():
    """Print all registered experiments."""
    print(f"\n{'Phase':<6} {'Tier':<12} {'ID':<40} {'Scene':<25} {'Target'}")
    print("-" * 120)
    for eid, exp in sorted(EXPERIMENTS.items(), key=lambda x: (x[1]["phase"], x[0])):
        print(f"{exp['phase']:<6} {exp['tier']:<12} {eid:<40} "
              f"{SCENE_DISPLAY.get(exp['scene'], exp['scene']):<25} {exp['paper_target']}")
    print(f"\nTotal: {len(EXPERIMENTS)} experiments")
    counts = {}
    for exp in EXPERIMENTS.values():
        counts[exp["tier"]] = counts.get(exp["tier"], 0) + exp.get("repeats", 1)
    for tier, n in sorted(counts.items()):
        print(f"  {tier}: {n} runs")


def main():
    parser = argparse.ArgumentParser(
        description="CPSForge Journal Experiment Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--phase",
        choices=["1", "2", "3", "4", "5", "P", "all"],
        help="Which phase to run (1-5 = PLC phases, P = post-processing, all = everything)",
    )
    parser.add_argument("--scene", choices=FIVE_SCENES, help="Filter to one scene")
    parser.add_argument("--list", action="store_true", help="List all experiments and exit")
    args = parser.parse_args()

    if args.list:
        list_experiments()
        return

    if not args.phase:
        parser.print_help()
        return

    manifest = load_manifest()

    if args.phase == "all":
        for p in [1, 2, 3, 4, 5]:
            run_phase(p, args.scene, manifest)
        run_postprocessing()
    elif args.phase == "P":
        run_postprocessing()
    else:
        run_phase(int(args.phase), args.scene, manifest)

    save_manifest(manifest)
    logger.info("Done. Manifest saved to %s", MANIFEST_PATH)


if __name__ == "__main__":
    main()
