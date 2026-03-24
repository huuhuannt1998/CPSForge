#!/usr/bin/env python
"""
Evaluate false positive rates of all detectors on benign baseline traces.

Replays existing baseline (no-attack) traces through every available detector
and measures false-alarm rates. This establishes the FP floor for each
detector-scene combination, which is required for a journal-quality evaluation.

Reads:
  - Baseline traces from data/raw/baseline_*/
  - Detector configs from configs/defenders/

Produces:
  - data/processed/benign_fp/per_detector_fp.csv
  - data/processed/benign_fp/per_scene_fp.csv
  - data/processed/benign_fp/summary.json

Usage:
    python scripts/evaluate_benign_fp.py
    python scripts/evaluate_benign_fp.py --data-dir data --output-dir data/processed/benign_fp
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cpsforge.core.config import DefenderConfig
from cpsforge.core.models import PlantSnapshot, AttackContext, DefenseContext, SafetyContext
from cpsforge.defenders.factory import build_defender

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Map baseline experiment folders to scene names
BASELINE_EXPERIMENTS = {
    "baseline_from_a_to_b":           "from_a_to_b",
    "baseline_filling_tank":          "filling_tank",
    "baseline_level_control":         "level_control",
    "baseline_sorting_height_basic":  "sorting_height_basic",
    "baseline_queue_items":           "queue_items",
    "level_control_baseline":         "level_control",
    "sorting_weight_baseline":        "sorting_weight",
}

# Map scene names to display names
SCENE_DISPLAY = {
    "from_a_to_b": "From A to B",
    "filling_tank": "Filling Tank",
    "level_control": "Level Control",
    "sorting_height_basic": "Sorting by Height",
    "sorting_weight": "Sorting by Weight",
    "queue_items": "Queue Items",
}


def discover_baselines(raw_dir: Path) -> dict[str, list[Path]]:
    """Find all baseline trace files grouped by scene."""
    scene_traces: dict[str, list[Path]] = defaultdict(list)
    for exp_name, scene in BASELINE_EXPERIMENTS.items():
        exp_dir = raw_dir / exp_name
        if not exp_dir.exists():
            continue
        for rd in sorted(exp_dir.iterdir()):
            if not rd.is_dir():
                continue
            trace_path = rd / "trace.parquet"
            if trace_path.exists():
                scene_traces[scene].append(trace_path)
                logger.info("Found baseline trace: %s (%s)", trace_path, scene)
    return dict(scene_traces)


def discover_detectors(configs_dir: Path) -> dict[str, list[DefenderConfig]]:
    """Load detector configs grouped by scene."""
    scene_detectors: dict[str, list[DefenderConfig]] = defaultdict(list)
    defenders_dir = configs_dir / "defenders"
    if not defenders_dir.exists():
        logger.warning("No defenders config directory found at %s", defenders_dir)
        return dict(scene_detectors)

    for fp in sorted(defenders_dir.glob("*.yaml")) + sorted(defenders_dir.glob("*.yml")):
        try:
            import yaml
            with fp.open() as f:
                cfg_data = yaml.safe_load(f)
            if cfg_data is None:
                continue
            config = DefenderConfig(**cfg_data)
            scene_detectors[config.scene_name].append(config)
        except Exception as e:
            logger.warning("Failed to load detector config %s: %s", fp, e)
    return dict(scene_detectors)


def trace_to_snapshots(trace_path: Path, scene_name: str, run_id: str) -> list[PlantSnapshot]:
    """Convert a parquet trace into a list of PlantSnapshot objects."""
    df = pd.read_parquet(trace_path)
    snapshots = []

    for _, row in df.iterrows():
        # Extract tag values from columns
        sensors = {}
        actuators = {}
        setpoints = {}
        controller_state = {}
        alarms = {}

        for col in df.columns:
            if col in ("timestamp", "step_id", "run_id", "scene_name",
                       "attack_active", "attack_action_id", "attack_type"):
                continue
            val = row[col]
            if pd.isna(val):
                continue
            # Classify by common naming patterns
            col_lower = col.lower()
            if any(k in col_lower for k in ("sensor", "level", "meter", "weight",
                                            "temperature", "pressure", "flow")):
                sensors[col] = float(val) if isinstance(val, (int, float)) else val
            elif any(k in col_lower for k in ("valve", "pump", "motor", "conveyor",
                                              "actuator", "speed", "piston")):
                actuators[col] = float(val) if isinstance(val, (int, float)) else val
            elif "setpoint" in col_lower or "target" in col_lower:
                setpoints[col] = float(val) if isinstance(val, (int, float)) else val
            elif "alarm" in col_lower:
                alarms[col] = val
            elif "mode" in col_lower or "state" in col_lower:
                controller_state[col] = val
            else:
                sensors[col] = float(val) if isinstance(val, (int, float)) else val

        ts = row.get("timestamp", datetime.now(timezone.utc))
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        elif not isinstance(ts, datetime):
            ts = datetime.now(timezone.utc)

        snap = PlantSnapshot(
            timestamp=ts,
            scene_name=scene_name,
            run_id=run_id,
            step_id=int(row.get("step_id", 0)),
            sensors=sensors,
            actuators=actuators,
            controller_state=controller_state,
            alarms=alarms,
            setpoints=setpoints,
            derived_features={},
            attack_context=AttackContext(),
            defense_context=DefenseContext(),
            safety_context=SafetyContext(),
        )
        snapshots.append(snap)

    return snapshots


def evaluate_detector_on_trace(
    detector_config: DefenderConfig,
    snapshots: list[PlantSnapshot],
) -> dict:
    """Run a detector on benign snapshots and count false positives."""
    try:
        detector = build_defender(detector_config)
    except Exception as e:
        return {"error": str(e), "fp_count": -1, "fp_rate": 0.0,
                "detector_name": detector_config.name,
                "detector_type": detector_config.detector_type,
                "total_steps": len(snapshots), "severity_counts": {},
                "affected_tags": []}

    total_events = []
    for snap in snapshots:
        try:
            detector.observe(snap)
            events = detector.detect(snap)
            total_events.extend(events)
        except Exception as e:
            # Feature dimension mismatch or other runtime errors
            logger.debug("Detector %s error on step: %s", detector_config.name, e)
            return {"error": str(e), "fp_count": -1, "fp_rate": 0.0,
                    "detector_name": detector_config.name,
                    "detector_type": detector_config.detector_type,
                    "total_steps": len(snapshots), "severity_counts": {},
                    "affected_tags": []}

    return {
        "detector_name": detector_config.name,
        "detector_type": detector_config.detector_type,
        "total_steps": len(snapshots),
        "fp_count": len(total_events),  # All events on benign data are FPs
        "fp_rate": len(total_events) / len(snapshots) if snapshots else 0.0,
        "severity_counts": _count_severities(total_events),
        "affected_tags": list(set(t for ev in total_events for t in ev.affected_tags)),
    }


def _count_severities(events: list) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for ev in events:
        sev = str(ev.severity) if hasattr(ev, "severity") else "unknown"
        counts[sev] += 1
    return dict(counts)


def main():
    parser = argparse.ArgumentParser(description="Evaluate benign FP rates for all detectors")
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    parser.add_argument("--configs-dir", type=Path, default=Path("configs"))
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args()

    raw_dir = args.data_dir / "raw"
    out_dir = args.output_dir or (args.data_dir / "processed" / "benign_fp")
    out_dir.mkdir(parents=True, exist_ok=True)

    # Discover baselines
    scene_traces = discover_baselines(raw_dir)
    if not scene_traces:
        logger.error("No baseline traces found in %s. Run benign baseline experiments first.", raw_dir)
        sys.exit(1)
    logger.info("Found baseline traces for %d scenes", len(scene_traces))

    # Discover detectors
    scene_detectors = discover_detectors(args.configs_dir)
    if not scene_detectors:
        logger.error("No detector configs found in %s/defenders/", args.configs_dir)
        sys.exit(1)
    logger.info("Found detector configs for %d scenes", len(scene_detectors))

    # Evaluate
    all_results = []
    for scene, trace_paths in scene_traces.items():
        detectors = scene_detectors.get(scene, [])
        if not detectors:
            logger.warning("No detectors configured for scene %s, skipping", scene)
            continue

        for trace_path in trace_paths:
            run_id = trace_path.parent.name
            logger.info("Loading trace %s (%d steps expected)", trace_path, -1)
            snapshots = trace_to_snapshots(trace_path, scene, run_id)
            logger.info("Loaded %d snapshots from %s", len(snapshots), trace_path)

            for det_config in detectors:
                logger.info("  Evaluating %s (%s) on %s...",
                            det_config.name, det_config.detector_type, scene)
                result = evaluate_detector_on_trace(det_config, snapshots)
                result["scene"] = scene
                result["scene_display"] = SCENE_DISPLAY.get(scene, scene)
                result["trace_path"] = str(trace_path)
                result["run_id"] = run_id
                result["total_baseline_steps"] = len(snapshots)
                all_results.append(result)

                fp_rate = result.get("fp_rate", 0)
                logger.info("    → %d FP events / %d steps (FP rate: %.4f)",
                            result["fp_count"], len(snapshots), fp_rate)

    if not all_results:
        logger.error("No evaluations completed. Check configs and baselines.")
        sys.exit(1)

    # Save per-detector results
    df = pd.DataFrame(all_results)
    df.to_csv(out_dir / "per_detector_fp.csv", index=False)

    # Per-scene summary
    scene_summary = df.groupby(["scene_display", "detector_name"]).agg({
        "fp_count": "mean",
        "fp_rate": "mean",
        "total_baseline_steps": "sum",
    }).round(4).reset_index()
    scene_summary.to_csv(out_dir / "per_scene_fp.csv", index=False)

    # Overall summary
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
        "total_evaluations": len(all_results),
        "scenes_evaluated": sorted(df["scene"].unique().tolist()),
        "detectors_evaluated": sorted(df["detector_name"].unique().tolist()),
        "overall_fp_rate": round(float(df["fp_rate"].mean()), 4),
        "per_scene": {},
    }
    for scene in df["scene"].unique():
        sdf = df[df["scene"] == scene]
        summary["per_scene"][scene] = {
            "display_name": SCENE_DISPLAY.get(scene, scene),
            "n_traces": len(sdf["run_id"].unique()),
            "n_detectors": len(sdf["detector_name"].unique()),
            "mean_fp_rate": round(float(sdf["fp_rate"].mean()), 4),
            "detectors": {},
        }
        for _, row in sdf.iterrows():
            summary["per_scene"][scene]["detectors"][row["detector_name"]] = {
                "fp_count": int(row["fp_count"]),
                "fp_rate": round(float(row["fp_rate"]), 4),
                "steps": int(row["total_baseline_steps"]),
            }

    with (out_dir / "summary.json").open("w") as f:
        json.dump(summary, f, indent=2, default=str)

    # Print summary
    print("\n" + "=" * 60)
    print("BENIGN FALSE-POSITIVE EVALUATION")
    print("=" * 60)
    print(f"Scenes evaluated:    {len(df['scene'].unique())}")
    print(f"Total evaluations:   {len(all_results)}")
    print(f"Overall mean FP rate: {summary['overall_fp_rate']:.4f}")
    print()
    for scene, info in summary["per_scene"].items():
        print(f"  {info['display_name']}:")
        for det, det_info in info["detectors"].items():
            print(f"    {det}: FP={det_info['fp_count']}, rate={det_info['fp_rate']:.4f}")
    print(f"\nOutputs: {out_dir}")


if __name__ == "__main__":
    main()
