#!/usr/bin/env python
"""
Measure computational overhead of CPSForge framework components.

Instruments per-step timing for: PLC polling, shield evaluation,
detector inference, trace logging, and total cycle time.

Can run in two modes:
  1. Replay mode (default): Replays existing baseline traces offline
  2. Live mode (--live): Measures overhead during real PLC polling

Produces:
  - data/processed/overhead/per_step_timing.csv
  - data/processed/overhead/summary.json
  - data/processed/overhead/timing_boxplot.pdf

Usage:
    python scripts/measure_overhead.py
    python scripts/measure_overhead.py --live --scene level_control --steps 100
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def replay_overhead(data_dir: Path, configs_dir: Path) -> pd.DataFrame:
    """Measure overhead by replaying baseline traces through detectors."""
    from cpsforge.core.config import DefenderConfig
    from cpsforge.core.models import (
        PlantSnapshot, AttackAction, AttackContext, DefenseContext,
        SafetyContext, AttackType, ExecutionStatus,
    )
    from cpsforge.defenders.factory import build_defender
    from cpsforge.shield.engine import ShieldEngine

    raw_dir = data_dir / "raw"
    import yaml

    # Find baseline traces
    baselines = {}
    for exp_dir in sorted(raw_dir.iterdir()):
        if not exp_dir.is_dir() or "baseline" not in exp_dir.name:
            continue
        for rd in sorted(exp_dir.iterdir()):
            if not rd.is_dir():
                continue
            tp = rd / "trace.parquet"
            if tp.exists():
                scene = exp_dir.name.replace("baseline_", "").replace("_baseline", "")
                baselines[scene] = tp
                break  # One trace per scene

    if not baselines:
        logger.error("No baseline traces found.")
        return pd.DataFrame()

    # Load detector configs
    scene_detectors: dict[str, list] = defaultdict(list)
    det_dir = configs_dir / "defenders"
    if det_dir.exists():
        for fp in sorted(det_dir.glob("*.yaml")) + sorted(det_dir.glob("*.yml")):
            try:
                with fp.open() as f:
                    cfg = yaml.safe_load(f)
                if cfg:
                    dc = DefenderConfig(**cfg)
                    scene_detectors[dc.scene_name].append(dc)
            except Exception:
                pass

    # Load shield configs
    scene_shields = {}
    shield_dir = configs_dir / "scenes"
    if shield_dir.exists():
        for fp in sorted(shield_dir.glob("*.yaml")) + sorted(shield_dir.glob("*.yml")):
            try:
                with fp.open() as f:
                    cfg = yaml.safe_load(f)
                if cfg and "safety_rules" in cfg:
                    scene_name = cfg.get("scene_name", fp.stem)
                    scene_shields[scene_name] = cfg
            except Exception:
                pass

    timing_rows = []

    for scene, trace_path in baselines.items():
        logger.info("Measuring overhead for scene: %s", scene)
        df = pd.read_parquet(trace_path)

        # Build detectors for this scene
        detectors = []
        for dc in scene_detectors.get(scene, []):
            try:
                det = build_defender(dc)
                detectors.append(det)
            except Exception as e:
                logger.warning("Failed to build detector %s: %s", dc.name, e)

        # Build a dummy shield for timing
        shield = None
        try:
            shield_cfg = scene_shields.get(scene)
            if shield_cfg:
                from cpsforge.shield.engine import ShieldEngine
                shield = ShieldEngine(shield_cfg.get("safety_rules", []),
                                      shield_cfg.get("writable_tags", []))
        except Exception:
            pass

        # Build a dummy attack action for shield timing
        dummy_action = AttackAction(
            action_id="overhead_test",
            attack_type=AttackType.SETPOINT_SHIFT,
            target="dummy_tag",
            mode="override",
            value=50.0,
            duration_ms=500,
            rationale="overhead measurement",
            expected_effect="none",
            source="scripted",
        )

        for idx, row in df.iterrows():
            step = int(row.get("step_id", idx))

            # Simulate snapshot construction timing
            t0 = time.perf_counter()
            sensors = {}
            actuators = {}
            for col in df.columns:
                if col in ("timestamp", "step_id", "run_id", "scene_name",
                           "attack_active", "attack_action_id", "attack_type"):
                    continue
                val = row[col]
                if pd.notna(val):
                    sensors[col] = val

            snap = PlantSnapshot(
                timestamp=datetime.now(timezone.utc),
                scene_name=scene,
                run_id="overhead_test",
                step_id=step,
                sensors=sensors,
                actuators=actuators,
                controller_state={},
                alarms={},
                setpoints={},
                derived_features={},
                attack_context=AttackContext(),
                defense_context=DefenseContext(),
                safety_context=SafetyContext(),
            )
            t_snapshot = time.perf_counter() - t0

            # Shield evaluation timing
            t0 = time.perf_counter()
            if shield:
                try:
                    shield.evaluate(dummy_action, snap)
                except Exception:
                    pass
            t_shield = time.perf_counter() - t0

            # Detection timing (all detectors)
            t0 = time.perf_counter()
            for det in detectors:
                try:
                    det.observe(snap)
                    det.detect(snap)
                except Exception:
                    pass
            t_detect = time.perf_counter() - t0

            # Trace logging timing (serialize snapshot)
            t0 = time.perf_counter()
            _ = snap.model_dump() if hasattr(snap, "model_dump") else snap.dict()
            t_log = time.perf_counter() - t0

            t_total = t_snapshot + t_shield + t_detect + t_log

            timing_rows.append({
                "scene": scene,
                "step_id": step,
                "t_snapshot_ms": t_snapshot * 1000,
                "t_shield_ms": t_shield * 1000,
                "t_detect_ms": t_detect * 1000,
                "t_log_ms": t_log * 1000,
                "t_total_ms": t_total * 1000,
                "n_detectors": len(detectors),
            })

    return pd.DataFrame(timing_rows)


def generate_summary(df: pd.DataFrame) -> dict:
    """Compute summary statistics from timing data."""
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
        "total_steps_measured": len(df),
        "scenes": sorted(df["scene"].unique().tolist()),
        "overall": {},
        "per_scene": {},
        "per_component": {},
    }

    # Overall timing
    for col in ["t_snapshot_ms", "t_shield_ms", "t_detect_ms", "t_log_ms", "t_total_ms"]:
        vals = df[col].dropna().values
        summary["overall"][col] = {
            "mean": round(float(np.mean(vals)), 3),
            "std": round(float(np.std(vals)), 3),
            "p50": round(float(np.percentile(vals, 50)), 3),
            "p90": round(float(np.percentile(vals, 90)), 3),
            "p95": round(float(np.percentile(vals, 95)), 3),
            "p99": round(float(np.percentile(vals, 99)), 3),
            "max": round(float(np.max(vals)), 3),
        }

    # Per-scene
    for scene, sdf in df.groupby("scene"):
        scene_stats = {}
        for col in ["t_snapshot_ms", "t_shield_ms", "t_detect_ms", "t_log_ms", "t_total_ms"]:
            vals = sdf[col].dropna().values
            scene_stats[col] = {
                "mean": round(float(np.mean(vals)), 3),
                "p50": round(float(np.percentile(vals, 50)), 3),
                "p99": round(float(np.percentile(vals, 99)), 3),
            }
        scene_stats["n_steps"] = len(sdf)
        scene_stats["n_detectors"] = int(sdf["n_detectors"].iloc[0]) if len(sdf) > 0 else 0
        summary["per_scene"][scene] = scene_stats

    return summary


def generate_boxplot(df: pd.DataFrame, out_dir: Path, fmt: str = "pdf"):
    """Generate timing boxplot figure."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    components = {
        "Snapshot": "t_snapshot_ms",
        "Shield": "t_shield_ms",
        "Detection": "t_detect_ms",
        "Logging": "t_log_ms",
        "Total": "t_total_ms",
    }

    fig, ax = plt.subplots(figsize=(8, 4))
    data = [df[col].dropna().values for col in components.values()]
    bp = ax.boxplot(data, labels=list(components.keys()), patch_artist=True,
                    showfliers=False)

    colors = ["#3498db", "#e74c3c", "#2ecc71", "#f39c12", "#9b59b6"]
    for patch, color in zip(bp["boxes"], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)

    ax.set_ylabel("Time (ms)")
    ax.set_title("Per-Step Computational Overhead")
    ax.grid(axis="y", alpha=0.3)

    path = out_dir / f"timing_boxplot.{fmt}"
    fig.savefig(path, bbox_inches="tight", dpi=300)
    plt.close(fig)
    logger.info("Saved %s", path)


def main():
    parser = argparse.ArgumentParser(description="Measure CPSForge overhead")
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    parser.add_argument("--configs-dir", type=Path, default=Path("configs"))
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--format", choices=["pdf", "png"], default="pdf")
    args = parser.parse_args()

    out_dir = args.output_dir or (args.data_dir / "processed" / "overhead")
    out_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Running overhead measurement in replay mode...")
    df = replay_overhead(args.data_dir, args.configs_dir)

    if df.empty:
        logger.error("No timing data collected.")
        sys.exit(1)

    # Save raw timing data
    csv_path = out_dir / "per_step_timing.csv"
    df.to_csv(csv_path, index=False)
    logger.info("Saved per-step timing: %s (%d rows)", csv_path, len(df))

    # Summary statistics
    summary = generate_summary(df)
    with (out_dir / "summary.json").open("w") as f:
        json.dump(summary, f, indent=2)
    logger.info("Saved summary.json")

    # Boxplot
    try:
        generate_boxplot(df, out_dir, args.format)
    except Exception as e:
        logger.warning("Failed to generate boxplot: %s", e)

    # Print summary
    print("\n" + "=" * 60)
    print("OVERHEAD MEASUREMENT SUMMARY")
    print("=" * 60)
    print(f"Total steps measured: {len(df)}")
    print(f"Scenes: {', '.join(summary['scenes'])}")
    print()
    print("Per-component timing (ms):")
    print(f"  {'Component':<15} {'Mean':>8} {'P50':>8} {'P95':>8} {'P99':>8} {'Max':>8}")
    print("  " + "-" * 55)
    for col_name, col_key in [("Snapshot", "t_snapshot_ms"), ("Shield", "t_shield_ms"),
                               ("Detection", "t_detect_ms"), ("Logging", "t_log_ms"),
                               ("Total", "t_total_ms")]:
        s = summary["overall"][col_key]
        print(f"  {col_name:<15} {s['mean']:8.3f} {s['p50']:8.3f} "
              f"{s['p95']:8.3f} {s['p99']:8.3f} {s['max']:8.3f}")

    print(f"\nOutputs: {out_dir}")


if __name__ == "__main__":
    main()
