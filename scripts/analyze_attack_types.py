#!/usr/bin/env python
"""
Analyze attack type distribution and per-type effectiveness.

Reads attacks.json from all experiment runs and computes:
  - Distribution of attack types per attacker
  - Per-type shield approval rate
  - Per-type execution success rate
  - Per-type process impact (where available)

Produces:
  - data/processed/attack_analysis/type_distribution.csv
  - data/processed/attack_analysis/per_type_metrics.csv
  - data/processed/attack_analysis/type_by_scene.csv
  - data/processed/attack_analysis/summary.json

Usage:
    python scripts/analyze_attack_types.py
    python scripts/analyze_attack_types.py --data-dir data
"""
from __future__ import annotations

import argparse
import json
import logging
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

ATTACKER_MAP = {
    "live_scripted_": "scripted",
    "live_random_": "random",
    "live_llm_": "llm_batch",
    "campaign_": "campaign",
    "agent_": "agent",
}

SCENE_MAP = {
    "from_a_to_b": "From A to B",
    "filling_tank": "Filling Tank",
    "level_control": "Level Control",
    "sorting_height_basic": "Sorting by Height",
    "sorting_weight": "Sorting by Weight",
}


def classify_experiment(name: str) -> tuple[str, str]:
    for prefix, attacker in ATTACKER_MAP.items():
        if name.startswith(prefix):
            scene_part = name[len(prefix):]
            for suffix in ("_attack", "_eval", "_debug"):
                if scene_part.endswith(suffix):
                    scene_part = scene_part[: -len(suffix)]
            return attacker, SCENE_MAP.get(scene_part, scene_part)
    return "unknown", name


def main():
    parser = argparse.ArgumentParser(description="Analyze attack type distribution")
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args()

    raw_dir = args.data_dir / "raw"
    out_dir = args.output_dir or (args.data_dir / "processed" / "attack_analysis")
    out_dir.mkdir(parents=True, exist_ok=True)

    all_attacks = []

    for exp_dir in sorted(raw_dir.iterdir()):
        if not exp_dir.is_dir():
            continue
        attacker, scene = classify_experiment(exp_dir.name)
        if attacker == "unknown":
            continue

        for rd in sorted(exp_dir.iterdir()):
            if not rd.is_dir():
                continue
            attacks_path = rd / "attacks.json"
            if not attacks_path.exists():
                continue
            with attacks_path.open() as f:
                attacks = json.load(f)
            if not isinstance(attacks, list):
                continue

            for a in attacks:
                atype = a.get("attack_type", "unknown")
                if isinstance(atype, dict):
                    atype = atype.get("value", str(atype))

                all_attacks.append({
                    "experiment": exp_dir.name,
                    "run_id": rd.name,
                    "attacker": attacker,
                    "scene": scene,
                    "attack_type": atype,
                    "target": a.get("target", ""),
                    "approved": bool(a.get("approved_by_shield", False)),
                    "executed": a.get("execution_status", "") in ("executed", "dry_run"),
                    "value": a.get("value"),
                    "duration_ms": a.get("duration_ms", 0),
                    "source": a.get("source", attacker),
                })

    if not all_attacks:
        logger.error("No attack records found.")
        return

    df = pd.DataFrame(all_attacks)
    logger.info("Loaded %d attack records from %d experiments",
                len(df), df["experiment"].nunique())

    # 1. Type distribution per attacker
    dist = df.groupby(["attacker", "attack_type"]).size().reset_index(name="count")
    dist_pivot = dist.pivot_table(
        index="attack_type", columns="attacker", values="count", fill_value=0
    )
    dist_pivot["total"] = dist_pivot.sum(axis=1)
    dist_pivot.to_csv(out_dir / "type_distribution.csv")
    logger.info("Saved type_distribution.csv")

    # 2. Per-type metrics
    type_metrics = []
    for atype, group in df.groupby("attack_type"):
        total = len(group)
        approved = group["approved"].sum()
        executed = group["executed"].sum()
        type_metrics.append({
            "attack_type": atype,
            "total_actions": total,
            "approved": int(approved),
            "executed": int(executed),
            "approval_rate": round(approved / total, 4) if total > 0 else 0,
            "execution_rate": round(executed / total, 4) if total > 0 else 0,
            "mean_duration_ms": round(float(group["duration_ms"].mean()), 1),
        })
    pd.DataFrame(type_metrics).to_csv(out_dir / "per_type_metrics.csv", index=False)
    logger.info("Saved per_type_metrics.csv")

    # 3. Type × scene matrix
    scene_type = df.groupby(["scene", "attack_type"]).agg(
        count=("approved", "size"),
        approved=("approved", "sum"),
        executed=("executed", "sum"),
    ).reset_index()
    scene_type["approval_rate"] = (scene_type["approved"] / scene_type["count"]).round(4)
    scene_type.to_csv(out_dir / "type_by_scene.csv", index=False)
    logger.info("Saved type_by_scene.csv")

    # 4. Summary
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
        "total_actions": len(df),
        "attack_types": sorted(df["attack_type"].unique().tolist()),
        "attackers": sorted(df["attacker"].unique().tolist()),
        "scenes": sorted(df["scene"].unique().tolist()),
        "type_counts": dist_pivot["total"].to_dict(),
        "overall_approval_rate": round(float(df["approved"].mean()), 4),
        "overall_execution_rate": round(float(df["executed"].mean()), 4),
    }
    with (out_dir / "summary.json").open("w") as f:
        json.dump(summary, f, indent=2, default=str)

    # Print
    print("\n" + "=" * 60)
    print("ATTACK TYPE ANALYSIS")
    print("=" * 60)
    print(f"Total actions: {len(df)}")
    print(f"Attack types:  {', '.join(summary['attack_types'])}")
    print()
    print("Type distribution:")
    print(dist_pivot.to_string())
    print()
    print("Per-type approval/execution rates:")
    for m in type_metrics:
        print(f"  {m['attack_type']:25s}  n={m['total_actions']:4d}  "
              f"appr={m['approval_rate']:.2f}  exec={m['execution_rate']:.2f}")
    print(f"\nOutputs: {out_dir}")


if __name__ == "__main__":
    main()
