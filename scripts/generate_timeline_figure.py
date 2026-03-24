#!/usr/bin/env python
"""
Generate timeline figure showing sensor values, attack windows, and detection events.

Reads a single representative run and plots:
  - Top panel: sensor time series with attack injection windows shaded
  - Bottom panel: detection events (as markers with severity coloring)

Usage:
    python scripts/generate_timeline_figure.py --experiment live_scripted_level_control
    python scripts/generate_timeline_figure.py --experiment live_scripted_level_control --run-id 20260317T... --format pdf
"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def find_run_dir(raw_dir: Path, experiment: str, run_id: str | None = None) -> Path | None:
    """Locate a run directory within an experiment."""
    exp_dir = raw_dir / experiment
    if not exp_dir.exists():
        logger.error("Experiment directory not found: %s", exp_dir)
        return None

    if run_id:
        rd = exp_dir / run_id
        return rd if rd.exists() else None

    # Use the first run directory
    for rd in sorted(exp_dir.iterdir()):
        if rd.is_dir() and (rd / "trace.parquet").exists():
            return rd
    return None


def generate_timeline(run_dir: Path, out_dir: Path, fmt: str, max_tags: int = 4):
    """Generate the timeline figure from a single run."""
    trace_path = run_dir / "trace.parquet"
    if not trace_path.exists():
        logger.error("No trace.parquet in %s", run_dir)
        return None

    # Load data
    df = pd.read_parquet(trace_path)
    logger.info("Loaded trace: %d steps, %d columns", len(df), len(df.columns))

    attacks = []
    attacks_path = run_dir / "attacks.json"
    if attacks_path.exists():
        with attacks_path.open() as f:
            attacks = json.load(f)
        if not isinstance(attacks, list):
            attacks = []

    detections = []
    det_path = run_dir / "detections.json"
    if det_path.exists():
        with det_path.open() as f:
            detections = json.load(f)
        if not isinstance(detections, list):
            detections = []

    # Identify numeric sensor columns (excluding metadata)
    skip_cols = {"timestamp", "step_id", "run_id", "scene_name",
                 "attack_active", "attack_action_id", "attack_type"}
    numeric_cols = []
    for col in df.columns:
        if col in skip_cols:
            continue
        if pd.api.types.is_numeric_dtype(df[col]):
            # Prefer columns with actual variance
            if df[col].std() > 0.01:
                numeric_cols.append(col)

    # Pick the most interesting tags (highest variance)
    if len(numeric_cols) > max_tags:
        variances = {c: df[c].var() for c in numeric_cols}
        numeric_cols = sorted(variances, key=variances.get, reverse=True)[:max_tags]

    if not numeric_cols:
        logger.error("No numeric columns with variance found in trace.")
        return None

    logger.info("Plotting tags: %s", numeric_cols)

    # Create figure
    fig, axes = plt.subplots(
        2, 1, figsize=(10, 6),
        height_ratios=[3, 1],
        sharex=True,
        gridspec_kw={"hspace": 0.08},
    )

    ax_sensor = axes[0]
    ax_detect = axes[1]

    x = df["step_id"].values if "step_id" in df.columns else np.arange(len(df))
    colors = plt.cm.tab10(np.linspace(0, 0.8, len(numeric_cols)))

    # Plot sensor time series
    for i, col in enumerate(numeric_cols):
        ax_sensor.plot(x, df[col].values, label=col, color=colors[i], linewidth=1.2, alpha=0.9)

    # Shade attack windows
    if "attack_active" in df.columns:
        attack_mask = df["attack_active"].fillna(False).astype(bool)
        in_attack = False
        start = 0
        for idx_pos in range(len(attack_mask)):
            if attack_mask.iloc[idx_pos] and not in_attack:
                start = x[idx_pos]
                in_attack = True
            elif not attack_mask.iloc[idx_pos] and in_attack:
                ax_sensor.axvspan(start, x[idx_pos], alpha=0.15, color="red")
                ax_detect.axvspan(start, x[idx_pos], alpha=0.15, color="red")
                in_attack = False
        if in_attack:
            ax_sensor.axvspan(start, x[-1], alpha=0.15, color="red")
            ax_detect.axvspan(start, x[-1], alpha=0.15, color="red")

    ax_sensor.set_ylabel("Tag Value")
    ax_sensor.legend(loc="upper right", fontsize=7, ncol=2, frameon=False)
    ax_sensor.set_title(f"Process Timeline — {run_dir.parent.name}", fontsize=11)

    # Plot detection events
    severity_colors = {
        "critical": "#e74c3c",
        "high": "#e67e22",
        "medium": "#f1c40f",
        "low": "#3498db",
        "info": "#95a5a6",
    }

    det_steps = []
    det_colors = []
    det_sizes = []
    for ev in detections:
        step = ev.get("step_id")
        if step is None:
            continue
        sev = str(ev.get("severity", "info")).lower()
        det_steps.append(step)
        det_colors.append(severity_colors.get(sev, "#95a5a6"))
        det_sizes.append({"critical": 60, "high": 45, "medium": 30, "low": 20, "info": 15}.get(sev, 20))

    if det_steps:
        ax_detect.scatter(det_steps, [1] * len(det_steps), c=det_colors, s=det_sizes,
                          marker="|", linewidths=1.5, zorder=5)

    # Add attack markers on the detection axis
    for attack in attacks:
        if attack.get("execution_status") in ("executed", "dry_run"):
            atype = attack.get("attack_type", "")
            if isinstance(atype, dict):
                atype = atype.get("value", "")
            # Try to find step from trace
            aid = attack.get("action_id", "")
            if "attack_action_id" in df.columns:
                match = df[df["attack_action_id"] == aid]
                if not match.empty:
                    step = match.iloc[0]["step_id"]
                    ax_detect.axvline(x=step, color="red", alpha=0.3, linestyle="--", linewidth=0.8)

    ax_detect.set_ylabel("Det. Events")
    ax_detect.set_xlabel("Step")
    ax_detect.set_yticks([])
    ax_detect.set_ylim(0.5, 1.5)

    # Legend for severities
    patches = [mpatches.Patch(color=c, label=s.capitalize()) for s, c in severity_colors.items()
               if s in [str(ev.get("severity", "")).lower() for ev in detections]]
    patches.append(mpatches.Patch(color="red", alpha=0.15, label="Attack window"))
    if patches:
        ax_detect.legend(handles=patches, loc="lower right", fontsize=7, ncol=3, frameon=False)

    path = out_dir / f"fig_timeline_{run_dir.parent.name}.{fmt}"
    fig.savefig(path, bbox_inches="tight", dpi=300)
    plt.close(fig)
    logger.info("Saved %s", path)
    return path


def main():
    parser = argparse.ArgumentParser(description="Generate timeline figure")
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    parser.add_argument("--experiment", type=str, default=None,
                        help="Experiment folder name (e.g., live_scripted_level_control)")
    parser.add_argument("--run-id", type=str, default=None)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--format", choices=["pdf", "png", "svg"], default="pdf")
    parser.add_argument("--max-tags", type=int, default=4)
    parser.add_argument("--all-scenes", action="store_true",
                        help="Generate timeline for one representative run per scene")
    args = parser.parse_args()

    raw_dir = args.data_dir / "raw"
    out_dir = args.output_dir or (args.data_dir / "processed" / "paper_figures")
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.all_scenes:
        # Generate for all scripted experiments (best for timelines)
        experiments = [
            "live_scripted_level_control",
            "live_scripted_sorting_weight",
            "live_scripted_from_a_to_b",
            "live_scripted_filling_tank",
            "live_scripted_sorting_height_basic",
        ]
        for exp in experiments:
            rd = find_run_dir(raw_dir, exp)
            if rd:
                generate_timeline(rd, out_dir, args.format, args.max_tags)
            else:
                logger.warning("No run found for %s", exp)
    elif args.experiment:
        rd = find_run_dir(raw_dir, args.experiment, args.run_id)
        if rd:
            generate_timeline(rd, out_dir, args.format, args.max_tags)
        else:
            logger.error("Run not found for experiment=%s", args.experiment)
    else:
        # Default: generate for level_control scripted
        rd = find_run_dir(raw_dir, "live_scripted_level_control")
        if rd:
            generate_timeline(rd, out_dir, args.format, args.max_tags)
        else:
            logger.error("No default experiment found. Specify --experiment.")


if __name__ == "__main__":
    main()
