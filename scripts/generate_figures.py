#!/usr/bin/env python
"""
Generate publication-ready figures from CPSForge experiment data.

Produces PDF/PNG figures for:
  1. ASR comparison bar chart (Fig 1)
  2. Detector F1 comparison bar chart (Fig 2)
  3. Cross-detector comparison grouped bar chart (Fig 3)
  4. Adaptation round progression line plot (Fig 4)
  5. Attack type distribution pie/bar (Fig 5)
  6. Detection latency box plot (Fig 6)
  7. Dataset composition stacked bar (Fig 7)

Usage:
    python scripts/generate_figures.py
    python scripts/generate_figures.py --data-dir data --output-dir data/processed/paper_figures --format pdf
"""
from __future__ import annotations

import argparse
import json
import logging
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Consistent style
plt.rcParams.update({
    "font.size": 10,
    "axes.labelsize": 11,
    "axes.titlesize": 12,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "legend.fontsize": 9,
    "figure.dpi": 150,
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
    "axes.grid": True,
    "grid.alpha": 0.3,
})

SCENES = ["From A to B", "Filling Tank", "Level Ctrl", "Sort Height", "Sort Weight"]
SCENE_SHORT = ["A→B", "Fill", "Level", "SortH", "SortW"]
ATTACKERS = ["Scripted", "Random", "LLM batch"]
ATTACKER_COLORS = {"Scripted": "#e74c3c", "Random": "#3498db", "LLM batch": "#2ecc71"}

BATCH_EXPERIMENTS = {
    ("From A to B", "Scripted"):    "live_scripted_from_a_to_b",
    ("From A to B", "Random"):      "live_random_from_a_to_b",
    ("From A to B", "LLM batch"):   "live_llm_from_a_to_b",
    ("Filling Tank", "Scripted"):   "live_scripted_filling_tank",
    ("Filling Tank", "Random"):     "live_random_filling_tank",
    ("Filling Tank", "LLM batch"):  "live_llm_filling_tank",
    ("Level Ctrl", "Scripted"):     "live_scripted_level_control",
    ("Level Ctrl", "Random"):       "live_random_level_control",
    ("Level Ctrl", "LLM batch"):    "live_llm_level_control",
    ("Sort Height", "Scripted"):    "live_scripted_sorting_height_basic",
    ("Sort Height", "Random"):      "live_random_sorting_height_basic",
    ("Sort Height", "LLM batch"):   "live_llm_sorting_height_basic",
    ("Sort Weight", "Scripted"):    "live_scripted_sorting_weight",
    ("Sort Weight", "Random"):      "live_random_sorting_weight",
    ("Sort Weight", "LLM batch"):   "live_llm_sorting_weight",
}


def _load_metrics(raw_dir: Path, exp_name: str) -> list[dict]:
    """Load all metrics.json from runs within an experiment folder."""
    exp_path = raw_dir / exp_name
    if not exp_path.exists():
        return []
    results = []
    for rd in sorted(exp_path.iterdir()):
        if not rd.is_dir():
            continue
        mp = rd / "metrics.json"
        if mp.exists():
            with mp.open() as f:
                results.append(json.load(f))
    return results


def _get_batch_metric(raw_dir: Path, metric_key: str) -> dict[tuple[str, str], float]:
    """Get a metric averaged across runs for each (scene, attacker) pair."""
    result = {}
    for (scene, attacker), exp_name in BATCH_EXPERIMENTS.items():
        metrics = _load_metrics(raw_dir, exp_name)
        if metrics:
            vals = [m.get(metric_key, 0.0) for m in metrics]
            result[(scene, attacker)] = float(np.mean(vals))
        else:
            result[(scene, attacker)] = 0.0
    return result


# ── Figure 1: ASR Comparison ─────────────────────────────────────────────

def fig_asr_comparison(raw_dir: Path, out_dir: Path, fmt: str):
    """Bar chart comparing ASR across scenes and attacker types."""
    data = _get_batch_metric(raw_dir, "attack_success_rate")

    fig, ax = plt.subplots(figsize=(7, 4))
    x = np.arange(len(SCENES))
    width = 0.22

    for i, attacker in enumerate(ATTACKERS):
        vals = [data.get((scene, attacker), 0.0) for scene in SCENES]
        bars = ax.bar(x + i * width, vals, width, label=attacker,
                      color=ATTACKER_COLORS[attacker], edgecolor="white", linewidth=0.5)
        for bar, v in zip(bars, vals):
            if v > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.02,
                        f"{v:.2f}", ha="center", va="bottom", fontsize=7)

    ax.set_ylabel("Attack Success Rate (ASR)")
    ax.set_xticks(x + width)
    ax.set_xticklabels(SCENE_SHORT, rotation=0)
    ax.set_ylim(0, 1.0)
    ax.legend(loc="upper left", frameon=False)
    ax.set_title("Attack Success Rate by Scene and Attacker Type")

    path = out_dir / f"fig_asr_comparison.{fmt}"
    fig.savefig(path)
    plt.close(fig)
    logger.info("Saved %s", path)
    return path


# ── Figure 2: Detector F1 Comparison ─────────────────────────────────────

def fig_detector_f1(raw_dir: Path, out_dir: Path, fmt: str):
    """Bar chart comparing detector F1 across scenes and attacker types."""
    data = _get_batch_metric(raw_dir, "detector_f1")

    fig, ax = plt.subplots(figsize=(7, 4))
    x = np.arange(len(SCENES))
    width = 0.22

    for i, attacker in enumerate(ATTACKERS):
        vals = [data.get((scene, attacker), 0.0) for scene in SCENES]
        bars = ax.bar(x + i * width, vals, width, label=attacker,
                      color=ATTACKER_COLORS[attacker], edgecolor="white", linewidth=0.5)
        for bar, v in zip(bars, vals):
            if v > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.02,
                        f"{v:.2f}", ha="center", va="bottom", fontsize=7)

    ax.set_ylabel("Detector F1 Score")
    ax.set_xticks(x + width)
    ax.set_xticklabels(SCENE_SHORT, rotation=0)
    ax.set_ylim(0, 1.0)
    ax.legend(loc="upper left", frameon=False)
    ax.set_title("Detector F1 Score by Attacker Type and Scene")

    path = out_dir / f"fig_detector_f1.{fmt}"
    fig.savefig(path)
    plt.close(fig)
    logger.info("Saved %s", path)
    return path


# ── Figure 3: Cross-Detector Comparison ──────────────────────────────────

def fig_cross_detector(data_dir: Path, out_dir: Path, fmt: str):
    """Grouped bar chart of F1 scores for all detectors on two scenes."""
    processed = data_dir / "processed"

    det_names = ["Threshold", "Invariant", "CUSUM", "OCSVM", "IForest", "LSTM-AD"]
    scene_colors = {"Level Ctrl": "#3498db", "Sort Weight": "#e67e22"}
    scene_data: dict[str, dict[str, float]] = {}

    # Try to load from processed detector comparison results
    for scene_key, scene_display in [("level_control", "Level Ctrl"), ("sorting_weight", "Sort Weight")]:
        comp_dir = processed / f"detector_comparison_{scene_key}"
        if not comp_dir.exists():
            continue
        summary_path = comp_dir / "comparison_summary.json"
        if summary_path.exists():
            with summary_path.open() as f:
                data = json.load(f)
            scene_data[scene_display] = {}
            for det_name, det_info in data.items():
                if isinstance(det_info, dict):
                    f1 = det_info.get("f1", det_info.get("detector_f1", 0))
                    scene_data[scene_display][det_name] = f1

    if not scene_data:
        logger.warning("No cross-detector data found. Skipping figure.")
        return None

    fig, ax = plt.subplots(figsize=(7, 4))
    x = np.arange(len(det_names))
    width = 0.35

    for i, (scene_display, color) in enumerate(scene_colors.items()):
        if scene_display not in scene_data:
            continue
        vals = [scene_data[scene_display].get(d, 0.0) for d in det_names]
        bars = ax.bar(x + i * width, vals, width, label=scene_display,
                      color=color, edgecolor="white", linewidth=0.5)
        for bar, v in zip(bars, vals):
            if v > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                        f"{v:.2f}", ha="center", va="bottom", fontsize=7)

    ax.set_ylabel("F1 Score")
    ax.set_xticks(x + width / 2)
    ax.set_xticklabels(det_names, rotation=20, ha="right")
    ax.set_ylim(0, 0.85)
    ax.legend(frameon=False)
    ax.set_title("Cross-Detector F1 Comparison")

    path = out_dir / f"fig_cross_detector.{fmt}"
    fig.savefig(path)
    plt.close(fig)
    logger.info("Saved %s", path)
    return path


# ── Figure 4: Adaptation Progression ─────────────────────────────────────

def fig_adaptation(raw_dir: Path, out_dir: Path, fmt: str):
    """Line plot showing F1 and recall across adaptation rounds."""
    adapt_scenes = {
        "adapt_level_control": "Level Ctrl",
        "adapt_sorting_weight": "Sort Weight",
    }

    fig, axes = plt.subplots(1, 2, figsize=(10, 4), sharey=True)
    colors = {"Level Ctrl": "#e74c3c", "Sort Weight": "#3498db"}
    markers = {"Level Ctrl": "o", "Sort Weight": "s"}

    for idx, (exp_name, scene) in enumerate(adapt_scenes.items()):
        metrics = _load_metrics(raw_dir, exp_name)
        if not metrics:
            continue

        by_round: dict[int, list[dict]] = defaultdict(list)
        for m in metrics:
            by_round[m.get("adaptation_round", 0)].append(m)

        rounds = sorted(by_round.keys())
        f1_vals = [np.mean([m.get("detector_f1", 0) for m in by_round[r]]) for r in rounds]
        rec_vals = [np.mean([m.get("detector_recall", 0) for m in by_round[r]]) for r in rounds]
        prec_vals = [np.mean([m.get("detector_precision", 0) for m in by_round[r]]) for r in rounds]

        ax = axes[idx]
        ax.plot(rounds, f1_vals, "-o", color=colors[scene], label="F1", linewidth=2)
        ax.plot(rounds, rec_vals, "--s", color=colors[scene], alpha=0.7, label="Recall")
        ax.plot(rounds, prec_vals, ":^", color=colors[scene], alpha=0.5, label="Precision")
        ax.set_xlabel("Adaptation Round")
        ax.set_title(scene)
        ax.set_ylim(0, 1.05)
        ax.set_xticks(rounds)
        ax.legend(frameon=False, fontsize=8)

    axes[0].set_ylabel("Score")
    fig.suptitle("Defender Performance Across Adaptation Rounds", fontsize=12)
    fig.tight_layout()

    path = out_dir / f"fig_adaptation.{fmt}"
    fig.savefig(path)
    plt.close(fig)
    logger.info("Saved %s", path)
    return path


# ── Figure 5: Attack Type Distribution ───────────────────────────────────

def fig_attack_types(raw_dir: Path, out_dir: Path, fmt: str):
    """Stacked bar showing attack type distribution per attacker."""
    type_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for (scene, attacker), exp_name in BATCH_EXPERIMENTS.items():
        exp_path = raw_dir / exp_name
        if not exp_path.exists():
            continue
        for rd in sorted(exp_path.iterdir()):
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
                type_counts[attacker][atype] += 1

    if not type_counts:
        logger.warning("No attack data found. Skipping attack type figure.")
        return None

    all_types = sorted(set(t for d in type_counts.values() for t in d.keys()))
    type_colors = plt.cm.Set2(np.linspace(0, 1, len(all_types)))

    fig, ax = plt.subplots(figsize=(7, 4))
    x = np.arange(len(ATTACKERS))
    width = 0.5
    bottoms = np.zeros(len(ATTACKERS))

    for i, atype in enumerate(all_types):
        vals = [type_counts.get(att, {}).get(atype, 0) for att in ATTACKERS]
        ax.bar(x, vals, width, bottom=bottoms, label=atype, color=type_colors[i])
        bottoms += np.array(vals, dtype=float)

    ax.set_ylabel("Number of Actions")
    ax.set_xticks(x)
    ax.set_xticklabels(ATTACKERS)
    ax.legend(title="Attack Type", bbox_to_anchor=(1.02, 1), loc="upper left", fontsize=8)
    ax.set_title("Attack Type Distribution by Attacker")
    fig.tight_layout()

    path = out_dir / f"fig_attack_types.{fmt}"
    fig.savefig(path)
    plt.close(fig)
    logger.info("Saved %s", path)
    return path


# ── Figure 6: Dataset Composition ────────────────────────────────────────

def fig_dataset_composition(raw_dir: Path, out_dir: Path, fmt: str):
    """Stacked horizontal bar showing normal vs attack steps per scene."""
    scene_steps: dict[str, dict[str, int]] = {}

    scene_exp_mapping = {
        "From A to B":  "live_scripted_from_a_to_b",
        "Filling Tank": "live_scripted_filling_tank",
        "Level Ctrl":   "live_scripted_level_control",
        "Sort Height":  "live_scripted_sorting_height_basic",
        "Sort Weight":  "live_scripted_sorting_weight",
    }

    for scene, exp_name in scene_exp_mapping.items():
        exp_path = raw_dir / exp_name
        if not exp_path.exists():
            continue
        for rd in sorted(exp_path.iterdir()):
            if not rd.is_dir():
                continue
            trace_path = rd / "trace.parquet"
            if not trace_path.exists():
                continue
            try:
                df = pd.read_parquet(trace_path, columns=["step_id", "attack_active"])
                total = len(df)
                attack = int(df["attack_active"].sum())
                normal = total - attack
                scene_steps[scene] = {"normal": normal, "attack": attack}
            except Exception:
                pass
            break  # Use first run per scene

    if not scene_steps:
        logger.warning("No trace data found. Skipping dataset figure.")
        return None

    fig, ax = plt.subplots(figsize=(7, 3.5))
    scenes_ordered = [s for s in reversed(SCENES) if s in scene_steps]
    y = np.arange(len(scenes_ordered))
    normals = [scene_steps[s]["normal"] for s in scenes_ordered]
    attacks = [scene_steps[s]["attack"] for s in scenes_ordered]

    ax.barh(y, normals, height=0.5, label="Normal steps", color="#bdc3c7", edgecolor="white")
    ax.barh(y, attacks, height=0.5, left=normals, label="Attack steps", color="#e74c3c", edgecolor="white")

    for i, (n, a) in enumerate(zip(normals, attacks)):
        ax.text(n / 2, i, str(n), ha="center", va="center", fontsize=8, color="black")
        ax.text(n + a / 2, i, str(a), ha="center", va="center", fontsize=8, color="white")

    ax.set_yticks(y)
    ax.set_yticklabels(scenes_ordered)
    ax.set_xlabel("Time-series Steps")
    ax.legend(loc="lower right", frameon=False)
    ax.set_title("Dataset Composition: Normal vs Attack Steps")

    path = out_dir / f"fig_dataset_composition.{fmt}"
    fig.savefig(path)
    plt.close(fig)
    logger.info("Saved %s", path)
    return path


# ── Figure 7: Shield Decision Summary ────────────────────────────────────

def fig_shield_summary(raw_dir: Path, out_dir: Path, fmt: str):
    """Bar chart showing shield approval/rejection rates per scene."""
    data_appr = _get_batch_metric(raw_dir, "shield_approval_rate")
    data_rej = _get_batch_metric(raw_dir, "shield_rejection_rate")

    fig, ax = plt.subplots(figsize=(7, 4))
    x = np.arange(len(SCENES))
    width = 0.22

    for i, attacker in enumerate(ATTACKERS):
        appr = [data_appr.get((s, attacker), 0) for s in SCENES]
        rej = [data_rej.get((s, attacker), 0) for s in SCENES]
        ax.bar(x + i * width, appr, width, label=f"{attacker} (approved)",
               color=ATTACKER_COLORS[attacker], edgecolor="white", linewidth=0.5)
        # Overlay rejection as hatched
        bars = ax.bar(x + i * width, rej, width, bottom=appr,
                      color=ATTACKER_COLORS[attacker], alpha=0.3, hatch="//",
                      edgecolor=ATTACKER_COLORS[attacker])

    ax.set_ylabel("Rate")
    ax.set_xticks(x + width)
    ax.set_xticklabels(SCENE_SHORT, rotation=0)
    ax.set_ylim(0, 1.15)
    ax.legend(loc="upper right", fontsize=7, frameon=False)
    ax.set_title("Shield Approval Rates (hatched = rejection portion)")

    path = out_dir / f"fig_shield_summary.{fmt}"
    fig.savefig(path)
    plt.close(fig)
    logger.info("Saved %s", path)
    return path


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Generate paper figures from CPSForge data")
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--format", choices=["pdf", "png", "svg"], default="pdf")
    args = parser.parse_args()

    out_dir = args.output_dir or (args.data_dir / "processed" / "paper_figures")
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = args.data_dir / "raw"

    figures = [
        ("ASR comparison",           lambda: fig_asr_comparison(raw_dir, out_dir, args.format)),
        ("Detector F1",              lambda: fig_detector_f1(raw_dir, out_dir, args.format)),
        ("Cross-detector comparison", lambda: fig_cross_detector(args.data_dir, out_dir, args.format)),
        ("Adaptation progression",   lambda: fig_adaptation(raw_dir, out_dir, args.format)),
        ("Attack type distribution", lambda: fig_attack_types(raw_dir, out_dir, args.format)),
        ("Dataset composition",      lambda: fig_dataset_composition(raw_dir, out_dir, args.format)),
        ("Shield summary",           lambda: fig_shield_summary(raw_dir, out_dir, args.format)),
    ]

    generated = 0
    for name, gen_fn in figures:
        try:
            result = gen_fn()
            if result:
                generated += 1
        except Exception as e:
            logger.error("Failed to generate %s: %s", name, e)

    print(f"\nGenerated {generated}/{len(figures)} figures in {out_dir}")


if __name__ == "__main__":
    main()
