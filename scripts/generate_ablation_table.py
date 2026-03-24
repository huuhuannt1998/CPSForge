#!/usr/bin/env python3
"""
Generate the defense ablation table (Table 7) from ablation experiment runs.

Reads metrics.json from ablation_* experiment folders and produces a LaTeX
table comparing ASR, Precision, Recall, F1, and FP across detector configs.

Output: data/processed/paper_tables/table7_ablation.tex

Usage:
    python scripts/generate_ablation_table.py
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

import numpy as np

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

RAW_DIR = Path("data/raw")
OUTPUT_DIR = Path("data/processed/paper_tables")

ABLATION_EXPERIMENTS = {
    # experiment_folder: (scene_display, config_display)
    "ablation_threshold_only_level_control":    ("Level Ctrl", "Threshold only"),
    "ablation_invariant_only_level_control":    ("Level Ctrl", "Invariant only"),
    "ablation_ml_only_level_control":           ("Level Ctrl", "ML only"),
    "ablation_full_ensemble_level_control":     ("Level Ctrl", "Full ensemble"),
    "ablation_threshold_only_sorting_weight":   ("Sort Weight", "Threshold only"),
    "ablation_invariant_only_sorting_weight":   ("Sort Weight", "Invariant only"),
    "ablation_ml_only_sorting_weight":          ("Sort Weight", "ML only"),
    "ablation_full_ensemble_sorting_weight":    ("Sort Weight", "Full ensemble"),
}

SCENE_ORDER = ["Level Ctrl", "Sort Weight"]
CONFIG_ORDER = ["Threshold only", "Invariant only", "ML only", "Full ensemble"]


def load_metrics(exp_folder: str) -> list[dict]:
    """Load all metrics.json from runs in an experiment folder."""
    exp_dir = RAW_DIR / exp_folder
    results = []
    if not exp_dir.exists():
        return results
    for run_dir in sorted(exp_dir.iterdir()):
        if not run_dir.is_dir():
            continue
        mp = run_dir / "metrics.json"
        if mp.exists():
            with mp.open() as f:
                results.append(json.load(f))
    return results


def mean_metric(metrics_list: list[dict], key: str) -> str:
    """Extract mean of a metric across runs, formatted for display."""
    vals = [m.get(key, 0.0) for m in metrics_list if m.get(key) is not None]
    if not vals:
        return "---"
    mean = np.mean(vals)
    if len(vals) >= 2:
        sd = np.std(vals, ddof=1)
        return f"{mean:.2f}$\\pm${sd:.2f}"
    return f"{mean:.2f}"


def generate_table() -> str:
    """Build the ablation LaTeX table."""
    rows: dict[str, dict[str, dict]] = {}

    for exp_folder, (scene_disp, config_disp) in ABLATION_EXPERIMENTS.items():
        metrics = load_metrics(exp_folder)
        if not metrics:
            logger.warning("No data for %s", exp_folder)
            continue
        rows.setdefault(scene_disp, {})[config_disp] = {
            "n": len(metrics),
            "asr": mean_metric(metrics, "attack_success_rate"),
            "prec": mean_metric(metrics, "detector_precision"),
            "recall": mean_metric(metrics, "detector_recall"),
            "f1": mean_metric(metrics, "detector_f1"),
            "fp": mean_metric(metrics, "false_positives"),
        }

    if not rows:
        logger.warning("No ablation data found. Table will be a placeholder.")
        return _placeholder_table()

    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Defense ablation study on two Factory~I/O scenes with scripted attacker. "
        r"Each row shows a different detector configuration. "
        r"ASR = attack success rate, Prec = precision, Rec = recall.}",
        r"\label{tab:ablation}",
        r"\small",
        r"\setlength{\tabcolsep}{4pt}",
        r"\begin{tabular}{llccccc}",
        r"\toprule",
        r"\textbf{Scene} & \textbf{Detectors} & \textbf{ASR} & \textbf{Prec} & "
        r"\textbf{Rec} & \textbf{F1} & \textbf{FP} \\",
        r"\midrule",
    ]

    for scene in SCENE_ORDER:
        if scene not in rows:
            continue
        first = True
        for config in CONFIG_ORDER:
            if config not in rows[scene]:
                continue
            r = rows[scene][config]
            sc_label = scene if first else ""
            lines.append(
                f"{sc_label} & {config} & {r['asr']} & {r['prec']} & "
                f"{r['recall']} & {r['f1']} & {r['fp']} \\\\"
            )
            first = False
        lines.append(r"\midrule")

    # Remove trailing midrule
    if lines[-1] == r"\midrule":
        lines[-1] = r"\bottomrule"

    lines.extend([
        r"\end{tabular}",
        r"\end{table}",
    ])

    return "\n".join(lines)


def _placeholder_table() -> str:
    """Return a placeholder table when no data is available yet."""
    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Defense ablation study on two Factory~I/O scenes with scripted attacker. "
        r"\textit{Placeholder --- run ablation experiments to populate.}}",
        r"\label{tab:ablation}",
        r"\small",
        r"\setlength{\tabcolsep}{4pt}",
        r"\begin{tabular}{llccccc}",
        r"\toprule",
        r"\textbf{Scene} & \textbf{Detectors} & \textbf{ASR} & \textbf{Prec} & "
        r"\textbf{Rec} & \textbf{F1} & \textbf{FP} \\",
        r"\midrule",
    ]
    for scene in SCENE_ORDER:
        first = True
        for config in CONFIG_ORDER:
            sc_label = scene if first else ""
            lines.append(f"{sc_label} & {config} & --- & --- & --- & --- & --- \\\\")
            first = False
        lines.append(r"\midrule")
    if lines[-1] == r"\midrule":
        lines[-1] = r"\bottomrule"
    lines.extend([r"\end{tabular}", r"\end{table}"])
    return "\n".join(lines)


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    table_tex = generate_table()
    out_path = OUTPUT_DIR / "table7_ablation.tex"
    out_path.write_text(table_tex)
    logger.info("Wrote %s", out_path)

    # Also write a summary JSON
    summary = {"generated_at": str(np.datetime64("now")), "output": str(out_path)}
    (OUTPUT_DIR / "table7_manifest.json").write_text(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
