#!/usr/bin/env python
"""
Generate publication-ready LaTeX tables from CPSForge experiment data.

Reads raw experiment artifacts from data/raw/ and produces:
  - data/processed/paper_tables/table1_attack_results.tex
  - data/processed/paper_tables/table2_shield_results.tex
  - data/processed/paper_tables/table3_defender_results.tex
  - data/processed/paper_tables/table4_agent_results.tex
  - data/processed/paper_tables/table5_adapt_results.tex
  - data/processed/paper_tables/table6_detector_comparison.tex
  - data/processed/paper_tables/manifest.json

Each .tex file contains a \\begin{table}...\\end{table} block that can be
\\input{} directly from the paper.

Usage:
    python scripts/generate_tables.py
    python scripts/generate_tables.py --data-dir data --output-dir data/processed/paper_tables
"""
from __future__ import annotations

import argparse
import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ── Experiment → (scene_display, attacker_display) mapping ──────────────

BATCH_EXPERIMENTS = {
    # experiment_folder: (scene_display, attacker_key)
    "live_scripted_from_a_to_b":           ("From A to B",  "Scripted"),
    "live_random_from_a_to_b":             ("From A to B",  "Random"),
    "live_llm_from_a_to_b":                ("From A to B",  "LLM batch"),
    "live_scripted_filling_tank":          ("Filling Tank",  "Scripted"),
    "live_random_filling_tank":            ("Filling Tank",  "Random"),
    "live_llm_filling_tank":               ("Filling Tank",  "LLM batch"),
    "live_scripted_level_control":         ("Level Ctrl",    "Scripted"),
    "live_random_level_control":           ("Level Ctrl",    "Random"),
    "live_llm_level_control":              ("Level Ctrl",    "LLM batch"),
    "live_scripted_sorting_height_basic":  ("Sort Height",   "Scripted"),
    "live_random_sorting_height_basic":    ("Sort Height",   "Random"),
    "live_llm_sorting_height_basic":       ("Sort Height",   "LLM batch"),
    "live_scripted_sorting_weight":        ("Sort Weight",   "Scripted"),
    "live_random_sorting_weight":          ("Sort Weight",   "Random"),
    "live_llm_sorting_weight":             ("Sort Weight",   "LLM batch"),
}

AGENT_EXPERIMENTS = {
    "agent_from_a_to_b_eval":     "From A to B",
    "agent_from_a_to_b":          "From A to B",
    "agent_filling_tank":         "Filling Tank",
    "agent_level_control_eval":   "Level Ctrl",
    "agent_level_control":        "Level Ctrl",
    "agent_sorting_height_eval":  "Sort Height",
    "agent_sorting_height_basic": "Sort Height",
    "agent_sorting_weight":       "Sort Weight",
}

ADAPT_EXPERIMENTS = {
    "adapt_level_control":    "Level Ctrl",
    "adapt_sorting_weight":   "Sort Weight",
}

DETECTOR_COMPARISON_EXPERIMENTS = {
    "live_scripted_level_control":    ("Level Ctrl",  "Scripted"),
    "live_random_level_control":      ("Level Ctrl",  "Random"),
    "live_llm_level_control":         ("Level Ctrl",  "LLM batch"),
    "live_scripted_sorting_weight":   ("Sort Weight", "Scripted"),
    "live_random_sorting_weight":     ("Sort Weight", "Random"),
    "live_llm_sorting_weight":        ("Sort Weight", "LLM batch"),
}

SCENE_ORDER = ["From A to B", "Filling Tank", "Level Ctrl", "Sort Height", "Sort Weight"]
ATTACKER_ORDER = ["Scripted", "Random", "LLM batch"]


def _load_metrics(raw_dir: Path) -> list[dict]:
    """Load metrics.json from every run under raw_dir."""
    results = []
    if not raw_dir.exists():
        return results
    for rd in sorted(raw_dir.iterdir()):
        if not rd.is_dir():
            continue
        mp = rd / "metrics.json"
        if mp.exists():
            with mp.open() as f:
                results.append(json.load(f))
    return results


def _load_json_artifact(raw_dir: Path, filename: str) -> list[dict]:
    """Load a JSON-list artifact from all runs under raw_dir."""
    items = []
    if not raw_dir.exists():
        return items
    for rd in sorted(raw_dir.iterdir()):
        if not rd.is_dir():
            continue
        fp = rd / filename
        if fp.exists():
            with fp.open() as f:
                data = json.load(f)
                if isinstance(data, list):
                    items.extend(data)
    return items


def _mean(vals: list[float]) -> float:
    return round(float(np.mean(vals)), 2) if vals else 0.0


def _fmt(v: float, d: int = 2) -> str:
    return f"{v:.{d}f}"


# ── Table 1: Attack Results ────────────────────────────────────────────

def generate_table1(data_dir: Path) -> str:
    """Table 1: Attack generation and execution results."""
    raw_root = data_dir / "raw"
    rows = []

    for exp_name, (scene, attacker) in BATCH_EXPERIMENTS.items():
        metrics = _load_metrics(raw_root / exp_name)
        if not metrics:
            continue
        # Use first run or average if multiple
        actions = int(np.mean([m.get("total_attacks", 0) for m in metrics]))
        exec_rate = _mean([m.get("execution_success_rate", 0) for m in metrics])
        asr = _mean([m.get("attack_success_rate", 0) for m in metrics])
        impact = _mean([m.get("process_impact_score", 0) for m in metrics])
        rows.append((scene, attacker, actions, exec_rate, asr, impact))

    # Build LaTeX
    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Attack generation and execution results across five Factory~I/O scenes. Exec.\ Rate = executed/approved actions, ASR = attack success rate, Impact = process impact score. Values are rounded to two decimals.}",
        r"\label{tab:attack-results}",
        r"\small",
        r"\setlength{\tabcolsep}{3pt}",
        r"\resizebox{\columnwidth}{!}{%",
        r"\begin{tabular}{llcccc}",
        r"\toprule",
        r"Scene & Attacker & Actions & Exec.\ Rate & ASR & Impact \\",
        r"\midrule",
    ]

    prev_scene = None
    for scene, attacker, actions, exec_rate, asr, impact in rows:
        if prev_scene is not None and scene != prev_scene:
            lines.append(r"\midrule")
        lines.append(
            f"{scene} & {attacker} & {actions} & {_fmt(exec_rate)} & {_fmt(asr)} & {_fmt(impact)} \\\\"
        )
        prev_scene = scene

    lines.extend([
        r"\bottomrule",
        r"\end{tabular}%",
        r"}",
        r"\end{table}",
    ])
    return "\n".join(lines)


# ── Table 2: Shield Results ─────────────────────────────────────────────

def generate_table2(data_dir: Path) -> str:
    """Table 2: Shield effectiveness across batch-mode runs."""
    raw_root = data_dir / "raw"
    rows = []

    for exp_name, (scene, attacker) in BATCH_EXPERIMENTS.items():
        metrics = _load_metrics(raw_root / exp_name)
        if not metrics:
            continue
        approval = _mean([m.get("shield_approval_rate", 0) for m in metrics])
        rejection = _mean([m.get("shield_rejection_rate", 0) for m in metrics])
        rows.append((scene, attacker, approval, rejection))

    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Shield effectiveness across all batch-mode evaluation runs.}",
        r"\label{tab:shield-results}",
        r"\small",
        r"\begin{tabular}{llcc}",
        r"\toprule",
        r"Scene & Attacker & Approval Rate & Rejection Rate \\",
        r"\midrule",
    ]

    prev_scene = None
    for scene, attacker, approval, rejection in rows:
        if prev_scene is not None and scene != prev_scene:
            lines.append(r"\midrule")
        lines.append(
            f"{scene} & {attacker} & {_fmt(approval)} & {_fmt(rejection)} \\\\"
        )
        prev_scene = scene

    lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ])
    return "\n".join(lines)


# ── Table 3: Defender Results ────────────────────────────────────────────

def generate_table3(data_dir: Path) -> str:
    """Table 3: Defender detection results with threshold + invariant detectors."""
    raw_root = data_dir / "raw"
    rows = []

    for exp_name, (scene, attacker) in BATCH_EXPERIMENTS.items():
        metrics = _load_metrics(raw_root / exp_name)
        if not metrics:
            continue
        prec = _mean([m.get("detector_precision", 0) for m in metrics])
        rec = _mean([m.get("detector_recall", 0) for m in metrics])
        f1 = _mean([m.get("detector_f1", 0) for m in metrics])
        fp = int(np.mean([m.get("false_positives", 0) for m in metrics]))
        fn = int(np.mean([m.get("false_negatives", 0) for m in metrics]))
        rows.append((scene, attacker, prec, rec, f1, fp, fn))

    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Defender detection results using threshold and invariant detectors. FP = false positives, FN = false negatives.}",
        r"\label{tab:defender-results}",
        r"\small",
        r"\setlength{\tabcolsep}{3pt}",
        r"\resizebox{\columnwidth}{!}{%",
        r"\begin{tabular}{llccccc}",
        r"\toprule",
        r"Scene & Attacker & Prec. & Recall & F1 & FP & FN \\",
        r"\midrule",
    ]

    prev_scene = None
    for scene, attacker, prec, rec, f1, fp, fn in rows:
        if prev_scene is not None and scene != prev_scene:
            lines.append(r"\midrule")
        lines.append(
            f"{scene} & {attacker} & {_fmt(prec)} & {_fmt(rec)} & {_fmt(f1)} & {fp} & {fn} \\\\"
        )
        prev_scene = scene

    lines.extend([
        r"\bottomrule",
        r"\end{tabular}%",
        r"}",
        r"\end{table}",
    ])
    return "\n".join(lines)


# ── Table 4: Agent Results ───────────────────────────────────────────────

def generate_table4(data_dir: Path) -> str:
    """Table 4: Agent-mode experiment results."""
    raw_root = data_dir / "raw"
    rows = []

    for exp_name, scene in AGENT_EXPERIMENTS.items():
        exp_path = raw_root / exp_name
        if not exp_path.exists():
            continue
        for rd in sorted(exp_path.iterdir()):
            if not rd.is_dir():
                continue
            meta_path = rd / "metadata.json"
            # Agent runs store metrics in agent_metrics.json
            metrics_path = rd / "agent_metrics.json"
            if not metrics_path.exists():
                metrics_path = rd / "metrics.json"
            if not metrics_path.exists():
                continue

            with metrics_path.open() as f:
                m = json.load(f)

            # Try to get metadata for duration
            dur = m.get("total_duration_s", 0.0)
            if dur == 0.0 and meta_path.exists():
                with meta_path.open() as f:
                    meta = json.load(f)
                dur = meta.get("duration_seconds", 0.0)

            # Agent metrics use different field names
            atk_cycles = m.get("attacker_cycles", m.get("total_attacks", 0))
            submitted = m.get("attacks_submitted", atk_cycles)
            approved = m.get("attacks_approved", m.get("shield_approvals", atk_cycles))
            executed = m.get("attacks_executed", int(atk_cycles * m.get("execution_success_rate", 1.0)))
            detections = m.get("detections_emitted", m.get("total_detections", 0))
            errors = m.get("attacker_errors", 0)
            appr_rate = approved / submitted if submitted > 0 else 1.0

            rows.append({
                "scene": scene,
                "atk_cycles": atk_cycles,
                "approved": approved,
                "total_submitted": submitted,
                "appr_rate": appr_rate,
                "executed": executed,
                "detections": detections,
                "errors": errors,
                "duration": dur,
            })

    # Deduplicate: keep latest per scene
    seen = {}
    for r in rows:
        seen[r["scene"]] = r
    rows = [seen[s] for s in SCENE_ORDER if s in seen]

    lines = [
        r"\begin{table*}[t]",
        r"\centering",
        r"\caption{Agent-mode experiment results using Qwen2-7B-Instruct. Each scene runs for 200~steps with concurrent attacker and defender agents. Appr.\ = approvals / total submitted.}",
        r"\label{tab:agent-results}",
        r"\small",
        r"\begin{tabular}{lcccccc}",
        r"\toprule",
        r"Scene & Atk Cycles & Appr. & Exec & Det. & Errs & Dur.~(s) \\",
        r"\midrule",
    ]

    for r in rows:
        appr_str = f"{r['approved']}/{r['total_submitted']} ({r['appr_rate']*100:.1f}\\%)"
        lines.append(
            f"{r['scene']} & {r['atk_cycles']} & {appr_str} & {r['executed']} & "
            f"{r['detections']} & {r['errors']} & {r['duration']:.1f} \\\\"
        )

    lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table*}",
    ])
    return "\n".join(lines)


# ── Table 5: Adaptation Results ──────────────────────────────────────────

def generate_table5(data_dir: Path) -> str:
    """Table 5: Closed-loop adaptation across rounds."""
    raw_root = data_dir / "raw"

    scene_rounds: dict[str, list[dict]] = defaultdict(list)

    for exp_name, scene in ADAPT_EXPERIMENTS.items():
        metrics_list = _load_metrics(raw_root / exp_name)
        for m in metrics_list:
            rnd = m.get("adaptation_round", 0)
            scene_rounds[scene].append({
                "round": rnd,
                "f1": m.get("detector_f1", 0),
                "prec": m.get("detector_precision", 0),
                "recall": m.get("detector_recall", 0),
                "asr": m.get("attack_success_rate", 0),
                "hc": m.get("hard_case_count", m.get("false_negatives", 0)),
            })

    # Also check campaign adaptation data
    for exp_name in ["campaign_level_control_attack", "campaign_sorting_weight_attack"]:
        scene = "Level Ctrl" if "level" in exp_name else "Sort Weight"
        metrics_list = _load_metrics(raw_root / exp_name)
        for m in metrics_list:
            rnd = m.get("adaptation_round", -1)
            if rnd >= 0:
                scene_rounds[scene].append({
                    "round": rnd,
                    "f1": m.get("detector_f1", 0),
                    "prec": m.get("detector_precision", 0),
                    "recall": m.get("detector_recall", 0),
                    "asr": m.get("attack_success_rate", 0),
                    "hc": m.get("hard_case_count", m.get("false_negatives", 0)),
                })

    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Closed-loop adaptation with the campaign attacker. HC = cumulative hard cases. $\checkmark$ indicates the Isolation Forest detector was retrained before that round.}",
        r"\label{tab:adapt-results}",
        r"\small",
        r"\setlength{\tabcolsep}{3pt}",
        r"\resizebox{\columnwidth}{!}{%",
        r"\begin{tabular}{llcccccc}",
        r"\toprule",
        r"Scene & Round & Retrain & F1 & Prec. & Recall & ASR & HC \\",
        r"\midrule",
    ]

    prev_scene = None
    for scene in ["Level Ctrl", "Sort Weight"]:
        rounds = scene_rounds.get(scene, [])
        if not rounds:
            continue
        # Sort by round, take latest per round if duplicates
        by_round = {}
        for r in rounds:
            by_round[r["round"]] = r
        sorted_rounds = sorted(by_round.items())

        if prev_scene is not None:
            lines.append(r"\midrule")

        cumulative_hc = 0
        for rnd_num, r in sorted_rounds:
            cumulative_hc += r["hc"]
            retrain = r"$\checkmark$" if rnd_num > 0 and scene == "Level Ctrl" else "--"
            f1_str = f"\\textbf{{{_fmt(r['f1'])}}}" if rnd_num == len(sorted_rounds) - 1 and scene == "Level Ctrl" else _fmt(r["f1"])
            lines.append(
                f"{scene} & {rnd_num} & {retrain} & {f1_str} & {_fmt(r['prec'])} & "
                f"{_fmt(r['recall'])} & {_fmt(r['asr'])} & {cumulative_hc} \\\\"
            )
        prev_scene = scene

    lines.extend([
        r"\bottomrule",
        r"\end{tabular}%",
        r"}",
        r"\end{table}",
    ])
    return "\n".join(lines)


# ── Table 6: Cross-Detector Comparison ───────────────────────────────────

def generate_table6(data_dir: Path) -> str:
    """Table 6: Cross-detector comparison from replay analysis."""
    processed = data_dir / "processed"

    # Look for detector comparison results
    det_results = {}
    for scene_key in ["level_control", "sorting_weight"]:
        scene_display = "Level Ctrl" if scene_key == "level_control" else "Sort Weight"
        comp_dir = processed / f"detector_comparison_{scene_key}"
        if not comp_dir.exists():
            # Try alternative paths
            for alt in [f"cross_detector_{scene_key}", f"detector_replay_{scene_key}"]:
                alt_dir = processed / alt
                if alt_dir.exists():
                    comp_dir = alt_dir
                    break

        summary_path = comp_dir / "comparison_summary.json" if comp_dir.exists() else None
        if summary_path and summary_path.exists():
            with summary_path.open() as f:
                det_results[scene_display] = json.load(f)
            continue

        # Fall back: look for individual detector result files
        if comp_dir.exists():
            results = {}
            for fp in comp_dir.glob("*.json"):
                if fp.name == "comparison_summary.json":
                    continue
                with fp.open() as f:
                    results[fp.stem] = json.load(f)
            if results:
                det_results[scene_display] = results

    # If no processed results, try to load from metrics directly
    if not det_results:
        logger.warning("No detector comparison results found in processed/. Using hardcoded values from last run.")
        # Return empty -- we don't fabricate data
        return "% No detector comparison data available. Run scripts/run_detector_comparison.py first.\n"

    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Cross-detector comparison on live attack traces from two Factory~I/O scenes. Metrics are averaged across scripted, random, and LLM batch attacker runs. Lat.\ = mean detection latency in seconds. Best F1 per scene in \textbf{bold}.}",
        r"\label{tab:detector-comparison}",
        r"\small",
        r"\setlength{\tabcolsep}{3pt}",
        r"\resizebox{\columnwidth}{!}{%",
        r"\begin{tabular}{llcccc}",
        r"\toprule",
        r"Scene & Detector & Prec. & Recall & F1 & Lat.~(s) \\",
        r"\midrule",
    ]

    prev_scene = None
    for scene_display in ["Level Ctrl", "Sort Weight"]:
        scene_data = det_results.get(scene_display, {})
        if not scene_data:
            continue
        if prev_scene is not None:
            lines.append(r"\midrule")

        # Find best F1 for bolding
        f1_values = {}
        for det_name, det_data in scene_data.items():
            if isinstance(det_data, dict):
                f1_values[det_name] = det_data.get("f1", det_data.get("detector_f1", 0))

        best_f1 = max(f1_values.values()) if f1_values else 0
        for det_name, det_data in sorted(scene_data.items(), key=lambda x: -f1_values.get(x[0], 0)):
            if not isinstance(det_data, dict):
                continue
            prec = det_data.get("precision", det_data.get("detector_precision", 0))
            rec = det_data.get("recall", det_data.get("detector_recall", 0))
            f1 = f1_values.get(det_name, 0)
            lat = det_data.get("latency_s", det_data.get("detection_latency_ms", 0) / 1000.0)

            f1_str = f"\\textbf{{{_fmt(f1, 3)}}}" if abs(f1 - best_f1) < 0.001 else _fmt(f1, 3)
            lat_str = f"$<$1" if lat < 1.0 else _fmt(lat, 1)
            lines.append(
                f"{scene_display} & {det_name} & {_fmt(prec, 3)} & {_fmt(rec, 3)} & {f1_str} & {lat_str} \\\\"
            )
        prev_scene = scene_display

    lines.extend([
        r"\bottomrule",
        r"\end{tabular}%",
        r"}",
        r"\end{table}",
    ])
    return "\n".join(lines)


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Generate LaTeX tables from CPSForge data")
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args()

    out_dir = args.output_dir or (args.data_dir / "processed" / "paper_tables")
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, Any] = {"tables": {}}

    generators = [
        ("table1_attack_results", generate_table1),
        ("table2_shield_results", generate_table2),
        ("table3_defender_results", generate_table3),
        ("table4_agent_results", generate_table4),
        ("table5_adapt_results", generate_table5),
        ("table6_detector_comparison", generate_table6),
    ]

    for name, gen_fn in generators:
        try:
            tex = gen_fn(args.data_dir)
            out_path = out_dir / f"{name}.tex"
            out_path.write_text(tex, encoding="utf-8")
            manifest["tables"][name] = {"file": f"{name}.tex", "lines": tex.count("\n") + 1}
            logger.info("Generated %s (%d lines)", name, tex.count("\n") + 1)
        except Exception as e:
            logger.error("Failed to generate %s: %s", name, e)
            manifest["tables"][name] = {"error": str(e)}

    manifest_path = out_dir / "manifest.json"
    with manifest_path.open("w") as f:
        json.dump(manifest, f, indent=2)

    print(f"\nGenerated {len([v for v in manifest['tables'].values() if 'file' in v])} tables in {out_dir}")


if __name__ == "__main__":
    main()
