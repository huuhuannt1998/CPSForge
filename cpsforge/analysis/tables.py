"""
Paper-ready tables and aggregate statistics.
=============================================
Reads raw experiment artifacts (metrics.json, attacks.json, detections.json,
shield_events.json) and produces DataFrames that correspond directly to
the paper's evaluation tables:

  Table 1  ``cross_attacker_table``   — Attacker × {Validity, Exec, ASR, Impact}
  Table 2  ``shield_analysis_table``  — Shield effectiveness metrics
  Table 3  ``cross_detector_table``   — Detector × {Precision, Recall, F1, Latency}
  Table 4  ``adaptation_round_table`` — Round × {F1, Recall, Missed, HC count}
  Extra    ``attack_type_breakdown``  — AttackType × metrics
  Extra    ``latency_distribution``   — Per-detector latency percentiles

All functions accept a ``data_dir`` (root ``data/`` folder) and an
``experiment`` name. They load only ``eval_run=True`` rows by default.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_run_metrics(raw_dir: Path) -> List[Dict[str, Any]]:
    """Load metrics.json from every run under *raw_dir* into dicts."""
    metrics = []
    if not raw_dir.exists():
        return metrics
    for run_dir in sorted(raw_dir.iterdir()):
        mpath = run_dir / "metrics.json"
        if mpath.exists():
            with mpath.open() as fh:
                metrics.append(json.load(fh))
    return metrics


def _load_run_json(run_dir: Path, filename: str) -> List[Dict[str, Any]]:
    """Load a JSON list artifact from a run directory."""
    path = run_dir / filename
    if not path.exists():
        return []
    with path.open() as fh:
        data = json.load(fh)
    return data if isinstance(data, list) else []


def _raw_dir(data_dir: Path, experiment: str) -> Path:
    return data_dir / "raw" / experiment


def _agg(values: List[float]) -> Dict[str, float]:
    """Compute mean, std, min, max, median for a list of floats."""
    if not values:
        return {"mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0,
                "median": 0.0, "n": 0}
    arr = np.array(values, dtype=np.float64)
    return {
        "mean": round(float(np.mean(arr)), 4),
        "std": round(float(np.std(arr)), 4),
        "min": round(float(np.min(arr)), 4),
        "max": round(float(np.max(arr)), 4),
        "median": round(float(np.median(arr)), 4),
        "n": len(values),
    }


def _pct(values: List[float], percentiles: List[int] = (50, 90, 95, 99)) -> Dict[str, float]:
    """Compute percentiles p50, p90, p95, p99 for a list of floats."""
    if not values:
        return {f"p{p}": 0.0 for p in percentiles}
    arr = np.array(values, dtype=np.float64)
    return {f"p{p}": round(float(np.percentile(arr, p)), 2) for p in percentiles}


def _fmt(val: float, digits: int = 3) -> str:
    return f"{val:.{digits}f}"


# ---------------------------------------------------------------------------
# Table 1: Cross-Attacker Comparison
# ---------------------------------------------------------------------------


def cross_attacker_table(
    data_dir: Path,
    experiment: str,
    eval_only: bool = True,
) -> pd.DataFrame:
    """
    Produce **Table 1** — attack metrics by attacker type.

    Returns a DataFrame with rows = attacker names and columns:

    - ``n_runs`` — number of runs
    - ``validity_mean``, ``validity_std``
    - ``exec_success_mean``, ``exec_success_std``
    - ``attack_success_mean``, ``attack_success_std``
    - ``impact_mean``, ``impact_std``
    - ``shield_approval_mean``
    - ``total_attacks``
    """
    raw = _raw_dir(data_dir, experiment)
    all_metrics = _load_run_metrics(raw)
    if eval_only:
        all_metrics = [m for m in all_metrics if m.get("eval_run", False)]

    by_attacker: Dict[str, List[Dict]] = defaultdict(list)
    for m in all_metrics:
        by_attacker[m.get("attacker_name", "unknown")].append(m)

    rows = []
    for attacker, runs in sorted(by_attacker.items()):
        row = {"attacker": attacker, "n_runs": len(runs)}
        for field, col in [
            ("action_validity_rate", "validity"),
            ("execution_success_rate", "exec_success"),
            ("attack_success_rate", "attack_success"),
            ("process_impact_score", "impact"),
            ("shield_approval_rate", "shield_approval"),
        ]:
            vals = [r.get(field, 0.0) for r in runs]
            stats = _agg(vals)
            row[f"{col}_mean"] = stats["mean"]
            row[f"{col}_std"] = stats["std"]
        row["total_attacks"] = sum(r.get("total_attacks", 0) for r in runs)
        rows.append(row)

    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows).set_index("attacker")


# ---------------------------------------------------------------------------
# Table 2: Shield Effectiveness
# ---------------------------------------------------------------------------


def shield_analysis_table(
    data_dir: Path,
    experiment: str,
    eval_only: bool = True,
) -> pd.DataFrame:
    """
    Produce **Table 2** — shield effectiveness analysis.

    Returns a DataFrame with one row per attacker + a "Total" row.
    Columns:

    - ``total_actions`` — total actions generated
    - ``approval_rate``, ``rejection_rate``, ``unsafe_block_rate``
    - ``rule_rejection_counts`` — {rule_type: count} breakdown
    - ``normalization_count`` — how many actions had value normalization
    - ``rollback_count`` — how many shield decisions had rollback plans
    """
    raw = _raw_dir(data_dir, experiment)
    all_metrics = _load_run_metrics(raw)
    if eval_only:
        all_metrics = [m for m in all_metrics if m.get("eval_run", False)]

    # Aggregate per-attacker from metrics.json
    by_attacker: Dict[str, List[Dict]] = defaultdict(list)
    for m in all_metrics:
        by_attacker[m.get("attacker_name", "unknown")].append(m)

    # Also mine shield_events.json for per-rule breakdown
    run_dirs = sorted(d for d in raw.iterdir() if d.is_dir()) if raw.exists() else []
    global_rule_counts: Dict[str, int] = defaultdict(int)
    global_normalization = 0
    global_rollback = 0
    total_shield_events = 0

    for run_dir in run_dirs:
        shield_events = _load_run_json(run_dir, "shield_events.json")
        for event in shield_events:
            total_shield_events += 1
            if event.get("normalized_value") is not None:
                global_normalization += 1
            if event.get("rollback_plan"):
                global_rollback += 1
            if not event.get("approved", True):
                for rule_id in event.get("violated_rules", []):
                    # Extract rule type from rule_id pattern:
                    # rule IDs follow "<type>_<description>" convention
                    parts = rule_id.split("_", 1)
                    rule_type = parts[0] if parts else rule_id
                    global_rule_counts[rule_type] += 1

    rows = []
    for attacker, runs in sorted(by_attacker.items()):
        row = {
            "attacker": attacker,
            "n_runs": len(runs),
            "total_actions": sum(r.get("total_attacks", 0) for r in runs),
            "approval_rate": _agg([r.get("shield_approval_rate", 0) for r in runs])["mean"],
            "rejection_rate": _agg([r.get("shield_rejection_rate", 0) for r in runs])["mean"],
            "unsafe_block_rate": _agg([r.get("unsafe_block_rate", 0) for r in runs])["mean"],
        }
        rows.append(row)

    # Total row
    all_runs = all_metrics
    total_row = {
        "attacker": "TOTAL",
        "n_runs": len(all_runs),
        "total_actions": sum(r.get("total_attacks", 0) for r in all_runs),
        "approval_rate": _agg([r.get("shield_approval_rate", 0) for r in all_runs])["mean"],
        "rejection_rate": _agg([r.get("shield_rejection_rate", 0) for r in all_runs])["mean"],
        "unsafe_block_rate": _agg([r.get("unsafe_block_rate", 0) for r in all_runs])["mean"],
        "normalization_count": global_normalization,
        "rollback_count": global_rollback,
    }
    rows.append(total_row)

    df = pd.DataFrame(rows).set_index("attacker")

    # Write rule rejection breakdown as metadata
    df.attrs["rule_rejection_counts"] = dict(global_rule_counts)
    df.attrs["total_shield_events"] = total_shield_events
    return df


# ---------------------------------------------------------------------------
# Table 3: Cross-Detector Comparison
# ---------------------------------------------------------------------------


def cross_detector_table(
    data_dir: Path,
    experiment: str,
    eval_only: bool = True,
) -> pd.DataFrame:
    """
    Produce **Table 3** — detector performance comparison.

    Reads per-run detections.json to compute per-detector metrics rather
    than the aggregate ensemble metrics in metrics.json.

    Returns a DataFrame with rows = detector names and columns:

    - ``n_events`` — total detection events from this detector
    - ``mean_confidence``, ``std_confidence``
    - ``severity_high_pct`` — fraction of events at HIGH or CRITICAL
    - ``affected_tags_diversity`` — unique tags flagged
    - ``ensemble_precision``, ``ensemble_recall``, ``ensemble_f1``
      (from metrics.json, same for all detectors in a run — included
      for context; per-detector disaggregation computed from events)
    - ``per_detector_tp``, ``per_detector_fp`` — from events vs ground truth
    - ``per_detector_precision``, ``per_detector_recall``, ``per_detector_f1``
    - ``latency_mean``, ``latency_p50``, ``latency_p90``, ``latency_p99``
    """
    raw = _raw_dir(data_dir, experiment)
    run_dirs = sorted(d for d in raw.iterdir() if d.is_dir()) if raw.exists() else []

    # Filter to eval runs
    eval_run_dirs = []
    for rd in run_dirs:
        mpath = rd / "metrics.json"
        if not mpath.exists():
            continue
        with mpath.open() as fh:
            m = json.load(fh)
        if eval_only and not m.get("eval_run", False):
            continue
        eval_run_dirs.append((rd, m))

    # Per-detector data accumulators
    det_events: Dict[str, List[Dict]] = defaultdict(list)
    det_confidences: Dict[str, List[float]] = defaultdict(list)
    det_tags: Dict[str, set] = defaultdict(set)
    det_latencies: Dict[str, List[float]] = defaultdict(list)
    det_tp: Dict[str, int] = defaultdict(int)
    det_fp: Dict[str, int] = defaultdict(int)
    det_fn_total = 0

    for rd, m in eval_run_dirs:
        detections = _load_run_json(rd, "detections.json")
        attacks = _load_run_json(rd, "attacks.json")

        # Ground truth: steps where attacks were active (from trace)
        trace_path = rd / "trace.parquet"
        attack_steps: set = set()
        sampling_ms = 500  # default
        if trace_path.exists():
            try:
                tdf = pd.read_parquet(trace_path, columns=["step_id", "attack_active"])
                attack_steps = set(tdf.loc[tdf["attack_active"] == True, "step_id"].astype(int))
            except Exception:
                pass

        # Group detections by detector
        per_det_steps: Dict[str, set] = defaultdict(set)
        for ev in detections:
            name = ev.get("detector_name", "unknown")
            det_events[name].append(ev)
            det_confidences[name].append(ev.get("confidence", 0.0))
            for tag in ev.get("affected_tags", []):
                det_tags[name].add(tag)
            step = ev.get("step_id")
            if step is not None:
                per_det_steps[name].add(int(step))

        # Per-detector TP/FP vs ground truth
        for name, steps in per_det_steps.items():
            tp = len(steps & attack_steps)
            fp = len(steps - attack_steps)
            det_tp[name] += tp
            det_fp[name] += fp

        # Per-detector latency: from attack start step to first detection
        # by that specific detector
        for attack in attacks:
            if attack.get("execution_status") not in ("executed", "dry_run"):
                continue
            aid = attack.get("action_id")
            # Find start step from trace
            if trace_path.exists():
                try:
                    tdf_a = pd.read_parquet(
                        trace_path,
                        columns=["step_id", "attack_action_id"],
                    )
                    starts = tdf_a.loc[
                        tdf_a["attack_action_id"] == aid, "step_id"
                    ]
                    if starts.empty:
                        continue
                    start_step = int(starts.iloc[0])
                except Exception:
                    continue
            else:
                continue

            for ev in detections:
                name = ev.get("detector_name", "unknown")
                ev_step = ev.get("step_id")
                if ev_step is not None and int(ev_step) >= start_step:
                    lat_ms = (int(ev_step) - start_step) * sampling_ms
                    det_latencies[name].append(max(0.0, lat_ms))
                    break  # only first detection

        # FN contribution: attack steps not detected by any detector
        all_detected = set()
        for steps in per_det_steps.values():
            all_detected |= steps
        det_fn_total += len(attack_steps - all_detected)

    # Build table rows
    all_detectors = sorted(set(det_events.keys()))
    rows = []
    for name in all_detectors:
        tp = det_tp.get(name, 0)
        fp = det_fp.get(name, 0)
        fn = det_fn_total  # conservative: FN is global across all detectors

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

        conf_stats = _agg(det_confidences.get(name, []))
        lat_stats = _agg(det_latencies.get(name, []))
        lat_pcts = _pct(det_latencies.get(name, []))

        events = det_events.get(name, [])
        high_count = sum(
            1 for e in events
            if e.get("severity", "").lower() in ("high", "critical")
        )

        row = {
            "detector": name,
            "n_events": len(events),
            "mean_confidence": conf_stats["mean"],
            "std_confidence": conf_stats["std"],
            "severity_high_pct": round(high_count / len(events), 4) if events else 0.0,
            "affected_tags_diversity": len(det_tags.get(name, set())),
            "per_detector_tp": tp,
            "per_detector_fp": fp,
            "per_detector_precision": round(prec, 4),
            "per_detector_recall": round(rec, 4),
            "per_detector_f1": round(f1, 4),
            "latency_mean": lat_stats["mean"],
            "latency_p50": lat_pcts.get("p50", 0.0),
            "latency_p90": lat_pcts.get("p90", 0.0),
            "latency_p99": lat_pcts.get("p99", 0.0),
        }
        rows.append(row)

    return pd.DataFrame(rows).set_index("detector") if rows else pd.DataFrame()


# ---------------------------------------------------------------------------
# Table 4: Adaptation Across Rounds
# ---------------------------------------------------------------------------


def adaptation_round_table(
    data_dir: Path,
    experiment: str,
) -> pd.DataFrame:
    """
    Produce **Table 4** — defender performance across adaptation rounds.

    Reads ``round_metrics.csv`` from the processed directory.
    Returns a DataFrame with one row per round.
    """
    processed = data_dir / "processed" / experiment
    csv_path = processed / "round_metrics.csv"

    if csv_path.exists():
        df = pd.read_csv(csv_path)
        # Add delta columns
        if "detector_f1" in df.columns and len(df) > 1:
            df["f1_delta"] = df["detector_f1"].diff().round(4)
            df["recall_delta"] = df["detector_recall"].diff().round(4) if "detector_recall" in df.columns else 0.0
        return df

    # Fall back to metrics.json per round
    raw = _raw_dir(data_dir, experiment)
    all_metrics = _load_run_metrics(raw)
    by_round: Dict[int, List[Dict]] = defaultdict(list)
    for m in all_metrics:
        by_round[m.get("adaptation_round", 0)].append(m)

    rows = []
    cumulative_hc = 0
    for rnd in sorted(by_round.keys()):
        runs = by_round[rnd]
        f1_vals = [r.get("detector_f1", 0) for r in runs]
        rec_vals = [r.get("detector_recall", 0) for r in runs]
        fn_vals = [r.get("false_negatives", 0) for r in runs]
        hc_this = sum(fn_vals)
        cumulative_hc += hc_this
        rows.append({
            "round": rnd,
            "n_runs": len(runs),
            "detector_f1": _agg(f1_vals)["mean"],
            "detector_recall": _agg(rec_vals)["mean"],
            "detector_precision": _agg([r.get("detector_precision", 0) for r in runs])["mean"],
            "detection_latency_ms": _agg([r.get("detection_latency_ms", 0) for r in runs])["mean"],
            "false_negatives": sum(fn_vals),
            "hard_case_count": hc_this,
            "hard_case_cumulative": cumulative_hc,
            "attack_success_rate": _agg([r.get("attack_success_rate", 0) for r in runs])["mean"],
        })

    return pd.DataFrame(rows).set_index("round") if rows else pd.DataFrame()


# ---------------------------------------------------------------------------
# Attack Type Breakdown
# ---------------------------------------------------------------------------


def attack_type_breakdown(
    data_dir: Path,
    experiment: str,
    eval_only: bool = True,
) -> pd.DataFrame:
    """
    Break down attack success by attack type (sensor_spoof, actuator_override, etc.).

    Reads attacks.json from each run and cross-references with shield_events.json.
    """
    raw = _raw_dir(data_dir, experiment)
    run_dirs = sorted(d for d in raw.iterdir() if d.is_dir()) if raw.exists() else []

    type_stats: Dict[str, Dict[str, int]] = defaultdict(
        lambda: {"total": 0, "approved": 0, "executed": 0, "success": 0}
    )
    type_impacts: Dict[str, List[float]] = defaultdict(list)

    for rd in run_dirs:
        # Check eval_run flag
        if eval_only:
            mpath = rd / "metrics.json"
            if mpath.exists():
                with mpath.open() as fh:
                    m = json.load(fh)
                if not m.get("eval_run", False):
                    continue

        attacks = _load_run_json(rd, "attacks.json")
        for attack in attacks:
            atype = attack.get("attack_type", "unknown")
            if isinstance(atype, dict):
                atype = atype.get("value", str(atype))
            type_stats[atype]["total"] += 1
            if attack.get("approved_by_shield"):
                type_stats[atype]["approved"] += 1
            if attack.get("execution_status") in ("executed", "dry_run"):
                type_stats[atype]["executed"] += 1

    rows = []
    for atype, stats in sorted(type_stats.items()):
        total = stats["total"]
        rows.append({
            "attack_type": atype,
            "total": total,
            "approved": stats["approved"],
            "executed": stats["executed"],
            "approval_rate": round(stats["approved"] / total, 4) if total > 0 else 0.0,
            "execution_rate": round(stats["executed"] / total, 4) if total > 0 else 0.0,
        })

    return pd.DataFrame(rows).set_index("attack_type") if rows else pd.DataFrame()


# ---------------------------------------------------------------------------
# Latency Distribution
# ---------------------------------------------------------------------------


def latency_distribution(
    data_dir: Path,
    experiment: str,
    eval_only: bool = True,
) -> Dict[str, Any]:
    """
    Compute detection latency distribution across all runs.

    Returns a dict suitable for JSON serialization:

    - ``global``: {mean, std, p50, p90, p95, p99, min, max, n}
    - ``per_detector``: {detector_name: {mean, std, p50, p90, p95, p99, ...}}
    - ``per_attacker``: {attacker_name: {mean, std, p50, p90, p95, p99, ...}}
    - ``raw_latencies``: list of all latency values (for histogram plotting)
    """
    raw = _raw_dir(data_dir, experiment)
    run_dirs = sorted(d for d in raw.iterdir() if d.is_dir()) if raw.exists() else []

    global_latencies: List[float] = []
    per_detector: Dict[str, List[float]] = defaultdict(list)
    per_attacker: Dict[str, List[float]] = defaultdict(list)

    for rd in run_dirs:
        mpath = rd / "metrics.json"
        if not mpath.exists():
            continue
        with mpath.open() as fh:
            m = json.load(fh)
        if eval_only and not m.get("eval_run", False):
            continue

        attacker_name = m.get("attacker_name", "unknown")
        sampling_ms = 500  # default

        trace_path = rd / "trace.parquet"
        detections = _load_run_json(rd, "detections.json")
        attacks = _load_run_json(rd, "attacks.json")

        if not trace_path.exists():
            continue

        try:
            tdf = pd.read_parquet(trace_path, columns=["step_id", "attack_action_id"])
        except Exception:
            continue

        for attack in attacks:
            if attack.get("execution_status") not in ("executed", "dry_run"):
                continue
            aid = attack.get("action_id")
            starts = tdf.loc[tdf["attack_action_id"] == aid, "step_id"]
            if starts.empty:
                continue
            start_step = int(starts.iloc[0])

            # Find first detection per detector
            found: Dict[str, float] = {}
            for ev in detections:
                ev_step = ev.get("step_id")
                if ev_step is None or int(ev_step) < start_step:
                    continue
                name = ev.get("detector_name", "unknown")
                lat = (int(ev_step) - start_step) * sampling_ms
                if name not in found:
                    found[name] = max(0.0, lat)

            # Global latency = min latency across all detectors (first to catch)
            if found:
                first_lat = min(found.values())
                global_latencies.append(first_lat)
                per_attacker[attacker_name].append(first_lat)

            for det_name, lat in found.items():
                per_detector[det_name].append(lat)

    result: Dict[str, Any] = {
        "global": {**_agg(global_latencies), **_pct(global_latencies)},
        "per_detector": {},
        "per_attacker": {},
        "raw_latencies": global_latencies,
    }
    for name, lats in per_detector.items():
        result["per_detector"][name] = {**_agg(lats), **_pct(lats)}
    for name, lats in per_attacker.items():
        result["per_attacker"][name] = {**_agg(lats), **_pct(lats)}

    return result


# ---------------------------------------------------------------------------
# Cross-Model Comparison
# ---------------------------------------------------------------------------


def cross_model_table(
    data_dir: Path,
    experiment: str,
    eval_only: bool = True,
) -> pd.DataFrame:
    """
    Compare LLM attack performance across different models.

    Reads ``metadata.json`` from each run to determine the ``llm_model``
    used, then groups ``metrics.json`` by model name.

    Returns a DataFrame with rows = model names and columns:

    - ``n_runs``
    - ``validity_mean``, ``validity_std``
    - ``attack_success_mean``, ``attack_success_std``
    - ``impact_mean``, ``impact_std``
    - ``shield_approval_mean``
    - ``detector_f1_mean``
    - ``llm_avg_latency_ms``
    - ``llm_parse_success_rate``
    """
    raw = _raw_dir(data_dir, experiment)
    if not raw.exists():
        return pd.DataFrame()

    model_runs: Dict[str, List[Dict]] = defaultdict(list)
    model_llm_meta: Dict[str, List[Dict]] = defaultdict(list)

    for run_dir in sorted(raw.iterdir()):
        if not run_dir.is_dir():
            continue
        meta_path = run_dir / "metadata.json"
        metrics_path = run_dir / "metrics.json"

        if not meta_path.exists() or not metrics_path.exists():
            continue

        with meta_path.open() as fh:
            meta = json.load(fh)

        model_name = meta.get("llm_model", "")
        if not model_name:
            continue

        with metrics_path.open() as fh:
            metrics = json.load(fh)

        if eval_only and not metrics.get("eval_run", False):
            continue

        model_runs[model_name].append(metrics)
        model_llm_meta[model_name].append(meta)

    if not model_runs:
        return pd.DataFrame()

    rows = []
    for model, runs in sorted(model_runs.items()):
        row: Dict[str, Any] = {"model": model, "n_runs": len(runs)}
        for field, col in [
            ("action_validity_rate", "validity"),
            ("attack_success_rate", "attack_success"),
            ("process_impact_score", "impact"),
            ("shield_approval_rate", "shield_approval"),
            ("detector_f1", "detector_f1"),
            ("detection_latency_ms", "detection_latency"),
        ]:
            vals = [r.get(field, 0.0) for r in runs]
            stats = _agg(vals)
            row[f"{col}_mean"] = stats["mean"]
            row[f"{col}_std"] = stats["std"]

        row["total_attacks"] = sum(r.get("total_attacks", 0) for r in runs)

        # LLM-specific metadata from metadata.json
        llm_metas = model_llm_meta.get(model, [])
        avg_lats = [m.get("llm_avg_latency_ms", 0.0) for m in llm_metas if m.get("llm_avg_latency_ms")]
        parse_rates = [m.get("llm_parse_success_rate", 0.0) for m in llm_metas if m.get("llm_parse_success_rate") is not None]
        row["llm_avg_latency_ms"] = _agg(avg_lats)["mean"] if avg_lats else 0.0
        row["llm_parse_success_rate"] = _agg(parse_rates)["mean"] if parse_rates else 0.0

        rows.append(row)

    return pd.DataFrame(rows).set_index("model")


# ---------------------------------------------------------------------------
# Full Paper Export
# ---------------------------------------------------------------------------


def full_paper_export(
    data_dir: Path,
    experiment: str,
    output_dir: Optional[Path] = None,
    eval_only: bool = True,
) -> Path:
    """
    Generate all paper-ready artifacts in one call.

    Writes to ``<output_dir>/`` (defaults to ``data/processed/<experiment>/paper/``):

    - ``table1_attack_results.csv``
    - ``table2_shield_results.csv``
    - ``table3_defender_results.csv``
    - ``table4_adaptation_results.csv``
    - ``attack_type_breakdown.csv``
    - ``latency_distribution.json``
    - ``paper_export_manifest.json``

    Returns the output directory path.
    """
    out = output_dir or (data_dir / "processed" / experiment / "paper")
    out.mkdir(parents=True, exist_ok=True)

    manifest: Dict[str, Any] = {
        "experiment": experiment,
        "eval_only": eval_only,
        "tables": {},
    }

    # Table 1
    try:
        t1 = cross_attacker_table(data_dir, experiment, eval_only)
        t1.to_csv(out / "table1_attack_results.csv")
        manifest["tables"]["table1_attack_results"] = {
            "file": "table1_attack_results.csv",
            "paper_ref": "tab:attack-results",
            "rows": len(t1),
        }
    except Exception as e:
        logger.warning("Table 1 generation failed: %s", e)

    # Table 2
    try:
        t2 = shield_analysis_table(data_dir, experiment, eval_only)
        t2.to_csv(out / "table2_shield_results.csv")
        manifest["tables"]["table2_shield_results"] = {
            "file": "table2_shield_results.csv",
            "paper_ref": "tab:shield-results",
            "rows": len(t2),
            "rule_rejection_counts": t2.attrs.get("rule_rejection_counts", {}),
        }
    except Exception as e:
        logger.warning("Table 2 generation failed: %s", e)

    # Table 3
    try:
        t3 = cross_detector_table(data_dir, experiment, eval_only)
        t3.to_csv(out / "table3_defender_results.csv")
        manifest["tables"]["table3_defender_results"] = {
            "file": "table3_defender_results.csv",
            "paper_ref": "tab:defender-results",
            "rows": len(t3),
        }
    except Exception as e:
        logger.warning("Table 3 generation failed: %s", e)

    # Table 4
    try:
        t4 = adaptation_round_table(data_dir, experiment)
        t4.to_csv(out / "table4_adaptation_results.csv")
        manifest["tables"]["table4_adaptation_results"] = {
            "file": "table4_adaptation_results.csv",
            "paper_ref": "tab:adaptation-results",
            "rows": len(t4),
        }
    except Exception as e:
        logger.warning("Table 4 generation failed: %s", e)

    # Attack type breakdown
    try:
        atb = attack_type_breakdown(data_dir, experiment, eval_only)
        atb.to_csv(out / "attack_type_breakdown.csv")
        manifest["tables"]["attack_type_breakdown"] = {
            "file": "attack_type_breakdown.csv",
            "rows": len(atb),
        }
    except Exception as e:
        logger.warning("Attack type breakdown failed: %s", e)

    # Cross-model comparison (only if LLM metadata is present)
    try:
        cmt = cross_model_table(data_dir, experiment, eval_only)
        if not cmt.empty:
            cmt.to_csv(out / "cross_model_comparison.csv")
            manifest["tables"]["cross_model_comparison"] = {
                "file": "cross_model_comparison.csv",
                "paper_ref": "tab:model-comparison",
                "rows": len(cmt),
            }
    except Exception as e:
        logger.warning("Cross-model table failed: %s", e)

    # Latency distribution
    try:
        ld = latency_distribution(data_dir, experiment, eval_only)
        with (out / "latency_distribution.json").open("w") as fh:
            # Don't write raw_latencies to JSON for size (can be huge)
            export_ld = {k: v for k, v in ld.items() if k != "raw_latencies"}
            export_ld["n_latencies"] = len(ld.get("raw_latencies", []))
            json.dump(export_ld, fh, indent=2)
        manifest["tables"]["latency_distribution"] = {
            "file": "latency_distribution.json",
            "n_latencies": len(ld.get("raw_latencies", [])),
        }
    except Exception as e:
        logger.warning("Latency distribution failed: %s", e)

    # Manifest
    with (out / "paper_export_manifest.json").open("w") as fh:
        json.dump(manifest, fh, indent=2)

    # v2 context ablation (RQ1)
    try:
        ca = context_ablation_table(data_dir, experiment)
        if not ca.empty:
            ca.to_csv(out / "context_ablation.csv")
            manifest["tables"]["context_ablation"] = {
                "file": "context_ablation.csv",
                "paper_ref": "tab:context-ablation",
                "rows": len(ca),
            }
    except Exception as e:
        logger.warning("Context ablation table failed: %s", e)

    # v2 defense comparison (RQ4)
    try:
        dc = defense_comparison_table(data_dir, experiment)
        if not dc.empty:
            dc.to_csv(out / "defense_comparison.csv")
            manifest["tables"]["defense_comparison"] = {
                "file": "defense_comparison.csv",
                "paper_ref": "tab:defense-comparison",
                "rows": len(dc),
            }
    except Exception as e:
        logger.warning("Defense comparison table failed: %s", e)

    # v2 fine-tuning deltas (RQ2)
    try:
        ft = finetune_delta_table(data_dir, experiment)
        if not ft.empty:
            ft.to_csv(out / "finetune_deltas.csv")
            manifest["tables"]["finetune_deltas"] = {
                "file": "finetune_deltas.csv",
                "paper_ref": "tab:finetune-deltas",
                "rows": len(ft),
            }
    except Exception as e:
        logger.warning("Finetune delta table failed: %s", e)

    # Manifest
    with (out / "paper_export_manifest.json").open("w") as fh:
        json.dump(manifest, fh, indent=2)

    logger.info("Paper export written to %s (%d tables).", out, len(manifest["tables"]))
    return out


# ---------------------------------------------------------------------------
# v2 Table: Context Ablation (RQ1)
# ---------------------------------------------------------------------------


def context_ablation_table(
    data_dir: Path,
    experiment: str,
) -> pd.DataFrame:
    """Produce RQ1 context-ablation table from v2 unified step logs.

    Reads unified_steps.parquet from all RQ1 runs and computes per-tier
    (minimal, partial, full) metrics: ASR, VAR, TFS, SSR.
    """
    from cpsforge.analysis.context_analysis import ContextAblationAnalyzer
    raw_base = data_dir / "raw"
    analyzer = ContextAblationAnalyzer(raw_base)
    return analyzer.run()


# ---------------------------------------------------------------------------
# v2 Table: Defense Comparison (RQ4)
# ---------------------------------------------------------------------------


def defense_comparison_table(
    data_dir: Path,
    experiment: str,
) -> pd.DataFrame:
    """Produce RQ4 defense comparison table from v2 unified step logs.

    Groups runs by defense_variant and computes prevention rate, FPR,
    and normal-operation preservation metrics.
    """
    from cpsforge.analysis.context_analysis import _load_step_logs
    raw_base = data_dir / "raw"

    # Discover all RQ4 experiment dirs
    frames = []
    if raw_base.exists():
        for d in sorted(raw_base.iterdir()):
            if d.is_dir() and "RQ4" in d.name:
                df = _load_step_logs(d)
                if not df.empty:
                    frames.append(df)

    if not frames:
        return pd.DataFrame()

    all_steps = pd.concat(frames, ignore_index=True)
    results = []

    for (defense, scene), group in all_steps.groupby(["defense_variant", "scene"]):
        attack_decisions = group[group["parsed_decision"] == "attack"]
        n_attacks = len(attack_decisions)
        n_blocked_phase = int(group["phase_shield_blocked"].sum()) if "phase_shield_blocked" in group else 0
        n_blocked_intent = int(group["intent_check_blocked"].sum()) if "intent_check_blocked" in group else 0
        n_blocked_shield = int((group["shield_decision"] == "blocked").sum()) if "shield_decision" in group else 0
        n_success = int(group["attack_success"].sum()) if "attack_success" in group else 0

        prevention_rate = (n_blocked_shield + n_blocked_phase + n_blocked_intent) / n_attacks if n_attacks > 0 else 0.0
        asr = n_success / n_attacks if n_attacks > 0 else 0.0

        # FPR: detector alerts on steps without active attacks
        normal_steps = group[group["attack_active"] == False] if "attack_active" in group else group
        if len(normal_steps) > 0:
            false_alerts = normal_steps[
                normal_steps["detector_alerts"].apply(
                    lambda x: len(x) > 0 if isinstance(x, list) else False
                )
            ] if "detector_alerts" in normal_steps else pd.DataFrame()
            fpr = len(false_alerts) / len(normal_steps)
        else:
            fpr = 0.0

        results.append({
            "defense_variant": defense,
            "scene": scene,
            "n_runs": group["run_id"].nunique(),
            "n_attacks": n_attacks,
            "prevention_rate": round(prevention_rate, 4),
            "ASR": round(asr, 4),
            "FPR": round(fpr, 4),
            "n_blocked_phase": n_blocked_phase,
            "n_blocked_intent": n_blocked_intent,
            "n_blocked_shield": n_blocked_shield,
        })

    return pd.DataFrame(results)


# ---------------------------------------------------------------------------
# v2 Table: Fine-Tuning Deltas (RQ2)
# ---------------------------------------------------------------------------


def finetune_delta_table(
    data_dir: Path,
    experiment: str,
) -> pd.DataFrame:
    """Produce RQ2 fine-tuning delta table from v2 unified step logs."""
    from cpsforge.analysis.finetune_analysis import FinetuneAnalyzer
    raw_base = data_dir / "raw"
    analyzer = FinetuneAnalyzer(raw_base)
    return analyzer.compute_deltas()
