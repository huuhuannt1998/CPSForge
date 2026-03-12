"""
CPSForge Run Artifact Writer
==============================
Persists all run artifacts to the structured experiment folder layout:

  data/raw/<experiment_name>/<run_id>/
    trace.parquet          -- full PlantSnapshot timeseries
    attacks.json           -- list of AttackAction objects
    detections.json        -- list of DetectionEvent objects
    shield_events.json     -- list of ShieldDecision objects
    metrics.json           -- EvalMetrics for this run
    metadata.json          -- run configuration and metadata

After all runs in an experiment, :func:`write_experiment_summary` aggregates:

  data/processed/<experiment_name>/
    run_index.csv
    aggregate_metrics.csv
    summary.json
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

import pandas as pd

from cpsforge.core.models import (
    AttackAction,
    DetectionEvent,
    EvalMetrics,
    PlantSnapshot,
    ShieldDecision,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Run folder helpers
# ---------------------------------------------------------------------------


def make_run_id() -> str:
    """Generate a unique run ID with a timestamp prefix for easy sorting."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    short = str(uuid4())[:8]
    return f"{ts}_{short}"


def get_run_dir(base_dir: Path, experiment_name: str, run_id: str) -> Path:
    """Return the path to a run's artifact directory (does not create it)."""
    return base_dir / experiment_name / run_id


def get_processed_dir(base_dir: Path, experiment_name: str) -> Path:
    """Return the path to an experiment's processed-summary directory."""
    # Go up one level from raw/ to data/, then into processed/
    processed = base_dir.parent / "processed" / experiment_name
    return processed


# ---------------------------------------------------------------------------
# Trace recorder
# ---------------------------------------------------------------------------


class TraceRecorder:
    """
    Accumulates PlantSnapshot objects during a run and writes them to Parquet.

    Usage::

        recorder = TraceRecorder(run_dir)
        recorder.record(snapshot)       # called per polling cycle
        recorder.flush()                # write trace.parquet
    """

    def __init__(self, run_dir: Path) -> None:
        self._run_dir = run_dir
        self._snapshots: List[PlantSnapshot] = []

    def record(self, snapshot: PlantSnapshot) -> None:
        """Append a snapshot to the in-memory buffer."""
        self._snapshots.append(snapshot)

    def flush(self) -> Path:
        """
        Serialise accumulated snapshots to ``trace.parquet``.
        Returns the path of the written file.
        """
        if not self._snapshots:
            logger.warning("TraceRecorder.flush() called with no snapshots.")
            return self._run_dir / "trace.parquet"

        rows = []
        for snap in self._snapshots:
            row: Dict[str, Any] = {
                "timestamp": snap.timestamp.isoformat(),
                "scene_name": snap.scene_name,
                "run_id": snap.run_id,
                "step_id": snap.step_id,
            }
            row.update({f"sensor__{k}": v for k, v in snap.sensors.items()})
            row.update({f"actuator__{k}": v for k, v in snap.actuators.items()})
            row.update({f"ctrl__{k}": v for k, v in snap.controller_state.items()})
            row.update({f"alarm__{k}": v for k, v in snap.alarms.items()})
            row.update({f"setpoint__{k}": v for k, v in snap.setpoints.items()})
            row.update({f"feat__{k}": v for k, v in snap.derived_features.items()})
            # Attack context
            row["attack_active"] = snap.attack_context.active
            row["attack_action_id"] = snap.attack_context.action_id
            row["attack_type"] = (
                snap.attack_context.attack_type.value
                if snap.attack_context.attack_type
                else None
            )
            row["attack_target"] = snap.attack_context.target_tag
            # Defense context
            row["anomaly_score"] = snap.defense_context.anomaly_score
            row["latest_detection"] = snap.defense_context.latest_detection
            rows.append(row)

        df = pd.DataFrame(rows)
        out_path = self._run_dir / "trace.parquet"
        self._run_dir.mkdir(parents=True, exist_ok=True)
        df.to_parquet(out_path, index=False)
        logger.info("Trace written: %s (%d steps)", out_path, len(rows))
        return out_path

    def as_dataframe(self) -> pd.DataFrame:
        """Return accumulated snapshots as a DataFrame (without writing)."""
        rows = []
        for snap in self._snapshots:
            row: Dict[str, Any] = {"timestamp": snap.timestamp.isoformat(), "step_id": snap.step_id}
            row.update(snap.sensors)
            row.update(snap.actuators)
            row.update(snap.controller_state)
            row.update(snap.alarms)
            row.update(snap.setpoints)
            row.update(snap.derived_features)
            rows.append(row)
        return pd.DataFrame(rows)

    @property
    def step_count(self) -> int:
        return len(self._snapshots)


# ---------------------------------------------------------------------------
# Run artifact writer
# ---------------------------------------------------------------------------


class RunArtifactWriter:
    """
    Writes all structured artifacts for a completed run.

    Artifacts written:
      - attacks.json
      - detections.json
      - shield_events.json
      - metrics.json
      - metadata.json
    """

    def __init__(self, run_dir: Path) -> None:
        self._run_dir = run_dir

    def _write_json(self, filename: str, data: Any) -> Path:
        self._run_dir.mkdir(parents=True, exist_ok=True)
        path = self._run_dir / filename
        with path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        logger.debug("Artifact written: %s", path)
        return path

    def write_attacks(self, actions: List[AttackAction]) -> Path:
        return self._write_json(
            "attacks.json",
            [a.model_dump(mode="json") for a in actions],
        )

    def write_detections(self, events: List[DetectionEvent]) -> Path:
        return self._write_json(
            "detections.json",
            [e.model_dump(mode="json") for e in events],
        )

    def write_shield_events(self, decisions: List[ShieldDecision]) -> Path:
        return self._write_json(
            "shield_events.json",
            [d.model_dump(mode="json") for d in decisions],
        )

    def write_metrics(self, metrics: EvalMetrics) -> Path:
        return self._write_json("metrics.json", metrics.model_dump(mode="json"))

    def write_metadata(self, metadata: Dict[str, Any]) -> Path:
        return self._write_json("metadata.json", metadata)


# ---------------------------------------------------------------------------
# Trace replay helper (Phase 2)
# ---------------------------------------------------------------------------


def load_trace_snapshots(trace_path: Path, run_id: str) -> "List[PlantSnapshot]":
    """
    Reconstruct a list of :class:`PlantSnapshot` objects from a saved ``trace.parquet``.

    Column naming convention matches :class:`TraceRecorder.flush`:
      ``sensor__<name>``, ``actuator__<name>``, ``ctrl__<name>``,
      ``alarm__<name>``, ``setpoint__<name>``, ``feat__<name>``.

    Used by the ``cpsforge run detect-replay`` command to feed historical
    snapshots through updated or new detectors without re-running the PLC.

    Parameters
    ----------
    trace_path:
        Absolute path to the ``trace.parquet`` file.
    run_id:
        Run ID to stamp on the reconstructed snapshots (may differ from the
        original if post-processing across runs).

    Returns
    -------
    List[PlantSnapshot]
        Ordered list of snapshots, one per original polling step.
    """
    from cpsforge.core.models import (
        AttackContext,
        AttackSource,
        AttackType,
        DefenseContext,
        PlantSnapshot,
        SafetyContext,
    )

    df = pd.read_parquet(trace_path)
    snapshots: List[PlantSnapshot] = []

    for _, row in df.iterrows():
        def _unpack(prefix: str) -> Dict[str, Any]:
            """Extract and de-prefix columns that start with *prefix*."""
            return {
                k[len(prefix):]: (None if pd.isna(v) else v)  # type: ignore[arg-type]
                for k, v in row.items()
                if k.startswith(prefix)
            }

        # ------------------------------------------------------------------
        # Timestamp
        # ------------------------------------------------------------------
        ts_raw = row.get("timestamp")
        if isinstance(ts_raw, str):
            try:
                ts = datetime.fromisoformat(ts_raw)
            except ValueError:
                ts = datetime.now(timezone.utc)
        elif hasattr(ts_raw, "to_pydatetime"):  # pandas Timestamp
            ts = ts_raw.to_pydatetime()
        else:
            ts = datetime.now(timezone.utc)
        # Ensure timezone-aware
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        # ------------------------------------------------------------------
        # Attack context
        # ------------------------------------------------------------------
        attack_type_str = row.get("attack_type")
        try:
            raw_at = (
                AttackType(attack_type_str)
                if attack_type_str and not pd.isna(attack_type_str)
                else None
            )
        except ValueError:
            raw_at = None

        attack_ctx = AttackContext(
            active=bool(row.get("attack_active", False)),
            action_id=row.get("attack_action_id") or None,
            attack_type=raw_at,
            target_tag=row.get("attack_target") or None,
        )

        # ------------------------------------------------------------------
        # Defense context
        # ------------------------------------------------------------------
        anomaly_raw = row.get("anomaly_score")
        defense_ctx = DefenseContext(
            anomaly_score=float(anomaly_raw) if anomaly_raw is not None and not pd.isna(anomaly_raw) else None,
            latest_detection=row.get("latest_detection") or None,
        )

        snap = PlantSnapshot(
            timestamp=ts,
            scene_name=str(row.get("scene_name", "")),
            run_id=run_id,
            step_id=int(row.get("step_id", 0)),
            sensors=_unpack("sensor__"),
            actuators=_unpack("actuator__"),
            controller_state=_unpack("ctrl__"),
            alarms=_unpack("alarm__"),
            setpoints=_unpack("setpoint__"),
            derived_features={
                k: float(v)
                for k, v in _unpack("feat__").items()
                if v is not None
            },
            attack_context=attack_ctx,
            defense_context=defense_ctx,
            safety_context=SafetyContext(live_writes_enabled=False),
        )
        snapshots.append(snap)

    logger.debug("load_trace_snapshots: loaded %d steps from %s", len(snapshots), trace_path)
    return snapshots


# ---------------------------------------------------------------------------
# Experiment summary
# ---------------------------------------------------------------------------


def write_experiment_summary(
    experiment_name: str,
    run_ids: List[str],
    all_metrics: List[EvalMetrics],
    base_dir: Path,
    experiment_metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Write aggregate experiment summary to ``data/processed/<experiment_name>/``.

    Files written:
      - run_index.csv         : one row per run with key metrics columns
      - aggregate_metrics.csv : complete metrics for all runs
      - summary.json          : high-level statistics (mean, std, hard case totals)

    The summary covers all runs but computes statistical aggregates
    separately for eval-flagged runs (``eval_run=True``), which are the
    runs used for paper-reported results.
    """

    def _mean(vals: list) -> float:
        return round(sum(vals) / len(vals), 4) if vals else 0.0

    def _std(vals: list) -> float:
        if len(vals) < 2:
            return 0.0
        mu = sum(vals) / len(vals)
        return round((sum((x - mu) ** 2 for x in vals) / len(vals)) ** 0.5, 4)

    out_dir = get_processed_dir(base_dir, experiment_name)
    out_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Run index CSV -- one row per run with key metric columns included
    # ------------------------------------------------------------------
    metrics_by_run = {m.run_id: m for m in all_metrics} if all_metrics else {}
    index_rows: List[Dict[str, Any]] = []
    for rid in run_ids:
        m = metrics_by_run.get(rid)
        row: Dict[str, Any] = {"run_id": rid, "has_metrics": m is not None}
        if m:
            row.update({
                "eval_run": m.eval_run,
                "attacker_name": m.attacker_name,
                "total_steps": m.total_steps,
                "total_attacks": m.total_attacks,
                # Attack pipeline rates (form a cascade: validity ≥ approval ≥ execution)
                "action_validity_rate": m.action_validity_rate,
                "execution_success_rate": m.execution_success_rate,
                "attack_success_rate": m.attack_success_rate,
                "process_impact_score": m.process_impact_score,
                # Shield rates
                "shield_approval_rate": m.shield_approval_rate,
                "shield_rejection_rate": m.shield_rejection_rate,
                "unsafe_block_rate": m.unsafe_block_rate,
                # Detector performance
                "detector_precision": m.detector_precision,
                "detector_recall": m.detector_recall,
                "detector_f1": m.detector_f1,
                "false_positives": m.false_positives,
                "false_negatives": m.false_negatives,
                "detection_latency_ms": m.detection_latency_ms,
                # Meta
                "hard_case_flag": m.hard_case_flag,
                "adaptation_round": m.adaptation_round,
            })
        index_rows.append(row)
    pd.DataFrame(index_rows).to_csv(out_dir / "run_index.csv", index=False)

    # ------------------------------------------------------------------
    # Aggregate metrics CSV -- full serialisation of all EvalMetrics rows
    # ------------------------------------------------------------------
    if all_metrics:
        rows = [m.model_dump(mode="json") for m in all_metrics]
        pd.DataFrame(rows).to_csv(out_dir / "aggregate_metrics.csv", index=False)

    # ------------------------------------------------------------------
    # Hard case totals -- read hard_cases.json from each run directory
    # ------------------------------------------------------------------
    total_hard_cases = 0
    hard_case_runs = 0
    for rid in run_ids:
        hc_path = base_dir / experiment_name / rid / "hard_cases.json"
        if hc_path.exists():
            try:
                with hc_path.open() as fh:
                    hc_data = json.load(fh)
                count = hc_data.get("hard_case_count", 0)
                total_hard_cases += count
                if count > 0:
                    hard_case_runs += 1
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Per-model grouping -- read metadata.json for llm_model field
    # ------------------------------------------------------------------
    model_to_metrics: Dict[str, List[EvalMetrics]] = {}
    model_to_llm_meta: Dict[str, Dict[str, Any]] = {}
    for rid in run_ids:
        meta_path = base_dir / experiment_name / rid / "metadata.json"
        if not meta_path.exists():
            continue
        try:
            with meta_path.open() as fh:
                meta_data = json.load(fh)
        except Exception:
            continue
        model_name = meta_data.get("llm_model", "")
        if not model_name:
            continue
        if model_name not in model_to_metrics:
            model_to_metrics[model_name] = []
            model_to_llm_meta[model_name] = {
                k: v for k, v in meta_data.items()
                if k.startswith("llm_")
            }
        m = metrics_by_run.get(rid)
        if m:
            model_to_metrics[model_name].append(m)

    # ------------------------------------------------------------------
    # Summary JSON
    # ------------------------------------------------------------------
    summary: Dict[str, Any] = {
        "experiment_name": experiment_name,
        "total_runs": len(run_ids),
        "eval_runs": sum(1 for m in all_metrics if m.eval_run),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "total_hard_cases": total_hard_cases,
        "hard_case_runs": hard_case_runs,
    }
    if experiment_metadata:
        summary.update(experiment_metadata)

    if all_metrics:
        eval_only = [m for m in all_metrics if m.eval_run]
        # Use eval-only subset when available; fall back to all metrics.
        target = eval_only if eval_only else all_metrics

        pre_vals = [m.detector_precision for m in target]
        rec_vals = [m.detector_recall for m in target]
        f1_vals  = [m.detector_f1 for m in target]
        asr_vals = [m.attack_success_rate for m in target]
        lat_vals = [m.detection_latency_ms for m in target]
        rej_vals = [m.shield_rejection_rate for m in target]
        ubr_vals = [m.unsafe_block_rate for m in target]
        imp_vals = [m.process_impact_score for m in target]
        avr_vals = [m.action_validity_rate for m in target]
        esr_vals = [m.execution_success_rate for m in target]
        fp_vals  = [m.false_positives for m in target]
        fn_vals  = [m.false_negatives for m in target]

        summary.update({
            # Detector performance
            "mean_detector_precision": _mean(pre_vals),
            "mean_detector_recall": _mean(rec_vals),
            "mean_detector_f1": _mean(f1_vals),
            "std_detector_f1": _std(f1_vals),
            # Attack pipeline
            "mean_action_validity_rate": _mean(avr_vals),
            "mean_execution_success_rate": _mean(esr_vals),
            "mean_attack_success_rate": _mean(asr_vals),
            "std_attack_success_rate": _std(asr_vals),
            # Detection latency
            "mean_detection_latency_ms": round(_mean(lat_vals), 2),
            "std_detection_latency_ms": round(_std(lat_vals), 2),
            # Shield rates
            "mean_shield_rejection_rate": _mean(rej_vals),
            "mean_unsafe_block_rate": _mean(ubr_vals),
            # Process impact
            "mean_process_impact_score": _mean(imp_vals),
            # FP/FN counts
            "mean_false_positives": _mean(fp_vals),
            "mean_false_negatives": _mean(fn_vals),
            # Meta
            "adaptation_rounds": max((m.adaptation_round for m in target), default=0),
            "stats_source": "eval_runs" if eval_only else "all_runs",
        })

    # ------------------------------------------------------------------
    # Per-model summary (for multi-model comparison)
    # ------------------------------------------------------------------
    if model_to_metrics:
        per_model: Dict[str, Any] = {}
        for model_name, m_list in sorted(model_to_metrics.items()):
            if not m_list:
                continue
            per_model[model_name] = {
                "n_runs": len(m_list),
                "mean_attack_success_rate": _mean([m.attack_success_rate for m in m_list]),
                "mean_action_validity_rate": _mean([m.action_validity_rate for m in m_list]),
                "mean_detector_f1": _mean([m.detector_f1 for m in m_list]),
                "mean_process_impact_score": _mean([m.process_impact_score for m in m_list]),
                "mean_detection_latency_ms": round(_mean([m.detection_latency_ms for m in m_list]), 2),
                "mean_shield_rejection_rate": _mean([m.shield_rejection_rate for m in m_list]),
            }
            # Merge LLM-specific metadata (avg latency, parse rate, etc.)
            llm_meta = model_to_llm_meta.get(model_name, {})
            if llm_meta:
                per_model[model_name]["llm_metadata"] = llm_meta
        summary["per_model"] = per_model

    with (out_dir / "summary.json").open("w") as fh:
        json.dump(summary, fh, indent=2)

    logger.info("Experiment summary written to %s", out_dir)
