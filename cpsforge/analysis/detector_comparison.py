"""
CPSForge Detector Comparison Tool
====================================
Replays saved experiment traces through multiple detector configurations
and produces a structured comparison of precision, recall, F1, and latency
across all detectors.

This enables head-to-head comparison of:
  - ThresholdDetector
  - InvariantDetector
  - SequenceModelDetector (IsolationForest)
  - CUSUMDetector
  - OCSVMDetector
  - IsolationForestDetector (point-wise)
  - LSTMADDetector

Usage::

    from cpsforge.analysis.detector_comparison import DetectorComparison

    comp = DetectorComparison(
        run_dir=Path("data/raw/eval_level_control/20250101_120000_abc123"),
        detector_names=["threshold_level_control", "cusum_level_control"],
    )
    results = comp.run()
    comp.save_results(Path("comparison_results.csv"))
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import pandas as pd

from cpsforge.adaptation.replay import RunReplayLoader
from cpsforge.core.config import ConfigLoader, DefenderConfig
from cpsforge.core.models import DetectionEvent, EvalMetrics, PlantSnapshot
from cpsforge.defenders.base import BaseDetector
from cpsforge.defenders.factory import build_defender

logger = logging.getLogger(__name__)


class DetectorComparisonResult:
    """Results for a single detector on a single run."""

    def __init__(
        self,
        detector_name: str,
        detector_type: str,
        run_id: str,
        scene_name: str,
        precision: float,
        recall: float,
        f1: float,
        false_positives: int,
        false_negatives: int,
        true_positives: int,
        detection_count: int,
        mean_latency_ms: float,
        total_steps: int,
        attack_steps: int,
    ) -> None:
        self.detector_name = detector_name
        self.detector_type = detector_type
        self.run_id = run_id
        self.scene_name = scene_name
        self.precision = precision
        self.recall = recall
        self.f1 = f1
        self.false_positives = false_positives
        self.false_negatives = false_negatives
        self.true_positives = true_positives
        self.detection_count = detection_count
        self.mean_latency_ms = mean_latency_ms
        self.total_steps = total_steps
        self.attack_steps = attack_steps

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detector_name": self.detector_name,
            "detector_type": self.detector_type,
            "run_id": self.run_id,
            "scene_name": self.scene_name,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "FP": self.false_positives,
            "FN": self.false_negatives,
            "TP": self.true_positives,
            "detections": self.detection_count,
            "latency_ms": round(self.mean_latency_ms, 1),
            "total_steps": self.total_steps,
            "attack_steps": self.attack_steps,
        }


class DetectorComparison:
    """
    Run multiple detectors over a saved experiment trace and compare.

    Parameters
    ----------
    run_dir:
        Path to a completed run directory containing trace.parquet,
        attacks.json, metadata.json.
    detector_names:
        List of defender config names (e.g. "threshold_level_control",
        "cusum_level_control"). Each must have a YAML config in
        configs/defenders/.
    loader:
        Optional ConfigLoader. Created automatically if not provided.
    """

    def __init__(
        self,
        run_dir: Path,
        detector_names: List[str],
        loader: Optional[ConfigLoader] = None,
    ) -> None:
        self._run_dir = Path(run_dir)
        self._detector_names = detector_names
        self._loader = loader or ConfigLoader()
        self._results: List[DetectorComparisonResult] = []

    def run(self) -> List[DetectorComparisonResult]:
        """
        Replay the trace through all configured detectors.

        Returns a list of :class:`DetectorComparisonResult`, one per detector.
        """
        replay = RunReplayLoader(self._run_dir)
        snapshots = replay.load_snapshots()
        attack_step_range = replay.load_attack_step_range()
        metadata = replay.load_metadata()

        scene_name = metadata.get("scene", "unknown")
        run_id = metadata.get("run_id", self._run_dir.name)
        sampling_ms = metadata.get("sampling_interval_ms", 500)

        logger.info(
            "DetectorComparison: %d snapshots, %d attack steps, %d detectors",
            len(snapshots), len(attack_step_range), len(self._detector_names),
        )

        self._results = []
        for det_name in self._detector_names:
            try:
                result = self._evaluate_detector(
                    det_name, snapshots, attack_step_range,
                    scene_name, run_id, sampling_ms,
                )
                self._results.append(result)
                logger.info(
                    "  %s: P=%.3f R=%.3f F1=%.3f FP=%d FN=%d",
                    det_name, result.precision, result.recall,
                    result.f1, result.false_positives, result.false_negatives,
                )
            except Exception as exc:
                logger.warning(
                    "  %s: FAILED — %s", det_name, exc
                )

        return self._results

    def save_results(self, path: Path) -> None:
        """Save comparison results to CSV."""
        if not self._results:
            logger.warning("No results to save.")
            return
        df = pd.DataFrame([r.to_dict() for r in self._results])
        path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(path, index=False)
        logger.info("Comparison results saved to %s", path)

    def to_dataframe(self) -> pd.DataFrame:
        """Return results as a DataFrame."""
        return pd.DataFrame([r.to_dict() for r in self._results])

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _evaluate_detector(
        self,
        det_name: str,
        snapshots: List[PlantSnapshot],
        attack_steps: Set[int],
        scene_name: str,
        run_id: str,
        sampling_ms: int,
    ) -> DetectorComparisonResult:
        """Run a single detector over the trace and compute metrics."""
        cfg = self._loader.load_defender(det_name)
        detector = build_defender(cfg)
        detector.reset()

        # Replay
        detections: List[DetectionEvent] = []
        for snap in snapshots:
            events = detector.detect(snap)
            detections.extend(events)

        # Compute metrics
        detected_steps: Set[int] = set()
        for ev in detections:
            if ev.step_id is not None:
                detected_steps.add(ev.step_id)

        tp = len(attack_steps & detected_steps)
        fp = len(detected_steps - attack_steps)
        fn = len(attack_steps - detected_steps)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        # Detection latency (simplified: first detection after each attack region start)
        latencies = []
        if attack_steps:
            sorted_attack = sorted(attack_steps)
            # Find contiguous regions
            regions = []
            start = sorted_attack[0]
            prev = sorted_attack[0]
            for s in sorted_attack[1:]:
                if s > prev + 1:
                    regions.append((start, prev))
                    start = s
                prev = s
            regions.append((start, prev))

            for region_start, _ in regions:
                first_det = None
                for ev in detections:
                    if ev.step_id is not None and ev.step_id >= region_start:
                        if first_det is None or ev.step_id < first_det:
                            first_det = ev.step_id
                if first_det is not None:
                    latencies.append((first_det - region_start) * sampling_ms)

        mean_latency = sum(latencies) / len(latencies) if latencies else 0.0

        return DetectorComparisonResult(
            detector_name=det_name,
            detector_type=cfg.detector_type,
            run_id=run_id,
            scene_name=scene_name,
            precision=precision,
            recall=recall,
            f1=f1,
            false_positives=fp,
            false_negatives=fn,
            true_positives=tp,
            detection_count=len(detections),
            mean_latency_ms=mean_latency,
            total_steps=len(snapshots),
            attack_steps=len(attack_steps),
        )


def compare_detectors_across_runs(
    experiment_dir: Path,
    detector_names: List[str],
    loader: Optional[ConfigLoader] = None,
) -> pd.DataFrame:
    """
    Compare detectors across all runs in an experiment directory.

    Returns a DataFrame with one row per (detector, run) combination,
    suitable for computing mean ± std across runs.
    """
    loader = loader or ConfigLoader()
    all_results = []

    run_dirs = sorted(
        d for d in experiment_dir.iterdir()
        if d.is_dir() and (d / "metadata.json").exists()
    )

    for run_dir in run_dirs:
        comp = DetectorComparison(run_dir, detector_names, loader)
        results = comp.run()
        all_results.extend(results)

    if not all_results:
        return pd.DataFrame()

    df = pd.DataFrame([r.to_dict() for r in all_results])
    return df


def aggregate_comparison(df: pd.DataFrame) -> pd.DataFrame:
    """
    Aggregate per-run detector results into mean ± std per detector.

    Parameters
    ----------
    df:
        DataFrame from :func:`compare_detectors_across_runs`.

    Returns
    -------
    Aggregated DataFrame with columns like ``f1_mean``, ``f1_std``, etc.
    """
    if df.empty:
        return df

    numeric_cols = ["precision", "recall", "f1", "FP", "FN", "TP",
                    "detections", "latency_ms"]

    agg = df.groupby(["detector_name", "detector_type", "scene_name"])[
        numeric_cols
    ].agg(["mean", "std"]).round(4)

    # Flatten MultiIndex columns
    agg.columns = [f"{col}_{stat}" for col, stat in agg.columns]
    agg = agg.reset_index()
    return agg
