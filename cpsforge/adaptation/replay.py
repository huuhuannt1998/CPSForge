"""
CPSForge Run Replay Loader
============================
Programmatic API for loading a completed run's artifacts and re-running its
trace through a revised or new detector stack.  Used by the adaptation loop
and the ``cpsforge adapt`` / ``cpsforge run detect-replay`` command groups.

Typical workflow::

    loader = RunReplayLoader(run_dir)

    # Load updated or new detectors
    detectors = [ThresholdDetector(cfg_updated)]

    # Replay through the saved trace
    replayed = loader.replay_detectors(detectors)

    # Compare with the original detection set
    original = loader.load_original_detections()
    attack_steps = loader.load_attack_step_range()
    stats = loader.compute_comparison(original, replayed, attack_steps)
    print(stats)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from cpsforge.core.models import (
    AttackAction,
    DetectionEvent,
    EvalMetrics,
    PlantSnapshot,
)
from cpsforge.defenders.base import BaseDetector
from cpsforge.logging.artifacts import load_trace_snapshots

logger = logging.getLogger(__name__)


class RunReplayLoader:
    """
    Load all artifacts for a saved run and replay them through a detector stack.

    Parameters
    ----------
    run_dir:
        Path to the run folder,
        e.g. ``data/raw/<experiment_name>/<run_id>``.
    """

    def __init__(self, run_dir: Path) -> None:
        self._run_dir = Path(run_dir)
        self._run_id = self._run_dir.name

    # ------------------------------------------------------------------
    # Loaders
    # ------------------------------------------------------------------

    def load_snapshots(self) -> List[PlantSnapshot]:
        """
        Load ``trace.parquet`` as an ordered list of :class:`PlantSnapshot` objects.

        Raises
        ------
        FileNotFoundError
            If ``trace.parquet`` is absent from the run directory.
        """
        trace_path = self._run_dir / "trace.parquet"
        if not trace_path.exists():
            raise FileNotFoundError(f"trace.parquet not found in {self._run_dir}")
        return load_trace_snapshots(trace_path, run_id=self._run_id)

    def load_attacks(self) -> List[AttackAction]:
        """Load ``attacks.json``, returning an empty list if absent or malformed."""
        path = self._run_dir / "attacks.json"
        if not path.exists():
            return []
        with path.open() as fh:
            raw = json.load(fh)
        results: List[AttackAction] = []
        for item in raw:
            try:
                results.append(AttackAction(**item))
            except Exception as exc:
                logger.warning("Could not parse attack entry: %s", exc)
        return results

    def load_original_detections(self) -> List[DetectionEvent]:
        """Load ``detections.json``, returning an empty list if absent or malformed."""
        path = self._run_dir / "detections.json"
        if not path.exists():
            return []
        with path.open() as fh:
            raw = json.load(fh)
        results: List[DetectionEvent] = []
        for item in raw:
            try:
                results.append(DetectionEvent(**item))
            except Exception as exc:
                logger.warning("Could not parse detection entry: %s", exc)
        return results

    def load_metrics(self) -> Optional[EvalMetrics]:
        """Load ``metrics.json``, returning None if absent or invalid."""
        path = self._run_dir / "metrics.json"
        if not path.exists():
            return None
        try:
            with path.open() as fh:
                return EvalMetrics(**json.load(fh))
        except Exception as exc:
            logger.warning("Could not load metrics.json from %s: %s", self._run_dir, exc)
            return None

    def load_metadata(self) -> Dict[str, Any]:
        """Load ``metadata.json``, returning an empty dict if absent."""
        path = self._run_dir / "metadata.json"
        if not path.exists():
            return {}
        with path.open() as fh:
            return json.load(fh)

    def load_attack_step_range(self) -> Set[int]:
        """
        Reconstruct the set of step IDs where an attack was active, by reading
        the ``attack_active`` boolean column from ``trace.parquet``.

        Returns an empty set if the trace is absent or the column is missing.
        """
        trace_path = self._run_dir / "trace.parquet"
        if not trace_path.exists():
            return set()
        try:
            import pandas as pd
            df = pd.read_parquet(trace_path, columns=["step_id", "attack_active"])
            active_mask = df["attack_active"].fillna(False).astype(bool)
            return set(int(s) for s in df.loc[active_mask, "step_id"].tolist())
        except Exception as exc:
            logger.warning("Could not extract attack step range: %s", exc)
            return set()

    # ------------------------------------------------------------------
    # Replay
    # ------------------------------------------------------------------

    def replay_detectors(self, detectors: List[BaseDetector]) -> List[DetectionEvent]:
        """
        Run ``detectors`` over every snapshot in the saved trace.

        Each detector's :meth:`detect` method is called once per snapshot in
        chronological order.  Events are stamped with the original
        ``run_id`` and returned in order.

        Parameters
        ----------
        detectors:
            Detector instances to replay.  Stateful detectors are NOT reset
            before replay — call ``det.reset()`` explicitly if needed.

        Returns
        -------
        All :class:`DetectionEvent` objects produced during replay, in order.
        """
        snapshots = self.load_snapshots()
        events: List[DetectionEvent] = []
        for snap in snapshots:
            for det in detectors:
                for ev in det.detect(snap):
                    ev.run_id = self._run_id
                    events.append(ev)
        logger.info(
            "Replay %s: %d detectors x %d steps -> %d events.",
            self._run_id,
            len(detectors),
            len(snapshots),
            len(events),
        )
        return events

    # ------------------------------------------------------------------
    # Comparison
    # ------------------------------------------------------------------

    def compute_comparison(
        self,
        original_detections: List[DetectionEvent],
        replayed_detections: List[DetectionEvent],
        attack_step_range: Optional[Set[int]] = None,
    ) -> Dict[str, Any]:
        """
        Compare the original and replayed detection sets and compute statistics.

        Parameters
        ----------
        original_detections:
            Detection events from the original run (loaded from
            ``detections.json``).
        replayed_detections:
            Detection events from the replay (returned by
            :meth:`replay_detectors`).
        attack_step_range:
            Optional ground-truth set of step IDs where attacks were active.
            When provided, precision, recall, and F1 are computed for the
            replayed detector against ground truth.

        Returns
        -------
        Dict with comparison statistics suitable for logging or JSON export.
        """
        orig_steps = {ev.step_id for ev in original_detections if ev.step_id is not None}
        rpl_steps = {ev.step_id for ev in replayed_detections if ev.step_id is not None}

        result: Dict[str, Any] = {
            "run_id": self._run_id,
            "original_event_count": len(original_detections),
            "replayed_event_count": len(replayed_detections),
            "new_detection_steps": sorted(rpl_steps - orig_steps),
            "lost_detection_steps": sorted(orig_steps - rpl_steps),
            "common_step_count": len(orig_steps & rpl_steps),
        }

        if attack_step_range is not None:
            ar = set(attack_step_range)
            tp = len(rpl_steps & ar)
            fp = len(rpl_steps - ar)
            fn = len(ar - rpl_steps)
            p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
            result.update({
                "replayed_true_positives": tp,
                "replayed_false_positives": fp,
                "replayed_false_negatives": fn,
                "replayed_precision": round(p, 4),
                "replayed_recall": round(r, 4),
                "replayed_f1": round(f1, 4),
            })

        return result
