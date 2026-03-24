"""
CPSForge Sequence Model Detector
==================================
A rolling-window anomaly detector that scores sequences of plant snapshots
using a trained :class:`~sklearn.ensemble.IsolationForest`.

Architecture overview
---------------------
At each polling step the detector:

1. Extracts a fixed-length feature vector from the current
   :class:`~cpsforge.core.models.PlantSnapshot`.
2. Appends it to an internal rolling buffer of length ``window_size``.
3. When the buffer is full, computes aggregate features
   (per-feature mean and standard deviation across the window).
4. Passes the aggregated vector through the trained IsolationForest to
   obtain an anomaly score in ``[0, 1]``.
5. Fires a :class:`~cpsforge.core.models.DetectionEvent` when the score
   exceeds ``anomaly_threshold``.

Training
--------
The model is trained offline by
:class:`~cpsforge.adaptation.trainer.SequenceDetectorTrainer` and persisted
to disk with :mod:`joblib`.  The path is provided via
``DefenderConfig.model_path``.  When no trained model is available the
detector operates in *untrained* mode (returns no events but buffers data).

Key properties
--------------
- No GPU required — IsolationForest runs on CPU.
- Works with small datasets (10-100 samples from hard cases).
- Supports online incremental operation (one snapshot at a time).
- Export/import model state for experiment reproducibility.
"""

from __future__ import annotations

import logging
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

import numpy as np

from cpsforge.core.config import DefenderConfig
from cpsforge.core.models import DetectionEvent, DetectionSeverity, PlantSnapshot
from cpsforge.defenders.base import BaseDetector

logger = logging.getLogger(__name__)

# Severity thresholds for graded alerts
_SEVERITY_BANDS = [
    (0.9, DetectionSeverity.CRITICAL),
    (0.75, DetectionSeverity.HIGH),
    (0.55, DetectionSeverity.MEDIUM),
    (0.0, DetectionSeverity.LOW),
]


def _snapshot_to_vector(snapshot: PlantSnapshot) -> Optional[np.ndarray]:
    """
    Convert a PlantSnapshot to a flat numpy feature vector.

    Extracts all numeric values from sensors, actuators, controller_state,
    setpoints, and derived_features dicts — matching the column order written
    by :class:`~cpsforge.logging.artifacts.TraceRecorder` so that the feature
    dimension is consistent between offline training and online inference.

    Returns ``None`` if no numeric values are found.
    """
    values: List[float] = []
    for d in (
        snapshot.sensors,
        snapshot.actuators,
        snapshot.controller_state,
        snapshot.setpoints,
        snapshot.derived_features,
    ):
        for v in d.values():
            if v is None:
                values.append(0.0)
            else:
                try:
                    values.append(float(v))
                except (TypeError, ValueError):
                    values.append(0.0)
    if not values:
        return None
    return np.array(values, dtype=np.float32)


def _window_to_feature(window: np.ndarray) -> np.ndarray:
    """
    Aggregate a ``(window_size, n_features)`` window into a 1-D vector.

    Concatenates the per-column mean and standard deviation, yielding a
    feature vector of length ``2 × n_features``.  This simple aggregation
    compresses temporal structure into a fixed-size input for IsolationForest.
    """
    mean = window.mean(axis=0)
    std = window.std(axis=0)
    return np.concatenate([mean, std])


class SequenceModelDetector(BaseDetector):
    """
    Rolling-window anomaly detector backed by an IsolationForest.

    Parameters
    ----------
    config:
        :class:`~cpsforge.core.config.DefenderConfig` with:

        - ``window_size`` — rolling window length (default 20 steps).
        - ``anomaly_threshold`` — score above which to fire (default 0.5).
        - ``model_path`` — path to a :mod:`joblib`-serialised
          :class:`~cpsforge.adaptation.trainer.SequenceDetectorTrainer`
          bundle written by :meth:`SequenceDetectorTrainer.save`.
    """

    def __init__(self, config: DefenderConfig) -> None:
        self._config = config
        self._window_size: int = max(2, config.window_size)
        self._threshold: float = config.anomaly_threshold
        self._buffer: Deque[np.ndarray] = deque(maxlen=self._window_size)
        self._model: Optional[Any] = None          # sklearn IsolationForest
        self._scaler: Optional[Any] = None         # sklearn StandardScaler
        self._feature_dim: Optional[int] = None    # inferred on first snapshot
        self._detection_count: int = 0
        self._step_count: int = 0
        self._last_score: float = 0.0
        self._trained: bool = False

        # Attempt to load a pre-trained model from disk
        if config.model_path:
            self._try_load_model(Path(config.model_path))
        else:
            logger.info(
                "SequenceModelDetector '%s': no model_path set — "
                "operating in untrained mode (no detections until trained).",
                self.name,
            )

    # ------------------------------------------------------------------
    # BaseDetector interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return self._config.name

    def observe(self, snapshot: PlantSnapshot) -> None:
        """Update the rolling buffer (called before detect in the main loop)."""
        vec = _snapshot_to_vector(snapshot)
        if vec is not None:
            self._buffer.append(vec)
            if self._feature_dim is None:
                self._feature_dim = len(vec)

    def detect(self, snapshot: PlantSnapshot) -> List[DetectionEvent]:
        """
        Score the current window and return a :class:`DetectionEvent` if the
        anomaly score exceeds the configured threshold.

        Returns an empty list when:
        - The buffer is not full yet (warm-up period).
        - No model has been loaded (untrained mode).
        - The anomaly score is below the threshold.
        """
        # Buffer the snapshot
        self.observe(snapshot)
        self._step_count += 1

        if not self._trained or len(self._buffer) < self._window_size:
            return []

        score = self._score_window()
        self._last_score = score

        if score < self._threshold:
            return []

        self._detection_count += 1
        severity = self._score_to_severity(score)

        event = DetectionEvent(
            timestamp=snapshot.timestamp or datetime.now(timezone.utc),
            run_id=snapshot.run_id,
            detector_name=self.name,
            severity=severity,
            label="sequence_anomaly",
            confidence=float(np.clip(score, 0.0, 1.0)),
            explanation=(
                f"Rolling window anomaly score {score:.3f} exceeds threshold "
                f"{self._threshold:.3f} (window={self._window_size} steps)."
            ),
            affected_tags=list(snapshot.sensors.keys())
            + list(snapshot.actuators.keys()),
            step_id=snapshot.step_id,
        )
        return [event]

    def reset(self) -> None:
        """Clear the rolling buffer (call before replaying a trace)."""
        self._buffer.clear()
        self._step_count = 0
        self._detection_count = 0
        self._last_score = 0.0

    def export_state(self) -> Dict[str, Any]:
        """Serialise detector metadata (not the model weights)."""
        return {
            "name": self.name,
            "window_size": self._window_size,
            "anomaly_threshold": self._threshold,
            "trained": self._trained,
            "step_count": self._step_count,
            "detection_count": self._detection_count,
            "last_score": self._last_score,
            "model_path": self._config.model_path,
        }

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _score_window(self) -> float:
        """
        Convert the current buffer to a single anomaly score in ``[0, 1]``.

        IsolationForest's ``decision_function`` returns a real number where
        *lower* means *more anomalous*.  We negate and normalise to produce
        a score where *higher = more anomalous*.
        """
        buf = list(self._buffer)

        # Ensure all vectors in the buffer share the same dimensionality.
        # If a PLC read partially failed, some snapshots may yield vectors
        # of a different length.  Pad/truncate to the mode dimension.
        if buf:
            target_dim = buf[0].shape[0]
            aligned: List[np.ndarray] = []
            for v in buf:
                if v.shape[0] == target_dim:
                    aligned.append(v)
                elif v.shape[0] < target_dim:
                    aligned.append(np.pad(v, (0, target_dim - v.shape[0])))
                else:
                    aligned.append(v[:target_dim])
            buf = aligned

        window = np.stack(buf)                    # (window_size, n_features)
        feature_vec = _window_to_feature(window)  # (2 * n_features,)

        X = feature_vec.reshape(1, -1)

        # Guard against dimension mismatch with the trained model
        expected_dim = getattr(self._model, "n_features_in_", None)
        if self._scaler is not None:
            expected_dim = expected_dim or getattr(self._scaler, "n_features_in_", None)
        if expected_dim is not None and X.shape[1] != expected_dim:
            # Pad or truncate to match the model's expected input
            if X.shape[1] < expected_dim:
                X = np.pad(X, ((0, 0), (0, expected_dim - X.shape[1])))
            else:
                X = X[:, :expected_dim]

        if self._scaler is not None:
            X = self._scaler.transform(X)

        # IsolationForest.decision_function: < 0 = anomalous, > 0 = normal
        raw = float(self._model.decision_function(X)[0])

        # Map to [0, 1]: offset offset 0.5 → clamp → invert
        # Typical range is [-0.5, 0.5]; shift so normal ≈ 0, anomaly ≈ 1.
        score = float(np.clip(0.5 - raw, 0.0, 1.0))
        return score

    # ------------------------------------------------------------------
    # Model I/O
    # ------------------------------------------------------------------

    def load_model(self, path: Path) -> None:
        """
        Load a trained model bundle from *path* (written by
        :class:`~cpsforge.adaptation.trainer.SequenceDetectorTrainer`).

        The bundle is a dict with keys ``model`` and optionally ``scaler``.
        """
        self._try_load_model(path)

    def _try_load_model(self, path: Path) -> None:
        try:
            import joblib

            bundle = joblib.load(path)
            self._model = bundle["model"]
            self._scaler = bundle.get("scaler")
            self._trained = True
            logger.info(
                "SequenceModelDetector '%s': loaded model from %s.",
                self.name,
                path,
            )
        except FileNotFoundError:
            logger.warning(
                "SequenceModelDetector '%s': model file not found at %s — "
                "untrained mode.",
                self.name,
                path,
            )
        except Exception as exc:
            logger.warning(
                "SequenceModelDetector '%s': could not load model from %s: %s",
                self.name,
                path,
                exc,
            )

    @staticmethod
    def _score_to_severity(score: float) -> DetectionSeverity:
        for threshold, severity in _SEVERITY_BANDS:
            if score >= threshold:
                return severity
        return DetectionSeverity.LOW
        return []
