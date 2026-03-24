"""
CPSForge Isolation Forest Detector (Point-wise)
=================================================
Standalone point-wise Isolation Forest anomaly detector.

Unlike :class:`~cpsforge.defenders.sequence_model.SequenceModelDetector`
which uses a windowed aggregate, this detector scores each individual
snapshot as a single point.  This makes it more responsive to sudden
anomalies but less suited to detecting slow drifts.

Operation
---------
1. Convert each :class:`PlantSnapshot` to a flat numeric feature vector.
2. Optionally scale using a pre-fitted :class:`StandardScaler`.
3. Score using :class:`~sklearn.ensemble.IsolationForest.decision_function`.
4. Map to ``[0, 1]`` where higher = more anomalous.
5. Fire a :class:`DetectionEvent` when the score exceeds ``anomaly_threshold``.

Configuration (via ``parameters`` dict in DefenderConfig YAML)::

    parameters:
      n_estimators: 100
      contamination: auto
      point_wise: true        # default; set false for windowed mode
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


def _snapshot_to_vector(snapshot: PlantSnapshot) -> Optional[np.ndarray]:
    """Extract numeric values from snapshot into a flat feature vector."""
    values: List[float] = []
    for d in (snapshot.sensors, snapshot.actuators, snapshot.setpoints,
              snapshot.derived_features):
        for v in d.values():
            if v is None:
                values.append(0.0)
            else:
                try:
                    values.append(float(v))
                except (TypeError, ValueError):
                    values.append(0.0)
    return np.array(values, dtype=np.float32) if values else None


class IsolationForestDetector(BaseDetector):
    """
    Point-wise (or optionally windowed) Isolation Forest anomaly detector.

    Trained offline on normal-operation data and loaded from disk.
    Each snapshot is scored individually, providing fast detection of
    abrupt anomalies.
    """

    def __init__(self, config: DefenderConfig) -> None:
        self._config = config
        params = config.parameters or {}

        self._point_wise: bool = bool(params.get("point_wise", True))
        self._window_size: int = max(2, config.window_size)
        self._threshold: float = config.anomaly_threshold
        self._buffer: Deque[np.ndarray] = deque(maxlen=self._window_size)

        self._model: Optional[Any] = None
        self._scaler: Optional[Any] = None
        self._trained: bool = False
        self._step_count: int = 0
        self._detection_count: int = 0
        self._last_score: float = 0.0

        if config.model_path:
            self._try_load_model(Path(config.model_path))
        else:
            logger.info(
                "IsolationForestDetector '%s': no model_path — untrained mode.",
                self.name,
            )

    @property
    def name(self) -> str:
        return self._config.name

    def observe(self, snapshot: PlantSnapshot) -> None:
        vec = _snapshot_to_vector(snapshot)
        if vec is not None:
            self._buffer.append(vec)

    def detect(self, snapshot: PlantSnapshot) -> List[DetectionEvent]:
        self.observe(snapshot)
        self._step_count += 1

        if not self._trained:
            return []

        if self._point_wise:
            vec = _snapshot_to_vector(snapshot)
            if vec is None:
                return []
            feature = vec
        else:
            if len(self._buffer) < self._window_size:
                return []
            window = np.stack(list(self._buffer))
            feature = np.concatenate([window.mean(axis=0), window.std(axis=0)])

        X = feature.reshape(1, -1)
        if self._scaler is not None:
            X = self._scaler.transform(X)

        raw = float(self._model.decision_function(X)[0])
        score = float(np.clip(0.5 - raw, 0.0, 1.0))
        self._last_score = score

        if score < self._threshold:
            return []

        self._detection_count += 1
        severity = (
            DetectionSeverity.CRITICAL if score > 0.9
            else DetectionSeverity.HIGH if score > 0.75
            else DetectionSeverity.MEDIUM if score > 0.55
            else DetectionSeverity.LOW
        )

        mode_label = "point-wise" if self._point_wise else f"window={self._window_size}"
        return [DetectionEvent(
            timestamp=snapshot.timestamp or datetime.now(timezone.utc),
            run_id=snapshot.run_id,
            detector_name=self.name,
            severity=severity,
            label="iforest_anomaly",
            confidence=float(np.clip(score, 0.0, 1.0)),
            explanation=(
                f"IsolationForest ({mode_label}) anomaly score {score:.3f} "
                f"exceeds threshold {self._threshold:.3f}"
            ),
            affected_tags=(
                list(snapshot.sensors.keys()) + list(snapshot.actuators.keys())
            ),
            step_id=snapshot.step_id,
        )]

    def reset(self) -> None:
        self._buffer.clear()
        self._step_count = 0
        self._detection_count = 0
        self._last_score = 0.0

    def export_state(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "detector_type": "isolation_forest",
            "trained": self._trained,
            "step_count": self._step_count,
            "detection_count": self._detection_count,
            "last_score": self._last_score,
            "point_wise": self._point_wise,
            "window_size": self._window_size,
            "threshold": self._threshold,
            "model_path": self._config.model_path,
        }

    def load_model(self, path: Path) -> None:
        self._try_load_model(path)

    def _try_load_model(self, path: Path) -> None:
        try:
            import joblib
            bundle = joblib.load(path)
            self._model = bundle["model"]
            self._scaler = bundle.get("scaler")
            self._trained = True
            logger.info(
                "IsolationForestDetector '%s': loaded model from %s",
                self.name, path,
            )
        except Exception as exc:
            logger.warning(
                "IsolationForestDetector '%s': failed to load model from %s: %s",
                self.name, path, exc,
            )
