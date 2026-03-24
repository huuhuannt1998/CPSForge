"""
CPSForge One-Class SVM Detector
=================================
Anomaly detector using a One-Class SVM trained on normal plant operation.

One-Class SVM (Scholkopf et al., 2001) learns a decision boundary around
normal data in kernel space.  Points that fall outside the boundary are
scored as anomalies.  This is a standard baseline in CPS intrusion
detection literature.

Operation Modes
---------------
- **Trained mode**: A pre-fitted model is loaded from ``model_path``.
  Each snapshot is scored against the learned boundary.
- **Untrained mode**: No model available.  The detector buffers snapshots
  and returns no events.  Use the companion trainer to fit offline.

Configuration (via ``parameters`` dict in DefenderConfig YAML)::

    parameters:
      kernel: rbf
      nu: 0.05
      gamma: scale
      use_window: true       # aggregate a sliding window, else point-wise
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


class OCSVMDetector(BaseDetector):
    """
    One-Class SVM anomaly detector.

    Scores each incoming snapshot (or sliding window aggregate) against a
    pre-trained One-Class SVM.  Fires a :class:`DetectionEvent` when the
    decision function score indicates the observation lies outside the
    learned boundary of normal operation.
    """

    def __init__(self, config: DefenderConfig) -> None:
        self._config = config
        params = config.parameters or {}

        self._use_window: bool = bool(params.get("use_window", True))
        self._window_size: int = max(2, config.window_size)
        self._threshold: float = config.anomaly_threshold  # score above which to fire
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
                "OCSVMDetector '%s': no model_path — untrained mode.", self.name
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

        if self._use_window:
            if len(self._buffer) < self._window_size:
                return []
            window = np.stack(list(self._buffer))
            feature = np.concatenate([window.mean(axis=0), window.std(axis=0)])
        else:
            vec = _snapshot_to_vector(snapshot)
            if vec is None:
                return []
            feature = vec

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

        return [DetectionEvent(
            timestamp=snapshot.timestamp or datetime.now(timezone.utc),
            run_id=snapshot.run_id,
            detector_name=self.name,
            severity=severity,
            label="ocsvm_anomaly",
            confidence=float(np.clip(score, 0.0, 1.0)),
            explanation=(
                f"OCSVM anomaly score {score:.3f} exceeds threshold "
                f"{self._threshold:.3f} (raw decision_function={raw:.3f})"
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
            "detector_type": "ocsvm",
            "trained": self._trained,
            "step_count": self._step_count,
            "detection_count": self._detection_count,
            "last_score": self._last_score,
            "use_window": self._use_window,
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
            logger.info("OCSVMDetector '%s': loaded model from %s", self.name, path)
        except Exception as exc:
            logger.warning(
                "OCSVMDetector '%s': failed to load model from %s: %s",
                self.name, path, exc,
            )
