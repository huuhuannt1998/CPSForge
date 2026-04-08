"""

Cumulative Sum (CUSUM) change-point detector for CPS process variables.

CUSUM is a sequential analysis technique that detects small persistent
shifts in the mean of a process variable.  It is widely used in industrial
quality control and is a strong classical baseline for CPS anomaly detection.

"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import numpy as np

from cpsforge.core.config import DefenderConfig
from cpsforge.core.models import DetectionEvent, DetectionSeverity, PlantSnapshot
from cpsforge.defenders.base import BaseDetector

logger = logging.getLogger(__name__)


class CUSUMDetector(BaseDetector):
    """
    CUSUM (Cumulative Sum) change-point detector.

    Monitors a set of target tags for persistent mean shifts that may
    indicate sensor spoofing, actuator override, or setpoint manipulation.
    """

    def __init__(self, config: DefenderConfig) -> None:
        self._config = config
        params = config.parameters or {}

        self._target_tags: List[str] = params.get("target_tags", [])
        self._slack: float = float(params.get("slack", 0.5))
        self._threshold: float = float(params.get("threshold", 5.0))
        self._warmup_steps: int = int(params.get("warmup_steps", 30))
        self._reset_on_alarm: bool = bool(params.get("reset_on_alarm", True))

        # Per-tag running state
        self._means: Dict[str, float] = {}
        self._s_pos: Dict[str, float] = defaultdict(float)
        self._s_neg: Dict[str, float] = defaultdict(float)
        self._warmup_buffer: Dict[str, List[float]] = defaultdict(list)
        self._step_count: int = 0
        self._detection_count: int = 0

    @property
    def name(self) -> str:
        return self._config.name

    # ------------------------------------------------------------------
    # BaseDetector interface
    # ------------------------------------------------------------------

    def observe(self, snapshot: PlantSnapshot) -> None:
        self._step_count += 1
        for tag in self._target_tags:
            val = self._get_value(snapshot, tag)
            if val is None:
                continue
            fval = float(val)

            # Warm-up: accumulate samples to estimate baseline mean
            if tag not in self._means:
                buf = self._warmup_buffer[tag]
                buf.append(fval)
                if len(buf) >= self._warmup_steps:
                    self._means[tag] = float(np.mean(buf))
                    del self._warmup_buffer[tag]
                continue

            # Update CUSUM statistics
            z = fval - self._means[tag]
            self._s_pos[tag] = max(0.0, self._s_pos[tag] + z - self._slack)
            self._s_neg[tag] = max(0.0, self._s_neg[tag] - z - self._slack)

    def detect(self, snapshot: PlantSnapshot) -> List[DetectionEvent]:
        self.observe(snapshot)
        events: List[DetectionEvent] = []

        for tag in self._target_tags:
            if tag not in self._means:
                continue

            s_pos = self._s_pos[tag]
            s_neg = self._s_neg[tag]
            max_s = max(s_pos, s_neg)

            if max_s <= self._threshold:
                continue

            self._detection_count += 1
            direction = "upward" if s_pos >= s_neg else "downward"
            confidence = float(np.clip(max_s / (self._threshold * 2), 0.5, 1.0))
            severity = (
                DetectionSeverity.CRITICAL if max_s > self._threshold * 3
                else DetectionSeverity.HIGH if max_s > self._threshold * 2
                else DetectionSeverity.MEDIUM
            )

            events.append(DetectionEvent(
                timestamp=snapshot.timestamp or datetime.now(timezone.utc),
                run_id=snapshot.run_id,
                detector_name=self.name,
                severity=severity,
                label="cusum_shift",
                confidence=confidence,
                explanation=(
                    f"CUSUM detected {direction} mean shift on '{tag}': "
                    f"S+={s_pos:.2f} S-={s_neg:.2f} (threshold={self._threshold:.1f}, "
                    f"baseline_mean={self._means[tag]:.3f})"
                ),
                affected_tags=[tag],
                step_id=snapshot.step_id,
            ))

            if self._reset_on_alarm:
                self._s_pos[tag] = 0.0
                self._s_neg[tag] = 0.0

        return events

    def reset(self) -> None:
        self._means.clear()
        self._s_pos.clear()
        self._s_neg.clear()
        self._warmup_buffer.clear()
        self._step_count = 0
        self._detection_count = 0

    def export_state(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "detector_type": "cusum",
            "step_count": self._step_count,
            "detection_count": self._detection_count,
            "slack": self._slack,
            "threshold": self._threshold,
            "warmup_steps": self._warmup_steps,
            "monitored_tags": self._target_tags,
            "baseline_means": dict(self._means),
            "s_pos": dict(self._s_pos),
            "s_neg": dict(self._s_neg),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_value(snapshot: PlantSnapshot, tag_name: str) -> Optional[Any]:
        for bucket in (
            snapshot.sensors,
            snapshot.actuators,
            snapshot.controller_state,
            snapshot.setpoints,
            snapshot.alarms,
        ):
            if tag_name in bucket:
                return bucket[tag_name]
        return None
