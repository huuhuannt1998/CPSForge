"""
CPSForge Threshold Detector
============================
Simple rule-based anomaly detector that fires when any monitored tag value
crosses a configured threshold.

Configuration example (from YAML)::

  thresholds:
    - tag: tank_level
      operator: ">"
      value: 88.0
      severity: high
      label: "high_level"

Supported operators: ``>``, ``<``, ``>=``, ``<=``, ``==``, ``!=``
"""

from __future__ import annotations

import logging
import operator as op
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from cpsforge.core.config import DefenderConfig
from cpsforge.core.models import DetectionEvent, DetectionSeverity, PlantSnapshot
from cpsforge.defenders.base import BaseDetector

logger = logging.getLogger(__name__)

_OPS: Dict[str, Callable[[Any, Any], bool]] = {
    ">":  op.gt,
    "<":  op.lt,
    ">=": op.ge,
    "<=": op.le,
    "==": op.eq,
    "!=": op.ne,
}


class ThresholdDetector(BaseDetector):
    """
    Fires a :class:`DetectionEvent` for each threshold violation.
    Each threshold rule is evaluated independently per polling step.
    """

    def __init__(self, config: DefenderConfig) -> None:
        self._config = config
        self._rules: List[Dict] = config.thresholds  # list of rule dicts
        self._name = config.name

    @property
    def name(self) -> str:
        return self._name

    def observe(self, snapshot: PlantSnapshot) -> None:
        """No stateful memory needed for pure threshold detection."""

    def detect(self, snapshot: PlantSnapshot) -> List[DetectionEvent]:
        events: List[DetectionEvent] = []
        for rule in self._rules:
            tag_name = rule.get("tag")
            op_str = rule.get("operator", ">")
            threshold = rule.get("value")
            severity = DetectionSeverity(rule.get("severity", "low"))
            label = rule.get("label", "threshold_violation")
            description = rule.get("description", "")

            if tag_name is None or threshold is None:
                continue

            current = self._get_value(snapshot, tag_name)
            if current is None:
                continue

            compare = _OPS.get(op_str)
            if compare is None:
                logger.warning("Unknown operator '%s' in threshold rule.", op_str)
                continue

            try:
                if compare(float(current), float(threshold)):
                    event = DetectionEvent(
                        timestamp=datetime.now(timezone.utc),
                        run_id=snapshot.run_id,
                        detector_name=self.name,
                        severity=severity,
                        label=label,
                        confidence=1.0,
                        explanation=(
                            f"{description} | {tag_name}={current} {op_str} {threshold}"
                        ),
                        affected_tags=[tag_name],
                        step_id=snapshot.step_id,
                    )
                    events.append(event)
            except (TypeError, ValueError):
                pass

        return events

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
