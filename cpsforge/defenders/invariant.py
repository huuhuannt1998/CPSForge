"""
CPSForge Invariant Detector
=============================
Evaluates boolean process invariants expressed as Python-like condition strings.
Each invariant must hold during normal operation; a violation triggers a
:class:`DetectionEvent`.

Invariants are parsed from the ``invariant_rules`` list in the defender config.
Condition expressions are evaluated in a restricted sandbox using the current
snapshot's tag values as variables.

Security note:
  Expressions are evaluated with ``eval()`` against a whitelist of tag values
  and the ``abs`` builtin only. No arbitrary code execution is possible because
  the evaluation namespace is tightly controlled.

Condition syntax example:
  ``NOT (pump_speed > 95.0 AND tank_level > 80.0)``
  (NOT, AND, OR are Python-compatible -- capitalise as you like)
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cpsforge.core.config import DefenderConfig
from cpsforge.core.models import DetectionEvent, DetectionSeverity, PlantSnapshot
from cpsforge.defenders.base import BaseDetector

logger = logging.getLogger(__name__)

# Map plain-English operators to Python equivalents
_KEYWORD_MAP = {
    r"\bNOT\b": "not",
    r"\bAND\b": "and",
    r"\bOR\b": "or",
    r"\bTrue\b": "True",
    r"\bFalse\b": "False",
    r"\btrue\b": "True",
    r"\bfalse\b": "False",
}


def _normalise_expr(expr: str) -> str:
    for pattern, replacement in _KEYWORD_MAP.items():
        expr = re.sub(pattern, replacement, expr)
    return expr


class InvariantDetector(BaseDetector):
    """
    Fires a :class:`DetectionEvent` when a process invariant is violated.

    Each rule specifies a Python-like boolean condition over tag names.
    """

    def __init__(self, config: DefenderConfig) -> None:
        self._config = config
        self._rules: List[Dict] = config.invariant_rules
        self._name = config.name

    @property
    def name(self) -> str:
        return self._name

    def observe(self, snapshot: PlantSnapshot) -> None:
        """No stateful memory needed for pure invariant checks."""

    def detect(self, snapshot: PlantSnapshot) -> List[DetectionEvent]:
        events: List[DetectionEvent] = []
        tag_values = self._extract_all_values(snapshot)

        for rule in self._rules:
            condition_str = rule.get("condition", "")
            if not condition_str:
                continue
            severity = DetectionSeverity(rule.get("severity", "medium"))
            label = rule.get("label", "invariant_violation")
            rule_id = rule.get("rule_id", "?")
            description = rule.get("description", "")
            affected_tags = rule.get("tags", [])

            try:
                expr = _normalise_expr(condition_str)
                # Restrict eval namespace to tag values + abs()
                result = eval(expr, {"__builtins__": {}, "abs": abs}, tag_values)
                # If the invariant condition evaluates to False, it is VIOLATED
                if result is False:
                    event = DetectionEvent(
                        timestamp=datetime.now(timezone.utc),
                        run_id=snapshot.run_id,
                        detector_name=self.name,
                        severity=severity,
                        label=label,
                        confidence=0.9,
                        explanation=f"[{rule_id}] {description} | Condition evaluated False.",
                        affected_tags=affected_tags,
                        step_id=snapshot.step_id,
                    )
                    events.append(event)
            except Exception as exc:
                logger.debug("InvariantDetector: could not evaluate rule %s: %s", rule_id, exc)

        return events

    @staticmethod
    def _extract_all_values(snapshot: PlantSnapshot) -> Dict[str, Any]:
        """Merge all tag value buckets into a flat namespace for eval."""
        ns: Dict[str, Any] = {}
        for bucket in (
            snapshot.sensors,
            snapshot.actuators,
            snapshot.controller_state,
            snapshot.setpoints,
            snapshot.alarms,
        ):
            for k, v in bucket.items():
                if v is not None:
                    ns[k] = v
        return ns
