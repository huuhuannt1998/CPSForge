"""
phase_inference.py — Rule-based operational phase detection per scene.

PhaseInferenceEngine maps the current PlantSnapshot (optionally plus a
short history window) to one of a set of scene-specific PhaseLabel values.
Phase labels are used by:
  - The context builder   (PhaseLabel goes into full-context prompts)
  - The phase-aware shield (blocks phase-inconsistent writes)
  - RQ1/RQ3 analysis      (timing/phase attacks are measured relative to phase)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any

from cpsforge.core.models import PlantSnapshot

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PhaseLabel — universal set (scenes may use a subset)
# ---------------------------------------------------------------------------

class PhaseLabel(str, Enum):
    """Canonical operational phase labels across all scenes."""

    UNKNOWN      = "unknown"
    IDLE         = "idle"
    STARTUP      = "startup"
    FILLING      = "filling"
    DRAINING     = "draining"
    REGULATING   = "regulating"
    ALARM        = "alarm"
    TRANSPORT    = "transport"
    SORTING      = "sorting"
    PROCESSING   = "processing"
    TRANSITION   = "transition"   # between any two identifiable phases
    SHUTDOWN     = "shutdown"


# ---------------------------------------------------------------------------
# PhaseResult
# ---------------------------------------------------------------------------

@dataclass
class PhaseResult:
    """Output of a single phase inference call."""

    phase: PhaseLabel
    confidence: float               # [0.0, 1.0]
    matched_rule: Optional[str]     # ID of the rule that fired
    rationale: str                  # Human-readable explanation


# ---------------------------------------------------------------------------
# PhaseRule — a single if-then rule
# ---------------------------------------------------------------------------

@dataclass
class PhaseRule:
    """One rule: if ALL conditions hold → infer phase with given confidence."""

    rule_id: str
    phase: PhaseLabel
    conditions: List[Dict[str, Any]]  # list of {tag, op, value} dicts
    confidence: float = 1.0
    priority: int = 0
    rationale: str = ""


# ---------------------------------------------------------------------------
# PhaseInferenceEngine
# ---------------------------------------------------------------------------

class PhaseInferenceEngine:
    """Infer the current operational phase of a CPS scene.

    Rules are evaluated in descending priority order.  The first matching
    rule determines the phase.  If no rule matches, UNKNOWN is returned.

    Scene-specific rule sets are registered via ``register_scene_rules()``
    or loaded from the built-in defaults for the supported scenes.

    Parameters
    ----------
    scene_name : str
        Name of the scene (used to look up built-in rules if no explicit
        rules are provided).
    rules : list of PhaseRule, optional
        Explicit rule list.  If None, built-in defaults are loaded.
    """

    def __init__(
        self,
        scene_name: str,
        rules: Optional[List[PhaseRule]] = None,
    ) -> None:
        self._scene_name = scene_name
        if rules is not None:
            self._rules = sorted(rules, key=lambda r: r.priority, reverse=True)
        else:
            self._rules = sorted(
                _BUILTIN_RULES.get(scene_name, []),
                key=lambda r: r.priority,
                reverse=True,
            )
        logger.debug(
            "PhaseInferenceEngine for scene '%s' loaded %d rules",
            scene_name,
            len(self._rules),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def infer(
        self,
        snapshot: PlantSnapshot,
        history: Optional[List[PlantSnapshot]] = None,
    ) -> PhaseResult:
        """Infer the operational phase from the current snapshot.

        Parameters
        ----------
        snapshot : PlantSnapshot
            Current sensor/actuator state.
        history : list of PlantSnapshot, optional
            Recent history window (not used by default rules but available
            for custom rule implementations).
        """
        all_values = _extract_all_values(snapshot)

        for rule in self._rules:
            if _evaluate_conditions(rule.conditions, all_values):
                return PhaseResult(
                    phase=rule.phase,
                    confidence=rule.confidence,
                    matched_rule=rule.rule_id,
                    rationale=rule.rationale or f"Rule {rule.rule_id} matched",
                )

        return PhaseResult(
            phase=PhaseLabel.UNKNOWN,
            confidence=0.0,
            matched_rule=None,
            rationale="No rule matched current state",
        )

    def add_rule(self, rule: PhaseRule) -> None:
        """Add a rule at runtime and re-sort by priority."""
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority, reverse=True)

    @property
    def scene_name(self) -> str:
        return self._scene_name

    @property
    def rules(self) -> List[PhaseRule]:
        return list(self._rules)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_all_values(snapshot: PlantSnapshot) -> Dict[str, Any]:
    """Flatten all tag categories into one lookup dict."""
    values: Dict[str, Any] = {}
    for category in (
        snapshot.sensors,
        snapshot.actuators,
        snapshot.setpoints,
        snapshot.controller_state,
        snapshot.alarms,
        snapshot.derived_features,
    ):
        values.update(category)
    return values


_OPS = {
    ">":  lambda a, b: a > b,
    "<":  lambda a, b: a < b,
    ">=": lambda a, b: a >= b,
    "<=": lambda a, b: a <= b,
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
}


def _evaluate_conditions(
    conditions: List[Dict[str, Any]],
    values: Dict[str, Any],
) -> bool:
    """Return True iff ALL conditions hold against *values*."""
    for cond in conditions:
        tag   = cond["tag"]
        op    = cond["op"]
        threshold = cond["value"]
        val = values.get(tag)
        if val is None:
            return False
        fn = _OPS.get(op)
        if fn is None:
            logger.warning("Unknown operator '%s' in phase rule condition", op)
            return False
        try:
            if not fn(float(val), float(threshold)):
                return False
        except (TypeError, ValueError):
            return False
    return True


# ---------------------------------------------------------------------------
# Built-in rule sets (one per supported scene)
# ---------------------------------------------------------------------------

_BUILTIN_RULES: Dict[str, List[PhaseRule]] = {

    # -----------------------------------------------------------------------
    "level_control": [
        # ALARM: any alarm active → highest priority
        PhaseRule(
            rule_id="LC-PHASE-ALARM",
            phase=PhaseLabel.ALARM,
            conditions=[
                {"tag": "high_level_alarm", "op": "==", "value": 1},
            ],
            confidence=1.0,
            priority=100,
            rationale="High-level alarm is active",
        ),
        PhaseRule(
            rule_id="LC-PHASE-ALARM-LOW",
            phase=PhaseLabel.ALARM,
            conditions=[
                {"tag": "low_level_alarm", "op": "==", "value": 1},
            ],
            confidence=1.0,
            priority=99,
            rationale="Low-level alarm is active",
        ),
        # IDLE: system disabled
        PhaseRule(
            rule_id="LC-PHASE-IDLE",
            phase=PhaseLabel.IDLE,
            conditions=[
                {"tag": "enable", "op": "==", "value": 0},
            ],
            confidence=1.0,
            priority=80,
            rationale="System disabled (enable=0)",
        ),
        # FILLING: fill valve open, level rising
        PhaseRule(
            rule_id="LC-PHASE-FILLING",
            phase=PhaseLabel.FILLING,
            conditions=[
                {"tag": "fill_valve",      "op": ">",  "value": 0.0},
                {"tag": "discharge_valve", "op": "<=", "value": 0.5},
            ],
            confidence=0.9,
            priority=60,
            rationale="Fill valve open, discharge valve nearly closed",
        ),
        # DRAINING: discharge valve open, level falling
        PhaseRule(
            rule_id="LC-PHASE-DRAINING",
            phase=PhaseLabel.DRAINING,
            conditions=[
                {"tag": "discharge_valve", "op": ">",  "value": 0.0},
                {"tag": "fill_valve",      "op": "<=", "value": 0.5},
            ],
            confidence=0.9,
            priority=60,
            rationale="Discharge valve open, fill valve nearly closed",
        ),
        # REGULATING: both valves active (PID hunting)
        PhaseRule(
            rule_id="LC-PHASE-REGULATING",
            phase=PhaseLabel.REGULATING,
            conditions=[
                {"tag": "fill_valve",      "op": ">", "value": 0.0},
                {"tag": "discharge_valve", "op": ">", "value": 0.0},
            ],
            confidence=0.7,
            priority=40,
            rationale="Both valves active — controller regulating toward setpoint",
        ),
    ],

    # -----------------------------------------------------------------------
    "filling_tank": [
        PhaseRule(
            rule_id="FT-PHASE-IDLE",
            phase=PhaseLabel.IDLE,
            conditions=[{"tag": "enable", "op": "==", "value": 0}],
            confidence=1.0, priority=90,
            rationale="System disabled",
        ),
        PhaseRule(
            rule_id="FT-PHASE-ALARM-FULL",
            phase=PhaseLabel.ALARM,
            conditions=[{"tag": "full_sensor", "op": "==", "value": 1}],
            confidence=0.95, priority=80,
            rationale="Tank-full sensor active",
        ),
        PhaseRule(
            rule_id="FT-PHASE-FILLING",
            phase=PhaseLabel.FILLING,
            conditions=[{"tag": "fill_valve", "op": ">", "value": 0.0}],
            confidence=0.9, priority=60,
            rationale="Fill valve open — tank filling",
        ),
        PhaseRule(
            rule_id="FT-PHASE-DRAINING",
            phase=PhaseLabel.DRAINING,
            conditions=[{"tag": "drain_valve", "op": ">", "value": 0.0}],
            confidence=0.9, priority=60,
            rationale="Drain valve open — tank draining",
        ),
    ],

    # -----------------------------------------------------------------------
    "sorting_weight": [
        PhaseRule(
            rule_id="SW-PHASE-IDLE",
            phase=PhaseLabel.IDLE,
            conditions=[{"tag": "enable", "op": "==", "value": 0}],
            confidence=1.0, priority=90,
            rationale="System disabled",
        ),
        PhaseRule(
            rule_id="SW-PHASE-SORTING",
            phase=PhaseLabel.SORTING,
            conditions=[{"tag": "conveyor_belt", "op": ">", "value": 0.0}],
            confidence=0.8, priority=50,
            rationale="Conveyor belt running — item in transport",
        ),
        PhaseRule(
            rule_id="SW-PHASE-PROCESSING",
            phase=PhaseLabel.PROCESSING,
            conditions=[{"tag": "weight_sensor", "op": ">", "value": 0.1}],
            confidence=0.85, priority=60,
            rationale="Weight sensor measuring — item on scale",
        ),
    ],

    # -----------------------------------------------------------------------
    "sorting_height_basic": [
        # ALARM: emergency stop active — highest priority
        PhaseRule(
            rule_id="SH-PHASE-ALARM",
            phase=PhaseLabel.ALARM,
            conditions=[{"tag": "emergency_stop", "op": "==", "value": 1}],
            confidence=1.0,
            priority=100,
            rationale="Emergency stop active",
        ),
        # IDLE: system disabled (enable flag de-asserted)
        PhaseRule(
            rule_id="SH-PHASE-IDLE-DISABLED",
            phase=PhaseLabel.IDLE,
            conditions=[{"tag": "enable", "op": "==", "value": 0}],
            confidence=1.0,
            priority=90,
            rationale="System disabled (enable=0)",
        ),
        # IDLE: process not running
        PhaseRule(
            rule_id="SH-PHASE-IDLE-STOPPED",
            phase=PhaseLabel.IDLE,
            conditions=[{"tag": "running", "op": "==", "value": 0}],
            confidence=0.95,
            priority=85,
            rationale="Process not running",
        ),
        # TRANSPORT: state=0 (Feed) — entry conveyor feeding item toward pallet
        PhaseRule(
            rule_id="SH-PHASE-TRANSPORT",
            phase=PhaseLabel.TRANSPORT,
            conditions=[{"tag": "state", "op": "==", "value": 0}],
            confidence=0.9,
            priority=70,
            rationale="Feed state — entry conveyor transporting item",
        ),
        # PROCESSING: state=1 (Load) — item being loaded onto pallet
        PhaseRule(
            rule_id="SH-PHASE-PROCESSING-LOAD",
            phase=PhaseLabel.PROCESSING,
            conditions=[{"tag": "state", "op": "==", "value": 1}],
            confidence=0.9,
            priority=65,
            rationale="Load state — item being loaded onto pallet",
        ),
        # SORTING: state=2 (Transfer) — pallet being sorted left or right
        PhaseRule(
            rule_id="SH-PHASE-SORTING",
            phase=PhaseLabel.SORTING,
            conditions=[{"tag": "state", "op": "==", "value": 2}],
            confidence=0.9,
            priority=60,
            rationale="Transfer state — pallet routed by height classification",
        ),
        # TRANSITION: state=3 (Clear) — clearing pallet for next cycle
        PhaseRule(
            rule_id="SH-PHASE-TRANSITION",
            phase=PhaseLabel.TRANSITION,
            conditions=[{"tag": "state", "op": "==", "value": 3}],
            confidence=0.85,
            priority=55,
            rationale="Clear state — pallet clearing for next item",
        ),
        # SHUTDOWN: state=4 (Finish) — cycle complete, awaiting next start
        PhaseRule(
            rule_id="SH-PHASE-SHUTDOWN",
            phase=PhaseLabel.SHUTDOWN,
            conditions=[{"tag": "state", "op": "==", "value": 4}],
            confidence=0.85,
            priority=50,
            rationale="Finish state — sort cycle complete",
        ),
    ],

    # -----------------------------------------------------------------------
    "from_a_to_b": [
        PhaseRule(
            rule_id="FAB-PHASE-IDLE",
            phase=PhaseLabel.IDLE,
            conditions=[{"tag": "conveyor_1", "op": "==", "value": 0}],
            confidence=0.9, priority=80,
            rationale="All conveyors stopped",
        ),
        PhaseRule(
            rule_id="FAB-PHASE-TRANSPORT",
            phase=PhaseLabel.TRANSPORT,
            conditions=[{"tag": "conveyor_1", "op": ">", "value": 0.0}],
            confidence=0.8, priority=50,
            rationale="Conveyor moving — item in transit",
        ),
    ],

    # -----------------------------------------------------------------------
    "tank_control": [
        PhaseRule(
            rule_id="TC-PHASE-IDLE",
            phase=PhaseLabel.IDLE,
            conditions=[{"tag": "pump", "op": "==", "value": 0}],
            confidence=0.9, priority=80,
            rationale="Pump off — idle",
        ),
        PhaseRule(
            rule_id="TC-PHASE-FILLING",
            phase=PhaseLabel.FILLING,
            conditions=[
                {"tag": "pump", "op": ">", "value": 0.0},
                {"tag": "level", "op": "<", "value": 60.0},
            ],
            confidence=0.85, priority=60,
            rationale="Pump running, level below 60% — filling",
        ),
        PhaseRule(
            rule_id="TC-PHASE-REGULATING",
            phase=PhaseLabel.REGULATING,
            conditions=[
                {"tag": "pump", "op": ">", "value": 0.0},
                {"tag": "level", "op": ">=", "value": 40.0},
            ],
            confidence=0.8, priority=50,
            rationale="Pump running, level mid-range — regulating",
        ),
    ],
}
