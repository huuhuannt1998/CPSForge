"""
phase_aware_shield.py — Phase-aware safety shield (Contribution C4).

PhaseAwareShield blocks PLC writes that are inconsistent with the current
operational phase of the process.

Scientific motivation
---------------------
A context-aware LLM attacker (RQ3) learns to time attacks to process
transitions (e.g., attack the discharge valve during the fill phase for
maximum overflow impact).  Standard range-check and interlock rules cannot
block this because the proposed values are individually legal.
PhaseAwareShield adds a phase-level reasoning layer: if the proposed write
is semantically inconsistent with what the process should be doing right
now, it is blocked.

Design
------
Each scene has a PhaseRuleSet: a dict mapping PhaseLabel → list of
PhaseWriteRule.  A PhaseWriteRule says "while in phase X, writing tag T
to value V is suspicious."

The shield evaluates:
  1. Get current phase from PhaseInferenceEngine.
  2. Look up applicable phase-write rules for the proposed action.
  3. Return BLOCKED with explanation if any rule fires.
  4. Otherwise PASS (no phase-level objection).

This is intentionally a blocking decision, not a scoring decision.
It runs after the standard ShieldEngine so it only sees already range-
and duration-approved actions.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from cpsforge.core.models import AttackAction, PlantSnapshot, ShieldDecision
from cpsforge.observation.phase_inference import PhaseInferenceEngine, PhaseLabel
from cpsforge.observation.history_buffer import HistoryBuffer

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PhaseWriteRule
# ---------------------------------------------------------------------------

class PhaseBlockMode(str, Enum):
    """How to interpret the rule's value condition."""
    EXACT           = "exact"           # block if value == rule_value
    LESS_THAN       = "less_than"       # block if value < rule_value
    GREATER_THAN    = "greater_than"    # block if value > rule_value
    ANY_WRITE       = "any_write"       # block any write to this tag in this phase


@dataclass
class PhaseWriteRule:
    """One rule: block writes to *tag* in *phase* under *condition*."""
    rule_id: str
    phase: PhaseLabel
    tag: str
    mode: PhaseBlockMode
    value: Optional[float]          # threshold / exact match (None for ANY_WRITE)
    rationale: str = ""


# ---------------------------------------------------------------------------
# PhaseAwareShield
# ---------------------------------------------------------------------------

class PhaseAwareShield:
    """Block writes inconsistent with the current operational phase.

    Parameters
    ----------
    scene_name : str
    phase_engine : PhaseInferenceEngine
        Shared engine used for phase inference.
    history : HistoryBuffer
        Shared rolling window (history passed to phase_engine.infer).
    rules : list of PhaseWriteRule, optional
        Explicit rule list.  If None, built-in defaults for *scene_name* are used.
    """

    def __init__(
        self,
        scene_name: str,
        phase_engine: PhaseInferenceEngine,
        history: HistoryBuffer,
        rules: Optional[List[PhaseWriteRule]] = None,
    ) -> None:
        self._scene_name = scene_name
        self._phase_engine = phase_engine
        self._history = history
        self._rules = rules if rules is not None else _BUILTIN_RULES.get(scene_name, [])
        logger.debug(
            "PhaseAwareShield for '%s' loaded %d rules",
            scene_name, len(self._rules),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(
        self,
        action: AttackAction,
        snapshot: PlantSnapshot,
    ) -> ShieldDecision:
        """Check whether *action* is phase-consistent.

        Returns a ShieldDecision with approved=True if no phase rule fires,
        or approved=False with a populated violated_rules list.
        """
        phase_result = self._phase_engine.infer(
            snapshot, self._history.window(20)
        )
        current_phase = phase_result.phase

        violations: List[str] = []
        reasons: List[str] = []

        for rule in self._rules:
            if rule.phase != current_phase:
                continue
            if rule.tag != action.target:
                continue
            if _rule_fires(rule, action.value):
                violations.append(rule.rule_id)
                reasons.append(
                    f"[PhaseShield/{rule.rule_id}] "
                    f"Write to '{action.target}' "
                    f"(value={action.value}) is inconsistent with "
                    f"current phase '{current_phase.value}': {rule.rationale}"
                )

        approved = len(violations) == 0
        if not approved:
            logger.info(
                "PhaseAwareShield BLOCKED action on '%s': phase=%s, rules=%s",
                action.target,
                current_phase.value,
                violations,
            )

        return ShieldDecision(
            action_id=action.action_id,
            approved=approved,
            reasons=reasons,
            violated_rules=violations,
            rollback_plan=None,
        )

    @property
    def rules(self) -> List[PhaseWriteRule]:
        return list(self._rules)


# ---------------------------------------------------------------------------
# Rule evaluation helper
# ---------------------------------------------------------------------------

def _rule_fires(rule: PhaseWriteRule, value: Optional[float]) -> bool:
    if rule.mode == PhaseBlockMode.ANY_WRITE:
        return True
    if value is None:
        return False
    v = float(value)
    thresh = rule.value
    if rule.mode == PhaseBlockMode.EXACT:
        return thresh is not None and abs(v - thresh) < 1e-6
    if rule.mode == PhaseBlockMode.LESS_THAN:
        return thresh is not None and v < thresh
    if rule.mode == PhaseBlockMode.GREATER_THAN:
        return thresh is not None and v > thresh
    return False


# ---------------------------------------------------------------------------
# Built-in rule sets
# ---------------------------------------------------------------------------

_BUILTIN_RULES: Dict[str, List[PhaseWriteRule]] = {

    "level_control": [
        # During FILLING, blocking the discharge valve (setting it to 0) is
        # redundant — it's already closed.  But forcing it *open* during
        # filling stage DEFEATS the fill operation (legitimate attack target).
        # However, an attacker closing the FILL VALVE during fill = sabotage.
        PhaseWriteRule(
            rule_id="LC-PS-001",
            phase=PhaseLabel.FILLING,
            tag="fill_valve",
            mode=PhaseBlockMode.EXACT,
            value=0.0,
            rationale="Closing fill valve during filling phase halts the intended fill operation",
        ),
        PhaseWriteRule(
            rule_id="LC-PS-002",
            phase=PhaseLabel.DRAINING,
            tag="discharge_valve",
            mode=PhaseBlockMode.EXACT,
            value=0.0,
            rationale="Closing discharge valve during draining phase halts the intended drain operation",
        ),
        PhaseWriteRule(
            rule_id="LC-PS-003",
            phase=PhaseLabel.ALARM,
            tag="setpoint_in",
            mode=PhaseBlockMode.ANY_WRITE,
            value=None,
            rationale="Setpoint changes during alarm state are unsafe — alarm must be cleared first",
        ),
        PhaseWriteRule(
            rule_id="LC-PS-004",
            phase=PhaseLabel.IDLE,
            tag="fill_valve",
            mode=PhaseBlockMode.GREATER_THAN,
            value=0.0,
            rationale="Opening fill valve while system is disabled is inconsistent with idle phase",
        ),
        PhaseWriteRule(
            rule_id="LC-PS-005",
            phase=PhaseLabel.IDLE,
            tag="discharge_valve",
            mode=PhaseBlockMode.GREATER_THAN,
            value=0.0,
            rationale="Opening discharge valve while system is disabled is inconsistent with idle phase",
        ),
    ],

    "filling_tank": [
        PhaseWriteRule(
            rule_id="FT-PS-001",
            phase=PhaseLabel.FILLING,
            tag="fill_valve",
            mode=PhaseBlockMode.EXACT,
            value=0.0,
            rationale="Closing fill valve during fill phase aborts intended fill operation",
        ),
        PhaseWriteRule(
            rule_id="FT-PS-002",
            phase=PhaseLabel.ALARM,
            tag="fill_valve",
            mode=PhaseBlockMode.GREATER_THAN,
            value=0.0,
            rationale="Opening fill valve during tank-full alarm would cause overflow",
        ),
    ],

    "sorting_weight": [
        PhaseWriteRule(
            rule_id="SW-PS-001",
            phase=PhaseLabel.IDLE,
            tag="conveyor_belt",
            mode=PhaseBlockMode.GREATER_THAN,
            value=0.0,
            rationale="Starting conveyor while system is disabled is inconsistent with idle phase",
        ),
        PhaseWriteRule(
            rule_id="SW-PS-002",
            phase=PhaseLabel.PROCESSING,
            tag="conveyor_belt",
            mode=PhaseBlockMode.GREATER_THAN,
            value=0.0,
            rationale="Running conveyor while weighing is in progress corrupts the measurement",
        ),
    ],

    "sorting_height_basic": [
        PhaseWriteRule(
            rule_id="SH-PS-001",
            phase=PhaseLabel.IDLE,
            tag="entry_conveyor",
            mode=PhaseBlockMode.GREATER_THAN,
            value=0.0,
            rationale="Starting entry conveyor while system is disabled is inconsistent with idle phase",
        ),
        PhaseWriteRule(
            rule_id="SH-PS-002",
            phase=PhaseLabel.PROCESSING,
            tag="entry_conveyor",
            mode=PhaseBlockMode.ANY_WRITE,
            value=None,
            rationale="Modifying entry conveyor during load/measurement phase disrupts item positioning",
        ),
        PhaseWriteRule(
            rule_id="SH-PS-003",
            phase=PhaseLabel.SORTING,
            tag="entry_conveyor",
            mode=PhaseBlockMode.ANY_WRITE,
            value=None,
            rationale="Modifying entry conveyor during sorting phase disrupts active diversion",
        ),
        PhaseWriteRule(
            rule_id="SH-PS-004",
            phase=PhaseLabel.IDLE,
            tag="sort_conveyor",
            mode=PhaseBlockMode.GREATER_THAN,
            value=0.0,
            rationale="Starting sort conveyor while system is disabled is inconsistent with idle phase",
        ),
    ],

    "from_a_to_b": [
        PhaseWriteRule(
            rule_id="FAB-PS-001",
            phase=PhaseLabel.TRANSPORT,
            tag="conveyor_1",
            mode=PhaseBlockMode.EXACT,
            value=0.0,
            rationale="Stopping conveyor during active transport halts item delivery",
        ),
        PhaseWriteRule(
            rule_id="FAB-PS-002",
            phase=PhaseLabel.IDLE,
            tag="conveyor_1",
            mode=PhaseBlockMode.GREATER_THAN,
            value=0.0,
            rationale="Starting conveyor while system is idle is inconsistent with idle phase",
        ),
    ],
}
