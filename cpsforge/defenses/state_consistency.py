"""
state_consistency.py — State consistency defender against deep state attacks.

StateConsistencyChecker detects and blocks PLC writes that would cause
illegal state transitions, timer anomalies, or unauthorized changes to
internal variables that the PLC logic never writes.

This defender is the primary countermeasure against Tier 2 (deep state)
attacks that target internal PLC state variables via S7 protocol.

Detection strategies
--------------------
1. **State machine transition validation**: Blocks iState writes that
   jump to non-adjacent states (e.g., 0→4 when only 0→1 is valid).
2. **Timer progression monitoring**: Blocks timer writes that jump by
   more than a configurable delta (normal: increment by 1 per scan).
3. **Never-written variable protection**: Blocks writes to variables
   that should only be set during initialization (Enable, thresholds).
4. **Classification flag consistency**: Blocks IsTall/MeasuredWeight
   changes when the process is past the measurement phase.

Design
------
Like PhaseAwareShield, this operates AFTER the standard ShieldEngine
and only sees already-range-approved actions. It adds semantic
consistency checks that range rules cannot express.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from cpsforge.core.models import AttackAction, PlantSnapshot, ShieldDecision
from cpsforge.observation.history_buffer import HistoryBuffer
from cpsforge.observation.phase_inference import PhaseInferenceEngine

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# State transition rules
# ---------------------------------------------------------------------------

@dataclass
class StateTransitionRule:
    """Defines valid state machine transitions for a tag."""
    tag: str
    valid_transitions: Dict[int, List[int]]  # {from_state: [valid_to_states]}
    description: str = ""


@dataclass
class TimerRule:
    """Defines valid timer progression bounds."""
    tag: str
    max_jump: int  # Maximum allowed single-step increase
    max_value: int  # Absolute maximum
    description: str = ""


@dataclass
class ProtectedVariable:
    """A variable that should not be written during normal operation."""
    tag: str
    allowed_phases: List[str]  # Phases where writes ARE allowed (empty = never)
    description: str = ""


@dataclass
class ClassificationGuard:
    """Protects classification flags after measurement phase."""
    tag: str
    measurement_phase: str  # Phase when measurement occurs
    locked_after: bool = True  # Lock after measurement phase completes
    description: str = ""


# ---------------------------------------------------------------------------
# Check result
# ---------------------------------------------------------------------------

@dataclass
class StateConsistencyResult:
    """Result of one state consistency check."""
    consistent: bool
    reason: str
    rule_id: str
    tag: str
    current_value: Any = None
    proposed_value: Any = None


# ---------------------------------------------------------------------------
# StateConsistencyChecker
# ---------------------------------------------------------------------------

class StateConsistencyChecker:
    """Block PLC writes that violate state machine consistency.

    Parameters
    ----------
    scene_name : str
        Name of the active scene.
    phase_engine : PhaseInferenceEngine
        Phase inference engine (for phase-dependent guards).
    history : HistoryBuffer
        Shared rolling window.
    """

    def __init__(
        self,
        scene_name: str,
        phase_engine: PhaseInferenceEngine,
        history: HistoryBuffer,
    ) -> None:
        self._scene_name = scene_name
        self._phase_engine = phase_engine
        self._history = history

        # Load built-in rules for this scene
        rules = _BUILTIN_RULES.get(scene_name, {})
        self._transition_rules: List[StateTransitionRule] = rules.get("transitions", [])
        self._timer_rules: List[TimerRule] = rules.get("timers", [])
        self._protected_vars: List[ProtectedVariable] = rules.get("protected", [])
        self._classification_guards: List[ClassificationGuard] = rules.get("classification", [])

        # Track last known state values for transition validation
        self._last_known: Dict[str, Any] = {}
        self._call_count = 0
        self._block_count = 0

        logger.debug(
            "StateConsistencyChecker for '%s': %d transition rules, "
            "%d timer rules, %d protected vars, %d classification guards",
            scene_name,
            len(self._transition_rules),
            len(self._timer_rules),
            len(self._protected_vars),
            len(self._classification_guards),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(
        self,
        action: AttackAction,
        snapshot: PlantSnapshot,
    ) -> ShieldDecision:
        """Check whether the proposed write is consistent with state machine rules."""
        self._call_count += 1

        # Update tracked state from snapshot
        self._update_tracked_state(snapshot)

        violations: List[str] = []
        reasons: List[str] = []

        # 1. State machine transition validation
        for rule in self._transition_rules:
            if rule.tag != action.target:
                continue
            result = self._check_transition(rule, action, snapshot)
            if not result.consistent:
                violations.append(result.rule_id)
                reasons.append(result.reason)

        # 2. Timer progression validation
        for rule in self._timer_rules:
            if rule.tag != action.target:
                continue
            result = self._check_timer(rule, action, snapshot)
            if not result.consistent:
                violations.append(result.rule_id)
                reasons.append(result.reason)

        # 3. Protected variable validation
        for pv in self._protected_vars:
            if pv.tag != action.target:
                continue
            result = self._check_protected(pv, action, snapshot)
            if not result.consistent:
                violations.append(result.rule_id)
                reasons.append(result.reason)

        # 4. Classification flag guards
        for guard in self._classification_guards:
            if guard.tag != action.target:
                continue
            result = self._check_classification(guard, action, snapshot)
            if not result.consistent:
                violations.append(result.rule_id)
                reasons.append(result.reason)

        approved = len(violations) == 0
        if not approved:
            self._block_count += 1
            logger.info(
                "StateConsistencyChecker BLOCKED write to '%s' (value=%s): %s",
                action.target, action.value, violations,
            )

        return ShieldDecision(
            action_id=action.action_id,
            approved=approved,
            reasons=reasons,
            violated_rules=violations,
            rollback_plan=None,
        )

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "total_calls": self._call_count,
            "total_blocks": self._block_count,
            "block_rate": self._block_count / max(1, self._call_count),
        }

    # ------------------------------------------------------------------
    # Check implementations
    # ------------------------------------------------------------------

    def _check_transition(
        self,
        rule: StateTransitionRule,
        action: AttackAction,
        snapshot: PlantSnapshot,
    ) -> StateConsistencyResult:
        """Validate state machine transition."""
        current = self._get_value(rule.tag, snapshot)
        proposed = action.value

        if current is None or proposed is None:
            return StateConsistencyResult(
                consistent=True, reason="", rule_id="", tag=rule.tag,
            )

        try:
            current_int = int(current)
            proposed_int = int(proposed)
        except (TypeError, ValueError):
            return StateConsistencyResult(
                consistent=True, reason="", rule_id="", tag=rule.tag,
            )

        if current_int == proposed_int:
            return StateConsistencyResult(
                consistent=True, reason="", rule_id="", tag=rule.tag,
            )

        valid_next = rule.valid_transitions.get(current_int, [])
        if proposed_int not in valid_next:
            return StateConsistencyResult(
                consistent=False,
                reason=(
                    f"[StateConsistency/TRANSITION] Illegal state transition: "
                    f"{rule.tag} {current_int}→{proposed_int}. "
                    f"Valid transitions from {current_int}: {valid_next}. "
                    f"{rule.description}"
                ),
                rule_id=f"SC-TR-{rule.tag}",
                tag=rule.tag,
                current_value=current_int,
                proposed_value=proposed_int,
            )

        return StateConsistencyResult(
            consistent=True, reason="", rule_id="", tag=rule.tag,
        )

    def _check_timer(
        self,
        rule: TimerRule,
        action: AttackAction,
        snapshot: PlantSnapshot,
    ) -> StateConsistencyResult:
        """Validate timer progression is within bounds."""
        current = self._get_value(rule.tag, snapshot)
        proposed = action.value

        if current is None or proposed is None:
            return StateConsistencyResult(
                consistent=True, reason="", rule_id="", tag=rule.tag,
            )

        try:
            current_val = float(current)
            proposed_val = float(proposed)
        except (TypeError, ValueError):
            return StateConsistencyResult(
                consistent=True, reason="", rule_id="", tag=rule.tag,
            )

        jump = abs(proposed_val - current_val)
        if jump > rule.max_jump:
            return StateConsistencyResult(
                consistent=False,
                reason=(
                    f"[StateConsistency/TIMER] Timer jump too large: "
                    f"{rule.tag} {current_val}→{proposed_val} (jump={jump}, "
                    f"max_allowed={rule.max_jump}). {rule.description}"
                ),
                rule_id=f"SC-TM-{rule.tag}",
                tag=rule.tag,
                current_value=current_val,
                proposed_value=proposed_val,
            )

        if proposed_val > rule.max_value:
            return StateConsistencyResult(
                consistent=False,
                reason=(
                    f"[StateConsistency/TIMER] Timer value exceeds maximum: "
                    f"{rule.tag}={proposed_val} (max={rule.max_value}). {rule.description}"
                ),
                rule_id=f"SC-TM-{rule.tag}-MAX",
                tag=rule.tag,
                current_value=current_val,
                proposed_value=proposed_val,
            )

        return StateConsistencyResult(
            consistent=True, reason="", rule_id="", tag=rule.tag,
        )

    def _check_protected(
        self,
        pv: ProtectedVariable,
        action: AttackAction,
        snapshot: PlantSnapshot,
    ) -> StateConsistencyResult:
        """Check if write to protected variable is allowed in current phase."""
        if not pv.allowed_phases:
            # Never allowed — always block
            return StateConsistencyResult(
                consistent=False,
                reason=(
                    f"[StateConsistency/PROTECTED] Write to protected variable "
                    f"'{pv.tag}' is not allowed during normal operation. "
                    f"{pv.description}"
                ),
                rule_id=f"SC-PV-{pv.tag}",
                tag=pv.tag,
            )

        phase_result = self._phase_engine.infer(
            snapshot, self._history.window(10),
        )
        current_phase = phase_result.phase.value

        if current_phase not in pv.allowed_phases:
            return StateConsistencyResult(
                consistent=False,
                reason=(
                    f"[StateConsistency/PROTECTED] Write to '{pv.tag}' not allowed "
                    f"in phase '{current_phase}'. Allowed phases: {pv.allowed_phases}. "
                    f"{pv.description}"
                ),
                rule_id=f"SC-PV-{pv.tag}",
                tag=pv.tag,
            )

        return StateConsistencyResult(
            consistent=True, reason="", rule_id="", tag=pv.tag,
        )

    def _check_classification(
        self,
        guard: ClassificationGuard,
        action: AttackAction,
        snapshot: PlantSnapshot,
    ) -> StateConsistencyResult:
        """Check if classification flag change is valid in current phase."""
        phase_result = self._phase_engine.infer(
            snapshot, self._history.window(10),
        )
        current_phase = phase_result.phase.value

        if guard.locked_after and current_phase != guard.measurement_phase:
            return StateConsistencyResult(
                consistent=False,
                reason=(
                    f"[StateConsistency/CLASSIFICATION] Classification flag "
                    f"'{guard.tag}' is locked outside measurement phase "
                    f"'{guard.measurement_phase}' (current: '{current_phase}'). "
                    f"{guard.description}"
                ),
                rule_id=f"SC-CL-{guard.tag}",
                tag=guard.tag,
            )

        return StateConsistencyResult(
            consistent=True, reason="", rule_id="", tag=guard.tag,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_value(self, tag: str, snapshot: PlantSnapshot) -> Any:
        """Get the current value of a tag from the snapshot."""
        for cat in (snapshot.sensors, snapshot.actuators,
                    snapshot.setpoints, snapshot.controller_state,
                    snapshot.alarms):
            if tag in cat:
                return cat[tag]
        return self._last_known.get(tag)

    def _update_tracked_state(self, snapshot: PlantSnapshot) -> None:
        """Update tracked state from snapshot for transition validation."""
        for cat in (snapshot.sensors, snapshot.actuators,
                    snapshot.setpoints, snapshot.controller_state):
            for tag, val in cat.items():
                if val is not None:
                    self._last_known[tag] = val


# ---------------------------------------------------------------------------
# Built-in rule sets per scene
# ---------------------------------------------------------------------------

_BUILTIN_RULES: Dict[str, Dict[str, list]] = {

    "level_control": {
        "transitions": [],  # No discrete state machine
        "timers": [],
        "protected": [
            ProtectedVariable(
                tag="enable",
                allowed_phases=[],  # Never writable during operation
                description="Enable flag is set at initialization only",
            ),
            ProtectedVariable(
                tag="setpoint_in",
                allowed_phases=["idle", "stopped"],  # Only writable when stopped
                description="SetpointIn is frozen when Running=TRUE",
            ),
        ],
        "classification": [],
    },

    "sorting_weight": {
        "transitions": [
            StateTransitionRule(
                tag="i_state",
                valid_transitions={
                    0: [1],         # Idle → Weighed
                    1: [2, 4, 6],   # Weighed → SendLeft/SendRight/SendForward
                    2: [0],         # SendLeft → Idle
                    4: [0],         # SendRight → Idle
                    6: [0],         # SendForward → Idle
                },
                description="Sorting by Weight 8-state machine",
            ),
        ],
        "timers": [],
        "protected": [
            ProtectedVariable(
                tag="enable",
                allowed_phases=[],
                description="Enable flag is set at initialization only",
            ),
            ProtectedVariable(
                tag="light_thresh",
                allowed_phases=[],  # Never written by PLC
                description="Light threshold is a configuration parameter, not runtime variable",
            ),
            ProtectedVariable(
                tag="heavy_thresh",
                allowed_phases=[],
                description="Heavy threshold is a configuration parameter, not runtime variable",
            ),
        ],
        "classification": [
            ClassificationGuard(
                tag="measured_weight",
                measurement_phase="idle",
                locked_after=True,
                description="Weight is latched during Idle→Weighed transition",
            ),
        ],
    },

    "sorting_height_basic": {
        "transitions": [
            StateTransitionRule(
                tag="i_state",
                valid_transitions={
                    0: [1],     # Feed → Load
                    1: [2],     # Load → Transfer
                    2: [3],     # Transfer → Clear
                    3: [4],     # Clear → Finish
                    4: [0],     # Finish → Feed
                },
                description="Sorting by Height 5-state machine",
            ),
        ],
        "timers": [
            TimerRule(
                tag="dwell_timer",
                max_jump=50,    # Normal: increments by 1 per scan
                max_value=5000,
                description="Dwell timer should increment gradually, not jump",
            ),
        ],
        "protected": [
            ProtectedVariable(
                tag="enable",
                allowed_phases=[],
                description="Enable flag is set at initialization only",
            ),
        ],
        "classification": [
            ClassificationGuard(
                tag="is_tall",
                measurement_phase="feeding",
                locked_after=True,
                description="Height classification is latched during Feed phase",
            ),
        ],
    },
}
