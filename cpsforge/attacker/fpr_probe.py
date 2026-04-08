"""
fpr_probe.py — False Positive Rate probe attacker.

Generates KNOWN-LEGITIMATE write proposals to measure false positive rate
of the defense chain (especially the LLM defender).  Every proposal matches
the current controller behavior: values track what the PLC is already
outputting, with small perturbations aligned with the control direction.

A well-calibrated defender should ALLOW every proposal.  Any block is
counted as a false positive.

Design
------
Every ``probe_interval`` steps the probe:
  1. Reads current snapshot (sensors, actuators, setpoints).
  2. Picks a writable tag from the scene's attack_surface at random.
  3. Generates a write value that is close to the tag's current value
     and aligned with the controller's current trend.
  4. Returns an AttackAction that is routed through the standard defense
     chain (safety shield → phase_aware → intent_checker → llm_defender).
  5. Logs the result: allowed (true-negative) or blocked (false-positive).

The probe never actually executes writes on the PLC.
"""

from __future__ import annotations

import logging
import random
from typing import Any, Dict, List, Optional

from cpsforge.attacker.schema import AttackDecision, AttackDecisionType
from cpsforge.core.models import (
    AttackAction,
    AttackSource,
    AttackType,
    PlantSnapshot,
)
from cpsforge.observation.history_buffer import HistoryBuffer
from cpsforge.observation.phase_inference import PhaseInferenceEngine
from cpsforge.scenes.base import BaseScene

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Per-scene legitimate write generators
# ---------------------------------------------------------------------------

def _generate_level_control_write(
    snapshot: PlantSnapshot,
    tag: str,
    history: HistoryBuffer,
) -> Optional[Dict[str, Any]]:
    """Generate a legitimate write for Level Control."""
    obs = {}
    obs.update(snapshot.sensors or {})
    obs.update(snapshot.actuators or {})
    obs.update(snapshot.setpoints or {})
    obs.update(snapshot.controller_state or {})

    if tag == "setpoint_in":
        # Propose current setpoint ± small drift (within ±0.5 of current)
        current = obs.get("setpoint_in", 5.0)
        if current is None:
            current = 5.0
        delta = random.uniform(-0.3, 0.3)
        value = max(0.0, min(10.0, float(current) + delta))
        return {
            "value": round(value, 2),
            "attack_type": AttackType.SETPOINT_SHIFT,
            "rationale": "Small setpoint adjustment consistent with operator tuning",
        }

    if tag == "fill_valve":
        # Match current controller output
        current = obs.get("fill_valve", 0.0)
        if current is None:
            current = 0.0
        delta = random.uniform(-0.3, 0.3)
        value = max(0.0, min(10.0, float(current) + delta))
        return {
            "value": round(value, 2),
            "attack_type": AttackType.ACTUATOR_OVERRIDE,
            "rationale": "Valve adjustment tracking controller output",
        }

    if tag == "discharge_valve":
        current = obs.get("discharge_valve", 0.0)
        if current is None:
            current = 0.0
        delta = random.uniform(-0.3, 0.3)
        value = max(0.0, min(10.0, float(current) + delta))
        return {
            "value": round(value, 2),
            "attack_type": AttackType.ACTUATOR_OVERRIDE,
            "rationale": "Discharge adjustment tracking controller output",
        }

    if tag == "enable":
        # Always propose TRUE (legitimate operation)
        return {
            "value": 1.0,
            "attack_type": AttackType.ACTUATOR_OVERRIDE,
            "rationale": "Confirming system enable state",
        }

    return None


def _generate_sorting_weight_write(
    snapshot: PlantSnapshot,
    tag: str,
    history: HistoryBuffer,
) -> Optional[Dict[str, Any]]:
    """Generate a legitimate write for Sorting by Weight."""
    obs = {}
    obs.update(snapshot.sensors or {})
    obs.update(snapshot.actuators or {})
    obs.update(snapshot.setpoints or {})
    obs.update(snapshot.controller_state or {})

    if tag in ("send_left", "send_right", "send_forward"):
        # Match current actuator state (keep as-is)
        current = obs.get(tag, False)
        return {
            "value": 1.0 if current else 0.0,
            "attack_type": AttackType.ACTUATOR_OVERRIDE,
            "rationale": f"Maintaining current {tag} state",
        }

    if tag == "entry_conveyor":
        current = obs.get("entry_conveyor", True)
        return {
            "value": 1.0 if current else 0.0,
            "attack_type": AttackType.ACTUATOR_OVERRIDE,
            "rationale": "Maintaining entry conveyor state",
        }

    if tag == "load_scale":
        current = obs.get("load_scale", False)
        return {
            "value": 1.0 if current else 0.0,
            "attack_type": AttackType.ACTUATOR_OVERRIDE,
            "rationale": "Maintaining load scale state",
        }

    if tag in ("light_thresh", "heavy_thresh"):
        # Propose current threshold ± tiny drift (legitimate tuning)
        defaults = {"light_thresh": 2.0, "heavy_thresh": 5.0}
        current = obs.get(tag, defaults.get(tag, 3.0))
        if current is None:
            current = defaults.get(tag, 3.0)
        delta = random.uniform(-0.1, 0.1)
        value = max(0.1, float(current) + delta)
        return {
            "value": round(value, 2),
            "attack_type": AttackType.SETPOINT_SHIFT,
            "rationale": f"Fine-tuning {tag} threshold",
        }

    if tag == "enable":
        return {
            "value": 1.0,
            "attack_type": AttackType.ACTUATOR_OVERRIDE,
            "rationale": "Confirming system enable state",
        }

    return None


def _generate_sorting_height_write(
    snapshot: PlantSnapshot,
    tag: str,
    history: HistoryBuffer,
) -> Optional[Dict[str, Any]]:
    """Generate a legitimate write for Sorting by Height."""
    obs = {}
    obs.update(snapshot.sensors or {})
    obs.update(snapshot.actuators or {})
    obs.update(snapshot.setpoints or {})
    obs.update(snapshot.controller_state or {})

    if tag in ("conveyor_entry", "conveyor_left", "conveyor_right"):
        current = obs.get(tag, False)
        return {
            "value": 1.0 if current else 0.0,
            "attack_type": AttackType.ACTUATOR_OVERRIDE,
            "rationale": f"Maintaining {tag} state",
        }

    if tag in ("load_act", "unload_act", "transf_left", "transf_right"):
        current = obs.get(tag, False)
        return {
            "value": 1.0 if current else 0.0,
            "attack_type": AttackType.ACTUATOR_OVERRIDE,
            "rationale": f"Maintaining {tag} actuator state",
        }

    if tag == "enable":
        return {
            "value": 1.0,
            "attack_type": AttackType.ACTUATOR_OVERRIDE,
            "rationale": "Confirming system enable state",
        }

    return None


_SCENE_GENERATORS = {
    "level_control": _generate_level_control_write,
    "sorting_weight": _generate_sorting_weight_write,
    "sorting_height_basic": _generate_sorting_height_write,
}


# ---------------------------------------------------------------------------
# FPRProbeAttacker
# ---------------------------------------------------------------------------

class FPRProbeAttacker:
    """Generates known-legitimate write proposals for FPR measurement.

    This attacker produces writes that mirror the current controller state,
    testing whether the defense chain incorrectly blocks legitimate operations.

    Parameters
    ----------
    scene : BaseScene
        Scene definition with attack_surface.
    history : HistoryBuffer
        Shared history buffer.
    phase_engine : PhaseInferenceEngine
        Phase inference (for context, not used in generation).
    probe_interval : int
        Generate a probe every N steps.
    seed : int or None
        Random seed for reproducibility.
    """

    def __init__(
        self,
        scene: BaseScene,
        history: HistoryBuffer,
        phase_engine: PhaseInferenceEngine,
        probe_interval: int = 3,
        seed: Optional[int] = None,
    ) -> None:
        self._scene = scene
        self._history = history
        self._phase_engine = phase_engine
        self._probe_interval = probe_interval
        self._step_count = 0
        self._rng = random.Random(seed)

        # Get attack surface tags from scene
        self._attack_surface: List[str] = []
        if hasattr(scene, "profile") and hasattr(scene.profile, "attack_surface"):
            self._attack_surface = list(scene.profile.attack_surface or [])
        if not self._attack_surface:
            logger.warning("FPRProbeAttacker: no attack_surface tags in scene config")

        self._scene_name = scene.profile.scene_name if hasattr(scene, "profile") else "unknown"
        self._generator = _SCENE_GENERATORS.get(self._scene_name)
        if self._generator is None:
            logger.warning("FPRProbeAttacker: no generator for scene %s", self._scene_name)

        # Tracking
        self._total_probes = 0
        self._budget_remaining = 999  # Unlimited for FPR testing

        # Outcome tracking (for compatibility with OnlineMITMAttacker interface)
        self._decision_history: list = []

    @property
    def budget_remaining(self) -> int:
        return self._budget_remaining

    def should_call_llm(self) -> bool:
        """Return True every probe_interval steps."""
        self._step_count += 1
        return self._step_count % self._probe_interval == 0

    def decide(self, snapshot: PlantSnapshot) -> AttackDecision:
        """Generate a known-legitimate write proposal.

        Always returns decision=ATTACK so the defense chain evaluates it.
        The write value tracks the current controller output.
        """
        # Pick a random attack surface tag
        if not self._attack_surface or self._generator is None:
            return AttackDecision(
                decision=AttackDecisionType.WAIT,
                raw_output="no_attack_surface",
                parse_success=True,
            )

        tag = self._rng.choice(self._attack_surface)
        write_spec = self._generator(snapshot, tag, self._history)

        if write_spec is None:
            return AttackDecision(
                decision=AttackDecisionType.WAIT,
                raw_output=f"no_generator_for_{tag}",
                parse_success=True,
            )

        self._total_probes += 1

        return AttackDecision(
            decision=AttackDecisionType.ATTACK,
            target_tag=tag,
            action_type=str(write_spec["attack_type"].value),
            action_value=write_spec["value"],
            duration_ms=1000,
            expected_effect=write_spec["rationale"],
            confidence=0.95,
            reasoning=f"FPR_PROBE: {write_spec['rationale']}",
            timing_rationale="Legitimate operation probe",
            raw_output=f"fpr_probe_{tag}_{write_spec['value']}",
            parse_success=True,
        )

    def to_attack_action(self, decision: AttackDecision) -> Optional[AttackAction]:
        """Convert decision to AttackAction for defense chain evaluation."""
        if not decision.parse_success or decision.decision != AttackDecisionType.ATTACK:
            return None

        attack_type = AttackType.ACTUATOR_OVERRIDE
        if decision.action_type:
            try:
                attack_type = AttackType(decision.action_type)
            except ValueError:
                pass

        return AttackAction(
            attack_type=attack_type,
            target=decision.target_tag or "unknown",
            value=decision.action_value,
            duration_ms=decision.duration_ms or 1000,
            rationale=decision.reasoning or "",
            expected_effect=decision.expected_effect or "",
            confidence=decision.confidence or 0.95,
            source=AttackSource.SCRIPTED,  # Marks as scripted (not LLM)
        )

    def record_outcome(
        self,
        step_id: int,
        shield_approved: bool,
        write_executed: bool,
        attack_success: Optional[bool] = None,
    ) -> None:
        """Record outcome for logging. FPR probe never writes to PLC."""
        self._decision_history.append({
            "step_id": step_id,
            "shield_approved": shield_approved,
            "write_executed": write_executed,
            "is_false_positive": not shield_approved,  # Block on legitimate write = FP
        })

    @property
    def total_probes(self) -> int:
        return self._total_probes

    @property
    def false_positives(self) -> int:
        return sum(1 for d in self._decision_history if d.get("is_false_positive"))

    @property
    def fpr(self) -> float:
        if self._total_probes == 0:
            return 0.0
        return self.false_positives / self._total_probes
