"""
CPSForge Safety Shield Engine
================================
The shield is the mandatory safety gate between all proposed attack actions
and the real PLC. No write can bypass it in normal operation.

Responsibilities:
  1. Validate every AttackAction against scene-specific safety rules.
  2. Return a structured ShieldDecision (approved/rejected + reasons).
  3. Optionally normalise the action's value to the allowed range.
  4. Enforce cooldown windows between repeated writes to the same tag.
  5. Enforce maximum duration caps.
  6. Reject writes to tags not on the writable whitelist.
  7. Log all decisions for audit.

Rule engine:
  Rules are loaded from SceneProfile.safety_rules and evaluated in priority
  order (highest priority first). The first hard-reject rule short-circuits
  further evaluation. Soft warnings accumulate into the reasons list.

Design constraint:
  The shield never calls PLC write functions directly. It only evaluates
  and returns a ShieldDecision. The orchestrator is responsible for
  calling PlcClient.write_tag() after receiving approval.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from cpsforge.core.models import (
    AttackAction,
    PlantSnapshot,
    SafetyRule,
    SceneProfile,
    ShieldDecision,
)

logger = logging.getLogger(__name__)


class ShieldEngine:
    """
    Runtime safety shield for a single Factory I/O scene.

    Parameters
    ----------
    profile:
        The :class:`SceneProfile` whose ``safety_rules`` and ``writable_tags``
        define what this shield enforces.
    """

    def __init__(self, profile: SceneProfile) -> None:
        self._profile = profile
        self._writable_set = set(profile.writable_tags)
        self._attack_surface = set(profile.attack_surface)
        # Per-tag last-write timestamp for cooldown enforcement
        self._last_write: Dict[str, datetime] = {}
        # Sort rules by priority (descending)
        self._rules: List[SafetyRule] = sorted(
            [r for r in profile.safety_rules if r.enabled],
            key=lambda r: r.priority,
            reverse=True,
        )

    # ------------------------------------------------------------------
    # Primary evaluation method
    # ------------------------------------------------------------------

    def evaluate(
        self,
        action: AttackAction,
        snapshot: Optional[PlantSnapshot] = None,
    ) -> ShieldDecision:
        """
        Evaluate a proposed attack action and return a :class:`ShieldDecision`.

        Parameters
        ----------
        action:
            The proposed attack action to evaluate.
        snapshot:
            Optional current plant snapshot for context-aware checks.
        """
        reasons: List[str] = []
        violated: List[str] = []
        approved = True
        normalised_value: Optional[float] = action.value

        # --- 1. Whitelist check ---
        if action.target not in self._attack_surface:
            reasons.append(
                f"Tag '{action.target}' is not in the scene attack surface. "
                f"Allowed: {sorted(self._attack_surface)}"
            )
            violated.append("whitelist")
            approved = False

        # --- 2. Rule engine ---
        if approved:
            for rule in self._rules:
                ok, reason, norm = self._evaluate_rule(rule, action, snapshot)
                if not ok:
                    violated.append(rule.rule_id)
                    reasons.append(f"[{rule.rule_id}] {reason}")
                    approved = False
                    break  # first hard reject wins
                if norm is not None:
                    normalised_value = norm
                if reason:
                    reasons.append(f"[{rule.rule_id}] {reason}")

        # --- 3. Build rollback plan ---
        rollback: Optional[Dict[str, Any]] = None
        if approved and snapshot is not None:
            rollback = self._build_rollback(action, snapshot)

        # --- 4. Expiration time ---
        expiration: Optional[datetime] = None
        if approved and action.duration_ms > 0:
            expiration = datetime.now(timezone.utc) + timedelta(
                milliseconds=action.duration_ms
            )

        decision = ShieldDecision(
            action_id=action.action_id,
            approved=approved,
            reasons=reasons,
            violated_rules=violated,
            normalized_value=normalised_value,
            expiration_time=expiration,
            rollback_plan=rollback,
        )

        if approved:
            self._last_write[action.target] = datetime.now(timezone.utc)
            logger.debug("Shield APPROVED: %s -> %s=%s", action.attack_type.value, action.target, normalised_value)
        else:
            logger.info(
                "Shield REJECTED: %s -> %s. Violated: %s",
                action.attack_type.value,
                action.target,
                violated,
            )

        return decision

    def evaluate_corrective(
        self,
        action: AttackAction,
        snapshot: Optional[PlantSnapshot] = None,
    ) -> ShieldDecision:
        """
        Evaluate a *corrective* write proposed by the defender agent.

        Corrective actions use the same safety checks as attack actions
        (range, duration, invariant, interlock) but skip the cooldown rule
        to allow rapid recovery. The target must still be in the writable
        whitelist.
        """
        reasons: List[str] = []
        violated: List[str] = []
        approved = True
        normalised_value: Optional[float] = action.value

        # --- 1. Whitelist check (same as attack) ---
        if action.target not in self._attack_surface:
            reasons.append(
                f"Corrective tag '{action.target}' not in writable surface."
            )
            violated.append("whitelist")
            approved = False

        # --- 2. Rule engine (skip cooldown for corrective) ---
        if approved:
            for rule in self._rules:
                if rule.rule_type == "cooldown":
                    continue  # skip cooldown for corrective writes
                ok, reason, norm = self._evaluate_rule(rule, action, snapshot)
                if not ok:
                    violated.append(rule.rule_id)
                    reasons.append(f"[{rule.rule_id}] {reason}")
                    approved = False
                    break
                if norm is not None:
                    normalised_value = norm
                if reason:
                    reasons.append(f"[{rule.rule_id}] {reason}")

        rollback: Optional[Dict[str, Any]] = None
        if approved and snapshot is not None:
            rollback = self._build_rollback(action, snapshot)

        expiration: Optional[datetime] = None
        if approved and action.duration_ms > 0:
            expiration = datetime.now(timezone.utc) + timedelta(
                milliseconds=action.duration_ms
            )

        decision = ShieldDecision(
            action_id=action.action_id,
            approved=approved,
            reasons=reasons,
            violated_rules=violated,
            normalized_value=normalised_value,
            expiration_time=expiration,
            rollback_plan=rollback,
        )

        if approved:
            self._last_write[action.target] = datetime.now(timezone.utc)
            logger.debug(
                "Shield APPROVED corrective: %s -> %s=%s",
                action.attack_type.value, action.target, normalised_value,
            )
        else:
            logger.info(
                "Shield REJECTED corrective: %s -> %s. Violated: %s",
                action.attack_type.value, action.target, violated,
            )

        return decision

    # ------------------------------------------------------------------
    # Rule evaluators
    # ------------------------------------------------------------------

    def _evaluate_rule(
        self,
        rule: SafetyRule,
        action: AttackAction,
        snapshot: Optional[PlantSnapshot],
    ) -> tuple[bool, str, Optional[float]]:
        """
        Evaluate one safety rule.

        Returns
        -------
        (ok, message, normalised_value)
          ok               -- False means reject the action
          message          -- human-readable explanation (empty string if clean)
          normalised_value -- adjusted value if rule normalises it, else None
        """
        rt = rule.rule_type
        p = rule.parameters
        tags = rule.tags

        # Only evaluate rule if it applies to this tag (or is global)
        if tags and action.target not in tags:
            return True, "", None

        if rt == "range":
            return self._check_range(action, p)

        elif rt == "duration":
            return self._check_duration(action, p)

        elif rt == "cooldown":
            return self._check_cooldown(action, p)

        elif rt == "invariant":
            return self._check_invariant(action, snapshot, p)

        elif rt == "interlock":
            return self._check_interlock(action, snapshot, rule, p)

        elif rt == "mode_gate":
            return self._check_mode_gate(action, snapshot, p)

        elif rt == "mutual_exclusion":
            return True, "", None  # Enforced at a higher level with action queue

        else:
            logger.debug("Unknown rule type '%s' -- skipping.", rt)
            return True, "", None

    def _check_range(
        self, action: AttackAction, params: Dict[str, Any]
    ) -> tuple[bool, str, Optional[float]]:
        """Enforce min/max bounds on the action value."""
        if action.value is None:
            return True, "", None
        lo = params.get("min")
        hi = params.get("max")
        val = action.value
        if lo is not None and val < lo:
            return (
                False,
                f"Value {val} is below minimum {lo} for tag '{action.target}'.",
                None,
            )
        if hi is not None and val > hi:
            return (
                False,
                f"Value {val} exceeds maximum {hi} for tag '{action.target}'.",
                None,
            )
        return True, "", None

    def _check_duration(
        self, action: AttackAction, params: Dict[str, Any]
    ) -> tuple[bool, str, Optional[float]]:
        """Enforce maximum attack duration."""
        max_ms = params.get("max_duration_ms")
        if max_ms is not None and action.duration_ms > max_ms:
            return (
                False,
                f"Requested duration {action.duration_ms}ms exceeds cap of {max_ms}ms.",
                None,
            )
        return True, "", None

    def _check_cooldown(
        self, action: AttackAction, params: Dict[str, Any]
    ) -> tuple[bool, str, Optional[float]]:
        """Enforce minimum cooldown between repeated writes to the same tag."""
        cooldown_ms = params.get("cooldown_ms", 0)
        last = self._last_write.get(action.target)
        if last is not None:
            elapsed_ms = (datetime.now(timezone.utc) - last).total_seconds() * 1000
            if elapsed_ms < cooldown_ms:
                return (
                    False,
                    f"Cooldown for '{action.target}' not satisfied. "
                    f"Wait {cooldown_ms - elapsed_ms:.0f}ms more.",
                    None,
                )
        return True, "", None

    def _check_invariant(
        self,
        action: AttackAction,
        snapshot: Optional[PlantSnapshot],
        params: Dict[str, Any],
    ) -> tuple[bool, str, Optional[float]]:
        """Check that the resulting write does not violate a hard boundary."""
        if snapshot is None or action.value is None:
            return True, "", None
        lo = params.get("min")
        hi = params.get("max")
        # Fetch current sensor value for the tag
        current = self._get_snapshot_value(snapshot, action.target)
        if current is None:
            return True, "", None
        if lo is not None and float(action.value) < lo:
            return (
                False,
                f"Write of {action.value} would violate invariant min={lo} for '{action.target}'.",
                None,
            )
        if hi is not None and float(action.value) > hi:
            return (
                False,
                f"Write of {action.value} would violate invariant max={hi} for '{action.target}'.",
                None,
            )
        return True, "", None

    def _check_interlock(
        self,
        action: AttackAction,
        snapshot: Optional[PlantSnapshot],
        rule: SafetyRule,
        params: Dict[str, Any],
    ) -> tuple[bool, str, Optional[float]]:
        """Block a write when a condition tag has a specific state."""
        if snapshot is None:
            return True, "", None
        condition_tag = params.get("condition_tag")
        condition_value = params.get("condition_value")
        forbidden_val = params.get("forbidden_value")
        if condition_tag is None:
            return True, "", None

        current_cond = self._get_snapshot_value(snapshot, condition_tag)
        if current_cond is None:
            return True, "", None

        if current_cond == condition_value and action.value == forbidden_val:
            return (
                False,
                f"Interlock [{rule.rule_id}]: cannot write {forbidden_val} to "
                f"'{action.target}' when '{condition_tag}' == {condition_value}.",
                None,
            )
        return True, "", None

    def _check_mode_gate(
        self,
        action: AttackAction,
        snapshot: Optional[PlantSnapshot],
        params: Dict[str, Any],
    ) -> tuple[bool, str, Optional[float]]:
        """Block writes when a gate tag is in a forbidden state."""
        if snapshot is None:
            return True, "", None
        gate_tag = params.get("gate_tag")
        gate_must_be = params.get("gate_must_be")
        if gate_tag is None:
            return True, "", None

        gate_val = self._get_snapshot_value(snapshot, gate_tag)
        if gate_val is None:
            return True, "", None

        if gate_val != gate_must_be:
            return (
                False,
                f"Mode gate: '{gate_tag}' is {gate_val} (must be {gate_must_be}) -- write blocked.",
                None,
            )
        return True, "", None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_rollback(
        self, action: AttackAction, snapshot: PlantSnapshot
    ) -> Dict[str, Any]:
        """Build a rollback tag-value map to restore pre-attack state."""
        current = self._get_snapshot_value(snapshot, action.target)
        return {action.target: current}

    @staticmethod
    def _get_snapshot_value(snapshot: PlantSnapshot, tag_name: str) -> Optional[Any]:
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
