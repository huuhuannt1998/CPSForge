"""
CPSForge — Phase 2 Validation Test Suite
==========================================
Comprehensive tests for shield policy logic, attack schema validation,
attack compilation edge cases, PLC/experiment config parsing, and
CLI smoke tests.

Coverage targets
----------------
* Shield approval and rejection (all rule types: range, duration, cooldown,
  interlock, mode_gate, whitelist)
* Attack schema validation (Pydantic bounds, defaults, auto-generated fields)
* Attack compilation (override, offset, freeze, zero, unknown modes; scripted
  and random attacker policy behaviour)
* PLC and experiment config parsing (safety, correctness, validator logic)
* CLI smoke tests via typer CliRunner (--help pages + dry-run end-to-end)

All tests execute WITHOUT a live PLC.  No mock PLC backend is introduced.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _loader():
    from cpsforge.core.config import ConfigLoader
    return ConfigLoader(configs_dir=REPO_ROOT / "configs")


def _scene():
    from cpsforge.scenes.factory import load_scene
    return load_scene("tank_control", _loader())


def _make_snapshot(
    sensors: Optional[Dict[str, Any]] = None,
    actuators: Optional[Dict[str, Any]] = None,
    alarms: Optional[Dict[str, Any]] = None,
    setpoints: Optional[Dict[str, Any]] = None,
    controller_state: Optional[Dict[str, Any]] = None,
) -> Any:
    from cpsforge.core.models import (
        AttackContext, DefenseContext, PlantSnapshot, SafetyContext,
    )
    return PlantSnapshot(
        timestamp=datetime.now(timezone.utc),
        scene_name="tank_control",
        run_id="val-test",
        step_id=0,
        sensors=sensors if sensors is not None else {
            "tank_level": 50.0, "inlet_flow": 20.0, "outlet_flow": 20.0,
        },
        actuators=actuators if actuators is not None else {
            "pump_speed": 50.0, "drain_valve_position": 50.0,
        },
        controller_state=controller_state if controller_state is not None else {
            "pid_output": 50.0, "auto_mode": False,
        },
        alarms=alarms if alarms is not None else {
            "high_level_alarm": False, "low_level_alarm": False, "pump_fault": False,
        },
        setpoints=setpoints if setpoints is not None else {"level_setpoint": 50.0},
        attack_context=AttackContext(),
        defense_context=DefenseContext(),
        safety_context=SafetyContext(live_writes_enabled=False),
    )


def _make_shield():
    """Return a fresh ShieldEngine for the tank_control scene."""
    from cpsforge.shield.engine import ShieldEngine
    return ShieldEngine(_scene().profile)


def _invoke_cli(*args: str, **kwargs) -> Any:
    """Invoke the CPSForge CLI via typer CliRunner; returns the Result object."""
    from typer.testing import CliRunner
    from cpsforge.cli.app import app
    runner = CliRunner()
    return runner.invoke(app, list(args), catch_exceptions=False, **kwargs)


# ===========================================================================
# 1. Shield approval and rejection logic
# ===========================================================================


class TestShieldApprovalRejectionDetailed:
    """
    Tests all six rule categories enforced by the shield engine using the
    tank_control scene config (SR-001 through SR-008).

    Each test uses a freshly constructed ShieldEngine so cooldown state
    does not bleed between tests.
    """

    # ------------------------------------------------------------------
    # Range rule (SR-002 / SR-004)
    # ------------------------------------------------------------------

    def test_range_rejects_value_below_minimum(self):
        """SR-004: level_setpoint < 10.0 must be rejected."""
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        dec = _make_shield().evaluate(
            AttackAction(attack_type=AttackType.SETPOINT_SHIFT, target="level_setpoint",
                         value=5.0, source=AttackSource.SCRIPTED),
            _make_snapshot(),
        )
        assert dec.approved is False
        assert any("SR-004" in r for r in dec.reasons)

    def test_range_rejects_value_above_maximum(self):
        """SR-004: level_setpoint > 90.0 must be rejected."""
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        dec = _make_shield().evaluate(
            AttackAction(attack_type=AttackType.SETPOINT_SHIFT, target="level_setpoint",
                         value=95.0, source=AttackSource.SCRIPTED),
            _make_snapshot(),
        )
        assert dec.approved is False
        assert any("SR-004" in r for r in dec.reasons)

    def test_range_permits_value_at_lower_bound(self):
        """Exactly at SR-004 min (10.0) must be approved."""
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        dec = _make_shield().evaluate(
            AttackAction(attack_type=AttackType.SETPOINT_SHIFT, target="level_setpoint",
                         value=10.0, source=AttackSource.SCRIPTED),
            _make_snapshot(),
        )
        assert dec.approved is True

    def test_range_permits_value_at_upper_bound(self):
        """Exactly at SR-004 max (90.0) must be approved."""
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        dec = _make_shield().evaluate(
            AttackAction(attack_type=AttackType.SETPOINT_SHIFT, target="level_setpoint",
                         value=90.0, source=AttackSource.SCRIPTED),
            _make_snapshot(),
        )
        assert dec.approved is True

    def test_range_rejects_pump_speed_out_of_bounds(self):
        """SR-002: pump_speed above 100.0 must be rejected."""
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        dec = _make_shield().evaluate(
            AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                         value=150.0, source=AttackSource.SCRIPTED),
            _make_snapshot(),
        )
        assert dec.approved is False
        assert any("SR-002" in r for r in dec.reasons)

    # ------------------------------------------------------------------
    # Duration rule (SR-005)
    # ------------------------------------------------------------------

    def test_duration_cap_rejects_attack_over_30s(self):
        """SR-005: any action with duration_ms > 30 000 must be rejected."""
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        dec = _make_shield().evaluate(
            AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                         value=80.0, duration_ms=31_000, source=AttackSource.SCRIPTED),
            _make_snapshot(),
        )
        assert dec.approved is False
        assert any("SR-005" in r for r in dec.reasons)

    def test_duration_cap_permits_action_at_limit(self):
        """SR-005: duration_ms exactly at 30 000 must be permitted."""
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        dec = _make_shield().evaluate(
            AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                         value=80.0, duration_ms=30_000, source=AttackSource.SCRIPTED),
            _make_snapshot(),
        )
        assert dec.approved is True

    # ------------------------------------------------------------------
    # Cooldown rule (SR-006)
    # ------------------------------------------------------------------

    def test_cooldown_blocks_immediate_repeat_to_same_tag(self):
        """
        SR-006: after an approved write to pump_speed, an immediate second
        write to pump_speed must be blocked (cooldown_ms=5000).
        """
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        shield = _make_shield()
        # First write — registers the timestamp in shield._last_write
        dec1 = shield.evaluate(
            AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                         value=80.0, source=AttackSource.SCRIPTED),
            _make_snapshot(),
        )
        assert dec1.approved is True

        # Immediate second write to the same tag — cooldown not satisfied
        dec2 = shield.evaluate(
            AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                         value=70.0, source=AttackSource.SCRIPTED),
            _make_snapshot(),
        )
        assert dec2.approved is False
        assert any("SR-006" in r for r in dec2.reasons)

    def test_cooldown_is_tracked_independently_per_tag(self):
        """
        Cooldown on pump_speed must not affect a first write to drain_valve_position.
        Each tag has its own cooldown clock in the engine.
        """
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        shield = _make_shield()
        # Consume cooldown slot for pump_speed
        dec1 = shield.evaluate(
            AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                         value=80.0, source=AttackSource.SCRIPTED),
            _make_snapshot(),
        )
        assert dec1.approved is True

        # drain_valve_position has never been written — must not be blocked
        dec2 = shield.evaluate(
            AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="drain_valve_position",
                         value=50.0, source=AttackSource.SCRIPTED),
            _make_snapshot(),
        )
        assert dec2.approved is True, (
            "Cooldown on pump_speed should not block drain_valve_position"
        )

    # ------------------------------------------------------------------
    # Interlock rule (SR-007)
    # ------------------------------------------------------------------

    def test_interlock_sr007_blocks_pump_stop_when_alarm_is_false(self):
        """
        SR-007 config: condition_tag=high_level_alarm, condition_value=false,
        forbidden_value=0.0 — blocks writing pump_speed=0.0 when alarm is NOT active.
        """
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        dec = _make_shield().evaluate(
            AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                         value=0.0, source=AttackSource.SCRIPTED),
            _make_snapshot(
                alarms={"high_level_alarm": False, "low_level_alarm": False, "pump_fault": False},
            ),
        )
        assert dec.approved is False
        assert any("SR-007" in r for r in dec.reasons)

    def test_interlock_sr007_allows_pump_stop_when_alarm_is_active(self):
        """
        When high_level_alarm=True, SR-007 condition_value=false does not match,
        so writing pump_speed=0.0 must be allowed (other rules pass too).
        """
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        dec = _make_shield().evaluate(
            AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                         value=0.0, source=AttackSource.SCRIPTED),
            _make_snapshot(
                alarms={"high_level_alarm": True, "low_level_alarm": False, "pump_fault": False},
            ),
        )
        # SR-007 does NOT fire when high_level_alarm != condition_value(false)
        assert dec.approved is True

    def test_interlock_does_not_apply_to_other_tags(self):
        """SR-007 only applies to pump_speed; drain_valve_position=0.0 is not blocked."""
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        dec = _make_shield().evaluate(
            AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="drain_valve_position",
                         value=0.0, source=AttackSource.SCRIPTED),
            _make_snapshot(
                alarms={"high_level_alarm": False, "low_level_alarm": False, "pump_fault": False},
            ),
        )
        # drain_valve_position is not in SR-007 tags list, so interlock skipped
        assert dec.approved is True

    # ------------------------------------------------------------------
    # Mode gate rule (SR-008)
    # ------------------------------------------------------------------

    def test_mode_gate_sr008_blocks_write_when_pump_fault_active(self):
        """SR-008: any write to pump_speed is blocked when pump_fault=True."""
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        dec = _make_shield().evaluate(
            AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                         value=75.0, source=AttackSource.SCRIPTED),
            _make_snapshot(
                alarms={"high_level_alarm": False, "low_level_alarm": False, "pump_fault": True},
            ),
        )
        assert dec.approved is False
        assert any("SR-008" in r for r in dec.reasons)

    def test_mode_gate_sr008_permits_write_when_no_fault(self):
        """SR-008: writes proceed normally when pump_fault=False."""
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        dec = _make_shield().evaluate(
            AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                         value=75.0, source=AttackSource.SCRIPTED),
            _make_snapshot(
                alarms={"high_level_alarm": False, "low_level_alarm": False, "pump_fault": False},
            ),
        )
        assert dec.approved is True

    # ------------------------------------------------------------------
    # Whitelist (attack surface) check
    # ------------------------------------------------------------------

    def test_non_attack_surface_tag_is_rejected(self):
        """tank_level is read-only and not in attack_surface — must be rejected."""
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        dec = _make_shield().evaluate(
            AttackAction(attack_type=AttackType.SENSOR_SPOOF, target="tank_level",
                         value=99.0, source=AttackSource.SCRIPTED),
            _make_snapshot(),
        )
        assert dec.approved is False
        assert "whitelist" in dec.violated_rules

    def test_whitelist_rejection_reason_lists_allowed_tags(self):
        """The rejection reason for a whitelist failure should mention allowed tags."""
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        dec = _make_shield().evaluate(
            AttackAction(attack_type=AttackType.SENSOR_SPOOF, target="inlet_flow",
                         value=0.0, source=AttackSource.SCRIPTED),
            _make_snapshot(),
        )
        assert dec.approved is False
        combined = " ".join(dec.reasons).lower()
        assert "attack surface" in combined or "whitelist" in combined or "allowed" in combined

    # ------------------------------------------------------------------
    # Rollback plan and expiration metadata
    # ------------------------------------------------------------------

    def test_rollback_plan_captures_pre_attack_value(self):
        """An approved action must include a rollback_plan with the current value."""
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        dec = _make_shield().evaluate(
            AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                         value=80.0, source=AttackSource.SCRIPTED),
            _make_snapshot(actuators={"pump_speed": 42.0, "drain_valve_position": 50.0}),
        )
        assert dec.approved is True
        assert dec.rollback_plan is not None
        assert dec.rollback_plan.get("pump_speed") == pytest.approx(42.0)

    def test_expiration_time_set_when_duration_positive(self):
        """Approved action with duration_ms > 0 must have a future expiration_time."""
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        dec = _make_shield().evaluate(
            AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                         value=80.0, duration_ms=5_000, source=AttackSource.SCRIPTED),
            _make_snapshot(),
        )
        assert dec.approved is True
        assert dec.expiration_time is not None
        assert dec.expiration_time > datetime.now(timezone.utc)

    def test_rejection_reasons_are_non_empty_strings(self):
        """Every reason string in a rejection must be a non-empty str."""
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        dec = _make_shield().evaluate(
            AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                         value=999.0, source=AttackSource.SCRIPTED),
            _make_snapshot(),
        )
        assert dec.approved is False
        assert len(dec.reasons) > 0
        for r in dec.reasons:
            assert isinstance(r, str) and len(r.strip()) > 0

    def test_violated_rules_list_populated_on_rejection(self):
        """violated_rules must be non-empty when an action is rejected."""
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        dec = _make_shield().evaluate(
            AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                         value=999.0, source=AttackSource.SCRIPTED),
            _make_snapshot(),
        )
        assert dec.approved is False
        assert len(dec.violated_rules) > 0


# ===========================================================================
# 2. Attack schema validation
# ===========================================================================


class TestAttackSchemaValidation:
    """
    Validates Pydantic field constraints, auto-generated fields, enum coverage,
    and default values across all core CPSForge data models.
    """

    # ------------------------------------------------------------------
    # AttackAction field constraints
    # ------------------------------------------------------------------

    def test_confidence_below_zero_raises(self):
        from pydantic import ValidationError
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        with pytest.raises(ValidationError):
            AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                         source=AttackSource.SCRIPTED, confidence=-0.1)

    def test_confidence_above_one_raises(self):
        from pydantic import ValidationError
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        with pytest.raises(ValidationError):
            AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                         source=AttackSource.SCRIPTED, confidence=1.1)

    def test_duration_ms_negative_raises(self):
        from pydantic import ValidationError
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        with pytest.raises(ValidationError):
            AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                         source=AttackSource.SCRIPTED, duration_ms=-1)

    def test_action_id_is_unique_per_instance(self):
        """Each new AttackAction gets a distinct UUID."""
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        a1 = AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                          source=AttackSource.SCRIPTED)
        a2 = AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                          source=AttackSource.SCRIPTED)
        assert a1.action_id != a2.action_id

    def test_execution_status_defaults_to_pending(self):
        from cpsforge.core.models import AttackAction, AttackSource, AttackType, ExecutionStatus
        action = AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                              source=AttackSource.SCRIPTED)
        assert action.execution_status == ExecutionStatus.PENDING

    def test_approved_by_shield_initially_none(self):
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        action = AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                              source=AttackSource.SCRIPTED)
        assert action.approved_by_shield is None

    def test_default_mode_is_override(self):
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        action = AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                              source=AttackSource.SCRIPTED)
        assert action.mode == "override"

    def test_default_duration_ms_is_positive(self):
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        action = AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                              source=AttackSource.SCRIPTED)
        assert action.duration_ms > 0

    # ------------------------------------------------------------------
    # Enum coverage
    # ------------------------------------------------------------------

    def test_all_attack_types_have_string_values(self):
        from cpsforge.core.models import AttackType
        for at in AttackType:
            assert isinstance(at.value, str) and at.value

    def test_all_attack_sources_have_string_values(self):
        from cpsforge.core.models import AttackSource
        for src in AttackSource:
            assert isinstance(src.value, str) and src.value

    def test_execution_status_includes_dry_run_value(self):
        from cpsforge.core.models import ExecutionStatus
        assert ExecutionStatus.DRY_RUN.value == "dry_run"

    # ------------------------------------------------------------------
    # DetectionEvent
    # ------------------------------------------------------------------

    def test_detection_event_requires_run_id(self):
        from pydantic import ValidationError
        from cpsforge.core.models import DetectionEvent
        with pytest.raises(ValidationError):
            DetectionEvent(detector_name="threshold")  # run_id missing

    def test_detection_event_severity_defaults_to_low(self):
        from cpsforge.core.models import DetectionEvent, DetectionSeverity
        ev = DetectionEvent(run_id="r", detector_name="threshold")
        assert ev.severity == DetectionSeverity.LOW

    def test_detection_event_confidence_default_is_zero(self):
        from cpsforge.core.models import DetectionEvent
        ev = DetectionEvent(run_id="r", detector_name="threshold")
        assert ev.confidence == pytest.approx(0.0)

    # ------------------------------------------------------------------
    # PlantSnapshot
    # ------------------------------------------------------------------

    def test_plant_snapshot_step_id_must_be_nonneg(self):
        from pydantic import ValidationError
        from cpsforge.core.models import (
            AttackContext, DefenseContext, PlantSnapshot, SafetyContext,
        )
        with pytest.raises(ValidationError):
            PlantSnapshot(
                scene_name="tank_control", run_id="x", step_id=-1,
                attack_context=AttackContext(),
                defense_context=DefenseContext(),
                safety_context=SafetyContext(),
            )

    # ------------------------------------------------------------------
    # SafetyRule defaults
    # ------------------------------------------------------------------

    def test_safety_rule_defaults(self):
        from cpsforge.core.models import SafetyRule
        rule = SafetyRule(rule_id="SR-X", description="test", rule_type="range")
        assert rule.enabled is True
        assert rule.priority == 0
        assert rule.tags == []
        assert rule.parameters == {}

    # ------------------------------------------------------------------
    # HardCaseRecord / EvalMetrics
    # ------------------------------------------------------------------

    def test_hard_case_all_failure_modes_instantiate(self):
        from cpsforge.core.models import HardCaseFailureMode, HardCaseRecord
        for mode in HardCaseFailureMode:
            rec = HardCaseRecord(
                run_id="r", attack_id="a",
                detector_outcome="missed",
                failure_mode=mode,
                trace_path="/data/run1",
            )
            assert rec.failure_mode == mode
            assert rec.record_id  # auto UUID

    def test_eval_metrics_precision_above_one_raises(self):
        from pydantic import ValidationError
        from cpsforge.core.models import EvalMetrics
        with pytest.raises(ValidationError):
            EvalMetrics(
                run_id="r", scene_name="tank_control",
                attacker_name="scripted", detector_names=[],
                detector_precision=1.5,  # must be in [0, 1]
            )

    def test_eval_metrics_defaults_are_zero(self):
        from cpsforge.core.models import EvalMetrics
        m = EvalMetrics(
            run_id="r", scene_name="tank_control",
            attacker_name="scripted", detector_names=[],
        )
        assert m.attack_success_rate == pytest.approx(0.0)
        assert m.detector_f1 == pytest.approx(0.0)
        assert m.false_positives == 0


# ===========================================================================
# 3. Attack compilation — all modes and attacker policies
# ===========================================================================


class TestAttackCompilationDetailed:
    """
    Tests all compiler modes and edge cases, plus ScriptedAttacker and
    RandomAttacker policy behaviour.
    """

    # ------------------------------------------------------------------
    # Compiler modes
    # ------------------------------------------------------------------

    def test_zero_mode_numeric_tag_writes_zero(self):
        """zero mode on a REAL tag must produce {tag: 0.0}."""
        from cpsforge.attacks.compiler import compile_action
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        writes = compile_action(
            AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                         mode="zero", value=None, source=AttackSource.SCRIPTED),
            _scene(),
        )
        assert writes.get("pump_speed") == pytest.approx(0.0)

    def test_zero_mode_bool_tag_writes_false(self):
        """zero mode on a BOOL tag (auto_mode) must produce {tag: False}."""
        from cpsforge.attacks.compiler import compile_action
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        writes = compile_action(
            AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="auto_mode",
                         mode="zero", value=None, source=AttackSource.SCRIPTED),
            _scene(),
        )
        assert "auto_mode" in writes
        assert writes["auto_mode"] is False

    def test_offset_without_snapshot_falls_back_to_value(self):
        """offset mode with no snapshot uses the action value directly."""
        from cpsforge.attacks.compiler import compile_action
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        writes = compile_action(
            AttackAction(attack_type=AttackType.SETPOINT_SHIFT, target="level_setpoint",
                         mode="offset", value=10.0, source=AttackSource.SCRIPTED),
            _scene(),
            current_snapshot=None,
        )
        assert writes.get("level_setpoint") == pytest.approx(10.0)

    def test_offset_with_snapshot_adds_to_current(self):
        """offset mode with a snapshot should add value to the current reading."""
        from cpsforge.attacks.compiler import compile_action
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        snap = _make_snapshot(setpoints={"level_setpoint": 50.0})
        writes = compile_action(
            AttackAction(attack_type=AttackType.SETPOINT_SHIFT, target="level_setpoint",
                         mode="offset", value=10.0, source=AttackSource.SCRIPTED),
            _scene(),
            current_snapshot=snap,
        )
        assert writes.get("level_setpoint") == pytest.approx(60.0)

    def test_freeze_without_snapshot_produces_empty_dict(self):
        """freeze mode with no snapshot has nothing to freeze — must return {}."""
        from cpsforge.attacks.compiler import compile_action
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        writes = compile_action(
            AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                         mode="freeze", value=None, source=AttackSource.SCRIPTED),
            _scene(),
            current_snapshot=None,
        )
        assert writes == {}

    def test_freeze_with_snapshot_repeats_current_value(self):
        """freeze mode must lock the tag at its current snapshot reading."""
        from cpsforge.attacks.compiler import compile_action
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        snap = _make_snapshot(actuators={"pump_speed": 37.5, "drain_valve_position": 50.0})
        writes = compile_action(
            AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                         mode="freeze", value=None, source=AttackSource.SCRIPTED),
            _scene(),
            current_snapshot=snap,
        )
        assert writes.get("pump_speed") == pytest.approx(37.5)

    def test_unknown_mode_falls_through_to_override(self):
        """Unrecognised mode string must fall through to the override else-branch."""
        from cpsforge.attacks.compiler import compile_action
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        writes = compile_action(
            AttackAction(attack_type=AttackType.ACTUATOR_OVERRIDE, target="pump_speed",
                         mode="custom_experimental_mode", value=42.0,
                         source=AttackSource.SCRIPTED),
            _scene(),
        )
        assert writes.get("pump_speed") == pytest.approx(42.0)

    # ------------------------------------------------------------------
    # ScriptedAttacker
    # ------------------------------------------------------------------

    def test_scripted_attacker_uses_built_in_default_when_no_file(self):
        """ScriptedAttacker without script_file falls back to _DEFAULT_SCRIPTS."""
        from cpsforge.attacks.scripted import ScriptedAttacker
        from cpsforge.core.config import AttackPolicyConfig
        cfg = AttackPolicyConfig(
            name="test_scripted", attacker_type="scripted",
            scene_name="tank_control", max_actions=10, script_file=None,
        )
        actions = ScriptedAttacker(cfg).generate_actions(_scene())
        assert len(actions) >= 1
        for action in actions:
            assert action.source.value == "scripted"

    def test_scripted_attacker_respects_max_actions(self):
        """max_actions=1 must return exactly one action even if the script is longer."""
        from cpsforge.attacks.scripted import ScriptedAttacker
        from cpsforge.core.config import AttackPolicyConfig
        cfg = AttackPolicyConfig(
            name="test_scripted", attacker_type="scripted",
            scene_name="tank_control", max_actions=1,
        )
        actions = ScriptedAttacker(cfg).generate_actions(_scene())
        assert len(actions) == 1

    def test_scripted_attacker_loads_from_policy_config(self):
        """Loading the real scripted_tank_control policy must produce >=1 actions."""
        from cpsforge.attacks.scripted import ScriptedAttacker
        cfg = _loader().load_attack_policy("scripted_tank_control")
        actions = ScriptedAttacker(cfg).generate_actions(_scene())
        assert len(actions) >= 1

    # ------------------------------------------------------------------
    # RandomAttacker
    # ------------------------------------------------------------------

    def test_random_attacker_same_seed_produces_same_sequence(self):
        """Two RandomAttacker instances with identical seeds must produce identical actions."""
        from cpsforge.attacks.random_attacker import RandomAttacker
        from cpsforge.core.config import AttackPolicyConfig
        scene = _scene()
        cfg1 = AttackPolicyConfig(name="r1", attacker_type="random",
                                  scene_name="tank_control", random_seed=42, max_actions=5)
        cfg2 = AttackPolicyConfig(name="r2", attacker_type="random",
                                  scene_name="tank_control", random_seed=42, max_actions=5)
        a1 = RandomAttacker(cfg1).generate_actions(scene)
        a2 = RandomAttacker(cfg2).generate_actions(scene)
        assert [a.target for a in a1] == [a.target for a in a2]
        assert [a.value for a in a1] == [a.value for a in a2]

    def test_random_attacker_values_within_tag_bounds(self):
        """Every sampled value must fall within its tag's [min_value, max_value]."""
        from cpsforge.attacks.random_attacker import RandomAttacker
        from cpsforge.core.config import AttackPolicyConfig
        scene = _scene()
        cfg = AttackPolicyConfig(name="rb", attacker_type="random",
                                 scene_name="tank_control", random_seed=7, max_actions=20)
        tags_by_name = {t.name: t for t in scene.get_all_tags()}
        for action in RandomAttacker(cfg).generate_actions(scene):
            tag = tags_by_name.get(action.target)
            if tag is None or action.value is None:
                continue
            if tag.min_value is not None:
                assert action.value >= tag.min_value - 1e-9, (
                    f"{action.target}={action.value} below min={tag.min_value}"
                )
            if tag.max_value is not None:
                assert action.value <= tag.max_value + 1e-9, (
                    f"{action.target}={action.value} above max={tag.max_value}"
                )

    def test_random_attacker_targets_within_attack_surface(self):
        """All randomly chosen targets must come from the scene's attack_surface."""
        from cpsforge.attacks.random_attacker import RandomAttacker
        from cpsforge.core.config import AttackPolicyConfig
        scene = _scene()
        surface = set(scene.get_attack_surface())
        cfg = AttackPolicyConfig(name="rs", attacker_type="random",
                                 scene_name="tank_control", random_seed=99, max_actions=20)
        for action in RandomAttacker(cfg).generate_actions(scene):
            assert action.target in surface, (
                f"Target '{action.target}' not in attack_surface {sorted(surface)}"
            )

    def test_random_attacker_obeys_allowed_attack_types(self):
        """All generated attack_types must be from the configured whitelist."""
        from cpsforge.attacks.random_attacker import RandomAttacker
        from cpsforge.core.config import AttackPolicyConfig
        from cpsforge.core.models import AttackType
        allowed = ["actuator_override", "setpoint_shift"]
        allowed_set = {AttackType(t) for t in allowed}
        cfg = AttackPolicyConfig(
            name="rt", attacker_type="random", scene_name="tank_control",
            random_seed=3, max_actions=15, attack_types=allowed,
        )
        for action in RandomAttacker(cfg).generate_actions(_scene()):
            assert action.attack_type in allowed_set, (
                f"attack_type {action.attack_type!r} not in allowed {allowed}"
            )


# ===========================================================================
# 4. PLC and experiment config parsing
# ===========================================================================


class TestPLCConfigParsing:
    """
    Validates that YAML configs parse correctly to the expected typed objects,
    that safety invariants hold across config files, and that Pydantic
    validators enforce business rules (e.g. dry_run forced when not live).
    """

    # ------------------------------------------------------------------
    # PLCConfig
    # ------------------------------------------------------------------

    def test_plc_default_host_is_192_168_0_1(self):
        assert _loader().load_plc().host == "192.168.0.1"

    def test_plc_live_writes_disabled_by_default(self):
        import os
        env_val = os.environ.get("CPSFORGE_LIVE_WRITES", "").strip().lower()
        plc = _loader().load_plc()
        if env_val in ("1", "true", "yes"):
            assert plc.live_writes_enabled is True
        else:
            assert plc.live_writes_enabled is False

    def test_plc_rack_and_slot_defaults(self):
        plc = _loader().load_plc()
        assert plc.rack == 0
        assert plc.slot == 1

    def test_plc_port_default_is_102(self):
        assert _loader().load_plc().port == 102

    # ------------------------------------------------------------------
    # ExperimentConfig validator
    # ------------------------------------------------------------------

    def test_dry_run_forced_true_when_live_writes_off(self):
        """Setting dry_run=False while live_writes_enabled=False must be overridden."""
        from cpsforge.core.config import ExperimentConfig
        cfg = ExperimentConfig(
            name="t", scene_config="scenes/tank_control.yaml",
            live_writes_enabled=False, dry_run=False,  # validator overrides this
        )
        assert cfg.dry_run is True

    def test_dry_run_can_be_false_when_live_writes_enabled(self):
        """When live_writes_enabled=True, dry_run=False is permitted."""
        from cpsforge.core.config import ExperimentConfig
        cfg = ExperimentConfig(
            name="t", scene_config="scenes/tank_control.yaml",
            live_writes_enabled=True, dry_run=False,
        )
        assert cfg.dry_run is False

    # ------------------------------------------------------------------
    # Scene profile integrity
    # ------------------------------------------------------------------

    def test_tank_control_has_eleven_tags(self):
        raw = _loader().load_scene_raw("tank_control")
        assert len(raw["tags"]) == 11

    def test_sr005_duration_cap_is_30000ms(self):
        """SR-005 must cap attack duration at exactly 30 000 ms."""
        from cpsforge.scenes.factory import load_scene
        rules = {r.rule_id: r for r in load_scene("tank_control", _loader()).profile.safety_rules}
        assert "SR-005" in rules
        assert rules["SR-005"].parameters["max_duration_ms"] == 30_000

    def test_sr006_cooldown_is_5000ms(self):
        """SR-006 must enforce a 5-second cooldown between repeated tag writes."""
        from cpsforge.scenes.factory import load_scene
        rules = {r.rule_id: r for r in load_scene("tank_control", _loader()).profile.safety_rules}
        assert "SR-006" in rules
        assert rules["SR-006"].parameters["cooldown_ms"] == 5_000

    def test_attack_surface_is_subset_of_writable_tags(self):
        """Every tag in attack_surface must also appear in writable_tags."""
        from cpsforge.scenes.factory import load_scene
        p = load_scene("tank_control", _loader()).profile
        writable = set(p.writable_tags)
        for name in p.attack_surface:
            assert name in writable, f"'{name}' in attack_surface but not writable_tags"

    def test_read_only_sensors_excluded_from_attack_surface(self):
        """No read-only (access=read) tag may appear in the attack surface."""
        from cpsforge.scenes.factory import load_scene
        from cpsforge.core.models import TagAccess
        p = load_scene("tank_control", _loader()).profile
        surface = set(p.attack_surface)
        for tag in p.tags:
            if tag.access == TagAccess.READ:
                assert tag.name not in surface, (
                    f"Read-only tag '{tag.name}' must not be in attack_surface"
                )

    def test_all_scene_rules_have_known_rule_type(self):
        """Every safety rule must specify a recognised rule_type."""
        from cpsforge.scenes.factory import load_scene
        known = {"range", "duration", "cooldown", "invariant",
                 "interlock", "mode_gate", "mutual_exclusion"}
        for rule in load_scene("tank_control", _loader()).profile.safety_rules:
            assert rule.rule_type in known, (
                f"Unknown rule_type '{rule.rule_type}' in {rule.rule_id}"
            )

    def test_all_scene_rules_have_integer_priority(self):
        from cpsforge.scenes.factory import load_scene
        for rule in load_scene("tank_control", _loader()).profile.safety_rules:
            assert isinstance(rule.priority, int)

    # ------------------------------------------------------------------
    # Attack policy config
    # ------------------------------------------------------------------

    def test_scripted_policy_max_actions_is_five(self):
        cfg = _loader().load_attack_policy("scripted_tank_control")
        assert cfg.max_actions == 5
        assert cfg.attacker_type == "scripted"

    def test_random_policy_attacker_type(self):
        cfg = _loader().load_attack_policy("random_tank_control")
        assert cfg.attacker_type == "random"

    # ------------------------------------------------------------------
    # Defender config
    # ------------------------------------------------------------------

    def test_threshold_defender_has_threshold_list(self):
        cfg = _loader().load_defender("threshold_tank_control")
        assert cfg.detector_type == "threshold"
        assert len(cfg.thresholds) > 0

    def test_threshold_defender_high_level_rule_present(self):
        """Must have a tank_level > 88.0 rule labelled 'high_level'."""
        cfg = _loader().load_defender("threshold_tank_control")
        matches = [r for r in cfg.thresholds
                   if r.get("tag") == "tank_level" and r.get("label") == "high_level"]
        assert len(matches) == 1
        assert matches[0]["value"] == pytest.approx(88.0)

    def test_invariant_defender_has_invariant_rules(self):
        cfg = _loader().load_defender("invariant_tank_control")
        assert cfg.detector_type == "invariant"
        assert len(cfg.invariant_rules) > 0

    def test_invariant_defender_includes_pump_overspeed_rule(self):
        """INV-001 should be present in the invariant config."""
        cfg = _loader().load_defender("invariant_tank_control")
        ids = [r.get("rule_id") for r in cfg.invariant_rules]
        assert "INV-001" in ids


# ===========================================================================
# 5. CLI smoke tests
# ===========================================================================


class TestCLISmokeTests:
    """
    CLI smoke tests using typer's CliRunner.

    All tests run in-process without connecting to a PLC.
    Functional tests use --dry-run and a tmp_path output directory.

    Known limitation: the CliRunner captures stdout/stderr in-process; tests
    that exercise the full orchestrator loop (run_attack, run_baseline) depend
    on all config files being loadable but never attempt real PLC writes.
    """

    def _invoke(self, *args: str, **kwargs) -> Any:
        return _invoke_cli(*args, **kwargs)

    # ------------------------------------------------------------------
    # Help pages (always safe, no PLC needed)
    # ------------------------------------------------------------------

    def test_root_help_exits_zero(self):
        result = self._invoke("--help")
        assert result.exit_code == 0
        assert "cpsforge" in result.output.lower()

    def test_plc_probe_help_exits_zero(self):
        result = self._invoke("plc", "probe", "--help")
        assert result.exit_code == 0

    def test_plc_read_help_exits_zero(self):
        result = self._invoke("plc", "read", "--help")
        assert result.exit_code == 0

    def test_run_attack_help_exits_zero(self):
        result = self._invoke("run", "attack", "--help")
        assert result.exit_code == 0
        # Help text must mention the attacker option
        assert "attacker" in result.output.lower()

    def test_run_baseline_help_exits_zero(self):
        result = self._invoke("run", "baseline", "--help")
        assert result.exit_code == 0

    def test_run_closed_loop_help_exits_zero(self):
        result = self._invoke("run", "closed-loop", "--help")
        assert result.exit_code == 0

    def test_scene_validate_help_exits_zero(self):
        result = self._invoke("scene", "validate", "--help")
        assert result.exit_code == 0

    def test_report_metrics_help_exits_zero(self):
        result = self._invoke("report", "metrics", "--help")
        assert result.exit_code == 0

    def test_report_summarize_help_exits_zero(self):
        result = self._invoke("report", "summarize", "--help")
        assert result.exit_code == 0

    # ------------------------------------------------------------------
    # scene validate — no PLC, just config parsing
    # ------------------------------------------------------------------

    def test_scene_validate_tank_control_exits_zero(self):
        """Validating the reference scene must succeed and print its name."""
        result = self._invoke("scene", "validate", "--scene", "tank_control")
        assert result.exit_code == 0, f"Unexpected exit:\n{result.output}"
        assert "tank_control" in result.output

    def test_scene_validate_nonexistent_scene_exits_nonzero(self):
        """A nonexistent scene name must exit with a non-zero code."""
        result = self._invoke("scene", "validate", "--scene", "does_not_exist_xyz")
        assert result.exit_code != 0

    # ------------------------------------------------------------------
    # run attack / run baseline — dry-run end-to-end
    # ------------------------------------------------------------------

    def test_run_attack_scripted_dry_run_completes(self, tmp_path):
        """Full scripted dry-run must complete (exit 0) within 3 steps."""
        result = self._invoke(
            "run", "attack",
            "--scene", "tank_control",
            "--attacker", "scripted",
            "--max-steps", "3",
            "--dry-run",
            "--output-dir", str(tmp_path),
        )
        assert result.exit_code == 0, f"CLI failed:\n{result.output}"
        # Confirm a run ID was reported
        assert "run id" in result.output.lower() or "complete" in result.output.lower()

    def test_run_baseline_dry_run_completes(self, tmp_path):
        """Baseline dry-run must complete without error."""
        result = self._invoke(
            "run", "baseline",
            "--scene", "tank_control",
            "--max-steps", "3",
            "--dry-run",
            "--output-dir", str(tmp_path),
        )
        assert result.exit_code == 0, f"CLI failed:\n{result.output}"

    def test_run_attack_without_env_var_stays_safe(self, tmp_path):
        """
        With no CPSFORGE_LIVE_WRITES env var and --dry-run flag, no SafetyError
        should be raised — the run must complete cleanly.
        """
        import os
        saved = os.environ.pop("CPSFORGE_LIVE_WRITES", None)
        try:
            result = self._invoke(
                "run", "attack",
                "--scene", "tank_control",
                "--attacker", "scripted",
                "--max-steps", "3",
                "--dry-run",
                "--output-dir", str(tmp_path),
            )
            assert result.exit_code == 0, f"Unexpected error:\n{result.output}"
        finally:
            if saved is not None:
                os.environ["CPSFORGE_LIVE_WRITES"] = saved

    def test_run_attack_creates_trace_artifact(self, tmp_path):
        """After a dry-run attack, a trace.parquet must exist under the output dir."""
        self._invoke(
            "run", "attack",
            "--scene", "tank_control",
            "--attacker", "scripted",
            "--max-steps", "5",
            "--dry-run",
            "--output-dir", str(tmp_path),
        )
        # Walk all subdirectories of tmp_path looking for trace.parquet
        traces = list(tmp_path.rglob("trace.parquet"))
        assert len(traces) >= 1, (
            f"No trace.parquet found under {tmp_path}; "
            f"files present: {list(tmp_path.rglob('*'))}"
        )
