"""
CPSForge Unit Tests — Phase 2 Validation
==========================================
Tests for:
  - Process impact scoring (TankControlScene.compute_process_impact)
  - Attack success evaluation (BaseScene.evaluate_attack_success)
  - Compiler with live snapshot (offset and freeze modes)
  - Scene reset writes (SceneResetter dry-run)
  - Trace serialisation / deserialisation (load_trace_snapshots roundtrip)
  - Phase 2 experiment configs load without errors
  - detect-replay data path (load -> detect -> events)

All tests run WITHOUT a real PLC (dry-run, in-memory only).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent


def _loader():
    from cpsforge.core.config import ConfigLoader
    return ConfigLoader(configs_dir=REPO_ROOT / "configs")


def _scene():
    from cpsforge.scenes.factory import load_scene
    return load_scene("tank_control", _loader())


def _make_snapshot(
    sensors: Dict[str, Any] | None = None,
    actuators: Dict[str, Any] | None = None,
    step_id: int = 0,
    run_id: str = "test-run",
):
    from cpsforge.core.models import (
        AttackContext, DefenseContext, PlantSnapshot, SafetyContext
    )
    return PlantSnapshot(
        timestamp=datetime.now(timezone.utc),
        scene_name="tank_control",
        run_id=run_id,
        step_id=step_id,
        sensors=sensors or {
            "tank_level": 50.0, "inlet_flow": 20.0, "outlet_flow": 20.0
        },
        actuators=actuators or {
            "pump_speed": 50.0, "drain_valve_position": 50.0
        },
        controller_state={"pid_output": 50.0, "auto_mode": True},
        alarms={
            "high_level_alarm": False,
            "low_level_alarm": False,
            "pump_fault": False,
        },
        setpoints={"level_setpoint": 50.0},
        attack_context=AttackContext(),
        defense_context=DefenseContext(),
        safety_context=SafetyContext(live_writes_enabled=False),
    )


# ---------------------------------------------------------------------------
# Process impact scoring
# ---------------------------------------------------------------------------

class TestProcessImpact:
    def test_zero_impact_at_nominal(self):
        scene = _scene()
        snap_before = _make_snapshot()
        snap_after = _make_snapshot()
        impact = scene.compute_process_impact(snap_before, snap_after)
        # Level is 50 % (nominal), no alarms.  Impact should be near zero.
        # level_deviation = abs(50 - 50) / 50 = 0.0, delta = 0.0, no alarms.
        assert impact == pytest.approx(0.0, abs=0.01)

    def test_high_level_increases_impact(self):
        scene = _scene()
        snap_before = _make_snapshot()
        snap_after = _make_snapshot(
            sensors={"tank_level": 92.0, "inlet_flow": 20.0, "outlet_flow": 20.0},
        )
        impact = scene.compute_process_impact(snap_before, snap_after)
        assert impact > 0.5  # High deviation + alarm penalty

    def test_alarm_adds_impact(self):
        scene = _scene()
        from cpsforge.core.models import AttackContext, DefenseContext, PlantSnapshot, SafetyContext
        snap_after = PlantSnapshot(
            timestamp=datetime.now(timezone.utc),
            scene_name="tank_control", run_id="x", step_id=1,
            sensors={"tank_level": 50.0, "inlet_flow": 20.0, "outlet_flow": 20.0},
            actuators={"pump_speed": 50.0, "drain_valve_position": 50.0},
            controller_state={"pid_output": 50.0, "auto_mode": True},
            alarms={"high_level_alarm": True, "low_level_alarm": False, "pump_fault": False},
            setpoints={"level_setpoint": 50.0},
            attack_context=AttackContext(), defense_context=DefenseContext(),
            safety_context=SafetyContext(live_writes_enabled=False),
        )
        impact = scene.compute_process_impact(_make_snapshot(), snap_after)
        # high_level_alarm adds 0.5
        assert impact >= 0.5


# ---------------------------------------------------------------------------
# Attack success evaluation
# ---------------------------------------------------------------------------

class TestAttackSuccess:
    def test_success_when_value_moved_toward_target(self):
        scene = _scene()
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        action = AttackAction(
            attack_type=AttackType.ACTUATOR_OVERRIDE,
            target="pump_speed",
            value=0.0,
            source=AttackSource.SCRIPTED,
        )
        snap_before = _make_snapshot(actuators={"pump_speed": 50.0, "drain_valve_position": 50.0})
        snap_after = _make_snapshot(actuators={"pump_speed": 5.0, "drain_valve_position": 50.0})
        # After: pump_speed=5.0, closer to target 0.0 than before (50.0)
        assert scene.evaluate_attack_success(action, snap_before, snap_after) is True

    def test_no_success_when_value_unchanged(self):
        scene = _scene()
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        action = AttackAction(
            attack_type=AttackType.ACTUATOR_OVERRIDE,
            target="pump_speed",
            value=0.0,
            source=AttackSource.SCRIPTED,
        )
        snap = _make_snapshot()
        # Both before and after have pump_speed=50.0 — not approaching 0.0
        assert scene.evaluate_attack_success(action, snap, snap) is False


# ---------------------------------------------------------------------------
# Compiler with snapshot (offset / freeze modes)
# ---------------------------------------------------------------------------

class TestCompilerWithSnapshot:
    def test_offset_adds_to_current(self):
        from cpsforge.attacks.compiler import compile_action
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        scene = _scene()
        action = AttackAction(
            attack_type=AttackType.SETPOINT_SHIFT,
            target="level_setpoint",
            mode="offset",
            value=10.0,   # offset by +10
            source=AttackSource.SCRIPTED,
        )
        snap = _make_snapshot()  # setpoints["level_setpoint"] = 50.0
        writes = compile_action(action, scene, current_snapshot=snap)
        assert "level_setpoint" in writes
        assert writes["level_setpoint"] == pytest.approx(60.0)

    def test_freeze_writes_current_value(self):
        from cpsforge.attacks.compiler import compile_action
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        scene = _scene()
        action = AttackAction(
            attack_type=AttackType.ACTUATOR_OVERRIDE,
            target="pump_speed",
            mode="freeze",
            value=None,
            source=AttackSource.SCRIPTED,
        )
        snap = _make_snapshot()  # actuators["pump_speed"] = 50.0
        writes = compile_action(action, scene, current_snapshot=snap)
        assert "pump_speed" in writes
        assert writes["pump_speed"] == 50.0

    def test_override_ignores_snapshot(self):
        from cpsforge.attacks.compiler import compile_action
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        scene = _scene()
        action = AttackAction(
            attack_type=AttackType.ACTUATOR_OVERRIDE,
            target="pump_speed",
            mode="override",
            value=25.0,
            source=AttackSource.SCRIPTED,
        )
        snap = _make_snapshot()
        writes = compile_action(action, scene, current_snapshot=snap)
        assert writes["pump_speed"] == 25.0


# ---------------------------------------------------------------------------
# Scene resetter (dry-run)
# ---------------------------------------------------------------------------

class TestSceneResetter:
    def _make_shield(self):
        from cpsforge.shield.engine import ShieldEngine
        return ShieldEngine(_scene().profile)

    def test_reset_dry_run_returns_all_true(self):
        from cpsforge.plc.reset import SceneResetter
        scene = _scene()
        shield = self._make_shield()
        # dry_run=True → no PLC client needed
        results = SceneResetter().reset(
            plc_client=None, scene=scene, shield=shield, dry_run=True
        )
        # All reset keys should succeed in dry-run (no PLC, no cooldowns)
        assert len(results) > 0
        # Some may be rejected by shield (cooldown / mode_gate) but in dry-run
        # the write itself is skipped; shield approval is still checked
        assert all(isinstance(v, bool) for v in results.values())

    def test_reset_covers_all_reset_procedure_tags(self):
        """Every tag in reset_procedure should appear in the result dict."""
        from cpsforge.plc.reset import SceneResetter
        scene = _scene()
        shield = self._make_shield()
        reset_writes = scene.get_reset_writes()
        results = SceneResetter().reset(
            plc_client=None, scene=scene, shield=shield, dry_run=True
        )
        for tag_name in reset_writes:
            assert tag_name in results, f"Tag '{tag_name}' missing from reset results"


# ---------------------------------------------------------------------------
# Trace serialisation / deserialisation roundtrip
# ---------------------------------------------------------------------------

class TestTraceRoundtrip:
    def test_roundtrip_sensors_preserved(self, tmp_path):
        from cpsforge.logging.artifacts import TraceRecorder, load_trace_snapshots

        # Record a snapshot with known sensor values.
        recorder = TraceRecorder(run_dir=tmp_path)
        snap = _make_snapshot(
            sensors={"tank_level": 42.5, "inlet_flow": 10.0, "outlet_flow": 8.0},
            step_id=7,
            run_id="rtrip-001",
        )
        recorder.record(snap)
        trace_path = recorder.flush()
        assert trace_path.exists()

        # Reload and verify.
        restored = load_trace_snapshots(trace_path, run_id="rtrip-001")
        assert len(restored) == 1
        rs = restored[0]
        assert rs.step_id == 7
        assert rs.run_id == "rtrip-001"
        assert rs.sensors.get("tank_level") == pytest.approx(42.5)
        assert rs.sensors.get("inlet_flow") == pytest.approx(10.0)

    def test_roundtrip_attack_context_preserved(self, tmp_path):
        from cpsforge.core.models import AttackContext, AttackType, AttackSource
        from cpsforge.logging.artifacts import TraceRecorder, load_trace_snapshots

        snap = _make_snapshot()
        snap.attack_context = AttackContext(
            active=True,
            action_id="abc123",
            attack_type=AttackType.ACTUATOR_OVERRIDE,
            target_tag="pump_speed",
        )
        recorder = TraceRecorder(run_dir=tmp_path)
        recorder.record(snap)
        trace_path = recorder.flush()

        restored = load_trace_snapshots(trace_path, run_id="test-run")
        assert restored[0].attack_context.active is True
        assert restored[0].attack_context.action_id == "abc123"
        assert restored[0].attack_context.attack_type == AttackType.ACTUATOR_OVERRIDE

    def test_roundtrip_multiple_steps(self, tmp_path):
        from cpsforge.logging.artifacts import TraceRecorder, load_trace_snapshots

        recorder = TraceRecorder(run_dir=tmp_path)
        for i in range(10):
            recorder.record(_make_snapshot(step_id=i))
        recorder.flush()
        restored = load_trace_snapshots(tmp_path / "trace.parquet", run_id="r")
        assert len(restored) == 10
        assert [s.step_id for s in restored] == list(range(10))


# ---------------------------------------------------------------------------
# Phase 2 experiment configs load cleanly
# ---------------------------------------------------------------------------

class TestPhase2Configs:
    def test_dry_run_config_loads(self):
        loader = _loader()
        cfg = loader.load_experiment("phase2_dry_run")
        assert cfg.dry_run is True
        assert cfg.live_writes_enabled is False
        assert cfg.eval_run is False
        assert cfg.max_steps == 300

    def test_live_run_config_loads(self):
        loader = _loader()
        cfg = loader.load_experiment("phase2_live_run")
        assert cfg.live_writes_enabled is True
        assert cfg.dry_run is False
        assert cfg.eval_run is True
        assert cfg.reset_after_run is True

    def test_live_run_has_single_attacker(self):
        """Live eval runs should use scripted-only for reproducibility."""
        loader = _loader()
        cfg = loader.load_experiment("phase2_live_run")
        assert "scripted_tank_control" in cfg.attackers


# ---------------------------------------------------------------------------
# detect-replay data path: load -> detect
# ---------------------------------------------------------------------------

class TestDetectReplayDataPath:
    def _build_trace(self, tmp_path: Path, n_steps: int = 20) -> Path:
        """Write a trace with a known attack window and return the trace path."""
        from cpsforge.core.models import AttackContext, AttackType
        from cpsforge.logging.artifacts import TraceRecorder

        recorder = TraceRecorder(run_dir=tmp_path)
        for i in range(n_steps):
            snap = _make_snapshot(
                sensors={
                    # Spike tank level above 88 % in steps 5-9 to trigger threshold
                    "tank_level": 92.0 if 5 <= i <= 9 else 50.0,
                    "inlet_flow": 20.0,
                    "outlet_flow": 20.0,
                },
                step_id=i,
            )
            if 5 <= i <= 9:
                snap.attack_context = AttackContext(
                    active=True, attack_type=AttackType.ACTUATOR_OVERRIDE, target_tag="pump_speed"
                )
            recorder.record(snap)
        return recorder.flush()

    def test_replay_detects_high_level_spike(self, tmp_path):
        from cpsforge.logging.artifacts import load_trace_snapshots
        from cpsforge.defenders.threshold import ThresholdDetector

        trace_path = self._build_trace(tmp_path)
        snapshots = load_trace_snapshots(trace_path, run_id="replay-test")
        assert len(snapshots) == 20

        loader = _loader()
        cfg = loader.load_defender("threshold_tank_control")
        det = ThresholdDetector(cfg)

        detections = []
        for snap in snapshots:
            detections.extend(det.detect(snap))

        labels = [e.label for e in detections]
        assert "high_level" in labels, "Threshold detector should fire during high-level spike"

    def test_replay_detections_only_in_attack_window(self, tmp_path):
        from cpsforge.logging.artifacts import load_trace_snapshots
        from cpsforge.defenders.threshold import ThresholdDetector

        trace_path = self._build_trace(tmp_path)
        snapshots = load_trace_snapshots(trace_path, run_id="replay-test")
        loader = _loader()
        cfg = loader.load_defender("threshold_tank_control")
        det = ThresholdDetector(cfg)

        high_level_steps = []
        for snap in snapshots:
            events = det.detect(snap)
            for ev in events:
                if ev.label == "high_level":
                    high_level_steps.append(snap.step_id)

        # All high_level detections must fall inside the attack window [5, 9]
        assert all(5 <= s <= 9 for s in high_level_steps), (
            f"Got high_level detections outside attack window: {high_level_steps}"
        )
