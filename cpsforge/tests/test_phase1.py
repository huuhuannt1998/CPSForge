"""
CPSForge Unit Tests -- Phase 1 Validation
==========================================
These tests validate the core schema, config loader, shield engine,
attacker compilation, and artifact utilities WITHOUT requiring a live PLC.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent.parent  # cpsforge/tests/ -> repo root


def _loader():
    from cpsforge.core.config import ConfigLoader
    return ConfigLoader(configs_dir=REPO_ROOT / "configs")


# ---------------------------------------------------------------------------
# Schema / model tests
# ---------------------------------------------------------------------------


class TestModels:
    def test_tag_definition_roundtrip(self):
        from cpsforge.core.models import DataType, TagAccess, TagCategory, TagDefinition
        tag = TagDefinition(
            name="test_tag",
            address="DB1,REAL0",
            data_type=DataType.REAL,
            access=TagAccess.READ_WRITE,
            unit="%",
            min_value=0.0,
            max_value=100.0,
            description="A test tag",
            category=TagCategory.SENSOR,
            scene_name="test_scene",
        )
        d = tag.model_dump()
        tag2 = TagDefinition(**d)
        assert tag2.name == "test_tag"
        assert tag2.category == TagCategory.SENSOR

    def test_attack_action_defaults(self):
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        action = AttackAction(
            attack_type=AttackType.ACTUATOR_OVERRIDE,
            target="pump_speed",
            value=0.0,
            source=AttackSource.SCRIPTED,
        )
        assert action.action_id is not None
        assert action.approved_by_shield is None  # not yet evaluated by shield

    def test_shield_decision_model(self):
        from cpsforge.core.models import ShieldDecision
        sd = ShieldDecision(action_id="test-id", approved=True, reasons=[], violated_rules=[])
        assert sd.approved is True
        assert sd.rollback_plan is None

    def test_eval_metrics_defaults(self):
        from cpsforge.core.models import EvalMetrics
        m = EvalMetrics(
            run_id="test-run",
            scene_name="tank_control",
            attacker_name="scripted",
            detector_names=["threshold"],
        )
        assert m.eval_run is True  # EvalMetrics defaults to True (official results)
        assert m.detector_f1 == 0.0


# ---------------------------------------------------------------------------
# Config loader tests
# ---------------------------------------------------------------------------


class TestConfigLoader:
    def test_load_plc_config(self):
        loader = _loader()
        plc = loader.load_plc()
        assert plc.host == "192.168.0.1"
        # live_writes_enabled depends on CPSFORGE_LIVE_WRITES env var;
        # plc.yaml defaults to false but .env may override.
        import os
        env_val = os.environ.get("CPSFORGE_LIVE_WRITES", "").strip().lower()
        if env_val in ("1", "true", "yes"):
            assert plc.live_writes_enabled is True
        else:
            assert plc.live_writes_enabled is False

    def test_load_scene_existing(self):
        loader = _loader()
        data = loader.load_scene_raw("tank_control")
        assert "tags" in data
        assert data["scene_name"] == "tank_control"

    def test_load_scene_missing_raises(self):
        loader = _loader()
        with pytest.raises(FileNotFoundError):
            loader.load_scene_raw("nonexistent_scene")

    def test_load_defender_config(self):
        loader = _loader()
        cfg = loader.load_defender("threshold_tank_control")
        assert cfg.detector_type == "threshold"
        assert len(cfg.thresholds) > 0


# ---------------------------------------------------------------------------
# Address parser tests
# ---------------------------------------------------------------------------


class TestAddressParser:
    def test_parse_db_real(self):
        from cpsforge.plc.address import parse_address
        addr = parse_address("DB1,REAL0")
        assert addr.db_number == 1
        assert addr.start == 0

    def test_parse_db_word(self):
        from cpsforge.plc.address import parse_address
        addr = parse_address("DB2,WORD4")
        assert addr.db_number == 2
        assert addr.start == 4

    def test_parse_merker_word(self):
        from cpsforge.plc.address import parse_address
        addr = parse_address("MW10")
        assert addr.start == 10

    def test_invalid_address_raises(self):
        from cpsforge.plc.address import parse_address
        with pytest.raises(ValueError):
            parse_address("XX9999")


# ---------------------------------------------------------------------------
# Shield engine tests
# ---------------------------------------------------------------------------


class TestShieldEngine:
    def _make_shield(self):
        from cpsforge.core.config import ConfigLoader
        from cpsforge.scenes.factory import load_scene
        from cpsforge.shield.engine import ShieldEngine
        loader = _loader()
        scene = load_scene("tank_control", loader)
        return ShieldEngine(scene.profile), scene

    def _make_snapshot(self, sensors: dict[str, Any] | None = None):
        from datetime import datetime, timezone
        from cpsforge.core.models import (
            AttackContext, DefenseContext, PlantSnapshot, SafetyContext
        )
        return PlantSnapshot(
            timestamp=datetime.now(timezone.utc),
            scene_name="tank_control",
            run_id="test-run",
            step_id=0,
            sensors=sensors or {"tank_level": 50.0, "inlet_flow": 20.0, "outlet_flow": 20.0},
            actuators={"pump_speed": 50.0, "drain_valve_position": 50.0},
            controller_state={"pid_output": 50.0, "auto_mode": True},
            alarms={"high_level_alarm": False, "low_level_alarm": False, "pump_fault": False},
            setpoints={"level_setpoint": 50.0},
            attack_context=AttackContext(),
            defense_context=DefenseContext(),
            safety_context=SafetyContext(live_writes_enabled=False),
        )

    def test_approve_valid_action(self):
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        shield, _ = self._make_shield()
        action = AttackAction(
            attack_type=AttackType.ACTUATOR_OVERRIDE,
            target="pump_speed",
            value=80.0,
            source=AttackSource.SCRIPTED,
        )
        snap = self._make_snapshot()
        decision = shield.evaluate(action, snap)
        assert decision.approved is True

    def test_reject_out_of_range(self):
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        shield, _ = self._make_shield()
        action = AttackAction(
            attack_type=AttackType.ACTUATOR_OVERRIDE,
            target="pump_speed",
            value=999.0,  # way above max_value=100
            source=AttackSource.SCRIPTED,
        )
        snap = self._make_snapshot()
        decision = shield.evaluate(action, snap)
        assert decision.approved is False
        # Shield uses SR-002 for "value exceeds maximum" range violations
        assert any("SR-002" in r or "exceed" in r.lower() or "SR-001" in r for r in decision.reasons)

    def test_reject_non_whitelisted_tag(self):
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        shield, _ = self._make_shield()
        action = AttackAction(
            attack_type=AttackType.ACTUATOR_OVERRIDE,
            target="tank_level",  # read-only sensor, not in writable_tags
            value=99.0,
            source=AttackSource.SCRIPTED,
        )
        snap = self._make_snapshot()
        decision = shield.evaluate(action, snap)
        assert decision.approved is False


# ---------------------------------------------------------------------------
# Attack compiler tests
# ---------------------------------------------------------------------------


class TestAttackCompiler:
    def _make_scene(self):
        from cpsforge.scenes.factory import load_scene
        return load_scene("tank_control", _loader())

    def test_compile_override(self):
        from cpsforge.attacks.compiler import compile_action
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        scene = self._make_scene()
        action = AttackAction(
            attack_type=AttackType.ACTUATOR_OVERRIDE,
            target="pump_speed",
            value=0.0,
            mode="override",
            source=AttackSource.SCRIPTED,
        )
        writes = compile_action(action, scene)
        assert "pump_speed" in writes
        assert writes["pump_speed"] == 0.0

    def test_compile_offset(self):
        from cpsforge.attacks.compiler import compile_action
        from cpsforge.core.models import AttackAction, AttackSource, AttackType
        scene = self._make_scene()
        action = AttackAction(
            attack_type=AttackType.SETPOINT_SHIFT,
            target="level_setpoint",
            value=10.0,
            mode="offset",
            source=AttackSource.SCRIPTED,
        )
        writes = compile_action(action, scene)
        assert "level_setpoint" in writes


# ---------------------------------------------------------------------------
# Artifact utilities tests
# ---------------------------------------------------------------------------


class TestArtifacts:
    def test_make_run_id_format(self):
        from cpsforge.logging.artifacts import make_run_id
        run_id = make_run_id()
        # Format: 20YYMMDDTHHMMSSZ_<8hex>
        parts = run_id.split("_")
        assert len(parts) == 2
        assert len(parts[1]) == 8

    def test_trace_recorder_flush(self, tmp_path):
        from datetime import datetime, timezone
        from cpsforge.core.models import (
            AttackContext, DefenseContext, PlantSnapshot, SafetyContext
        )
        from cpsforge.logging.artifacts import TraceRecorder

        recorder = TraceRecorder(run_dir=tmp_path)
        snap = PlantSnapshot(
            timestamp=datetime.now(timezone.utc),
            scene_name="tank_control",
            run_id="test-run",
            step_id=0,
            sensors={"tank_level": 50.0},
            actuators={},
            controller_state={},
            alarms={},
            setpoints={},
            attack_context=AttackContext(),
            defense_context=DefenseContext(),
            safety_context=SafetyContext(live_writes_enabled=False),
        )
        recorder.record(snap)
        out = recorder.flush()
        assert out.exists()
        import pandas as pd
        df = pd.read_parquet(out)
        assert len(df) == 1
        assert "run_id" in df.columns


# ---------------------------------------------------------------------------
# Detector tests
# ---------------------------------------------------------------------------


class TestDetectors:
    def _make_snapshot(self, tank_level=50.0):
        from datetime import datetime, timezone
        from cpsforge.core.models import (
            AttackContext, DefenseContext, PlantSnapshot, SafetyContext
        )
        return PlantSnapshot(
            timestamp=datetime.now(timezone.utc),
            scene_name="tank_control",
            run_id="test-run",
            step_id=1,
            sensors={"tank_level": tank_level, "inlet_flow": 20.0, "outlet_flow": 20.0},
            actuators={"pump_speed": 50.0, "drain_valve_position": 50.0},
            controller_state={"pid_output": 50.0, "auto_mode": True},
            alarms={"high_level_alarm": tank_level > 90.0, "low_level_alarm": tank_level < 10.0,
                    "pump_fault": False},
            setpoints={"level_setpoint": 50.0},
            attack_context=AttackContext(),
            defense_context=DefenseContext(),
            safety_context=SafetyContext(live_writes_enabled=False),
        )

    def test_threshold_no_alarm_normal(self):
        loader = _loader()
        cfg = loader.load_defender("threshold_tank_control")
        from cpsforge.defenders.threshold import ThresholdDetector
        det = ThresholdDetector(cfg)
        snap = self._make_snapshot(tank_level=50.0)
        events = det.detect(snap)
        assert len(events) == 0

    def test_threshold_fires_high_level(self):
        loader = _loader()
        cfg = loader.load_defender("threshold_tank_control")
        from cpsforge.defenders.threshold import ThresholdDetector
        det = ThresholdDetector(cfg)
        snap = self._make_snapshot(tank_level=92.0)  # > 88.0 threshold
        events = det.detect(snap)
        labels = [e.label for e in events]
        assert "high_level" in labels

    def test_invariant_no_alarm_normal(self):
        loader = _loader()
        cfg = loader.load_defender("invariant_tank_control")
        from cpsforge.defenders.invariant import InvariantDetector
        det = InvariantDetector(cfg)
        snap = self._make_snapshot(tank_level=50.0)
        events = det.detect(snap)
        assert len(events) == 0
