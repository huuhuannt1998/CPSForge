"""CPSForge Unit Tests -- Phase 7 Agent Primitives + Phase 8 Comprehensive Tests"""

from __future__ import annotations

import json
import pickle
import tempfile
from multiprocessing import Queue
from pathlib import Path
from queue import Empty
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

from cpsforge.agents.event_bus import EventBus
from cpsforge.agents.messages import (
    AgentEvent,
    AgentEventType,
    RequestKind,
    WriteRequest,
    WriteResult,
)
from cpsforge.core.config import AgentConfig, AgentRole, ConfigLoader
from cpsforge.core.models import (
    AgentEvalMetrics,
    AttackAction,
    AttackContext,
    AttackSource,
    AttackType,
    DefenseContext,
    PlantSnapshot,
    SafetyContext,
    SceneProfile,
    ShieldDecision,
    TagCategory,
    TagDefinition,
    DataType,
    TagAccess,
)

REPO_ROOT = Path(__file__).parent.parent.parent


def _loader() -> ConfigLoader:
    return ConfigLoader(configs_dir=REPO_ROOT / "configs")


def _make_snapshot(**overrides: Any) -> PlantSnapshot:
    defaults = dict(
        scene_name="level_control",
        run_id="test-run",
        step_id=0,
        sensors={"level_meter": 5.0},
        actuators={"fill_valve": 0.5, "discharge_valve": 0.0},
        setpoints={"setpoint_in": 5.0},
        attack_context=AttackContext(),
        defense_context=DefenseContext(),
        safety_context=SafetyContext(),
    )
    defaults.update(overrides)
    return PlantSnapshot(**defaults)


def _make_scene_profile() -> SceneProfile:
    return SceneProfile(
        scene_name="level_control",
        description="Test level control",
        tags=[
            TagDefinition(
                name="fill_valve", address="DB21,REAL24", data_type=DataType.REAL,
                access=TagAccess.READ_WRITE, category=TagCategory.ACTUATOR,
                scene_name="level_control", min_value=0.0, max_value=10.0,
            ),
            TagDefinition(
                name="level_meter", address="DB21,REAL16", data_type=DataType.REAL,
                access=TagAccess.READ, category=TagCategory.SENSOR,
                scene_name="level_control", min_value=0.0, max_value=10.0,
            ),
            TagDefinition(
                name="setpoint_in", address="DB21,REAL4", data_type=DataType.REAL,
                access=TagAccess.READ_WRITE, category=TagCategory.SETPOINT,
                scene_name="level_control", min_value=0.0, max_value=10.0,
            ),
        ],
        writable_tags=["fill_valve", "setpoint_in"],
        attack_surface=["fill_valve", "setpoint_in"],
        safety_rules=[],
        sampling_interval_ms=500,
    )


# ---------------------------------------------------------------------------
# Phase 7: Original agent primitive tests
# ---------------------------------------------------------------------------


class TestAgentConfig:
    def test_load_attacker_config(self) -> None:
        loader = _loader()
        cfg = loader.load_agent("attacker_agent")
        assert cfg.role == AgentRole.ATTACKER
        assert cfg.scene_name == "level_control"
        assert cfg.max_history > 0

    def test_load_defender_config(self) -> None:
        loader = _loader()
        cfg = loader.load_agent("defender_agent")
        assert cfg.role == AgentRole.DEFENDER
        assert cfg.enabled is True

    def test_agent_config_validation(self) -> None:
        cfg = AgentConfig(
            name="test", role=AgentRole.ATTACKER,
            scene_name="level_control", max_history=50,
        )
        assert cfg.write_timeout_s == 10.0


class TestIPCMessages:
    def test_write_request_pickle_roundtrip(self) -> None:
        action = AttackAction(
            attack_type=AttackType.ACTUATOR_OVERRIDE,
            target="pump_command", mode="override",
            value=1.0, source=AttackSource.LLM,
        )
        req = WriteRequest(agent_name="a", kind=RequestKind.ATTACK, action=action)
        restored = pickle.loads(pickle.dumps(req))
        assert isinstance(restored, WriteRequest)
        assert restored.agent_name == "a"
        assert restored.action.target == "pump_command"

    def test_write_result_pickle_roundtrip(self) -> None:
        result = WriteResult(
            request_id="req-1", approved=True, executed=True,
            status="executed", reason="",
        )
        restored = pickle.loads(pickle.dumps(result))
        assert restored.approved is True
        assert restored.executed is True

    def test_agent_event_pickle_roundtrip(self) -> None:
        ev = AgentEvent(
            event_type=AgentEventType.ATTACK_SUBMITTED,
            agent_name="attacker", run_id="r1",
            payload={"target": "fill_valve"},
        )
        restored = pickle.loads(pickle.dumps(ev))
        assert restored.event_type == AgentEventType.ATTACK_SUBMITTED

    def test_request_kind_values(self) -> None:
        assert RequestKind.ATTACK.value == "attack"
        assert RequestKind.CORRECTIVE.value == "corrective"


class TestEventBus:
    def test_collect_drains_queue(self) -> None:
        q: Queue = Queue()
        bus = EventBus(q)
        bus.publish(AgentEvent(
            event_type=AgentEventType.AGENT_STARTED,
            agent_name="d", run_id="r",
        ))
        bus.publish(AgentEvent(
            event_type=AgentEventType.DETECTION_EMITTED,
            agent_name="d", run_id="r",
        ))
        events = bus.collect()
        assert len(events) == 2
        assert events[0].event_type == AgentEventType.AGENT_STARTED
        assert bus.collect() == []

    def test_collect_respects_max_items(self) -> None:
        q: Queue = Queue()
        bus = EventBus(q)
        for i in range(5):
            bus.publish(AgentEvent(
                event_type=AgentEventType.AGENT_STARTED,
                agent_name="a", run_id="r",
            ))
        events = bus.collect(max_items=3)
        assert len(events) == 3
        remaining = bus.collect()
        assert len(remaining) == 2

    def test_collect_ignores_non_events(self) -> None:
        q: Queue = Queue()
        bus = EventBus(q)
        q.put("not-an-event")
        q.put(42)
        bus.publish(AgentEvent(
            event_type=AgentEventType.AGENT_STARTED,
            agent_name="a", run_id="r",
        ))
        events = bus.collect()
        assert len(events) == 1


# ---------------------------------------------------------------------------
# Phase 8: PromptBuilder agent methods
# ---------------------------------------------------------------------------


class TestPromptBuilderAgentMethods:
    def test_attacker_agent_system_prompt_loads_template(self) -> None:
        from cpsforge.llm.prompt_builder import PromptBuilder

        pb = PromptBuilder(template_version="v1")
        profile = _make_scene_profile()

        class SceneObj:
            pass

        s = SceneObj()
        s.profile = profile  # type: ignore[attr-defined]
        prompt = pb.build_attacker_agent_system_prompt(scene=s)
        assert "level_control" in prompt
        assert "fill_valve" in prompt

    def test_attacker_agent_user_prompt(self) -> None:
        from cpsforge.llm.prompt_builder import PromptBuilder

        pb = PromptBuilder(template_version="v1")
        snap = _make_snapshot(step_id=5)
        prompt = pb.build_attacker_agent_user_prompt(
            snapshot=snap,
            prior_actions=[{"action": "test"}],
            attacker_objective="maximize impact",
        )
        assert "5" in prompt  # step_id
        assert "maximize impact" in prompt

    def test_defender_agent_system_prompt_loads_template(self) -> None:
        from cpsforge.llm.prompt_builder import PromptBuilder

        pb = PromptBuilder(template_version="v1")
        profile = _make_scene_profile()

        class SceneObj:
            pass

        s = SceneObj()
        s.profile = profile  # type: ignore[attr-defined]
        prompt = pb.build_defender_agent_system_prompt(scene=s)
        assert "defender" in prompt.lower()
        assert "level_control" in prompt

    def test_defender_agent_user_prompt(self) -> None:
        from cpsforge.llm.prompt_builder import PromptBuilder

        pb = PromptBuilder(template_version="v1")
        snap = _make_snapshot(step_id=3)
        prompt = pb.build_defender_agent_user_prompt(
            snapshot=snap,
            detector_alerts=["high_level", "pump_overspeed"],
            prior_detections=[{"label": "high_level"}],
        )
        assert "high_level" in prompt
        assert "pump_overspeed" in prompt


# ---------------------------------------------------------------------------
# Phase 8: Shield corrective evaluation
# ---------------------------------------------------------------------------


class TestShieldCorrective:
    def test_evaluate_corrective_skips_cooldown(self) -> None:
        from cpsforge.core.models import SafetyRule
        from cpsforge.shield.engine import ShieldEngine

        profile = _make_scene_profile()
        profile.safety_rules = [
            SafetyRule(
                rule_id="cooldown_fill",
                description="cooldown",
                rule_type="cooldown",
                tags=["fill_valve"],
                parameters={"cooldown_ms": 60000},
                priority=10,
            ),
            SafetyRule(
                rule_id="range_fill",
                description="range",
                rule_type="range",
                tags=["fill_valve"],
                parameters={"min": 0.0, "max": 10.0},
                priority=5,
            ),
        ]
        shield = ShieldEngine(profile)

        action = AttackAction(
            attack_type=AttackType.ACTUATOR_OVERRIDE,
            target="fill_valve", value=5.0, duration_ms=2000,
        )
        # First write triggers cooldown
        d1 = shield.evaluate(action, _make_snapshot())
        assert d1.approved

        # Second attack write should be blocked by cooldown
        action2 = AttackAction(
            attack_type=AttackType.ACTUATOR_OVERRIDE,
            target="fill_valve", value=3.0, duration_ms=2000,
        )
        d2 = shield.evaluate(action2, _make_snapshot())
        assert not d2.approved
        assert "cooldown" in str(d2.violated_rules).lower()

        # Corrective write should bypass cooldown
        corrective = AttackAction(
            attack_type=AttackType.ACTUATOR_OVERRIDE,
            target="fill_valve", value=5.0, duration_ms=2000,
        )
        d3 = shield.evaluate_corrective(corrective, _make_snapshot())
        assert d3.approved

    def test_evaluate_corrective_still_enforces_range(self) -> None:
        from cpsforge.core.models import SafetyRule
        from cpsforge.shield.engine import ShieldEngine

        profile = _make_scene_profile()
        profile.safety_rules = [
            SafetyRule(
                rule_id="range_fill",
                description="range",
                rule_type="range",
                tags=["fill_valve"],
                parameters={"min": 0.0, "max": 10.0},
                priority=5,
            ),
        ]
        shield = ShieldEngine(profile)
        bad_corrective = AttackAction(
            attack_type=AttackType.ACTUATOR_OVERRIDE,
            target="fill_valve", value=99.0, duration_ms=2000,
        )
        d = shield.evaluate_corrective(bad_corrective, _make_snapshot())
        assert not d.approved


# ---------------------------------------------------------------------------
# Phase 8: Coordinator write mediation
# ---------------------------------------------------------------------------


class TestCoordinatorWriteMediation:
    def test_corrective_uses_evaluate_corrective(self) -> None:
        """Verify coordinator dispatches CORRECTIVE requests to evaluate_corrective."""
        from cpsforge.agents.coordinator import AgentCoordinator

        profile = _make_scene_profile()
        mock_shield = MagicMock()
        mock_shield.evaluate.return_value = ShieldDecision(
            action_id="a1", approved=True, reasons=[],
        )
        mock_shield.evaluate_corrective.return_value = ShieldDecision(
            action_id="a2", approved=True, reasons=[],
        )

        mock_scene = MagicMock()
        mock_scene.profile = profile
        mock_scene.name = "level_control"
        mock_scene.get_tag.return_value = None

        from cpsforge.core.config import PLCConfig
        wr_q: Queue = Queue()
        att_q: Queue = Queue()
        def_q: Queue = Queue()

        coord = AgentCoordinator(
            plc_config=PLCConfig(),
            scene=mock_scene,
            shield=mock_shield,
            write_request_queue=wr_q,
            write_result_queues={"attacker": att_q, "defender": def_q},
            dry_run=True,
        )

        # Submit attack request
        attack_action = AttackAction(
            attack_type=AttackType.ACTUATOR_OVERRIDE,
            target="fill_valve", value=8.0,
        )
        wr_q.put(WriteRequest(
            agent_name="attacker", kind=RequestKind.ATTACK,
            action=attack_action,
        ))

        # Submit corrective request
        corrective_action = AttackAction(
            attack_type=AttackType.ACTUATOR_OVERRIDE,
            target="fill_valve", value=5.0,
        )
        wr_q.put(WriteRequest(
            agent_name="defender", kind=RequestKind.CORRECTIVE,
            action=corrective_action,
        ))

        coord.process_write_requests(_make_snapshot())

        mock_shield.evaluate.assert_called_once()
        mock_shield.evaluate_corrective.assert_called_once()

        # Both agents should get results
        att_result = att_q.get(timeout=1)
        def_result = def_q.get(timeout=1)
        assert att_result.approved
        assert def_result.approved


# ---------------------------------------------------------------------------
# Phase 8: Agent metrics computation
# ---------------------------------------------------------------------------


class TestAgentMetrics:
    def test_agent_eval_metrics_model(self) -> None:
        m = AgentEvalMetrics(
            run_id="r1", scene_name="level_control",
            attacks_submitted=10, attacks_approved=8,
            attacks_executed=7, attack_approval_rate=0.8,
        )
        assert m.mode == "agent"
        assert m.attack_approval_rate == 0.8

    def test_compute_agent_metrics(self) -> None:
        from cpsforge.logging.artifacts import compute_agent_metrics

        events = [
            AgentEvent(event_type=AgentEventType.ATTACK_SUBMITTED, agent_name="attacker", run_id="r1"),
            AgentEvent(event_type=AgentEventType.ATTACK_APPROVED, agent_name="attacker", run_id="r1"),
            AgentEvent(event_type=AgentEventType.ATTACK_EXECUTED, agent_name="attacker", run_id="r1"),
            AgentEvent(event_type=AgentEventType.ATTACK_SUBMITTED, agent_name="attacker", run_id="r1"),
            AgentEvent(event_type=AgentEventType.ATTACK_REJECTED, agent_name="attacker", run_id="r1"),
            AgentEvent(event_type=AgentEventType.DETECTION_EMITTED, agent_name="defender", run_id="r1"),
            AgentEvent(event_type=AgentEventType.CORRECTIVE_SUBMITTED, agent_name="defender", run_id="r1"),
            AgentEvent(event_type=AgentEventType.CORRECTIVE_APPROVED, agent_name="defender", run_id="r1"),
            AgentEvent(event_type=AgentEventType.CORRECTIVE_EXECUTED, agent_name="defender", run_id="r1"),
            AgentEvent(event_type=AgentEventType.AGENT_ERROR, agent_name="attacker", run_id="r1", payload={"error": "timeout"}),
        ]
        m = compute_agent_metrics(
            run_id="r1", scene_name="level_control",
            events=events, total_steps=100, duration_s=50.0,
        )
        assert m.attacks_submitted == 2
        assert m.attacks_approved == 1
        assert m.attacks_rejected == 1
        assert m.attacks_executed == 1
        assert m.detections_emitted == 1
        assert m.correctives_submitted == 1
        assert m.correctives_executed == 1
        assert m.attacker_errors == 1
        assert m.defender_errors == 0
        assert m.attack_approval_rate == 0.5
        assert m.corrective_success_rate == 1.0

    def test_compute_agent_metrics_empty(self) -> None:
        from cpsforge.logging.artifacts import compute_agent_metrics

        m = compute_agent_metrics(
            run_id="r2", scene_name="test",
            events=[], total_steps=0, duration_s=0.0,
        )
        assert m.attacks_submitted == 0
        assert m.attack_approval_rate == 0.0


# ---------------------------------------------------------------------------
# Phase 8: Artifact writer
# ---------------------------------------------------------------------------


class TestAgentArtifactWriter:
    def test_write_events(self) -> None:
        from cpsforge.logging.artifacts import AgentRunArtifactWriter

        with tempfile.TemporaryDirectory() as td:
            writer = AgentRunArtifactWriter(Path(td) / "run1")
            events = [
                AgentEvent(
                    event_type=AgentEventType.AGENT_STARTED,
                    agent_name="a", run_id="r",
                ),
            ]
            path = writer.write_events(events)
            assert path.exists()
            data = json.loads(path.read_text())
            assert len(data) == 1
            assert data[0]["event_type"] == "agent_started"

    def test_write_agent_metrics(self) -> None:
        from cpsforge.logging.artifacts import AgentRunArtifactWriter

        with tempfile.TemporaryDirectory() as td:
            writer = AgentRunArtifactWriter(Path(td) / "run2")
            m = AgentEvalMetrics(run_id="r", scene_name="test")
            path = writer.write_agent_metrics(m)
            assert path.exists()
            data = json.loads(path.read_text())
            assert data["run_id"] == "r"
            assert data["mode"] == "agent"

    def test_write_metadata(self) -> None:
        from cpsforge.logging.artifacts import AgentRunArtifactWriter

        with tempfile.TemporaryDirectory() as td:
            writer = AgentRunArtifactWriter(Path(td) / "run3")
            path = writer.write_metadata({"mode": "agent", "scene": "test"})
            assert path.exists()


# ---------------------------------------------------------------------------
# Phase 8: Agent experiment config loading
# ---------------------------------------------------------------------------


class TestAgentExperimentConfig:
    def test_load_agent_experiment(self) -> None:
        loader = _loader()
        exp = loader.load_experiment("agent_level_control")
        assert exp.mode == "agent"
        assert exp.attacker_agent == "attacker_agent"
        assert exp.defender_agent == "defender_agent"

    def test_agent_experiment_defaults(self) -> None:
        from cpsforge.core.config import ExperimentConfig
        exp = ExperimentConfig(
            name="test", scene_config="scenes/level_control.yaml",
            mode="agent",
        )
        assert exp.mode == "agent"
        assert exp.attacker_agent is None
        assert exp.dry_run is True
