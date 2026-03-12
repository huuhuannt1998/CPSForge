"""
CPSForge Phase 3 Test Suite
============================
Tests for:
  1. Hard case extraction (classify_attack_outcome, extract_and_write_hard_cases)
  2. RunReplayLoader (load artifacts, replay detectors, compute comparison)
  3. Detection latency fix in the orchestrator (_compute_metrics)
  4. Improved write_experiment_summary (std devs, hard case totals, run_index columns)
  5. Adapt CLI command group smoke tests

All tests run WITHOUT a live PLC (dry-run / in-memory only).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List
from unittest.mock import MagicMock

import pandas as pd
import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent.parent


def _invoke_cli(*args: str, **kwargs) -> Any:
    """Invoke the CPSForge CLI via typer CliRunner."""
    from typer.testing import CliRunner
    from cpsforge.cli.app import app
    runner = CliRunner()
    return runner.invoke(app, list(args), catch_exceptions=False, **kwargs)


def _make_action(target: str = "pump_speed", duration_ms: int = 5000,
                 status: str = "dry_run"):
    """Create an executed AttackAction for tests."""
    from cpsforge.core.models import AttackAction, AttackType, AttackSource, ExecutionStatus
    a = AttackAction(
        attack_type=AttackType.ACTUATOR_OVERRIDE,
        target=target,
        value=0.0,
        duration_ms=duration_ms,
        source=AttackSource.SCRIPTED,
    )
    a.execution_status = ExecutionStatus(status)
    a.approved_by_shield = True
    return a


def _make_detection(step_id: int, run_id: str = "test_run",
                    detector: str = "threshold") -> Any:
    from cpsforge.core.models import DetectionEvent
    return DetectionEvent(
        run_id=run_id,
        detector_name=detector,
        step_id=step_id,
    )


# ===========================================================================
# 1. Hard case extraction
# ===========================================================================

class TestHardCaseExtraction:
    """Unit tests for classify_attack_outcome and extract_and_write_hard_cases."""

    def test_classify_true_positive_when_detected_in_window(self):
        from cpsforge.adaptation.hard_cases import classify_attack_outcome, GRACE_STEPS
        from cpsforge.core.models import DetectionEvent
        action = _make_action()
        det = _make_detection(step_id=12)  # start=10, duration=10 → end=20, window=23
        outcome, mode, lat = classify_attack_outcome(
            action=action,
            start_step=10,
            duration_steps=10,
            detections=[det],
            attack_success=True,
            dry_run=True,
        )
        assert outcome == "true_positive"
        assert mode is None
        assert lat == pytest.approx(2.0)  # step 12 - step 10

    def test_classify_miss_in_dry_run_no_detection(self):
        from cpsforge.adaptation.hard_cases import classify_attack_outcome
        from cpsforge.core.models import HardCaseFailureMode
        action = _make_action()
        outcome, mode, lat = classify_attack_outcome(
            action=action,
            start_step=5,
            duration_steps=8,
            detections=[],
            attack_success=False,
            dry_run=True,   # dry_run → always flag as miss
        )
        assert outcome == "miss"
        assert mode == HardCaseFailureMode.MISS
        assert lat == pytest.approx(0.0)

    def test_classify_miss_when_attack_succeeded_no_detection(self):
        from cpsforge.adaptation.hard_cases import classify_attack_outcome
        from cpsforge.core.models import HardCaseFailureMode
        action = _make_action()
        outcome, mode, lat = classify_attack_outcome(
            action=action,
            start_step=0,
            duration_steps=5,
            detections=[],
            attack_success=True,   # process was impacted but not detected
            dry_run=False,
        )
        assert outcome == "miss"
        assert mode == HardCaseFailureMode.MISS

    def test_classify_no_impact_live_run_no_success_no_detection(self):
        from cpsforge.adaptation.hard_cases import classify_attack_outcome
        action = _make_action()
        outcome, mode, lat = classify_attack_outcome(
            action=action,
            start_step=0,
            duration_steps=5,
            detections=[],
            attack_success=False,
            dry_run=False,   # live run, no impact
        )
        assert outcome == "no_impact"
        assert mode is None

    def test_classify_late_detection_after_grace_window(self):
        from cpsforge.adaptation.hard_cases import classify_attack_outcome, GRACE_STEPS
        from cpsforge.core.models import HardCaseFailureMode
        action = _make_action()
        # attack: start=0, duration=5, end=5, window_end = 5 + GRACE_STEPS
        late_step = 5 + GRACE_STEPS + 2  # well past the grace window
        det = _make_detection(step_id=late_step)
        outcome, mode, lat = classify_attack_outcome(
            action=action,
            start_step=0,
            duration_steps=5,
            detections=[det],
            attack_success=True,
            dry_run=False,
        )
        assert outcome == "late_detection"
        assert mode == HardCaseFailureMode.LATE_DETECTION
        assert lat == pytest.approx(float(late_step))

    def test_classify_true_positive_at_grace_window_boundary(self):
        from cpsforge.adaptation.hard_cases import classify_attack_outcome, GRACE_STEPS
        action = _make_action()
        # Exactly at window_end must still be a true positive
        window_end_step = 5 + GRACE_STEPS  # = 8 if GRACE_STEPS=3
        det = _make_detection(step_id=window_end_step)
        outcome, mode, lat = classify_attack_outcome(
            action=action,
            start_step=0,
            duration_steps=5,
            detections=[det],
            attack_success=True,
            dry_run=False,
        )
        assert outcome == "true_positive"
        assert mode is None

    def test_extract_creates_hard_cases_json(self, tmp_path):
        from cpsforge.adaptation.hard_cases import extract_and_write_hard_cases
        action = _make_action()
        records = extract_and_write_hard_cases(
            actions=[action],
            detections=[],
            attack_start_steps={action.action_id: 0},
            attack_success_map={action.action_id: False},
            ground_truth_steps={0, 1, 2, 3, 4},
            sampling_interval_ms=500,
            run_id="test_run",
            run_dir=tmp_path,
            dry_run=True,  # dry_run → flagged as miss
        )
        hc_path = tmp_path / "hard_cases.json"
        assert hc_path.exists()
        data = json.loads(hc_path.read_text())
        assert data["run_id"] == "test_run"
        assert data["hard_case_count"] == len(records)
        assert len(data["outcomes"]) == 1
        assert data["outcomes"][0]["outcome"] == "miss"

    def test_extract_skips_non_executed_actions(self, tmp_path):
        from cpsforge.adaptation.hard_cases import extract_and_write_hard_cases
        from cpsforge.core.models import ExecutionStatus
        # PENDING action should not be counted
        pending_action = _make_action(status="pending")
        dry_action = _make_action(status="dry_run")
        records = extract_and_write_hard_cases(
            actions=[pending_action, dry_action],
            detections=[],
            attack_start_steps={dry_action.action_id: 0},
            attack_success_map={},
            ground_truth_steps=set(),
            sampling_interval_ms=500,
            run_id="skip_test",
            run_dir=tmp_path,
            dry_run=True,
        )
        data = json.loads((tmp_path / "hard_cases.json").read_text())
        # Only dry_run action should be counted
        assert data["total_executed"] == 1


# ===========================================================================
# 2. RunReplayLoader
# ===========================================================================

class TestRunReplayLoader:
    """Unit tests for RunReplayLoader."""

    def _make_run_dir(self, tmp_path: Path, run_id: str = "run_001") -> Path:
        """Create a minimal run directory with trace + artifacts."""
        run_dir = tmp_path / run_id
        run_dir.mkdir()

        # Minimal trace.parquet
        df = pd.DataFrame({
            "step_id": list(range(5)),
            "run_id": [run_id] * 5,
            "timestamp": [f"2024-01-01T00:00:0{i}Z" for i in range(5)],
            "scene_name": ["tank_control"] * 5,
            "attack_active": [False, True, True, True, False],
        })
        df.to_parquet(run_dir / "trace.parquet", index=False)

        # attacks.json
        from cpsforge.core.models import AttackAction, AttackType, AttackSource
        a = AttackAction(
            attack_type=AttackType.ACTUATOR_OVERRIDE,
            target="pump_speed",
            value=0.0,
            source=AttackSource.SCRIPTED,
        )
        (run_dir / "attacks.json").write_text(
            json.dumps([a.model_dump(mode="json")], default=str)
        )

        # detections.json (empty)
        (run_dir / "detections.json").write_text("[]")

        # metadata.json
        (run_dir / "metadata.json").write_text(
            json.dumps({"run_id": run_id, "scene": "tank_control"})
        )

        return run_dir

    def test_load_snapshots_returns_list(self, tmp_path):
        from cpsforge.adaptation.replay import RunReplayLoader
        run_dir = self._make_run_dir(tmp_path)
        loader = RunReplayLoader(run_dir)
        snaps = loader.load_snapshots()
        assert isinstance(snaps, list)
        assert len(snaps) == 5

    def test_load_attacks_returns_list(self, tmp_path):
        from cpsforge.adaptation.replay import RunReplayLoader
        run_dir = self._make_run_dir(tmp_path)
        loader = RunReplayLoader(run_dir)
        attacks = loader.load_attacks()
        assert len(attacks) == 1
        assert attacks[0].target == "pump_speed"

    def test_load_attacks_empty_when_no_file(self, tmp_path):
        from cpsforge.adaptation.replay import RunReplayLoader
        run_dir = tmp_path / "run_x"
        run_dir.mkdir()
        loader = RunReplayLoader(run_dir)
        assert loader.load_attacks() == []

    def test_load_original_detections_empty_when_no_file(self, tmp_path):
        from cpsforge.adaptation.replay import RunReplayLoader
        run_dir = tmp_path / "run_x"
        run_dir.mkdir()
        loader = RunReplayLoader(run_dir)
        assert loader.load_original_detections() == []

    def test_load_metrics_returns_none_when_absent(self, tmp_path):
        from cpsforge.adaptation.replay import RunReplayLoader
        run_dir = tmp_path / "run_x"
        run_dir.mkdir()
        loader = RunReplayLoader(run_dir)
        assert loader.load_metrics() is None

    def test_load_attack_step_range(self, tmp_path):
        from cpsforge.adaptation.replay import RunReplayLoader
        run_dir = self._make_run_dir(tmp_path)
        loader = RunReplayLoader(run_dir)
        step_range = loader.load_attack_step_range()
        # Steps 1, 2, 3 have attack_active=True
        assert step_range == {1, 2, 3}

    def test_compute_comparison_basic(self, tmp_path):
        from cpsforge.adaptation.replay import RunReplayLoader
        from cpsforge.core.models import DetectionEvent
        run_dir = self._make_run_dir(tmp_path)
        loader = RunReplayLoader(run_dir)
        orig = [DetectionEvent(run_id="r", detector_name="t", step_id=2)]
        rpl  = [
            DetectionEvent(run_id="r", detector_name="t", step_id=2),
            DetectionEvent(run_id="r", detector_name="t", step_id=4),
        ]
        stats = loader.compute_comparison(orig, rpl)
        assert stats["original_event_count"] == 1
        assert stats["replayed_event_count"] == 2
        assert stats["new_detection_steps"] == [4]
        assert stats["lost_detection_steps"] == []
        assert stats["common_step_count"] == 1

    def test_compute_comparison_with_attack_range_computes_f1(self, tmp_path):
        from cpsforge.adaptation.replay import RunReplayLoader
        from cpsforge.core.models import DetectionEvent
        run_dir = self._make_run_dir(tmp_path)
        loader = RunReplayLoader(run_dir)
        rpl = [
            DetectionEvent(run_id="r", detector_name="t", step_id=2),  # TP
            DetectionEvent(run_id="r", detector_name="t", step_id=9),  # FP (not in range)
        ]
        stats = loader.compute_comparison([], rpl, attack_step_range={1, 2, 3})
        # TP=1, FP=1, FN=2
        assert stats["replayed_true_positives"] == 1
        assert stats["replayed_false_positives"] == 1
        assert stats["replayed_false_negatives"] == 2
        assert 0 < stats["replayed_f1"] < 1.0


# ===========================================================================
# 3. Detection latency fix in the orchestrator
# ===========================================================================

class TestDetectionLatencyFix:
    """Verify that _compute_metrics computes detection latency relative to attack launch."""

    def _make_orchestrator(self):
        """Construct an ExperimentOrchestrator with a minimal dry-run config."""
        from cpsforge.core.config import ExperimentConfig, ConfigLoader
        from cpsforge.core.orchestrator import ExperimentOrchestrator
        loader = ConfigLoader(configs_dir=REPO_ROOT / "configs")
        cfg = ExperimentConfig(
            name="test_latency",
            scene_config="scenes/tank_control.yaml",
            live_writes_enabled=False,
            dry_run=True,
        )
        return ExperimentOrchestrator(cfg, loader)

    def _load_scene(self):
        from cpsforge.core.config import ConfigLoader
        from cpsforge.scenes.factory import load_scene
        loader = ConfigLoader(configs_dir=REPO_ROOT / "configs")
        return load_scene("tank_control", loader)

    def test_latency_relative_to_attack_start(self):
        """Latency must be (detection_step - launch_step) * interval, not absolute."""
        orch = self._make_orchestrator()
        action = _make_action()
        orch._actions = [action]
        orch._attack_start_steps[action.action_id] = 10  # attack launched at step 10
        orch._decisions = []
        orch._detections = [_make_detection(step_id=13)]  # detected at step 13

        scene = self._load_scene()
        metrics = orch._compute_metrics(scene)
        # Expected: (13 - 10) * 500 ms = 1500 ms
        assert metrics.detection_latency_ms == pytest.approx(1500.0)

    def test_latency_zero_when_no_detections(self):
        orch = self._make_orchestrator()
        action = _make_action()
        orch._actions = [action]
        orch._attack_start_steps[action.action_id] = 5
        orch._decisions = []
        orch._detections = []

        scene = self._load_scene()
        metrics = orch._compute_metrics(scene)
        assert metrics.detection_latency_ms == pytest.approx(0.0)

    def test_latency_ignores_detections_before_attack_start(self):
        """Detections issued before the attack launched should not count."""
        orch = self._make_orchestrator()
        action = _make_action()
        orch._actions = [action]
        orch._attack_start_steps[action.action_id] = 20  # attack at step 20
        orch._decisions = []
        # All detections are before step 20 -- should not contribute to latency
        orch._detections = [
            _make_detection(step_id=1),
            _make_detection(step_id=10),
        ]

        scene = self._load_scene()
        metrics = orch._compute_metrics(scene)
        assert metrics.detection_latency_ms == pytest.approx(0.0)


# ===========================================================================
# 3b. Corrected metric semantics (Bug fixes verified)
# ===========================================================================

class TestMetricSemantics:
    """
    Verify the corrected semantics for metrics that previously had aliased values.

    Each test isolates a single metric to confirm it is computed distinctly
    from the metric it was previously confused with.
    """

    def _make_orch(self):
        from cpsforge.core.config import ExperimentConfig
        from cpsforge.core.orchestrator import ExperimentOrchestrator
        from cpsforge.core.config import ConfigLoader
        loader = ConfigLoader(configs_dir=REPO_ROOT / "configs")
        cfg = ExperimentConfig(
            name="test_semantics",
            scene_config="scenes/tank_control.yaml",
            live_writes_enabled=False,
            dry_run=True,
        )
        return ExperimentOrchestrator(cfg, loader)

    def _load_scene(self):
        from cpsforge.core.config import ConfigLoader
        from cpsforge.scenes.factory import load_scene
        loader = ConfigLoader(configs_dir=REPO_ROOT / "configs")
        return load_scene("tank_control", loader)

    def _make_shield_rejection(self, action_id: str,
                                violated_rules: list) -> Any:
        from cpsforge.core.models import ShieldDecision
        return ShieldDecision(
            action_id=action_id,
            approved=False,
            reasons=["test rejection"],
            violated_rules=violated_rules,
        )

    # ----------------------------------------------------------
    # Bug 1: action_validity_rate ≠ shield_approval_rate
    # ----------------------------------------------------------

    def test_action_validity_rate_differs_from_shield_approval_rate(self):
        """An action with a valid target that gets rejected by cooldown
        must have action_validity_rate=1.0 but shield_approval_rate=0.0."""
        orch = self._make_orch()
        action = _make_action(target="pump_speed", status="rejected")
        action.approved_by_shield = False
        decision = self._make_shield_rejection(action.action_id, ["SR-006"])  # cooldown
        orch._actions = [action]
        orch._decisions = [decision]
        orch._detections = []

        scene = self._load_scene()
        metrics = orch._compute_metrics(scene)

        assert metrics.action_validity_rate == pytest.approx(1.0), (
            "pump_speed is in attack surface -- validity must be 1.0"
        )
        assert metrics.shield_approval_rate == pytest.approx(0.0), (
            "action was rejected -- approval rate must be 0.0"
        )
        # The two metrics must be different
        assert metrics.action_validity_rate != metrics.shield_approval_rate

    def test_action_validity_rate_zero_for_off_surface_target(self):
        """An action targeting a tag NOT in the attack surface must have validity=0."""
        orch = self._make_orch()
        action = _make_action(target="NOT_A_REAL_TAG", status="rejected")
        action.approved_by_shield = False
        decision = self._make_shield_rejection(action.action_id, ["whitelist"])
        orch._actions = [action]
        orch._decisions = [decision]
        orch._detections = []

        scene = self._load_scene()
        metrics = orch._compute_metrics(scene)
        assert metrics.action_validity_rate == pytest.approx(0.0)

    # ----------------------------------------------------------
    # Bug 2: unsafe_block_rate ≠ shield_rejection_rate
    # ----------------------------------------------------------

    def test_unsafe_block_rate_only_counts_safety_rule_violations(self):
        """An action blocked by a cooldown rule (SR-006) must NOT count toward
        unsafe_block_rate but MUST count toward shield_rejection_rate."""
        orch = self._make_orch()
        action = _make_action(target="pump_speed", status="rejected")
        action.approved_by_shield = False
        # SR-006 is type=cooldown -- operational constraint, not safety-critical
        decision = self._make_shield_rejection(action.action_id, ["SR-006"])
        orch._actions = [action]
        orch._decisions = [decision]
        orch._detections = []

        scene = self._load_scene()
        metrics = orch._compute_metrics(scene)

        assert metrics.shield_rejection_rate == pytest.approx(1.0)
        assert metrics.unsafe_block_rate == pytest.approx(0.0), (
            "SR-006 (cooldown) is not a safety-critical rule"
        )

    def test_unsafe_block_rate_counts_range_violations(self):
        """An action blocked by a range rule (e.g. SR-002) MUST count toward
        unsafe_block_rate AND shield_rejection_rate."""
        orch = self._make_orch()
        action = _make_action(target="pump_speed", status="rejected")
        action.approved_by_shield = False
        # SR-002 is type=range -- safety-critical
        decision = self._make_shield_rejection(action.action_id, ["SR-002"])
        orch._actions = [action]
        orch._decisions = [decision]
        orch._detections = []

        scene = self._load_scene()
        metrics = orch._compute_metrics(scene)

        assert metrics.shield_rejection_rate == pytest.approx(1.0)
        assert metrics.unsafe_block_rate == pytest.approx(1.0), (
            "SR-002 (range) is safety-critical -- must count"
        )

    def test_unsafe_and_rejection_rates_separate_with_mixed_violations(self):
        """Two actions: one blocked by safety rule, one by cooldown.
        unsafe_block_rate=0.5, shield_rejection_rate=1.0."""
        orch = self._make_orch()
        safety_action = _make_action(target="pump_speed", status="rejected")
        safety_action.approved_by_shield = False
        cooldown_action = _make_action(target="pump_speed", status="rejected")
        cooldown_action.approved_by_shield = False
        d1 = self._make_shield_rejection(safety_action.action_id, ["SR-002"])  # range
        d2 = self._make_shield_rejection(cooldown_action.action_id, ["SR-006"])  # cooldown
        orch._actions = [safety_action, cooldown_action]
        orch._decisions = [d1, d2]
        orch._detections = []

        scene = self._load_scene()
        metrics = orch._compute_metrics(scene)
        assert metrics.shield_rejection_rate == pytest.approx(1.0)
        assert metrics.unsafe_block_rate == pytest.approx(0.5)

    # ----------------------------------------------------------
    # Bug 3: execution_success_rate = executed / approved, not / total
    # ----------------------------------------------------------

    def test_execution_success_rate_denominator_is_approved(self):
        """3 actions total: 2 approved+executed, 1 rejected.
        execution_success_rate must be 2/2=1.0, not 2/3."""
        from cpsforge.core.models import ShieldDecision
        orch = self._make_orch()
        a1 = _make_action(status="dry_run"); a1.approved_by_shield = True
        a2 = _make_action(status="dry_run"); a2.approved_by_shield = True
        a3 = _make_action(status="rejected"); a3.approved_by_shield = False
        d_ok1 = ShieldDecision(action_id=a1.action_id, approved=True, reasons=[])
        d_ok2 = ShieldDecision(action_id=a2.action_id, approved=True, reasons=[])
        d_rej = self._make_shield_rejection(a3.action_id, ["SR-006"])
        orch._actions = [a1, a2, a3]
        orch._decisions = [d_ok1, d_ok2, d_rej]
        orch._detections = []

        scene = self._load_scene()
        metrics = orch._compute_metrics(scene)
        assert metrics.execution_success_rate == pytest.approx(1.0), (
            "2 executed out of 2 approved = 1.0, not 0.667"
        )
        assert metrics.shield_rejection_rate == pytest.approx(1/3, abs=1e-3)

    # ----------------------------------------------------------
    # Bug 4: still-active attacks counted in denominator
    # ----------------------------------------------------------

    def test_attack_success_rate_denominator_includes_in_progress_attacks(self):
        """An executed attack that never closed (run ended early) defaults to
        success=False and must NOT shrink the denominator."""
        orch = self._make_orch()
        a_closed = _make_action(status="dry_run"); a_closed.approved_by_shield = True
        a_active = _make_action(status="dry_run"); a_active.approved_by_shield = True
        orch._actions = [a_closed, a_active]
        orch._decisions = []
        orch._detections = []
        # Only the closed attack has an entry in success_map
        orch._attack_success_map[a_closed.action_id] = True
        # a_active is NOT in success_map (still in-progress when run ended)

        scene = self._load_scene()
        metrics = orch._compute_metrics(scene)
        # Denominator must be 2 (both executed), not 1 (only closed)
        assert metrics.attack_success_rate == pytest.approx(0.5), (
            "1 success out of 2 executed (1 closed, 1 still-active) = 0.5"
        )

    # ----------------------------------------------------------
    # Bug 5: detector_names from loaded defenders, not events
    # ----------------------------------------------------------

    def test_detector_names_populated_even_without_detections(self):
        """If no detection events fired, detector_names should still list the
        active defenders (not return an empty list)."""
        orch = self._make_orch()
        orch._defender_names = ["threshold_tank_control", "invariant_tank_control"]
        orch._actions = [_make_action()]
        orch._decisions = []
        orch._detections = []  # no events

        scene = self._load_scene()
        metrics = orch._compute_metrics(scene)
        assert "threshold_tank_control" in metrics.detector_names
        assert "invariant_tank_control" in metrics.detector_names

    def test_detector_names_fallback_to_event_names_when_no_defenders_loaded(self):
        """If _defender_names is empty (defenders not loaded), fall back to names
        extracted from detection events."""
        orch = self._make_orch()
        orch._defender_names = []  # no defenders stored
        orch._actions = [_make_action()]
        orch._decisions = []
        orch._detections = [_make_detection(step_id=1, detector="event_only_detector")]

        scene = self._load_scene()
        metrics = orch._compute_metrics(scene)
        assert "event_only_detector" in metrics.detector_names


# ===========================================================================
# 4. Improved write_experiment_summary
# ===========================================================================

class TestWriteExperimentSummaryPhase3:
    """Tests for the Phase 3 improvements to write_experiment_summary."""

    def _make_metrics(self, run_id: str, eval_run: bool = True, f1: float = 0.8,
                      asr: float = 0.5, latency: float = 1000.0) -> Any:
        from cpsforge.core.models import EvalMetrics
        return EvalMetrics(
            run_id=run_id,
            scene_name="tank_control",
            attacker_name="scripted",
            detector_names=["threshold"],
            eval_run=eval_run,
            detector_f1=f1,
            attack_success_rate=asr,
            detection_latency_ms=latency,
            adaptation_round=0,
        )

    def test_summary_json_written(self, tmp_path):
        from cpsforge.logging.artifacts import write_experiment_summary
        m = self._make_metrics("run_001")
        write_experiment_summary(
            experiment_name="test_exp",
            run_ids=["run_001"],
            all_metrics=[m],
            base_dir=tmp_path,
        )
        summary_path = tmp_path.parent / "processed" / "test_exp" / "summary.json"
        # get_processed_dir replaces "raw" with "processed" — but here base_dir is tmp_path
        # The function uses get_processed_dir(base_dir, experiment_name) which replaces
        # the last "raw" component. Let's check what was actually written.
        from cpsforge.logging.artifacts import get_processed_dir
        out_dir = get_processed_dir(tmp_path, "test_exp")
        assert (out_dir / "summary.json").exists()

    def test_summary_includes_std_dev(self, tmp_path):
        from cpsforge.logging.artifacts import write_experiment_summary, get_processed_dir
        metrics = [
            self._make_metrics("run_001", f1=0.6),
            self._make_metrics("run_002", f1=0.8),
            self._make_metrics("run_003", f1=1.0),
        ]
        write_experiment_summary(
            experiment_name="std_test",
            run_ids=["run_001", "run_002", "run_003"],
            all_metrics=metrics,
            base_dir=tmp_path,
        )
        out_dir = get_processed_dir(tmp_path, "std_test")
        data = json.loads((out_dir / "summary.json").read_text())
        assert "std_detector_f1" in data
        assert data["std_detector_f1"] >= 0.0
        assert "mean_detector_f1" in data
        assert abs(data["mean_detector_f1"] - 0.8) < 0.01
        # New aggregate fields added in this audit
        assert "mean_detector_precision" in data
        assert "mean_detector_recall" in data
        assert "mean_action_validity_rate" in data
        assert "mean_execution_success_rate" in data
        assert "mean_unsafe_block_rate" in data

    def test_run_index_csv_has_metrics_columns(self, tmp_path):
        from cpsforge.logging.artifacts import write_experiment_summary, get_processed_dir
        m = self._make_metrics("run_001")
        write_experiment_summary(
            experiment_name="idx_test",
            run_ids=["run_001"],
            all_metrics=[m],
            base_dir=tmp_path,
        )
        out_dir = get_processed_dir(tmp_path, "idx_test")
        df = pd.read_csv(out_dir / "run_index.csv")
        assert "run_id" in df.columns
        # Corrected: all cascade metrics present
        assert "action_validity_rate" in df.columns
        assert "execution_success_rate" in df.columns
        assert "attack_success_rate" in df.columns
        assert "unsafe_block_rate" in df.columns
        assert "shield_rejection_rate" in df.columns
        assert "shield_approval_rate" in df.columns
        assert "detector_precision" in df.columns
        assert "detector_recall" in df.columns
        assert "detector_f1" in df.columns
        assert "false_positives" in df.columns
        assert "false_negatives" in df.columns
        assert "total_steps" in df.columns
        assert "total_attacks" in df.columns
        assert "adaptation_round" in df.columns

    def test_summary_includes_hard_case_totals(self, tmp_path):
        from cpsforge.logging.artifacts import write_experiment_summary, get_processed_dir
        m = self._make_metrics("run_001")
        # Create a fake hard_cases.json for run_001
        run_dir = tmp_path / "test_hc" / "run_001"
        run_dir.mkdir(parents=True)
        hc = {
            "run_id": "run_001",
            "hard_case_count": 3,
            "total_executed": 5,
            "outcomes": [],
            "hard_cases": [],
        }
        (run_dir / "hard_cases.json").write_text(json.dumps(hc))

        write_experiment_summary(
            experiment_name="test_hc",
            run_ids=["run_001"],
            all_metrics=[m],
            base_dir=tmp_path,
        )
        out_dir = get_processed_dir(tmp_path, "test_hc")
        data = json.loads((out_dir / "summary.json").read_text())
        assert data["total_hard_cases"] == 3
        assert data["hard_case_runs"] == 1

    def test_aggregate_metrics_csv_written(self, tmp_path):
        from cpsforge.logging.artifacts import write_experiment_summary, get_processed_dir
        metrics = [self._make_metrics(f"run_{i:03d}") for i in range(3)]
        write_experiment_summary(
            experiment_name="agg_test",
            run_ids=[m.run_id for m in metrics],
            all_metrics=metrics,
            base_dir=tmp_path,
        )
        out_dir = get_processed_dir(tmp_path, "agg_test")
        assert (out_dir / "aggregate_metrics.csv").exists()
        df = pd.read_csv(out_dir / "aggregate_metrics.csv")
        assert len(df) == 3


# ===========================================================================
# 5. Adapt CLI smoke tests
# ===========================================================================

class TestAdaptCLI:
    """Smoke tests for the cpsforge adapt command group."""

    def _invoke(self, *args: str, **kwargs) -> Any:
        return _invoke_cli(*args, **kwargs)

    def test_adapt_help_exits_zero(self):
        result = self._invoke("adapt", "--help")
        assert result.exit_code == 0
        assert "adapt" in result.output.lower()

    def test_adapt_list_hard_cases_help_exits_zero(self):
        result = self._invoke("adapt", "list-hard-cases", "--help")
        assert result.exit_code == 0
        assert "experiment" in result.output.lower()

    def test_adapt_train_help_exits_zero(self):
        result = self._invoke("adapt", "train", "--help")
        assert result.exit_code == 0

    def test_adapt_list_hard_cases_missing_experiment_exits_nonzero(self, tmp_path):
        """Pointing at a non-existent experiment directory must exit with code 1."""
        result = _invoke_cli(
            "adapt", "list-hard-cases",
            "--experiment", "does_not_exist_xyz",
            "--data-dir", str(tmp_path),
            # catch_exceptions=False is set inside _invoke_cli, so SystemExit propagates
        )
        assert result.exit_code != 0

    def test_adapt_train_missing_experiment_exits_nonzero(self, tmp_path):
        result = _invoke_cli(
            "adapt", "train",
            "--experiment", "does_not_exist_xyz",
            "--data-dir", str(tmp_path),
        )
        assert result.exit_code != 0

    def test_adapt_list_hard_cases_empty_experiment_exits_zero(self, tmp_path):
        """An experiment directory that exists but has no runs should exit cleanly."""
        exp_dir = tmp_path / "raw" / "empty_exp"
        exp_dir.mkdir(parents=True)
        result = _invoke_cli(
            "adapt", "list-hard-cases",
            "--experiment", "empty_exp",
            "--data-dir", str(tmp_path),
        )
        # Should exit 0 even with no runs
        assert result.exit_code == 0

    def test_adapt_train_with_zero_hard_cases(self, tmp_path):
        """Train command with an empty experiment should report 0 hard cases and exit 0."""
        exp_dir = tmp_path / "raw" / "zero_hc_exp"
        exp_dir.mkdir(parents=True)
        result = _invoke_cli(
            "adapt", "train",
            "--experiment", "zero_hc_exp",
            "--data-dir", str(tmp_path),
        )
        assert result.exit_code == 0
        assert "0" in result.output
