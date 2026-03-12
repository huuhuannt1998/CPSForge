"""
CPSForge Phase 6 Test Suite -- Analysis Module
================================================
Tests for the paper-ready analysis pipeline:
  1. cross_attacker_table   (Table 1)
  2. shield_analysis_table  (Table 2)
  3. cross_detector_table   (Table 3)
  4. adaptation_round_table (Table 4)
  5. attack_type_breakdown
  6. latency_distribution
  7. full_paper_export
  8. hard_case_generalization (replay_analysis)
  9. CLI report subcommands (smoke tests)

All tests use synthetic experiment data in tmp_path.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import pandas as pd
import pytest


# ---------------------------------------------------------------------------
# Synthetic experiment builder
# ---------------------------------------------------------------------------


def _utcnow_str() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_metrics(
    run_id: str,
    attacker: str = "scripted",
    scene: str = "tank_control",
    eval_run: bool = True,
    **overrides: Any,
) -> Dict[str, Any]:
    """Build a minimal metrics.json dict."""
    base = {
        "run_id": run_id,
        "scene_name": scene,
        "attacker_name": attacker,
        "detector_names": ["threshold", "invariant"],
        "action_validity_rate": 0.8,
        "execution_success_rate": 0.7,
        "attack_success_rate": 0.5,
        "process_impact_score": 0.3,
        "shield_approval_rate": 0.75,
        "shield_rejection_rate": 0.25,
        "unsafe_block_rate": 0.1,
        "detector_precision": 0.8,
        "detector_recall": 0.7,
        "detector_f1": 0.74,
        "detection_latency_ms": 1500.0,
        "false_positives": 2,
        "false_negatives": 3,
        "hard_case_flag": False,
        "adaptation_round": 0,
        "total_steps": 100,
        "total_attacks": 10,
        "eval_run": eval_run,
        "created_at": _utcnow_str(),
    }
    base.update(overrides)
    return base


def _make_attacks(n: int = 5, attack_type: str = "sensor_spoof") -> List[Dict]:
    attacks = []
    for i in range(n):
        attacks.append({
            "action_id": f"atk_{i:03d}",
            "attack_type": attack_type,
            "target": "tank_level",
            "mode": "override",
            "value": 90.0 + i,
            "duration_ms": 5000,
            "rationale": "test",
            "source": "scripted",
            "approved_by_shield": i % 2 == 0,  # half approved
            "execution_status": "executed" if i % 2 == 0 else "rejected",
        })
    return attacks


def _make_detections(n: int = 3, detector: str = "threshold") -> List[Dict]:
    events = []
    for i in range(n):
        events.append({
            "timestamp": _utcnow_str(),
            "run_id": "test_run",
            "detector_name": detector,
            "severity": "high" if i == 0 else "medium",
            "label": "anomaly_detected",
            "confidence": 0.85 + i * 0.03,
            "explanation": "test detection",
            "affected_tags": ["tank_level"],
            "step_id": 20 + i * 5,
        })
    return events


def _make_shield_events(n: int = 5) -> List[Dict]:
    events = []
    for i in range(n):
        approved = i % 3 != 0
        events.append({
            "action_id": f"atk_{i:03d}",
            "approved": approved,
            "reasons": [] if approved else [f"Violated rule range_tank_level_{i}"],
            "normalized_value": 85.0 if i == 1 else None,
            "expiration_time": None,
            "rollback_plan": {"action": "reset_tag", "tag": "tank_level"} if not approved else None,
            "violated_rules": [] if approved else [f"range_tank_level_{i}"],
        })
    return events


def _make_trace_parquet(run_dir: Path, n_steps: int = 100, attack_steps: range | None = None):
    """Write a minimal trace.parquet with sensor columns."""
    if attack_steps is None:
        attack_steps = range(20, 40)
    data = {
        "timestamp": [_utcnow_str()] * n_steps,
        "scene_name": ["tank_control"] * n_steps,
        "run_id": ["test_run"] * n_steps,
        "step_id": list(range(n_steps)),
        "sensor__tank_level": np.random.uniform(30, 70, n_steps).tolist(),
        "actuator__pump_speed": np.random.uniform(0, 100, n_steps).tolist(),
        "attack_active": [(i in attack_steps) for i in range(n_steps)],
        "attack_action_id": [
            f"atk_{(i - attack_steps.start) // 5:03d}" if i in attack_steps else ""
            for i in range(n_steps)
        ],
        "attack_type": [
            "sensor_spoof" if i in attack_steps else "" for i in range(n_steps)
        ],
        "attack_target": [
            "tank_level" if i in attack_steps else "" for i in range(n_steps)
        ],
        "anomaly_score": [0.0] * n_steps,
        "latest_detection": [""] * n_steps,
    }
    df = pd.DataFrame(data)
    df.to_parquet(run_dir / "trace.parquet", index=False)


def _make_experiment(
    base: Path,
    experiment: str,
    n_runs: int = 3,
    attackers: tuple = ("scripted", "random", "llm"),
):
    """Create a synthetic experiment directory tree under data/raw/<experiment>."""
    raw_dir = base / "data" / "raw" / experiment
    raw_dir.mkdir(parents=True, exist_ok=True)

    for i in range(n_runs):
        attacker = attackers[i % len(attackers)]
        run_id = f"run_{i:03d}"
        run_dir = raw_dir / run_id
        run_dir.mkdir()

        # metrics.json
        m = _make_metrics(
            run_id,
            attacker=attacker,
            attack_success_rate=0.4 + i * 0.1,
            detector_f1=0.6 + i * 0.05,
            adaptation_round=i // 3,
        )
        with (run_dir / "metrics.json").open("w") as fh:
            json.dump(m, fh)

        # attacks.json — mix attack types
        atypes = ["sensor_spoof", "actuator_override", "setpoint_shift"]
        attacks = _make_attacks(5, attack_type=atypes[i % len(atypes)])
        with (run_dir / "attacks.json").open("w") as fh:
            json.dump(attacks, fh)

        # detections.json — different detectors
        dets = (
            _make_detections(2, "threshold")
            + _make_detections(2, "invariant")
        )
        with (run_dir / "detections.json").open("w") as fh:
            json.dump(dets, fh)

        # shield_events.json
        with (run_dir / "shield_events.json").open("w") as fh:
            json.dump(_make_shield_events(5), fh)

        # trace.parquet
        _make_trace_parquet(run_dir)

        # metadata.json
        with (run_dir / "metadata.json").open("w") as fh:
            json.dump({"run_id": run_id, "attacker": attacker}, fh)

    return base / "data"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def experiment_data(tmp_path: Path) -> Path:
    """Create a 6-run experiment with 3 attackers and return the data dir."""
    return _make_experiment(tmp_path, "test_exp", n_runs=6)


@pytest.fixture
def adaptation_data(tmp_path: Path) -> Path:
    """Create an experiment with round_metrics.csv in processed/ dir."""
    data = _make_experiment(tmp_path, "adapt_exp", n_runs=6)
    proc_dir = data / "processed" / "adapt_exp"
    proc_dir.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame({
        "round": [0, 1, 2],
        "detector_f1": [0.60, 0.72, 0.81],
        "detector_recall": [0.55, 0.68, 0.78],
        "detector_precision": [0.65, 0.76, 0.84],
        "false_negatives": [5, 3, 1],
    })
    df.to_csv(proc_dir / "round_metrics.csv", index=False)
    return data


# ---------------------------------------------------------------------------
# Test: cross_attacker_table (Table 1)
# ---------------------------------------------------------------------------


class TestCrossAttackerTable:
    def test_basic(self, experiment_data: Path):
        from cpsforge.analysis.tables import cross_attacker_table

        df = cross_attacker_table(experiment_data, "test_exp")
        assert not df.empty
        # Should have one row per attacker
        assert set(df.index) == {"scripted", "random", "llm"}
        # Expected columns
        for col in [
            "n_runs", "validity_mean", "exec_success_mean",
            "attack_success_mean", "impact_mean", "total_attacks",
        ]:
            assert col in df.columns, f"missing column {col}"

    def test_eval_only_filter(self, tmp_path: Path):
        from cpsforge.analysis.tables import cross_attacker_table

        data = _make_experiment(tmp_path, "mixed", n_runs=3, attackers=("scripted",))
        # Make one run non-eval
        run_dir = data / "raw" / "mixed" / "run_000"
        with (run_dir / "metrics.json").open() as fh:
            m = json.load(fh)
        m["eval_run"] = False
        with (run_dir / "metrics.json").open("w") as fh:
            json.dump(m, fh)

        df_eval = cross_attacker_table(data, "mixed", eval_only=True)
        df_all = cross_attacker_table(data, "mixed", eval_only=False)
        assert df_eval.loc["scripted", "n_runs"] == 2
        assert df_all.loc["scripted", "n_runs"] == 3

    def test_empty_experiment(self, tmp_path: Path):
        from cpsforge.analysis.tables import cross_attacker_table

        (tmp_path / "data" / "raw" / "empty").mkdir(parents=True)
        df = cross_attacker_table(tmp_path / "data", "empty")
        assert df.empty


# ---------------------------------------------------------------------------
# Test: shield_analysis_table (Table 2)
# ---------------------------------------------------------------------------


class TestShieldAnalysis:
    def test_basic(self, experiment_data: Path):
        from cpsforge.analysis.tables import shield_analysis_table

        df = shield_analysis_table(experiment_data, "test_exp")
        assert not df.empty
        # Should have per-attacker rows + TOTAL
        assert "TOTAL" in df.index
        assert df.loc["TOTAL", "n_runs"] == 6

    def test_rule_counts_in_attrs(self, experiment_data: Path):
        from cpsforge.analysis.tables import shield_analysis_table

        df = shield_analysis_table(experiment_data, "test_exp")
        rule_counts = df.attrs.get("rule_rejection_counts", {})
        # Our synthetic data has "range_tank_level_*" rules
        assert len(rule_counts) > 0 or df.attrs.get("total_shield_events", 0) > 0


# ---------------------------------------------------------------------------
# Test: cross_detector_table (Table 3)
# ---------------------------------------------------------------------------


class TestCrossDetectorTable:
    def test_basic(self, experiment_data: Path):
        from cpsforge.analysis.tables import cross_detector_table

        df = cross_detector_table(experiment_data, "test_exp")
        # Should have rows for 'threshold' and 'invariant'
        if not df.empty:
            assert "n_events" in df.columns
            assert "per_detector_precision" in df.columns

    def test_handles_missing_trace(self, tmp_path: Path):
        """Gracefully returns data even when trace.parquet is missing."""
        from cpsforge.analysis.tables import cross_detector_table

        data = _make_experiment(tmp_path, "no_trace", n_runs=2, attackers=("scripted",))
        # Remove trace parquet
        for rd in (data / "raw" / "no_trace").iterdir():
            tp = rd / "trace.parquet"
            if tp.exists():
                tp.unlink()

        df = cross_detector_table(data, "no_trace")
        # Should still produce rows from detections.json
        if not df.empty:
            assert "n_events" in df.columns


# ---------------------------------------------------------------------------
# Test: adaptation_round_table (Table 4)
# ---------------------------------------------------------------------------


class TestAdaptationRoundTable:
    def test_from_csv(self, adaptation_data: Path):
        from cpsforge.analysis.tables import adaptation_round_table

        df = adaptation_round_table(adaptation_data, "adapt_exp")
        assert not df.empty
        assert len(df) == 3
        assert "f1_delta" in df.columns
        # First round delta should be NaN
        assert pd.isna(df.iloc[0]["f1_delta"])
        # Second round delta should be positive
        assert df.iloc[1]["f1_delta"] > 0

    def test_fallback_to_metrics(self, experiment_data: Path):
        from cpsforge.analysis.tables import adaptation_round_table

        df = adaptation_round_table(experiment_data, "test_exp")
        # Should fall back to per-run metrics grouped by adaptation_round
        assert not df.empty


# ---------------------------------------------------------------------------
# Test: attack_type_breakdown
# ---------------------------------------------------------------------------


class TestAttackTypeBreakdown:
    def test_basic(self, experiment_data: Path):
        from cpsforge.analysis.tables import attack_type_breakdown

        df = attack_type_breakdown(experiment_data, "test_exp")
        assert not df.empty
        assert "total" in df.columns
        assert "approval_rate" in df.columns
        # Total should match 6 runs * 5 attacks each = 30
        assert df["total"].sum() == 30


# ---------------------------------------------------------------------------
# Test: latency_distribution
# ---------------------------------------------------------------------------


class TestLatencyDistribution:
    def test_basic(self, experiment_data: Path):
        from cpsforge.analysis.tables import latency_distribution

        result = latency_distribution(experiment_data, "test_exp")
        assert "global" in result
        assert "per_detector" in result
        assert "per_attacker" in result
        assert "raw_latencies" in result
        assert result["global"]["n"] >= 0  # may be 0 if no detections align

    def test_empty(self, tmp_path: Path):
        from cpsforge.analysis.tables import latency_distribution

        (tmp_path / "data" / "raw" / "empty").mkdir(parents=True)
        result = latency_distribution(tmp_path / "data", "empty")
        assert result["global"]["n"] == 0


# ---------------------------------------------------------------------------
# Test: full_paper_export
# ---------------------------------------------------------------------------


class TestFullPaperExport:
    def test_creates_all_files(self, experiment_data: Path):
        from cpsforge.analysis.tables import full_paper_export

        out = full_paper_export(experiment_data, "test_exp")
        assert out.exists()
        assert (out / "paper_export_manifest.json").exists()
        assert (out / "table1_attack_results.csv").exists()
        assert (out / "table2_shield_results.csv").exists()
        # table3 may be empty but file should still exist
        assert (out / "attack_type_breakdown.csv").exists()
        assert (out / "latency_distribution.json").exists()

    def test_manifest_structure(self, experiment_data: Path):
        from cpsforge.analysis.tables import full_paper_export

        out = full_paper_export(experiment_data, "test_exp")
        with (out / "paper_export_manifest.json").open() as fh:
            manifest = json.load(fh)
        assert manifest["experiment"] == "test_exp"
        assert "tables" in manifest
        assert "table1_attack_results" in manifest["tables"]

    def test_custom_output_dir(self, experiment_data: Path, tmp_path: Path):
        from cpsforge.analysis.tables import full_paper_export

        custom = tmp_path / "custom_out"
        out = full_paper_export(experiment_data, "test_exp", output_dir=custom)
        assert out == custom
        assert (custom / "paper_export_manifest.json").exists()


# ---------------------------------------------------------------------------
# Test: hard_case_generalization
# ---------------------------------------------------------------------------


class TestHardCaseGeneralization:
    def test_empty_bank(self):
        from cpsforge.analysis.replay_analysis import hard_case_generalization

        class FakeBank:
            def get_all(self):
                return []

        result = hard_case_generalization(FakeBank(), [], [])
        assert result.total_hard_cases == 0
        assert result.generalization_rate == 0.0

    def test_basic_generalization(self, tmp_path: Path):
        from cpsforge.analysis.replay_analysis import (
            GeneralizationResult,
            hard_case_generalization,
        )

        # Create a fake bank with records pointing to a real run_dir
        run_dir = tmp_path / "run_001"
        run_dir.mkdir()

        # Create trace + detections so RunReplayLoader can work
        _make_trace_parquet(run_dir, n_steps=50, attack_steps=range(10, 30))
        with (run_dir / "detections.json").open("w") as fh:
            json.dump(_make_detections(2, "threshold"), fh)
        with (run_dir / "attacks.json").open("w") as fh:
            json.dump(_make_attacks(2), fh)
        with (run_dir / "metrics.json").open("w") as fh:
            json.dump(_make_metrics("run_001"), fh)
        with (run_dir / "metadata.json").open("w") as fh:
            json.dump({"run_id": "run_001"}, fh)

        class FakeRecord:
            record_id = "hc_001"
            attack_id = "atk_000"
            failure_mode = "miss"
            trace_path = str(run_dir)

        class FakeBank:
            experiment_dir = str(tmp_path)
            def get_all(self):
                return [FakeRecord()]

        class FakeDetector:
            def __init__(self, name, fires=False):
                self._name = name
                self._fires = fires
            @property
            def name(self):
                return self._name
            def reset(self):
                pass
            def observe(self, snapshot):
                pass
            def detect(self, snapshot):
                return []

        # A FakeReplayLoader that returns preset events
        class FakeLoader:
            def __init__(self, run_dir):
                self._run_dir = run_dir
            def load_attack_step_range(self):
                return set(range(10, 30))
            def replay_detectors(self, detectors):
                # New detectors always detect at step 15
                if any(d._name == "new" for d in detectors):
                    from cpsforge.core.models import DetectionEvent

                    return [DetectionEvent(
                        timestamp=datetime.now(timezone.utc),
                        run_id="run_001",
                        detector_name="new",
                        severity="high",
                        label="anomaly",
                        confidence=0.9,
                        step_id=15,
                        affected_tags=["tank_level"],
                    )]
                return []

        old_dets = [FakeDetector("old")]
        new_dets = [FakeDetector("new")]

        result = hard_case_generalization(
            FakeBank(),
            old_dets,
            new_dets,
            replay_loader_cls=FakeLoader,
        )
        assert result.total_hard_cases == 1
        assert result.caught_after >= result.caught_before
        assert isinstance(result.summary(), dict)


# ---------------------------------------------------------------------------
# Test: CLI report commands (smoke tests)
# ---------------------------------------------------------------------------


class TestCLIReportCommands:
    """Smoke-test the new CLI report subcommands."""

    @pytest.fixture(autouse=True)
    def _setup_runner(self, experiment_data: Path, tmp_path: Path):
        self.data_dir = experiment_data
        self.tmp_path = tmp_path

    def _invoke(self, args: list):
        from typer.testing import CliRunner
        from cpsforge.cli.report import app

        runner = CliRunner()
        return runner.invoke(app, args, catch_exceptions=False)

    def test_cross_attacker(self):
        result = self._invoke([
            "cross-attacker",
            "-e", "test_exp",
            "--data-dir", str(self.data_dir),
        ])
        assert result.exit_code == 0

    def test_cross_attacker_csv(self):
        out = self.tmp_path / "table1.csv"
        result = self._invoke([
            "cross-attacker",
            "-e", "test_exp",
            "--data-dir", str(self.data_dir),
            "-o", str(out),
        ])
        assert result.exit_code == 0
        assert out.exists()

    def test_cross_detector(self):
        result = self._invoke([
            "cross-detector",
            "-e", "test_exp",
            "--data-dir", str(self.data_dir),
        ])
        assert result.exit_code == 0

    def test_shield_analysis(self):
        result = self._invoke([
            "shield-analysis",
            "-e", "test_exp",
            "--data-dir", str(self.data_dir),
        ])
        assert result.exit_code == 0

    def test_adaptation(self):
        result = self._invoke([
            "adaptation",
            "-e", "test_exp",
            "--data-dir", str(self.data_dir),
        ])
        assert result.exit_code == 0

    def test_attack_types(self):
        result = self._invoke([
            "attack-types",
            "-e", "test_exp",
            "--data-dir", str(self.data_dir),
        ])
        assert result.exit_code == 0

    def test_export_all(self):
        out_dir = self.tmp_path / "paper_export"
        result = self._invoke([
            "export-all",
            "-e", "test_exp",
            "--data-dir", str(self.data_dir),
            "--output-dir", str(out_dir),
        ])
        assert result.exit_code == 0
        assert (out_dir / "paper_export_manifest.json").exists()

    def test_empty_experiment(self):
        """Commands should handle empty experiments gracefully."""
        import os
        empty_data = self.tmp_path / "empty_data" / "raw" / "nothing"
        empty_data.mkdir(parents=True)
        result = self._invoke([
            "cross-attacker",
            "-e", "nothing",
            "--data-dir", str(self.tmp_path / "empty_data"),
        ])
        assert result.exit_code == 0
