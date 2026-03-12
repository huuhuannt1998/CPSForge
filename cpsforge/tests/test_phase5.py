"""
CPSForge Phase 5 Test Suite
============================
Tests for:
  1. HardCaseBank — aggregation, filtering, window extraction
  2. SequenceDetectorTrainer — fit, evaluate, save/load
  3. SequenceModelDetector — buffer, scoring, load model
  4. AdaptationLoop — single round, multi-round, retrain gating
  5. RoundSummary / write_round_metrics
  6. print_round_table (smoke)
  7. CLI smoke tests: adapt train, adapt run-rounds, adapt round-summary,
     run closed-loop (dry-run)

All tests run WITHOUT a live PLC (dry-run only).
Tests that require scikit-learn are skipped when it is not installed.
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent.parent

# Path to the sequence_model defender YAML that may be patched by AdaptationLoop
_SEQ_DEFENDER_YAML = REPO_ROOT / "configs" / "defenders" / "sequence_model_tank_control.yaml"


@pytest.fixture(autouse=True)
def _protect_defender_yaml():
    """
    Save and restore the sequence_model_tank_control.yaml config between tests.
    Prevents adaptation-loop tests from leaving stale model_path values on disk.
    """
    original = _SEQ_DEFENDER_YAML.read_text(encoding="utf-8") if _SEQ_DEFENDER_YAML.exists() else None
    yield
    if original is not None:
        _SEQ_DEFENDER_YAML.write_text(original, encoding="utf-8")


def _invoke_cli(*args: str, **kwargs) -> Any:
    """Invoke the CPSForge CLI via typer CliRunner."""
    from typer.testing import CliRunner
    from cpsforge.cli.app import app

    runner = CliRunner()
    return runner.invoke(app, list(args), catch_exceptions=False, **kwargs)


def _make_run_dir(tmp_path: Path, run_id: str = "test_run") -> Path:
    """Create a minimal run directory with a hard_cases.json."""
    run_dir = tmp_path / run_id
    run_dir.mkdir(parents=True)
    return run_dir


def _write_hard_cases_json(run_dir: Path, n_hard: int = 2) -> None:
    """Write a minimal hard_cases.json to *run_dir*."""
    import uuid
    from cpsforge.core.models import HardCaseFailureMode

    hard_cases = [
        {
            "record_id": str(uuid.uuid4()),
            "run_id": run_dir.name,
            "attack_id": str(uuid.uuid4()),
            "detector_outcome": "miss",
            "failure_mode": HardCaseFailureMode.MISS.value,
            "trace_path": str(run_dir),
            "summary": f"Test hard case {i}",
            "recommended_followup": "Retrain",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        for i in range(n_hard)
    ]
    data = {
        "run_id": run_dir.name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "hard_case_count": n_hard,
        "total_executed": n_hard,
        "outcomes": [],
        "hard_cases": hard_cases,
    }
    (run_dir / "hard_cases.json").write_text(json.dumps(data))


def _write_trace_parquet(run_dir: Path, n_steps: int = 40) -> None:
    """Write a minimal trace.parquet to *run_dir*."""
    import pandas as pd

    rows = []
    for i in range(n_steps):
        rows.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "step_id": i,
            "scene_name": "tank_control",
            "run_id": run_dir.name,
            "attack_active": i >= 10 and i < 20,
            "attack_action_id": "attack-abc" if (10 <= i < 20) else None,
            "sensor__tank_level": 50.0 + i * 0.1,
            "actuator__pump_speed": 60.0,
            "setpoint__level_setpoint": 60.0,
            "feat__level_rate": 0.1,
        })
    df = pd.DataFrame(rows)
    df.to_parquet(run_dir / "trace.parquet", index=False)


def _make_windows(n: int = 10, window_size: int = 10, n_feat: int = 4) -> List[np.ndarray]:
    rng = np.random.default_rng(42)
    return [rng.random((window_size, n_feat)).astype(np.float32) for _ in range(n)]


# ---------------------------------------------------------------------------
# 1. HardCaseBank
# ---------------------------------------------------------------------------


class TestHardCaseBank:
    def test_empty_bank(self, tmp_path):
        from cpsforge.adaptation.bank import HardCaseBank

        bank = HardCaseBank(tmp_path / "nonexistent", window_size=10)
        assert bank.count == 0

    def test_load_from_experiment(self, tmp_path):
        from cpsforge.adaptation.bank import HardCaseBank

        for i in range(3):
            run_dir = _make_run_dir(tmp_path, f"run_{i:04d}")
            _write_hard_cases_json(run_dir, n_hard=2)

        bank = HardCaseBank(tmp_path, window_size=10)
        loaded = bank.load_from_experiment()
        assert loaded == 6
        assert bank.count == 6

    def test_idempotent_load(self, tmp_path):
        from cpsforge.adaptation.bank import HardCaseBank

        run_dir = _make_run_dir(tmp_path, "run_0001")
        _write_hard_cases_json(run_dir, n_hard=3)

        bank = HardCaseBank(tmp_path, window_size=10)
        bank.load_from_experiment()
        n1 = bank.count
        bank.load_from_experiment()  # second call — should not double-count
        assert bank.count == n1

    def test_load_from_run(self, tmp_path):
        from cpsforge.adaptation.bank import HardCaseBank

        run_dir = _make_run_dir(tmp_path, "single_run")
        _write_hard_cases_json(run_dir, n_hard=4)

        bank = HardCaseBank(tmp_path, window_size=10)
        n = bank.load_from_run(run_dir)
        assert n == 4
        assert bank.count == 4

    def test_failure_mode_filter(self, tmp_path):
        from cpsforge.adaptation.bank import HardCaseBank

        run_dir = _make_run_dir(tmp_path, "run_fm")
        _write_hard_cases_json(run_dir, n_hard=5)

        bank = HardCaseBank(tmp_path, window_size=10)
        bank.load_from_experiment(failure_modes=["miss"])
        # All hard cases in helper have failure_mode="miss"
        assert bank.count == 5

    def test_failure_mode_filter_empty(self, tmp_path):
        from cpsforge.adaptation.bank import HardCaseBank

        run_dir = _make_run_dir(tmp_path, "run_fm2")
        _write_hard_cases_json(run_dir, n_hard=5)

        bank = HardCaseBank(tmp_path, window_size=10)
        bank.load_from_experiment(failure_modes=["late_detection"])
        # None have late_detection
        assert bank.count == 0

    def test_summary_fields(self, tmp_path):
        from cpsforge.adaptation.bank import HardCaseBank

        run_dir = _make_run_dir(tmp_path, "run_s")
        _write_hard_cases_json(run_dir, n_hard=2)

        bank = HardCaseBank(tmp_path, window_size=10)
        bank.load_from_experiment()
        s = bank.summary()
        assert s["total_hard_cases"] == 2
        assert s["loaded_runs"] == 1
        assert "miss" in s["failure_mode_counts"]

    def test_get_attack_windows_with_trace(self, tmp_path):
        from cpsforge.adaptation.bank import HardCaseBank

        run_dir = _make_run_dir(tmp_path, "run_w")
        _write_hard_cases_json(run_dir, n_hard=1)
        _write_trace_parquet(run_dir, n_steps=40)

        # Patch the trace_path in hard_cases.json to point to run_dir
        hc_path = run_dir / "hard_cases.json"
        raw = json.loads(hc_path.read_text())
        for rec in raw["hard_cases"]:
            rec["trace_path"] = str(run_dir)
            rec["attack_id"] = "attack-abc"  # matches the parquet
        hc_path.write_text(json.dumps(raw))

        bank = HardCaseBank(tmp_path, window_size=10)
        bank.load_from_experiment()
        windows = bank.get_attack_windows(window_before=5, window_after=10)
        assert len(windows) >= 1
        arr, mode, run_id = windows[0]
        assert arr.ndim == 2
        assert mode == "miss"

    def test_get_normal_windows(self, tmp_path):
        from cpsforge.adaptation.bank import HardCaseBank

        run_dir = _make_run_dir(tmp_path, "baseline_run")
        _write_trace_parquet(run_dir, n_steps=100)

        bank = HardCaseBank(tmp_path, window_size=10)
        windows = bank.get_normal_windows(
            baseline_run_dirs=[run_dir],
            num_windows=20,
            window_size=10,
        )
        assert len(windows) > 0
        assert windows[0].shape == (10, 4)  # 4 feature columns

    def test_export_manifest(self, tmp_path):
        from cpsforge.adaptation.bank import HardCaseBank

        run_dir = _make_run_dir(tmp_path, "run_manifest")
        _write_hard_cases_json(run_dir, n_hard=2)

        bank = HardCaseBank(tmp_path, window_size=10)
        bank.load_from_experiment()

        manifest_path = tmp_path / "manifest.json"
        bank.export_manifest(manifest_path)
        assert manifest_path.exists()
        data = json.loads(manifest_path.read_text())
        assert data["summary"]["total_hard_cases"] == 2
        assert len(data["records"]) == 2


# ---------------------------------------------------------------------------
# 2. get_feature_columns / find_attack_start_step
# ---------------------------------------------------------------------------


class TestBankHelpers:
    def test_get_feature_columns(self):
        import pandas as pd
        from cpsforge.adaptation.bank import get_feature_columns

        df = pd.DataFrame({
            "timestamp": [],
            "step_id": [],
            "sensor__tank_level": [],
            "actuator__pump": [],
            "alarm__high": [],
            "setpoint__sp": [],
            "feat__rate": [],
            "ctrl__pid": [],
        })
        cols = get_feature_columns(df)
        assert "sensor__tank_level" in cols
        assert "actuator__pump" in cols
        assert "setpoint__sp" in cols
        assert "feat__rate" in cols
        assert "ctrl__pid" in cols
        assert "timestamp" not in cols
        assert "step_id" not in cols

    def test_find_attack_start_step(self):
        import pandas as pd
        from cpsforge.adaptation.bank import find_attack_start_step

        df = pd.DataFrame({
            "step_id": [0, 1, 2, 3, 4],
            "attack_action_id": [None, None, "abc", "abc", None],
        })
        step = find_attack_start_step(df, "abc")
        assert step == 2

    def test_find_attack_start_step_not_found(self):
        import pandas as pd
        from cpsforge.adaptation.bank import find_attack_start_step

        df = pd.DataFrame({
            "step_id": [0, 1, 2],
            "attack_action_id": [None, None, None],
        })
        assert find_attack_start_step(df, "nonexistent") is None


# ---------------------------------------------------------------------------
# 3. SequenceDetectorTrainer
# ---------------------------------------------------------------------------

pytest.importorskip("sklearn", reason="scikit-learn not installed")


class TestSequenceDetectorTrainer:
    def test_fit_basic(self):
        from cpsforge.adaptation.trainer import SequenceDetectorTrainer

        trainer = SequenceDetectorTrainer(random_state=42)
        normal = _make_windows(n=30, window_size=10, n_feat=4)
        meta = trainer.fit(normal)
        assert trainer.is_trained
        assert meta["n_normal_windows"] == 30
        assert "contamination" in meta

    def test_fit_with_hard_cases(self):
        from cpsforge.adaptation.trainer import SequenceDetectorTrainer

        trainer = SequenceDetectorTrainer(random_state=42)
        normal = _make_windows(n=30, window_size=10, n_feat=4)
        hard = _make_windows(n=5, window_size=10, n_feat=4)
        meta = trainer.fit(normal, hard)
        assert meta["n_hard_case_windows"] == 5
        assert meta["contamination"] > 0

    def test_fit_requires_min_normal(self):
        from cpsforge.adaptation.trainer import SequenceDetectorTrainer

        trainer = SequenceDetectorTrainer()
        with pytest.raises(ValueError, match="at least 2"):
            trainer.fit([_make_windows(n=1)[0]])

    def test_evaluate(self):
        from cpsforge.adaptation.trainer import SequenceDetectorTrainer

        rng = np.random.default_rng(0)
        normal = [rng.random((10, 4)).astype(np.float32) for _ in range(20)]
        # Anomaly windows have much higher values
        anomaly = [(rng.random((10, 4)) * 10 + 5).astype(np.float32) for _ in range(10)]

        trainer = SequenceDetectorTrainer(random_state=0)
        trainer.fit(normal, anomaly)
        result = trainer.evaluate(normal[:5], anomaly[:5])
        assert "precision" in result
        assert "recall" in result
        assert "f1" in result
        assert "n_evaluated" in result
        assert result["n_evaluated"] == 10

    def test_evaluate_empty(self):
        from cpsforge.adaptation.trainer import SequenceDetectorTrainer

        trainer = SequenceDetectorTrainer(random_state=42)
        trainer.fit(_make_windows(5))
        result = trainer.evaluate([], [])
        assert result["n_evaluated"] == 0

    def test_save_load(self, tmp_path):
        from cpsforge.adaptation.trainer import SequenceDetectorTrainer

        model_path = tmp_path / "model.pkl"
        trainer = SequenceDetectorTrainer(random_state=42)
        trainer.fit(_make_windows(10, window_size=8, n_feat=3))
        trainer.save(model_path)
        assert model_path.exists()

        loaded = SequenceDetectorTrainer.load(model_path)
        assert loaded.is_trained
        assert loaded.training_meta["n_estimators"] == 100

    def test_save_before_fit_raises(self, tmp_path):
        from cpsforge.adaptation.trainer import SequenceDetectorTrainer

        trainer = SequenceDetectorTrainer()
        with pytest.raises(RuntimeError, match="call fit()"):
            trainer.save(tmp_path / "model.pkl")

    def test_load_missing_file(self, tmp_path):
        from cpsforge.adaptation.trainer import SequenceDetectorTrainer

        with pytest.raises(FileNotFoundError):
            SequenceDetectorTrainer.load(tmp_path / "no_such_file.pkl")


# ---------------------------------------------------------------------------
# 4. SequenceModelDetector
# ---------------------------------------------------------------------------


class TestSequenceModelDetector:
    def _make_cfg(self, model_path: str = "", threshold: float = 0.5, ws: int = 5):
        from cpsforge.core.config import DefenderConfig

        return DefenderConfig(
            name="test_seq",
            detector_type="sequence_model",
            scene_name="tank_control",
            window_size=ws,
            anomaly_threshold=threshold,
            model_path=model_path,
        )

    def _make_snapshot(self, level: float = 50.0, step: int = 0):
        from cpsforge.core.models import PlantSnapshot

        return PlantSnapshot(
            scene_name="tank_control",
            run_id="r0",
            step_id=step,
            sensors={"tank_level": level},
            actuators={"pump_speed": 60.0},
            setpoints={"level_setpoint": 60.0},
            derived_features={"level_rate": 0.1},
        )

    def test_untrained_no_detections(self):
        from cpsforge.defenders.sequence_model import SequenceModelDetector

        det = SequenceModelDetector(self._make_cfg())
        snap = self._make_snapshot()
        events = det.detect(snap)
        assert events == []

    def test_buffer_fills_gradually(self):
        from cpsforge.defenders.sequence_model import SequenceModelDetector

        det = SequenceModelDetector(self._make_cfg(ws=5))
        for i in range(4):
            det.observe(self._make_snapshot(step=i))
        # Buffer not full yet
        assert len(det._buffer) == 4

    def test_reset_clears_buffer(self):
        from cpsforge.defenders.sequence_model import SequenceModelDetector

        det = SequenceModelDetector(self._make_cfg(ws=5))
        for i in range(3):
            det.observe(self._make_snapshot(step=i))
        det.reset()
        assert len(det._buffer) == 0
        assert det._step_count == 0

    def test_export_state(self):
        from cpsforge.defenders.sequence_model import SequenceModelDetector

        det = SequenceModelDetector(self._make_cfg())
        state = det.export_state()
        assert state["name"] == "test_seq"
        assert state["trained"] is False
        assert state["window_size"] == 5

    def test_trained_detector_produces_events(self, tmp_path):
        """After loading a trained model, anomalous windows should fire events."""
        from cpsforge.adaptation.trainer import SequenceDetectorTrainer
        from cpsforge.defenders.sequence_model import (
            SequenceModelDetector,
            _snapshot_to_vector,
        )

        # Train on low-value normal data
        rng = np.random.default_rng(7)
        normal = [rng.random((5, 4)).astype(np.float32) * 0.1 for _ in range(20)]
        trainer = SequenceDetectorTrainer(random_state=7)
        trainer.fit(normal)

        model_path = tmp_path / "seq.pkl"
        trainer.save(model_path)

        cfg = self._make_cfg(model_path=str(model_path), threshold=0.01, ws=5)
        det = SequenceModelDetector(cfg)
        assert det._trained

        # Feed anomalous snapshots (high values far from normal distribution)
        events_total = []
        for i in range(5):
            snap = self._make_snapshot(level=999.0 + i * 10, step=i)
            events = det.detect(snap)
            events_total.extend(events)

        # Should have at least one detection across the window
        assert len(events_total) >= 1
        ev = events_total[0]
        assert ev.label == "sequence_anomaly"
        assert 0.0 <= ev.confidence <= 1.0

    def test_load_missing_model_graceful(self):
        from cpsforge.defenders.sequence_model import SequenceModelDetector

        cfg = self._make_cfg(model_path="/nonexistent/path/model.pkl")
        det = SequenceModelDetector(cfg)
        assert not det._trained  # graceful failure, no crash

    def test_snapshot_to_vector_empty(self):
        from cpsforge.defenders.sequence_model import _snapshot_to_vector
        from cpsforge.core.models import PlantSnapshot

        snap = PlantSnapshot(scene_name="s", run_id="r", step_id=0)
        # Empty snapshot yields None
        result = _snapshot_to_vector(snap)
        assert result is None


# ---------------------------------------------------------------------------
# 5. RoundSummary and round metrics
# ---------------------------------------------------------------------------


class TestRoundMetrics:
    def _make_eval_metrics(self, run_id: str = "r0", f1: float = 0.6):
        from cpsforge.core.models import EvalMetrics

        return EvalMetrics(
            run_id=run_id,
            scene_name="tank_control",
            attacker_name="scripted",
            detector_names=["threshold", "invariant"],
            detector_f1=f1,
            detector_precision=f1,
            detector_recall=f1,
            detection_latency_ms=1200.0,
            false_positives=2,
            false_negatives=1,
            attack_success_rate=0.4,
            shield_rejection_rate=0.1,
            total_steps=200,
            total_attacks=10,
            eval_run=True,
        )

    def test_from_eval_metrics(self):
        from cpsforge.adaptation.round_metrics import RoundSummary

        m = self._make_eval_metrics("r0", f1=0.72)
        s = RoundSummary.from_eval_metrics(
            round_idx=0,
            run_id="r0",
            metrics=m,
            hard_case_count=3,
            hard_case_cumulative=3,
        )
        assert s.round_idx == 0
        assert s.detector_f1 == pytest.approx(0.72)
        assert s.hard_case_count == 3

    def test_from_none_metrics(self):
        from cpsforge.adaptation.round_metrics import RoundSummary

        s = RoundSummary.from_eval_metrics(0, "r0", None, 0, 0)
        assert s.detector_f1 == 0.0

    def test_write_round_metrics_creates_files(self, tmp_path):
        from cpsforge.adaptation.round_metrics import RoundSummary, write_round_metrics

        summaries = [
            RoundSummary.from_eval_metrics(
                round_idx=i,
                run_id=f"r{i}",
                metrics=self._make_eval_metrics(f"r{i}", f1=0.5 + i * 0.1),
                hard_case_count=i * 2,
                hard_case_cumulative=i * 4,
                retrained=(i > 0),
            )
            for i in range(3)
        ]
        write_round_metrics(summaries, tmp_path, "test_exp")

        assert (tmp_path / "round_metrics.csv").exists()
        assert (tmp_path / "round_summary.json").exists()

    def test_round_summary_json_content(self, tmp_path):
        from cpsforge.adaptation.round_metrics import RoundSummary, write_round_metrics

        summaries = [
            RoundSummary.from_eval_metrics(
                0, "r0",
                self._make_eval_metrics("r0", f1=0.5),
                hard_case_count=2, hard_case_cumulative=2,
            ),
            RoundSummary.from_eval_metrics(
                1, "r1",
                self._make_eval_metrics("r1", f1=0.75),
                hard_case_count=3, hard_case_cumulative=5,
                retrained=True,
            ),
        ]
        write_round_metrics(summaries, tmp_path, "test_exp")
        summary = json.loads((tmp_path / "round_summary.json").read_text())
        assert summary["n_rounds"] == 2
        assert summary["f1_improvement"] == pytest.approx(0.25)
        assert summary["rounds_with_retraining"] == 1

    def test_print_round_table_smoke(self, capsys):
        from cpsforge.adaptation.round_metrics import RoundSummary, print_round_table

        summaries = [
            RoundSummary.from_eval_metrics(
                0, "r0",
                None,
                hard_case_count=0, hard_case_cumulative=0,
            )
        ]
        # Should not raise
        print_round_table(summaries)

    def test_round_metrics_csv_columns(self, tmp_path):
        import csv
        from cpsforge.adaptation.round_metrics import RoundSummary, write_round_metrics

        summaries = [
            RoundSummary.from_eval_metrics(
                0, "r0", None, 0, 0
            )
        ]
        write_round_metrics(summaries, tmp_path)
        with (tmp_path / "round_metrics.csv").open(newline="") as fh:
            reader = csv.DictReader(fh)
            headers = reader.fieldnames or []
        assert "round_idx" in headers
        assert "detector_f1" in headers
        assert "hard_case_count" in headers
        assert "retrained" in headers


# ---------------------------------------------------------------------------
# 6. AdaptationLoop — unit-level tests
# ---------------------------------------------------------------------------


class TestAdaptationLoop:
    def _make_base_config(self, tmp_dir: Path) -> Any:
        """Build a minimal ExperimentConfig for adaptation loop tests."""
        from cpsforge.core.config import ExperimentConfig

        return ExperimentConfig(
            name="test_adapt",
            scene_config="scenes/tank_control.yaml",
            attackers=["scripted_tank_control"],
            defenders=["threshold_tank_control"],
            dry_run=True,
            live_writes_enabled=False,
            max_steps=5,    # very short for speed
            save_metrics=True,
        )

    def test_round_result_fields(self):
        from cpsforge.adaptation.adaptation_loop import RoundResult

        rr = RoundResult(
            round_idx=0,
            run_id="r0",
            metrics=None,
            hard_case_count=0,
            hard_case_cumulative=0,
            retrained=False,
            model_path=None,
            run_dir=Path("/tmp/r0"),
        )
        assert rr.round_idx == 0
        assert rr.retrained is False

    def test_has_sequence_defender_false(self, tmp_path):
        from cpsforge.adaptation.adaptation_loop import AdaptationLoop
        from cpsforge.core.config import ConfigLoader

        loader = ConfigLoader()
        cfg = self._make_base_config(tmp_path)
        cfg.defenders = ["threshold_tank_control"]

        loop = AdaptationLoop(
            base_config=cfg,
            loader=loader,
            n_rounds=2,
            data_dir=tmp_path,
        )
        # threshold defender is not sequence_model type
        assert loop._has_sequence_defender() is False

    def test_has_sequence_defender_true(self, tmp_path):
        from cpsforge.adaptation.adaptation_loop import AdaptationLoop
        from cpsforge.core.config import ConfigLoader

        loader = ConfigLoader()
        cfg = self._make_base_config(tmp_path)
        cfg.defenders = ["sequence_model_tank_control"]

        loop = AdaptationLoop(
            base_config=cfg,
            loader=loader,
            n_rounds=2,
            data_dir=tmp_path,
        )
        assert loop._has_sequence_defender() is True

    def test_retrain_skipped_below_threshold(self, tmp_path):
        from cpsforge.adaptation.adaptation_loop import AdaptationLoop
        from cpsforge.core.config import ConfigLoader

        loader = ConfigLoader()
        cfg = self._make_base_config(tmp_path)
        cfg.defenders = ["sequence_model_tank_control"]

        loop = AdaptationLoop(
            base_config=cfg,
            loader=loader,
            n_rounds=3,
            data_dir=tmp_path,
            min_hard_cases_to_retrain=100,  # high threshold
        )
        # Bank is empty, so retrain should be skipped
        retrained = loop._maybe_retrain(round_idx=1)
        assert retrained is False

    def test_build_round_config_increments_round(self, tmp_path):
        from cpsforge.adaptation.adaptation_loop import AdaptationLoop
        from cpsforge.core.config import ConfigLoader

        loader = ConfigLoader()
        cfg = self._make_base_config(tmp_path)

        loop = AdaptationLoop(
            base_config=cfg,
            loader=loader,
            n_rounds=3,
            data_dir=tmp_path,
        )
        round_cfg = loop._build_round_config(2)
        assert round_cfg.adaptation_round == 2

    def test_run_writes_summaries(self, tmp_path):
        """
        Run the adaptation loop with the real orchestrator (dry-run, 5 steps).
        Verify that round_metrics.csv and round_summary.json are written.
        """
        from cpsforge.adaptation.adaptation_loop import AdaptationLoop
        from cpsforge.core.config import ConfigLoader

        loader = ConfigLoader()
        cfg = self._make_base_config(tmp_path)
        cfg.name = "test_adapt"
        cfg.save_metrics = True

        loop = AdaptationLoop(
            base_config=cfg,
            loader=loader,
            n_rounds=2,
            experiment_name="test_adapt",
            data_dir=tmp_path,
            min_hard_cases_to_retrain=999,  # never retrain in this test
        )
        results = loop.run()

        assert len(results) == 2
        assert all(r.run_id for r in results)

        processed_dir = tmp_path / "processed" / "test_adapt"
        assert (processed_dir / "round_metrics.csv").exists()
        assert (processed_dir / "round_summary.json").exists()

    def test_retrain_actually_trains(self, tmp_path):
        """
        Populate bank with hard cases (via JSON) and enough trace data,
        then call _retrain and verify a model file is written.
        """
        from cpsforge.adaptation.adaptation_loop import AdaptationLoop
        from cpsforge.core.config import ConfigLoader

        loader = ConfigLoader()
        cfg = self._make_base_config(tmp_path)
        cfg.defenders = ["sequence_model_tank_control"]

        loop = AdaptationLoop(
            base_config=cfg,
            loader=loader,
            n_rounds=1,
            experiment_name="test_retrain",
            data_dir=tmp_path,
            min_hard_cases_to_retrain=2,
        )

        # Manually inject hard cases and traces into bank
        run_dir = tmp_path / "raw" / "test_retrain" / "run_0001"
        run_dir.mkdir(parents=True)
        _write_hard_cases_json(run_dir, n_hard=3)
        _write_trace_parquet(run_dir, n_steps=60)
        # Fix trace_path in hard_cases.json
        hc_path = run_dir / "hard_cases.json"
        raw = json.loads(hc_path.read_text())
        for rec in raw["hard_cases"]:
            rec["trace_path"] = str(run_dir)
        hc_path.write_text(json.dumps(raw))

        loop._bank.load_from_run(run_dir)
        assert loop._bank.count >= 2

        retrained = loop._retrain(round_idx=1)
        assert retrained is True
        assert loop._current_model_path is not None
        assert loop._current_model_path.exists()


# ---------------------------------------------------------------------------
# 7. CLI smoke tests
# ---------------------------------------------------------------------------


class TestAdaptCLI:
    def test_list_hard_cases_no_runs(self, tmp_path):
        result = _invoke_cli(
            "adapt", "list-hard-cases",
            "--experiment", "nonexistent",
            "--data-dir", str(tmp_path),
        )
        # Should exit with code 1 (directory not found)
        assert result.exit_code == 1

    def test_list_hard_cases_empty(self, tmp_path):
        exp_dir = tmp_path / "raw" / "test_exp"
        exp_dir.mkdir(parents=True)
        result = _invoke_cli(
            "adapt", "list-hard-cases",
            "--experiment", "test_exp",
            "--data-dir", str(tmp_path),
        )
        # Empty experiment — exits clean
        assert result.exit_code == 0

    def test_list_hard_cases_with_data(self, tmp_path):
        exp_dir = tmp_path / "raw" / "exp1"
        run_dir = exp_dir / "run_001"
        run_dir.mkdir(parents=True)
        _write_hard_cases_json(run_dir, n_hard=2)

        result = _invoke_cli(
            "adapt", "list-hard-cases",
            "--experiment", "exp1",
            "--data-dir", str(tmp_path),
        )
        assert result.exit_code == 0
        assert "hard case" in result.output.lower() or "miss" in result.output.lower()

    def test_train_missing_experiment(self, tmp_path):
        result = _invoke_cli(
            "adapt", "train",
            "--experiment", "nonexistent",
            "--data-dir", str(tmp_path),
        )
        assert result.exit_code == 1

    def test_train_dry_run_flag(self, tmp_path):
        """train --dry-run should report readiness and exit 0."""
        exp_dir = tmp_path / "raw" / "exp_train"
        run_dir = exp_dir / "run_001"
        run_dir.mkdir(parents=True)
        _write_hard_cases_json(run_dir, n_hard=12)
        _write_trace_parquet(run_dir, n_steps=60)

        result = _invoke_cli(
            "adapt", "train",
            "--experiment", "exp_train",
            "--data-dir", str(tmp_path),
            "--dry-run",
        )
        assert result.exit_code == 0

    def test_round_summary_missing(self, tmp_path):
        result = _invoke_cli(
            "adapt", "round-summary",
            "--experiment", "nonexistent",
            "--data-dir", str(tmp_path),
        )
        assert result.exit_code == 1

    def test_round_summary_reads_csv(self, tmp_path):
        """Write round_metrics.csv manually then verify round-summary reads it."""
        from cpsforge.adaptation.round_metrics import RoundSummary, write_round_metrics

        processed_dir = tmp_path / "processed" / "exp_rs"
        summaries = [
            RoundSummary.from_eval_metrics(
                0, "r0", None, 0, 0
            ),
            RoundSummary.from_eval_metrics(
                1, "r1", None, 3, 3, retrained=True
            ),
        ]
        write_round_metrics(summaries, processed_dir, "exp_rs")

        result = _invoke_cli(
            "adapt", "round-summary",
            "--experiment", "exp_rs",
            "--data-dir", str(tmp_path),
        )
        assert result.exit_code == 0


class TestRunClosedLoopCLI:
    def test_closed_loop_dry_run(self, tmp_path):
        """Smoke test: closed-loop with 2 rounds, dry-run, no PLC."""
        result = _invoke_cli(
            "run", "closed-loop",
            "--scene", "tank_control",
            "--rounds", "2",
            "--max-steps", "5",
            "--experiment", "test_cl",
            "--dry-run",
            "--output-dir", str(tmp_path),
        )
        assert result.exit_code == 0
        assert "complete" in result.output.lower()
