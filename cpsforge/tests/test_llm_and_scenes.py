"""
CPSForge Tests -- LLM Provider, Model Metadata, Cross-Model Reporting, and New Scenes
========================================================================================
Tests covering:
  1. LocalOpenAICompatibleProvider (mocked httpx)
  2. LLMAttacker.get_run_metadata()
  3. cross_model_table() analysis function
  4. New scene classes (FromAtoB, LevelControl, SortingHeightBasic)
  5. Scene factory registration

All tests run WITHOUT a live LLM API (mock-only).
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent.parent


def _make_snapshot(
    scene_name: str = "tank_control",
    sensors: dict | None = None,
    actuators: dict | None = None,
    setpoints: dict | None = None,
    controller_state: dict | None = None,
    alarms: dict | None = None,
    step_id: int = 0,
) -> Any:
    from cpsforge.core.models import PlantSnapshot
    return PlantSnapshot(
        scene_name=scene_name,
        run_id="r1",
        step_id=step_id,
        sensors=sensors or {},
        actuators=actuators or {},
        setpoints=setpoints or {},
        controller_state=controller_state or {},
        alarms=alarms or {},
    )


def _make_mock_provider(response_text: str = "[]") -> MagicMock:
    from cpsforge.llm.base_provider import CompletionResult
    provider = MagicMock()
    provider.provider_name = "mock"
    provider.model_name = "test-model"
    result = CompletionResult(
        text=response_text,
        input_tokens=10,
        output_tokens=20,
        latency_ms=150.0,
        model="test-model",
        finish_reason="stop",
    )
    provider.complete.return_value = result
    return provider


# ===========================================================================
# 1. LocalOpenAICompatibleProvider
# ===========================================================================

class TestLocalOpenAICompatibleProvider:
    """Unit tests for LocalOpenAICompatibleProvider with mocked HTTP."""

    def test_complete_sends_correct_payload(self):
        """Verify the HTTP POST payload matches OpenAI chat/completions format."""
        from cpsforge.llm.local_openai_provider import LocalOpenAICompatibleProvider
        from cpsforge.core.config import LLMConfig

        cfg = LLMConfig(
            provider="local_openai_compatible",
            model="test-model",
            base_url="http://localhost:9999/v1",
            max_tokens=512,
            temperature=0.3,
        )
        provider = LocalOpenAICompatibleProvider(cfg)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [
                {"message": {"content": "hello"}, "finish_reason": "stop"}
            ],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3},
            "model": "test-model",
        }

        with patch.object(provider._http, "post", return_value=mock_response) as mock_post:
            result = provider.complete("sys prompt", "user prompt")
            mock_post.assert_called_once()
            call_kwargs = mock_post.call_args
            payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")

            assert payload["model"] == "test-model"
            assert payload["temperature"] == 0.3
            assert payload["max_tokens"] == 512
            assert payload["stream"] is False
            assert len(payload["messages"]) == 2
            assert payload["messages"][0]["role"] == "system"
            assert payload["messages"][1]["role"] == "user"

        assert result.text == "hello"
        assert result.input_tokens == 5
        assert result.output_tokens == 3
        assert result.finish_reason == "stop"
        provider.close()

    def test_complete_raises_on_timeout(self):
        """ProviderError raised when the server times out."""
        import httpx
        from cpsforge.llm.local_openai_provider import LocalOpenAICompatibleProvider
        from cpsforge.llm.base_provider import ProviderError
        from cpsforge.core.config import LLMConfig

        cfg = LLMConfig(
            provider="local_openai_compatible",
            model="test-model",
            base_url="http://localhost:9999/v1",
        )
        provider = LocalOpenAICompatibleProvider(cfg)

        with patch.object(provider._http, "post", side_effect=httpx.TimeoutException("timeout")):
            with pytest.raises(ProviderError, match="timed out"):
                provider.complete("sys", "usr")
        provider.close()

    def test_complete_raises_on_connect_error(self):
        """ProviderError raised when server is unreachable."""
        import httpx
        from cpsforge.llm.local_openai_provider import LocalOpenAICompatibleProvider
        from cpsforge.llm.base_provider import ProviderError
        from cpsforge.core.config import LLMConfig

        cfg = LLMConfig(
            provider="local_openai_compatible",
            model="m",
            base_url="http://localhost:9999/v1",
        )
        provider = LocalOpenAICompatibleProvider(cfg)

        with patch.object(provider._http, "post", side_effect=httpx.ConnectError("refused")):
            with pytest.raises(ProviderError, match="Cannot connect"):
                provider.complete("sys", "usr")
        provider.close()

    def test_complete_raises_on_non_200(self):
        """ProviderError raised on non-200 HTTP status."""
        from cpsforge.llm.local_openai_provider import LocalOpenAICompatibleProvider
        from cpsforge.llm.base_provider import ProviderError
        from cpsforge.core.config import LLMConfig

        cfg = LLMConfig(
            provider="local_openai_compatible",
            model="m",
            base_url="http://localhost:9999/v1",
        )
        provider = LocalOpenAICompatibleProvider(cfg)

        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"
        with patch.object(provider._http, "post", return_value=mock_resp):
            with pytest.raises(ProviderError, match="HTTP 500"):
                provider.complete("sys", "usr")
        provider.close()

    def test_complete_raises_on_empty_choices(self):
        """ProviderError raised when choices array is empty."""
        from cpsforge.llm.local_openai_provider import LocalOpenAICompatibleProvider
        from cpsforge.llm.base_provider import ProviderError
        from cpsforge.core.config import LLMConfig

        cfg = LLMConfig(
            provider="local_openai_compatible",
            model="m",
            base_url="http://localhost:9999/v1",
        )
        provider = LocalOpenAICompatibleProvider(cfg)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"choices": [], "usage": {}}
        with patch.object(provider._http, "post", return_value=mock_resp):
            with pytest.raises(ProviderError, match="empty"):
                provider.complete("sys", "usr")
        provider.close()

    def test_health_check_success(self):
        """health_check returns True on 200."""
        from cpsforge.llm.local_openai_provider import LocalOpenAICompatibleProvider
        from cpsforge.core.config import LLMConfig

        cfg = LLMConfig(
            provider="local_openai_compatible",
            model="m",
            base_url="http://localhost:9999/v1",
        )
        provider = LocalOpenAICompatibleProvider(cfg)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch.object(provider._http, "get", return_value=mock_resp):
            assert provider.health_check() is True
        provider.close()

    def test_health_check_failure(self):
        """health_check returns False on connection error."""
        import httpx
        from cpsforge.llm.local_openai_provider import LocalOpenAICompatibleProvider
        from cpsforge.core.config import LLMConfig

        cfg = LLMConfig(
            provider="local_openai_compatible",
            model="m",
            base_url="http://localhost:9999/v1",
        )
        provider = LocalOpenAICompatibleProvider(cfg)

        with patch.object(provider._http, "get", side_effect=httpx.ConnectError("nope")):
            assert provider.health_check() is False
        provider.close()

    def test_provider_name_and_model_name(self):
        from cpsforge.llm.local_openai_provider import LocalOpenAICompatibleProvider
        from cpsforge.core.config import LLMConfig

        cfg = LLMConfig(
            provider="local_openai_compatible",
            model="my-model",
            base_url="http://localhost:9999/v1",
        )
        provider = LocalOpenAICompatibleProvider(cfg)
        assert provider.provider_name == "local_openai_compatible"
        assert provider.model_name == "my-model"
        provider.close()


# ===========================================================================
# 2. LLMAttacker model metadata
# ===========================================================================

class TestLLMAttackerMetadata:
    """Tests for per-run model metadata collection."""

    def _make_attack_policy(self):
        from cpsforge.core.config import AttackPolicyConfig
        return AttackPolicyConfig(
            name="test_meta",
            attacker_type="llm",
            scene_name="tank_control",
            llm_provider="local_openai_compatible",
            max_actions=3,
            attack_types=["actuator_override", "setpoint_shift"],
            llm_max_retries=3,
        )

    def _make_scene(self):
        scene = MagicMock()
        profile = MagicMock()
        profile.scene_name = "tank_control"
        profile.description = "Test"
        profile.attack_surface = ["pump_speed", "level_setpoint"]
        profile.tags = []
        scene.profile = profile
        scene.name = "tank_control"
        scene.get_latest_snapshot = MagicMock(return_value=None)
        return scene

    def test_get_run_metadata_fields(self):
        """get_run_metadata returns all expected fields."""
        from cpsforge.llm.attacker import LLMAttacker

        valid_action = json.dumps([{
            "attack_type": "actuator_override",
            "target": "pump_speed",
            "value": 0.0,
            "duration_ms": 5000,
            "rationale": "test",
            "expected_effect": "test",
            "confidence": 0.9,
        }])
        provider = _make_mock_provider(valid_action)
        attacker = LLMAttacker(self._make_attack_policy(), provider=provider)
        attacker.generate_actions(self._make_scene())

        meta = attacker.get_run_metadata()
        assert meta["llm_provider"] == "mock"
        assert meta["llm_model"] == "test-model"
        assert meta["llm_total_calls"] == 1
        assert meta["llm_parse_successes"] == 1
        assert meta["llm_parse_failures"] == 0
        assert meta["llm_parse_success_rate"] == 1.0
        assert meta["llm_total_retries"] == 0
        assert meta["llm_avg_latency_ms"] > 0
        assert meta["llm_max_latency_ms"] > 0

    def test_metadata_tracks_failures(self):
        """get_run_metadata correctly counts parse failures on bad JSON."""
        from cpsforge.llm.attacker import LLMAttacker
        from cpsforge.llm.base_provider import CompletionResult

        valid_action = json.dumps([{
            "attack_type": "actuator_override",
            "target": "pump_speed",
            "value": 0.0,
            "duration_ms": 5000,
            "rationale": "test",
            "expected_effect": "test",
            "confidence": 0.9,
        }])

        provider = MagicMock()
        provider.provider_name = "mock"
        provider.model_name = "test-model"
        provider.complete.side_effect = [
            CompletionResult(text="not json at all", model="test-model", latency_ms=100.0),
            CompletionResult(text=valid_action, model="test-model", latency_ms=200.0),
        ]

        attacker = LLMAttacker(
            self._make_attack_policy(), provider=provider
        )
        attacker.generate_actions(self._make_scene())

        meta = attacker.get_run_metadata()
        assert meta["llm_total_calls"] == 2
        assert meta["llm_parse_successes"] == 1
        assert meta["llm_parse_failures"] == 1
        assert meta["llm_total_retries"] == 1
        assert meta["llm_parse_success_rate"] == 0.5

    def test_metadata_empty_before_any_call(self):
        """get_run_metadata has zero counts before generate_actions is called."""
        from cpsforge.llm.attacker import LLMAttacker

        attacker = LLMAttacker(
            self._make_attack_policy(), provider=_make_mock_provider()
        )
        meta = attacker.get_run_metadata()
        assert meta["llm_total_calls"] == 0
        assert meta["llm_parse_success_rate"] == 0.0


# ===========================================================================
# 3. Cross-model table
# ===========================================================================

class TestCrossModelTable:
    """Tests for the cross_model_table analysis function."""

    def _setup_experiment_data(self, tmp_path: Path, models: dict[str, int]):
        """
        Create mock experiment data with multiple runs and models.

        Parameters
        ----------
        models:
            {model_name: num_runs}
        """
        exp_dir = tmp_path / "raw" / "test_exp"
        run_idx = 0
        for model_name, n_runs in models.items():
            for _ in range(n_runs):
                run_id = f"run_{run_idx:03d}"
                run_dir = exp_dir / run_id
                run_dir.mkdir(parents=True)

                # metadata.json
                meta = {
                    "run_id": run_id,
                    "experiment_name": "test_exp",
                    "scene_name": "tank_control",
                    "attacker_name": "llm_tank_control",
                    "llm_model": model_name,
                    "llm_provider": "local_openai_compatible",
                    "llm_avg_latency_ms": 100.0 + run_idx * 10,
                    "llm_parse_success_rate": 0.9,
                    "eval_run": True,
                }
                (run_dir / "metadata.json").write_text(json.dumps(meta))

                # metrics.json
                metrics = {
                    "run_id": run_id,
                    "scene_name": "tank_control",
                    "attacker_name": "llm_tank_control",
                    "action_validity_rate": 0.8 + run_idx * 0.01,
                    "attack_success_rate": 0.5 + run_idx * 0.02,
                    "process_impact_score": 0.3 + run_idx * 0.01,
                    "shield_approval_rate": 0.7,
                    "shield_rejection_rate": 0.3,
                    "detector_f1": 0.6 + run_idx * 0.01,
                    "detection_latency_ms": 50.0 + run_idx * 5,
                    "eval_run": True,
                }
                (run_dir / "metrics.json").write_text(json.dumps(metrics))
                run_idx += 1

        return tmp_path

    def test_cross_model_table_produces_dataframe(self, tmp_path):
        from cpsforge.analysis.tables import cross_model_table

        data_dir = self._setup_experiment_data(tmp_path, {"modelA": 3, "modelB": 2})
        df = cross_model_table(data_dir=data_dir, experiment="test_exp")
        assert len(df) == 2
        assert "modelA" in df.index
        assert "modelB" in df.index
        assert "n_runs" in df.columns
        assert df.loc["modelA", "n_runs"] == 3
        assert df.loc["modelB", "n_runs"] == 2

    def test_cross_model_table_eval_only_filter(self, tmp_path):
        """With eval_only=True, only runs with eval_run=True are included."""
        from cpsforge.analysis.tables import cross_model_table

        # All runs have eval_run=True in our helper
        data_dir = self._setup_experiment_data(tmp_path, {"modelA": 2})
        df = cross_model_table(data_dir=data_dir, experiment="test_exp", eval_only=True)
        assert len(df) == 1

    def test_cross_model_table_empty_when_no_model(self, tmp_path):
        """Returns empty DataFrame when no metadata.json has llm_model."""
        from cpsforge.analysis.tables import cross_model_table

        exp_dir = tmp_path / "raw" / "empty_exp"
        run_dir = exp_dir / "run_000"
        run_dir.mkdir(parents=True)
        (run_dir / "metadata.json").write_text(json.dumps({"run_id": "run_000"}))
        (run_dir / "metrics.json").write_text(json.dumps({"run_id": "run_000"}))

        df = cross_model_table(data_dir=tmp_path, experiment="empty_exp")
        assert len(df) == 0


# ===========================================================================
# 4. New Scene Classes
# ===========================================================================

class TestFromAtoBScene:
    """Tests for the FromAtoB scene."""

    def _make_profile(self):
        from cpsforge.core.config import ConfigLoader
        loader = ConfigLoader()
        raw = loader.load_scene_raw("from_a_to_b")
        from cpsforge.scenes.factory import _parse_scene_profile
        return _parse_scene_profile(raw)

    def test_scene_loads_from_config(self):
        profile = self._make_profile()
        assert profile.scene_name == "from_a_to_b"
        assert len(profile.tags) > 0

    def test_extract_derived_features(self):
        from cpsforge.scenes.from_a_to_b import FromAtoBScene
        profile = self._make_profile()
        scene = FromAtoBScene(profile)

        snap = _make_snapshot(
            scene_name="from_a_to_b",
            sensors={"sensor": True},
            actuators={"conveyor": True},
            controller_state={"state": 1},
        )
        features = scene.extract_derived_features(snap)
        assert "transport_active" in features
        assert features["transport_active"] == 1.0
        assert "state_anomaly" in features
        assert features["state_anomaly"] == 0.0

    def test_state_anomaly_detection(self):
        from cpsforge.scenes.from_a_to_b import FromAtoBScene
        profile = self._make_profile()
        scene = FromAtoBScene(profile)

        # State 2 does not exist in the SCL (only 0=Transport, 1=Arrived)
        snap = _make_snapshot(
            scene_name="from_a_to_b",
            controller_state={"state": 2},
        )
        features = scene.extract_derived_features(snap)
        assert features["state_anomaly"] == 1.0

    def test_compute_process_impact(self):
        from cpsforge.scenes.from_a_to_b import FromAtoBScene
        profile = self._make_profile()
        scene = FromAtoBScene(profile)

        before = _make_snapshot(
            scene_name="from_a_to_b",
            actuators={"conveyor": True, "enable": True},
            controller_state={"state": 1},
        )
        after = _make_snapshot(
            scene_name="from_a_to_b",
            actuators={"conveyor": True, "enable": False},
            controller_state={"state": 1},
        )
        impact = scene.compute_process_impact(before, after)
        assert impact > 0  # enable toggled off


class TestLevelControlScene:
    """Tests for the LevelControl scene."""

    def _make_profile(self):
        from cpsforge.core.config import ConfigLoader
        loader = ConfigLoader()
        raw = loader.load_scene_raw("level_control")
        from cpsforge.scenes.factory import _parse_scene_profile
        return _parse_scene_profile(raw)

    def test_scene_loads_from_config(self):
        profile = self._make_profile()
        assert profile.scene_name == "level_control"
        assert len(profile.tags) >= 10

    def test_extract_derived_features(self):
        from cpsforge.scenes.level_control import LevelControlScene
        profile = self._make_profile()
        scene = LevelControlScene(profile)

        snap = _make_snapshot(
            scene_name="level_control",
            sensors={"level_meter": 6.0, "flow_meter": 2.0},
            setpoints={"setpoint_in": 5.0},
            actuators={"fill_valve": 3.0, "discharge_valve": 1.0},
        )
        features = scene.extract_derived_features(snap)
        assert "level_error" in features
        assert features["level_error"] == pytest.approx(-1.0)  # 5.0 - 6.0
        assert "valve_balance" in features
        assert features["valve_balance"] == pytest.approx(2.0)  # 3.0 - 1.0
        assert "level_deviation" in features
        assert features["level_deviation"] == pytest.approx(1.0)  # |6.0 - 5.0|

    def test_compute_process_impact_overflow(self):
        from cpsforge.scenes.level_control import LevelControlScene
        profile = self._make_profile()
        scene = LevelControlScene(profile)

        before = _make_snapshot(
            scene_name="level_control",
            sensors={"level_meter": 5.0},
            actuators={"fill_valve": 5.0, "discharge_valve": 5.0, "enable": True},
        )
        after = _make_snapshot(
            scene_name="level_control",
            sensors={"level_meter": 9.8},
            actuators={"fill_valve": 5.0, "discharge_valve": 5.0, "enable": True},
        )
        impact = scene.compute_process_impact(before, after)
        assert impact > 0.5  # level near overflow


class TestSortingHeightBasicScene:
    """Tests for the SortingHeightBasic scene."""

    def _make_profile(self):
        from cpsforge.core.config import ConfigLoader
        loader = ConfigLoader()
        raw = loader.load_scene_raw("sorting_height_basic")
        from cpsforge.scenes.factory import _parse_scene_profile
        return _parse_scene_profile(raw)

    def test_scene_loads_from_config(self):
        profile = self._make_profile()
        assert profile.scene_name == "sorting_height_basic"
        assert len(profile.tags) >= 20

    def test_extract_derived_features(self):
        from cpsforge.scenes.sorting_height_basic import SortingHeightBasicScene
        profile = self._make_profile()
        scene = SortingHeightBasicScene(profile)

        snap = _make_snapshot(
            scene_name="sorting_height_basic",
            controller_state={"state": 2, "is_tall": True, "item_count": 5},
            actuators={"transf_left": False, "transf_right": True,
                       "load_act": False, "unload_act": False},
        )
        features = scene.extract_derived_features(snap)
        assert features["sort_direction"] == 1.0  # tall → right
        assert features["state_anomaly"] == 0.0  # state 2 is valid
        assert features["transfer_conflict"] == 0.0

    def test_transfer_conflict_detected(self):
        from cpsforge.scenes.sorting_height_basic import SortingHeightBasicScene
        profile = self._make_profile()
        scene = SortingHeightBasicScene(profile)

        snap = _make_snapshot(
            scene_name="sorting_height_basic",
            controller_state={"state": 2, "is_tall": True, "item_count": 3},
            actuators={"transf_left": True, "transf_right": True,
                       "load_act": False, "unload_act": False},
        )
        features = scene.extract_derived_features(snap)
        assert features["transfer_conflict"] == 1.0

    def test_compute_process_impact_missort(self):
        from cpsforge.scenes.sorting_height_basic import SortingHeightBasicScene
        profile = self._make_profile()
        scene = SortingHeightBasicScene(profile)

        before = _make_snapshot(
            scene_name="sorting_height_basic",
            controller_state={"state": 2, "is_tall": True},
            actuators={"transf_left": False, "transf_right": True,
                       "enable": True},
        )
        # Tall item being sent left = mis-sort
        after = _make_snapshot(
            scene_name="sorting_height_basic",
            controller_state={"state": 2, "is_tall": True},
            actuators={"transf_left": True, "transf_right": False,
                       "enable": True},
        )
        impact = scene.compute_process_impact(before, after)
        assert impact >= 0.6  # mis-sort penalty


# ===========================================================================
# 5. Scene Factory Registration
# ===========================================================================

class TestSceneFactoryRegistration:
    """Verify all new scenes are registered and loadable."""

    def test_from_a_to_b_registered(self):
        from cpsforge.scenes.factory import _SCENE_REGISTRY
        assert "from_a_to_b" in _SCENE_REGISTRY

    def test_level_control_registered(self):
        from cpsforge.scenes.factory import _SCENE_REGISTRY
        assert "level_control" in _SCENE_REGISTRY

    def test_sorting_height_basic_registered(self):
        from cpsforge.scenes.factory import _SCENE_REGISTRY
        assert "sorting_height_basic" in _SCENE_REGISTRY

    def test_load_from_a_to_b(self):
        from cpsforge.core.config import ConfigLoader
        from cpsforge.scenes.factory import load_scene
        from cpsforge.scenes.from_a_to_b import FromAtoBScene
        scene = load_scene("from_a_to_b", ConfigLoader())
        assert isinstance(scene, FromAtoBScene)

    def test_load_level_control(self):
        from cpsforge.core.config import ConfigLoader
        from cpsforge.scenes.factory import load_scene
        from cpsforge.scenes.level_control import LevelControlScene
        scene = load_scene("level_control", ConfigLoader())
        assert isinstance(scene, LevelControlScene)

    def test_load_sorting_height_basic(self):
        from cpsforge.core.config import ConfigLoader
        from cpsforge.scenes.factory import load_scene
        from cpsforge.scenes.sorting_height_basic import SortingHeightBasicScene
        scene = load_scene("sorting_height_basic", ConfigLoader())
        assert isinstance(scene, SortingHeightBasicScene)
