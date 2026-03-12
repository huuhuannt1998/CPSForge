"""
CPSForge Phase 4 Test Suite
==============================
Tests for the LLM provider abstraction, prompt building, schema validation,
prompt logging, LLMAttacker, and factory dispatch.

All tests run WITHOUT a live LLM API (mock providers only).
No real API keys are consumed.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, List, Optional
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent.parent


def _make_attack_policy(
    *,
    attacker_type: str = "llm",
    llm_provider: str = "local_openai_compatible",
    max_actions: int = 3,
    attack_types: Optional[list] = None,
    llm_max_retries: int = 3,
    multi_step: bool = False,
    parameters: Optional[dict] = None,
) -> Any:
    """Create an AttackPolicyConfig for the LLM attacker."""
    from cpsforge.core.config import AttackPolicyConfig
    return AttackPolicyConfig(
        name="test_llm",
        attacker_type=attacker_type,
        scene_name="tank_control",
        llm_provider=llm_provider,
        max_actions=max_actions,
        attack_types=attack_types or ["actuator_override", "setpoint_shift", "sensor_spoof"],
        llm_max_retries=llm_max_retries,
        multi_step=multi_step,
        parameters=parameters or {},
    )


def _make_mock_provider(response_text: str = "[]") -> MagicMock:
    """Create a mock BaseLLMProvider that returns a fixed response text."""
    from cpsforge.llm.base_provider import CompletionResult
    provider = MagicMock()
    provider.provider_name = "mock"
    provider.model_name = "mock-model"
    result = CompletionResult(
        text=response_text,
        input_tokens=10,
        output_tokens=20,
        latency_ms=50.0,
        model="mock-model",
        finish_reason="stop",
    )
    provider.complete.return_value = result
    return provider


def _make_scene(attack_surface: Optional[list] = None) -> MagicMock:
    """Create a minimal fake scene for attacker tests."""
    scene = MagicMock()
    profile = MagicMock()
    profile.scene_name = "tank_control"
    profile.description = "Tank control test scene"
    profile.attack_surface = attack_surface or ["pump_speed", "level_setpoint", "drain_valve_position"]
    profile.tags = []
    scene.profile = profile
    scene.name = "tank_control"
    scene.get_latest_snapshot = MagicMock(return_value=None)
    return scene


def _valid_action_json(
    *,
    attack_type: str = "actuator_override",
    target: str = "pump_speed",
    value: float = 0.0,
    duration_ms: int = 5000,
    rationale: str = "Stop pump to drain tank",
    expected_effect: str = "Level drops",
    confidence: float = 0.9,
) -> dict:
    return {
        "attack_type": attack_type,
        "target": target,
        "value": value,
        "duration_ms": duration_ms,
        "rationale": rationale,
        "expected_effect": expected_effect,
        "confidence": confidence,
    }


# ===========================================================================
# 1. ActionSchemaValidator
# ===========================================================================

class TestActionSchemaValidator:
    """Unit tests for the LLM JSON output validator."""

    def test_valid_single_action_array(self):
        from cpsforge.llm.schema_validator import ActionSchemaValidator
        v = ActionSchemaValidator(attack_surface=["pump_speed"])
        raw = json.dumps([_valid_action_json()])
        actions = v.parse_and_validate(raw)
        assert len(actions) == 1
        assert actions[0].target == "pump_speed"

    def test_valid_object_wrapped_in_list(self):
        from cpsforge.llm.schema_validator import ActionSchemaValidator
        v = ActionSchemaValidator(attack_surface=["pump_speed"])
        raw = json.dumps(_valid_action_json())
        actions = v.parse_and_validate(raw)
        assert len(actions) == 1

    def test_json_embedded_in_text(self):
        """Validator strips leading/trailing prose from LLM response."""
        from cpsforge.llm.schema_validator import ActionSchemaValidator
        v = ActionSchemaValidator(attack_surface=["pump_speed"])
        raw = 'Here are my attacks:\n' + json.dumps([_valid_action_json()]) + '\nEnd.'
        actions = v.parse_and_validate(raw)
        assert len(actions) == 1

    def test_rejects_raw_s7_db_address(self):
        from cpsforge.llm.schema_validator import ActionSchemaValidator, ValidationError
        v = ActionSchemaValidator()
        item = _valid_action_json(target="DB1,REAL4")
        with pytest.raises(ValidationError, match="raw PLC memory address"):
            v.parse_and_validate(json.dumps([item]))

    def test_rejects_raw_s7_mw_address(self):
        from cpsforge.llm.schema_validator import ActionSchemaValidator, ValidationError
        v = ActionSchemaValidator()
        item = _valid_action_json(target="MW10")
        with pytest.raises(ValidationError, match="raw PLC memory address"):
            v.parse_and_validate(json.dumps([item]))

    def test_rejects_raw_s7_qw_address(self):
        from cpsforge.llm.schema_validator import ActionSchemaValidator, ValidationError
        v = ActionSchemaValidator()
        item = _valid_action_json(target="QW0")
        with pytest.raises(ValidationError, match="raw PLC memory address"):
            v.parse_and_validate(json.dumps([item]))

    def test_rejects_raw_s7_i_bit_address(self):
        from cpsforge.llm.schema_validator import ActionSchemaValidator, ValidationError
        v = ActionSchemaValidator()
        item = _valid_action_json(target="I0.1")
        with pytest.raises(ValidationError, match="raw PLC memory address"):
            v.parse_and_validate(json.dumps([item]))

    def test_rejects_target_not_in_attack_surface(self):
        from cpsforge.llm.schema_validator import ActionSchemaValidator, ValidationError
        v = ActionSchemaValidator(attack_surface=["pump_speed"])
        item = _valid_action_json(target="unknown_tag")
        with pytest.raises(ValidationError, match="attack surface"):
            v.parse_and_validate(json.dumps([item]))

    def test_rejects_invalid_attack_type(self):
        from cpsforge.llm.schema_validator import ActionSchemaValidator, ValidationError
        v = ActionSchemaValidator(attack_surface=["pump_speed"])
        item = _valid_action_json(attack_type="nuclear_strike")
        with pytest.raises(ValidationError, match="attack_type"):
            v.parse_and_validate(json.dumps([item]))

    def test_rejects_string_value(self):
        from cpsforge.llm.schema_validator import ActionSchemaValidator, ValidationError
        v = ActionSchemaValidator(attack_surface=["pump_speed"])
        item = {**_valid_action_json(), "value": "DB1,REAL4"}
        with pytest.raises(ValidationError, match="string"):
            v.parse_and_validate(json.dumps([item]))

    def test_rejects_empty_array(self):
        from cpsforge.llm.schema_validator import ActionSchemaValidator, ValidationError
        v = ActionSchemaValidator()
        with pytest.raises(ValidationError, match="empty"):
            v.parse_and_validate("[]")

    def test_rejects_garbage_json(self):
        from cpsforge.llm.schema_validator import ActionSchemaValidator, ValidationError
        v = ActionSchemaValidator()
        with pytest.raises(ValidationError):
            v.parse_and_validate("this is not json at all")

    def test_confidence_clamped_to_range(self):
        from cpsforge.llm.schema_validator import ActionSchemaValidator
        v = ActionSchemaValidator(attack_surface=["pump_speed"])
        item = {**_valid_action_json(), "confidence": 1.5}
        actions = v.parse_and_validate(json.dumps([item]))
        assert actions[0].confidence == 1.0

    def test_scene_attack_surface_wins_over_instance(self):
        from cpsforge.llm.schema_validator import ActionSchemaValidator, ValidationError
        v = ActionSchemaValidator(attack_surface=["pump_speed"])
        scene = _make_scene(attack_surface=["level_setpoint"])
        item = _valid_action_json(target="pump_speed")  # not in scene surface
        with pytest.raises(ValidationError, match="attack surface"):
            v.parse_and_validate(json.dumps([item]), scene=scene)

    def test_correction_prompt_contains_schema_hint(self):
        from cpsforge.llm.schema_validator import ValidationError
        exc = ValidationError("bad type")
        prompt = exc.correction_prompt()
        assert "JSON array" in prompt
        assert "attack_type" in prompt
        assert "DB1,REAL4" in prompt

    def test_source_stamped_as_llm(self):
        from cpsforge.llm.schema_validator import ActionSchemaValidator
        from cpsforge.core.models import AttackSource
        v = ActionSchemaValidator(attack_surface=["pump_speed"])
        actions = v.parse_and_validate(json.dumps([_valid_action_json()]))
        assert actions[0].source == AttackSource.LLM

    def test_valid_multiple_actions(self):
        from cpsforge.llm.schema_validator import ActionSchemaValidator
        v = ActionSchemaValidator(attack_surface=["pump_speed", "level_setpoint"])
        raw = json.dumps([
            _valid_action_json(target="pump_speed"),
            _valid_action_json(attack_type="setpoint_shift", target="level_setpoint", value=85.0),
        ])
        actions = v.parse_and_validate(raw)
        assert len(actions) == 2


# ===========================================================================
# 2. PromptBuilder
# ===========================================================================

class TestPromptBuilder:
    """Unit tests for template loading and prompt rendering."""

    def test_falls_back_to_builtin_when_no_templates(self):
        """PromptBuilder must not crash if the template directory doesn't exist."""
        from cpsforge.llm.prompt_builder import PromptBuilder
        builder = PromptBuilder(prompts_root=Path("/nonexistent/path"))
        system = builder.build_system_prompt(scene=_make_scene())
        assert len(system) > 50

    def test_system_prompt_contains_scene_name(self):
        from cpsforge.llm.prompt_builder import PromptBuilder
        builder = PromptBuilder(prompts_root=Path("/nonexistent/path"))
        system = builder.build_system_prompt(scene=_make_scene())
        assert "tank_control" in system

    def test_system_prompt_contains_attack_surface(self):
        from cpsforge.llm.prompt_builder import PromptBuilder
        builder = PromptBuilder(prompts_root=Path("/nonexistent/path"))
        system = builder.build_system_prompt(
            scene=_make_scene(attack_surface=["pump_speed", "drain_valve_position"])
        )
        assert "pump_speed" in system
        assert "drain_valve_position" in system

    def test_user_prompt_contains_step_id(self):
        from cpsforge.llm.prompt_builder import PromptBuilder
        from cpsforge.core.models import PlantSnapshot
        builder = PromptBuilder(prompts_root=Path("/nonexistent/path"))
        snap = PlantSnapshot(
            scene_name="tank_control",
            run_id="r1",
            step_id=42,
            sensors={"tank_level": 55.0},
        )
        user = builder.build_user_prompt(snapshot=snap, max_actions=2)
        assert "42" in user

    def test_user_prompt_with_none_snapshot(self):
        """build_user_prompt must not crash when no snapshot is available."""
        from cpsforge.llm.prompt_builder import PromptBuilder
        builder = PromptBuilder(prompts_root=Path("/nonexistent/path"))
        user = builder.build_user_prompt(snapshot=None)
        assert isinstance(user, str)
        assert len(user) > 0

    def test_loads_templates_from_disk(self, tmp_path):
        """Verify disk-loaded templates are preferred over fallbacks."""
        from cpsforge.llm.prompt_builder import PromptBuilder
        v1 = tmp_path / "v1"
        v1.mkdir()
        (v1 / "attacker_system.md").write_text("CUSTOM_SYSTEM {scene_name}")
        (v1 / "attacker_user.md").write_text("CUSTOM_USER step={step_id}")
        builder = PromptBuilder(template_version="v1", prompts_root=tmp_path)
        system = builder.build_system_prompt(scene=_make_scene())
        assert "CUSTOM_SYSTEM" in system
        assert "tank_control" in system

    def test_reload_switches_version(self, tmp_path):
        """reload() with a new version switches to the new templates."""
        from cpsforge.llm.prompt_builder import PromptBuilder
        v2 = tmp_path / "v2"
        v2.mkdir()
        (v2 / "attacker_system.md").write_text("V2_SYSTEM")
        (v2 / "attacker_user.md").write_text("V2_USER")
        builder = PromptBuilder(template_version="v1", prompts_root=tmp_path)
        builder.reload(version="v2")
        assert builder.version == "v2"
        system = builder.build_system_prompt(scene=_make_scene())
        assert "V2_SYSTEM" in system

    def test_missing_placeholder_does_not_raise(self):
        """Template with an unknown placeholder should not raise KeyError."""
        from cpsforge.llm.prompt_builder import PromptBuilder, _FALLBACK_SYSTEM
        builder = PromptBuilder(prompts_root=Path("/nonexistent/path"))
        # Patching the template to include an unknown placeholder
        builder._system_template = "Hello {unknown_key} world"
        result = builder.build_system_prompt(scene=_make_scene())
        assert "Hello" in result
        assert "world" in result


# ===========================================================================
# 3. PromptLogger
# ===========================================================================

class TestPromptLogger:
    """Unit tests for prompt logging and redaction."""

    def test_writes_jsonl_entry(self, tmp_path):
        from cpsforge.llm.prompt_logger import PromptLogger
        from cpsforge.llm.base_provider import CompletionResult
        logger = PromptLogger(log_dir=tmp_path, log_prompts=True, run_id="r1")
        result = CompletionResult(text="[]", input_tokens=5, output_tokens=10, latency_ms=25.0, model="m")
        logger.log_attempt(
            attempt=0,
            system_prompt="sys",
            user_prompt="usr",
            raw_text="[]",
            result=result,
            actions_count=0,
        )
        log_file = tmp_path / "llm_log.jsonl"
        assert log_file.exists()
        lines = log_file.read_text().strip().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["run_id"] == "r1"
        assert entry["attempt"] == 0
        assert entry["system_prompt"] == "sys"

    def test_prompt_not_logged_when_log_prompts_false(self, tmp_path):
        from cpsforge.llm.prompt_logger import PromptLogger
        from cpsforge.llm.base_provider import CompletionResult
        logger = PromptLogger(log_dir=tmp_path, log_prompts=False)
        result = CompletionResult(text="[]", latency_ms=10.0, model="m")
        logger.log_attempt(
            attempt=0,
            system_prompt="secret system prompt",
            user_prompt="secret user prompt",
            result=result,
            actions_count=0,
        )
        log_file = tmp_path / "llm_log.jsonl"
        entry = json.loads(log_file.read_text().strip())
        assert "system_prompt" not in entry
        assert "user_prompt" not in entry

    def test_redaction_applied_when_enabled(self, tmp_path):
        from cpsforge.llm.prompt_logger import PromptLogger
        from cpsforge.llm.base_provider import CompletionResult
        logger = PromptLogger(log_dir=tmp_path, log_prompts=True, redact_prompts=True)
        result = CompletionResult(text="[]", latency_ms=5.0, model="m")
        logger.log_attempt(
            attempt=0,
            system_prompt="sensitive text",
            user_prompt="also sensitive",
            raw_text="raw output",
            result=result,
            actions_count=0,
        )
        entry = json.loads((tmp_path / "llm_log.jsonl").read_text().strip())
        assert entry["system_prompt"] == "[REDACTED]"
        assert entry["user_prompt"] == "[REDACTED]"
        assert entry["response"] == "[REDACTED]"

    def test_validation_error_logged(self, tmp_path):
        from cpsforge.llm.prompt_logger import PromptLogger
        logger = PromptLogger(log_dir=tmp_path)
        logger.log_attempt(
            attempt=1,
            system_prompt="s",
            user_prompt="u",
            validation_error="target not in attack surface",
            actions_count=0,
        )
        entry = json.loads((tmp_path / "llm_log.jsonl").read_text().strip())
        assert "validation_error" in entry
        assert "attack surface" in entry["validation_error"]

    def test_summary_entry_written(self, tmp_path):
        from cpsforge.llm.prompt_logger import PromptLogger
        logger = PromptLogger(log_dir=tmp_path)
        logger.log_run_summary(total_attempts=3, actions_generated=2, exhausted_retries=False)
        lines = (tmp_path / "llm_log.jsonl").read_text().strip().splitlines()
        entry = json.loads(lines[-1])
        assert entry["type"] == "run_summary"
        assert entry["total_attempts"] == 3
        assert entry["actions_generated"] == 2

    def test_entries_written_counter(self, tmp_path):
        from cpsforge.llm.prompt_logger import PromptLogger
        logger = PromptLogger(log_dir=tmp_path)
        logger.log_attempt(attempt=0, system_prompt="s", user_prompt="u", actions_count=0)
        logger.log_attempt(attempt=1, system_prompt="s", user_prompt="u", actions_count=0)
        assert logger.entries_written == 2

    def test_null_logger_does_not_write(self):
        from cpsforge.llm.prompt_logger import NullPromptLogger
        logger = NullPromptLogger()
        logger.log_attempt(attempt=0, system_prompt="s", user_prompt="u", actions_count=0)
        logger.log_run_summary(total_attempts=1, actions_generated=0, exhausted_retries=True)
        # NullLogger counts entries but writes no files
        assert logger.entries_written == 2


# ===========================================================================
# 4. Provider Factory
# ===========================================================================

class TestProviderFactory:
    """Unit tests for build_provider() dispatch."""

    def test_local_openai_compatible_dispatch(self):
        """build_provider with provider='local_openai_compatible' returns LocalOpenAICompatibleProvider."""
        from cpsforge.llm.factory import build_provider
        from cpsforge.llm.local_openai_provider import LocalOpenAICompatibleProvider
        from cpsforge.core.config import LLMConfig
        cfg = LLMConfig(
            provider="local_openai_compatible",
            model="qwen2-7b-instruct",
            api_key_env="",
            base_url="http://127.0.0.1:1234/v1",
        )
        p = build_provider(cfg)
        assert isinstance(p, LocalOpenAICompatibleProvider)
        assert p.provider_name == "local_openai_compatible"
        assert p.model_name == "qwen2-7b-instruct"
        p.close()

    def test_unknown_provider_raises_value_error(self):
        from cpsforge.llm.factory import build_provider
        from cpsforge.core.config import LLMConfig
        cfg = LLMConfig(provider="galactic_ai", model="x")
        with pytest.raises(ValueError, match="Unknown LLM provider"):
            build_provider(cfg)

    def test_list_providers_returns_known_names(self):
        from cpsforge.llm.factory import list_providers
        names = list_providers()
        assert "local_openai_compatible" in names


# ===========================================================================
# 5. LLMAttacker
# ===========================================================================

class TestLLMAttacker:
    """Unit tests for the LLMAttacker with mock providers."""

    def test_generates_valid_actions_on_success(self):
        from cpsforge.llm.attacker import LLMAttacker
        response = json.dumps([_valid_action_json(target="pump_speed")])
        provider = _make_mock_provider(response)
        attacker = LLMAttacker(
            _make_attack_policy(), provider=provider
        )
        actions = attacker.generate_actions(_make_scene())
        assert len(actions) == 1
        assert actions[0].target == "pump_speed"
        provider.complete.assert_called_once()

    def test_returns_empty_list_when_all_retries_fail(self):
        from cpsforge.llm.attacker import LLMAttacker
        provider = _make_mock_provider("this is not json at all @@!!")
        attacker = LLMAttacker(
            _make_attack_policy(llm_max_retries=3), provider=provider
        )
        actions = attacker.generate_actions(_make_scene())
        assert actions == []
        assert provider.complete.call_count == 3

    def test_retries_on_validation_failure_then_succeeds(self):
        """Provider returns bad JSON first, then good JSON on second attempt."""
        from cpsforge.llm.attacker import LLMAttacker
        from cpsforge.llm.base_provider import CompletionResult

        good_response = json.dumps([_valid_action_json(target="pump_speed")])
        bad_response = "not json"

        provider = MagicMock()
        provider.provider_name = "mock"
        provider.model_name = "mock-model"
        provider.complete.side_effect = [
            CompletionResult(text=bad_response, model="m"),
            CompletionResult(text=good_response, model="m"),
        ]

        attacker = LLMAttacker(
            _make_attack_policy(llm_max_retries=3), provider=provider
        )
        actions = attacker.generate_actions(_make_scene())
        assert len(actions) == 1
        assert provider.complete.call_count == 2

    def test_provider_error_breaks_immediately(self):
        """A ProviderError (auth/timeout) should not trigger schema retries."""
        from cpsforge.llm.attacker import LLMAttacker
        from cpsforge.llm.base_provider import ProviderError

        provider = MagicMock()
        provider.provider_name = "mock"
        provider.model_name = "mock-model"
        provider.complete.side_effect = ProviderError("Auth failed")

        attacker = LLMAttacker(
            _make_attack_policy(llm_max_retries=3), provider=provider
        )
        actions = attacker.generate_actions(_make_scene())
        assert actions == []
        # Only 1 call -- no schema-correction retries for auth errors
        assert provider.complete.call_count == 1

    def test_attack_types_filtered_by_policy_whitelist(self):
        """Actions with attack_type not in policy whitelist are removed."""
        from cpsforge.llm.attacker import LLMAttacker
        response = json.dumps([
            _valid_action_json(attack_type="actuator_override", target="pump_speed"),
            _valid_action_json(attack_type="timing_delay", target="pump_speed"),
        ])
        provider = _make_mock_provider(response)
        attacker = LLMAttacker(
            _make_attack_policy(attack_types=["actuator_override"]),
            provider=provider,
        )
        # timing_delay not in whitelist
        actions = attacker.generate_actions(_make_scene())
        assert all(a.attack_type.value == "actuator_override" for a in actions)

    def test_max_actions_caps_output(self):
        """LLMAttacker should not return more than max_actions."""
        from cpsforge.llm.attacker import LLMAttacker
        response = json.dumps([
            _valid_action_json(target="pump_speed"),
            _valid_action_json(attack_type="setpoint_shift", target="level_setpoint", value=85.0),
            _valid_action_json(attack_type="sensor_spoof", target="pump_speed", value=0.0),
        ])
        provider = _make_mock_provider(response)
        attacker = LLMAttacker(
            _make_attack_policy(max_actions=2), provider=provider
        )
        actions = attacker.generate_actions(_make_scene())
        assert len(actions) <= 2

    def test_multi_step_accumulates_prior_actions(self):
        """In multi_step mode, prior actions are passed to subsequent calls."""
        from cpsforge.llm.attacker import LLMAttacker
        response = json.dumps([_valid_action_json(target="pump_speed")])
        provider = _make_mock_provider(response)
        attacker = LLMAttacker(
            _make_attack_policy(multi_step=True), provider=provider
        )
        scene = _make_scene()
        actions1 = attacker.generate_actions(scene)
        actions2 = attacker.generate_actions(scene)
        assert len(attacker._prior_actions) == 2

    def test_reset_prior_actions(self):
        from cpsforge.llm.attacker import LLMAttacker
        provider = _make_mock_provider(json.dumps([_valid_action_json(target="pump_speed")]))
        attacker = LLMAttacker(_make_attack_policy(multi_step=True), provider=provider)
        attacker.generate_actions(_make_scene())
        attacker.reset_prior_actions()
        assert attacker._prior_actions == []

    def test_attacker_name_matches_config(self):
        from cpsforge.llm.attacker import LLMAttacker
        attacker = LLMAttacker(_make_attack_policy(), provider=_make_mock_provider())
        assert attacker.name == "test_llm"

    def test_source_stamped_as_llm(self):
        from cpsforge.llm.attacker import LLMAttacker
        from cpsforge.core.models import AttackSource
        response = json.dumps([_valid_action_json(target="pump_speed")])
        attacker = LLMAttacker(
            _make_attack_policy(), provider=_make_mock_provider(response)
        )
        actions = attacker.generate_actions(_make_scene())
        assert actions[0].source == AttackSource.LLM

    def test_prompt_logger_receives_log_entry(self, tmp_path):
        """Verify the attacker writes an llm_log.jsonl entry."""
        from cpsforge.llm.attacker import LLMAttacker
        response = json.dumps([_valid_action_json(target="pump_speed")])
        attacker = LLMAttacker(
            _make_attack_policy(),
            provider=_make_mock_provider(response),
            log_dir=tmp_path,
            log_prompts=True,
        )
        attacker.generate_actions(_make_scene())
        log_file = tmp_path / "llm_log.jsonl"
        assert log_file.exists()
        lines = log_file.read_text().strip().splitlines()
        assert len(lines) >= 1  # at least one attempt + one summary

    def test_no_log_dir_uses_null_logger(self):
        """With no log_dir, NullPromptLogger is used -- no crash, no file."""
        from cpsforge.llm.attacker import LLMAttacker
        from cpsforge.llm.prompt_logger import NullPromptLogger
        attacker = LLMAttacker(_make_attack_policy(), provider=_make_mock_provider())
        assert isinstance(attacker.prompt_logger, NullPromptLogger)


# ===========================================================================
# 6. Config round-trip
# ===========================================================================

class TestConfigRoundTrip:
    """Test that LLM configs load cleanly and fields are correctly typed."""

    def test_local_config_loads(self):
        from cpsforge.core.config import ConfigLoader
        cfg = ConfigLoader().load_llm("local")
        assert cfg.provider == "local_openai_compatible"
        assert cfg.base_url is not None
        assert "1234" in cfg.base_url

    def test_llm_attack_policy_loads(self):
        from cpsforge.core.config import ConfigLoader
        pol = ConfigLoader().load_attack_policy("llm_tank_control")
        assert pol.attacker_type == "llm"
        assert pol.llm_provider == "local_openai_compatible"
        assert pol.llm_max_retries >= 1
        assert "attacker_objective" in pol.parameters

    def test_llm_config_defaults_local_openai_compatible(self):
        from cpsforge.core.config import LLMConfig
        cfg = LLMConfig()
        assert cfg.provider == "local_openai_compatible"
        assert cfg.model == "qwen2-7b-instruct"
        assert cfg.base_url == "http://127.0.0.1:1234/v1"

    def test_llm_config_api_key_from_env(self, monkeypatch):
        from cpsforge.core.config import LLMConfig
        monkeypatch.setenv("LM_STUDIO_KEY", "test-key-123")
        cfg = LLMConfig(api_key_env="LM_STUDIO_KEY")
        assert cfg.api_key == "test-key-123"

    def test_llm_config_api_key_none_when_empty_env_var(self):
        from cpsforge.core.config import LLMConfig
        cfg = LLMConfig(api_key_env="")
        assert cfg.api_key is None


# ===========================================================================
# 7. Attack factory integration
# ===========================================================================

class TestAttackFactoryLLMDispatch:
    """Verify the attack factory dispatches 'llm' to LLMAttacker."""

    def test_factory_returns_llm_attacker(self):
        from cpsforge.attacks.factory import build_attacker
        from cpsforge.llm.attacker import LLMAttacker
        config = _make_attack_policy()
        scene = _make_scene()
        with patch("cpsforge.llm.attacker.LLMAttacker._load_llm_config") as mock_load, \
             patch("cpsforge.llm.attacker.build_provider") as mock_prov:
            mock_load.return_value = MagicMock(
                provider="mock", model="mock", api_key_env="", base_url=None,
                max_tokens=100, temperature=0.2, timeout_s=10,
                log_prompts=False, redact_prompts=False,
                prompt_template_version="v1", log_llm_responses=True,
            )
            mock_prov.return_value = _make_mock_provider()
            attacker = build_attacker(config, scene)
        assert isinstance(attacker, LLMAttacker)
