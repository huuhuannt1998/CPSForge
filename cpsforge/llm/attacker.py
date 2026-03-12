"""
CPSForge LLM Attacker
=======================
The LLMAttacker uses a large language model to generate CPS attack actions
based on the current plant state and scene context.

Pipeline per :meth:`generate_actions` call::

    PromptBuilder → provider.complete() → ActionSchemaValidator
         ↓ on failure (up to max_retries)
    Corrective follow-up prompt → provider.complete() → validate
         ↓ all retries exhausted
    Return []   (safe default: no actions)

Important safety constraints:
- The LLM is **never** given raw PLC memory addresses to use as targets.
  The system prompt explicitly enumerates only tag names from the scene's
  attack_surface list.
- :class:`ActionSchemaValidator` rejects any target that matches a raw S7
  address pattern (DB1,REAL4 / MW10 / QW0 etc.).
- All generated actions pass through the :class:`ShieldEngine` in the
  orchestrator before any write reaches the PLC.
- The ``llm_log.jsonl`` file records every call and its outcome for audit.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

from cpsforge.attacks.base import BaseAttacker
from cpsforge.core.config import AttackPolicyConfig, ConfigLoader, LLMConfig
from cpsforge.core.models import AttackAction
from cpsforge.llm.base_provider import BaseLLMProvider, ProviderError
from cpsforge.llm.factory import build_provider
from cpsforge.llm.prompt_builder import PromptBuilder
from cpsforge.llm.prompt_logger import NullPromptLogger, PromptLogger
from cpsforge.llm.schema_validator import ActionSchemaValidator, ValidationError

logger = logging.getLogger(__name__)


class LLMAttacker(BaseAttacker):
    """
    Attack planner backed by an LLM provider.

    Parameters
    ----------
    config:
        :class:`AttackPolicyConfig` loaded from ``configs/attacks/<name>.yaml``.
        Key fields used:
        - ``llm_provider``          provider name ("local_openai_compatible")
        - ``llm_model``             optional model override
        - ``llm_max_retries``       max correction retries (default 3)
        - ``multi_step``            whether to pass prior actions to LLM
        - ``max_actions``           max actions to request per call
        - ``attack_types``          whitelisted attack types

    provider:
        Optional pre-built :class:`BaseLLMProvider`.  When provided,
        the ``llm_provider`` field in ``config`` is ignored.  Primarily
        useful for unit testing (inject a mock provider).

    log_dir:
        Directory where ``llm_log.jsonl`` is written.  When None,
        a :class:`NullPromptLogger` is used (no disk I/O).

    log_prompts:
        Whether to write prompt/response text to the log file.

    redact_prompts:
        When True, prompt/response text is replaced with ``[REDACTED]``.
    """

    def __init__(
        self,
        config: AttackPolicyConfig,
        *,
        provider: Optional[BaseLLMProvider] = None,
        log_dir: Optional[Path] = None,
        log_prompts: bool = False,
        redact_prompts: bool = False,
        run_id: str = "",
    ) -> None:
        super().__init__(config)
        self._max_retries = config.llm_max_retries
        self._multi_step = config.multi_step
        self._prior_actions: List[AttackAction] = []

        # Build or accept provider
        if provider is not None:
            self._provider = provider
        else:
            llm_cfg = self._load_llm_config(config)
            self._provider = build_provider(llm_cfg)

        # Apply model override from attack policy if specified
        if config.llm_model and not provider:
            logger.debug(
                "LLMAttacker: model override '%s' specified in attack policy "
                "(provider uses its own config model '%s').",
                config.llm_model,
                self._provider.model_name,
            )

        # Validator: attack surface is resolved at generate_actions() time
        # (scene may not be fully built yet at __init__)
        self._validator = ActionSchemaValidator()

        # Prompt builder (version from llm config if available, else v1 default)
        self._prompt_builder = PromptBuilder()

        # Per-run model metadata tracking
        self._call_latencies: list[float] = []
        self._total_retries: int = 0
        self._parse_successes: int = 0
        self._parse_failures: int = 0

        # Logger
        if log_dir is not None:
            self._prompt_logger: PromptLogger = PromptLogger(
                log_dir=log_dir,
                log_prompts=log_prompts,
                redact_prompts=redact_prompts,
                run_id=run_id,
                provider_name=self._provider.provider_name,
                model_name=self._provider.model_name,
            )
        else:
            self._prompt_logger = NullPromptLogger()

        logger.info(
            "LLMAttacker '%s' ready: provider=%s model=%s max_retries=%d multi_step=%s",
            self.name,
            self._provider.provider_name,
            self._provider.model_name,
            self._max_retries,
            self._multi_step,
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def generate_actions(self, scene: object) -> List[AttackAction]:
        """
        Ask the LLM to plan attacks for the current plant state.

        Pulls the most recent snapshot from the scene if available,
        constructs system + user prompts, calls the provider, validates
        the JSON output, and retries with corrective prompts on failure.

        Returns an empty list if all retries are exhausted (safe default).
        All returned actions are stamped ``source=AttackSource.LLM`` and
        limited to ``config.max_actions``.

        Parameters
        ----------
        scene:
            Active :class:`BaseScene`.  Used for attack surface resolution,
            snapshot access, and prompt context.

        Returns
        -------
        List[AttackAction]
            Validated attack actions ready for shield evaluation.
        """
        # Resolve scene snapshot (most recent, or None)
        snapshot = self._get_latest_snapshot(scene)

        # Build prompts
        system_prompt = self._prompt_builder.build_system_prompt(
            scene=scene,
            max_actions=self._config.max_actions,
        )
        user_prompt = self._prompt_builder.build_user_prompt(
            snapshot=snapshot,
            max_actions=self._config.max_actions,
            prior_actions=self._prior_actions if self._multi_step else None,
            attacker_objective=self._config.parameters.get("attacker_objective", ""),
            notes=self._config.parameters.get("prompt_notes", ""),
        )

        # Retry loop
        current_user_prompt = user_prompt
        total_attempts = 0
        actions: List[AttackAction] = []

        for attempt in range(self._max_retries):
            total_attempts += 1
            raw_text: Optional[str] = None
            prov_error: Optional[Exception] = None
            val_error: Optional[str] = None

            try:
                result = self._provider.complete(system_prompt, current_user_prompt)
                raw_text = result.text

                # Track latency
                if result.latency_ms is not None:
                    self._call_latencies.append(result.latency_ms)

                actions = self._validator.parse_and_validate(raw_text, scene)

                # Filter to whitelisted attack types from policy
                actions = self._filter_attack_types(actions)
                # Cap at max_actions
                actions = actions[: self._config.max_actions]

                self._parse_successes += 1

                # Filter to whitelisted attack types from policy
                actions = self._filter_attack_types(actions)
                # Cap at max_actions
                actions = actions[: self._config.max_actions]

                self._prompt_logger.log_attempt(
                    attempt=attempt,
                    system_prompt=system_prompt,
                    user_prompt=current_user_prompt,
                    raw_text=raw_text,
                    result=result,
                    actions_count=len(actions),
                )

                logger.info(
                    "LLMAttacker '%s': attempt %d succeeded -- %d actions generated.",
                    self.name,
                    attempt + 1,
                    len(actions),
                )
                break  # success

            except ProviderError as exc:
                prov_error = exc
                logger.warning(
                    "LLMAttacker '%s': attempt %d provider error: %s",
                    self.name,
                    attempt + 1,
                    exc,
                )
                self._prompt_logger.log_attempt(
                    attempt=attempt,
                    system_prompt=system_prompt,
                    user_prompt=current_user_prompt,
                    raw_text=raw_text,
                    error=exc,
                    actions_count=0,
                )
                # Provider errors (auth, timeout) are not correctable by
                # schema repair -- break immediately
                break

            except ValidationError as exc:
                val_error = str(exc)
                self._parse_failures += 1
                self._total_retries += 1
                logger.warning(
                    "LLMAttacker '%s': attempt %d validation error: %s",
                    self.name,
                    attempt + 1,
                    exc,
                )
                self._prompt_logger.log_attempt(
                    attempt=attempt,
                    system_prompt=system_prompt,
                    user_prompt=current_user_prompt,
                    raw_text=raw_text,
                    validation_error=val_error,
                    actions_count=0,
                )
                if attempt + 1 < self._max_retries:
                    # Send a corrective follow-up prompt, including the scene's
                    # attack-surface so the LLM can pick a valid target.
                    current_user_prompt = self._prompt_builder.build_correction_prompt(
                        exc, scene
                    )
                    logger.debug(
                        "LLMAttacker '%s': sending correction prompt for attempt %d.",
                        self.name,
                        attempt + 2,
                    )

        exhausted = len(actions) == 0
        self._prompt_logger.log_run_summary(
            total_attempts=total_attempts,
            actions_generated=len(actions),
            exhausted_retries=exhausted and total_attempts >= self._max_retries,
        )

        if exhausted:
            logger.warning(
                "LLMAttacker '%s': no valid actions after %d attempt(s). "
                "Returning empty list.",
                self.name,
                total_attempts,
            )
        else:
            # Store for multi-step chaining
            if self._multi_step:
                self._prior_actions.extend(actions)

        return actions

    def reset_prior_actions(self) -> None:
        """Clear the accumulated prior-action history for multi-step mode."""
        self._prior_actions.clear()

    # ------------------------------------------------------------------
    # Accessors (useful for testing)
    # ------------------------------------------------------------------

    @property
    def provider(self) -> BaseLLMProvider:
        return self._provider

    @property
    def prompt_builder(self) -> PromptBuilder:
        return self._prompt_builder

    @property
    def prompt_logger(self) -> PromptLogger:
        return self._prompt_logger

    def get_run_metadata(self) -> dict:
        """
        Return per-run LLM metadata for inclusion in experiment artifacts.

        Includes provider name, model name, latency stats, retry count,
        and parse success/failure rates.
        """
        total_calls = self._parse_successes + self._parse_failures
        return {
            "llm_provider": self._provider.provider_name,
            "llm_model": self._provider.model_name,
            "llm_total_calls": total_calls,
            "llm_parse_successes": self._parse_successes,
            "llm_parse_failures": self._parse_failures,
            "llm_parse_success_rate": (
                round(self._parse_successes / total_calls, 4)
                if total_calls > 0
                else 0.0
            ),
            "llm_total_retries": self._total_retries,
            "llm_avg_latency_ms": (
                round(sum(self._call_latencies) / len(self._call_latencies), 2)
                if self._call_latencies
                else 0.0
            ),
            "llm_max_latency_ms": (
                round(max(self._call_latencies), 2)
                if self._call_latencies
                else 0.0
            ),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_latest_snapshot(scene: object):
        """Return the most recent PlantSnapshot from the scene, or None."""
        # Scenes store history in self._trace or expose get_latest_snapshot()
        get_latest = getattr(scene, "get_latest_snapshot", None)
        if callable(get_latest):
            return get_latest()
        trace = getattr(scene, "_trace", None)
        if trace and isinstance(trace, list) and len(trace) > 0:
            return trace[-1]
        return None

    def _filter_attack_types(self, actions: List[AttackAction]) -> List[AttackAction]:
        """Remove actions whose attack_type is not whitelisted in the policy."""
        allowed = set(self._config.attack_types)
        if not allowed:
            return actions  # empty whitelist = allow all
        filtered = [a for a in actions if a.attack_type.value in allowed]
        removed = len(actions) - len(filtered)
        if removed:
            logger.debug(
                "LLMAttacker '%s': filtered out %d action(s) not in attack_types whitelist.",
                self.name,
                removed,
            )
        return filtered

    @staticmethod
    def _load_llm_config(config: AttackPolicyConfig) -> LLMConfig:
        """
        Load the LLMConfig for the provider named in the attack policy config.

        Falls back to the default ``anthropic.yaml`` if no config file is found
        for the requested provider, producing a warning.
        """
        provider_name = config.llm_provider or "local_openai_compatible"
        try:
            return ConfigLoader().load_llm(provider_name)
        except FileNotFoundError:
            logger.warning(
                "LLM config '%s.yaml' not found under configs/llm/. "
                "Falling back to local_openai_compatible defaults.",
                provider_name,
            )
            return LLMConfig(
                provider=provider_name,
                model="qwen2-7b-instruct",
                base_url="http://127.0.0.1:1234/v1",
            )
