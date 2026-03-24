"""
CPSForge Campaign Attacker
============================
A multi-step LLM-driven attack campaign planner that generates phased
attack sequences with strategic objectives.

Unlike the standard :class:`LLMAttacker` which generates a batch of
independent actions, the CampaignAttacker plans a multi-phase campaign:

1. **Reconnaissance phase**: probe the process to gather baseline state.
2. **Preparation phase**: make subtle changes to weaken defenses.
3. **Exploitation phase**: execute the main attack payload.
4. **Persistence phase**: maintain the attack while avoiding detection.

Each phase generates actions that are aware of prior phase outcomes,
enabling the LLM to adapt its strategy based on what happened.

This implements Option A of the paper contribution: demonstrating that
LLM attackers can discover multi-step attack strategies that simple
scripted or random attackers cannot.

Key Metrics
-----------
- **Campaign success rate**: fraction of campaigns achieving their objective
- **Stealth score**: fraction of attack steps not detected
- **Mean deviation**: average process impact during exploitation
- **Discovery novelty**: attack patterns not present in scripted baselines
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from cpsforge.attacks.base import BaseAttacker
from cpsforge.core.config import AttackPolicyConfig, ConfigLoader, LLMConfig
from cpsforge.core.models import AttackAction, AttackSource, AttackType, ExecutionStatus
from cpsforge.llm.base_provider import BaseLLMProvider
from cpsforge.llm.factory import build_provider
from cpsforge.llm.schema_validator import ActionSchemaValidator, ValidationError

logger = logging.getLogger(__name__)

# Phase definitions
CAMPAIGN_PHASES = ["reconnaissance", "preparation", "exploitation", "persistence"]

# System prompt template for campaign planning
_CAMPAIGN_SYSTEM_PROMPT = """\
You are a CPS security researcher conducting a structured red-team campaign \
against an industrial control system for research purposes.

## Plant Description
Scene: {scene_name}
Description: {scene_description}

## Attack Surface (writable tags with ranges)
{attack_surface}

## Campaign Objective
{campaign_objective}

## Current Phase: {phase}
{phase_instruction}

## Rules
1. You must output ONLY valid JSON — a single object or array of objects.
2. Each object must have these fields:
   - "attack_type": one of {attack_types}
   - "target": a tag name from the attack surface above (EXACTLY as listed)
   - "value": a numeric value within the tag's allowed range
   - "duration_ms": integer ≥ 500 and ≤ 30000
   - "rationale": explain why this action advances the campaign objective
   - "expected_effect": what process impact you expect
   - "confidence": float 0.0–1.0
   - "stealth_notes": how you are attempting to avoid detection
3. For boolean tags, value must be 0 or 1.
4. Consider what values would be physically plausible to avoid detection.
5. Previous phase outcomes are provided — adapt your strategy accordingly.

## Prior Phase Results
{prior_results}
"""

_PHASE_INSTRUCTIONS = {
    "reconnaissance": (
        "Goal: Propose small, subtle probes to characterize the process.\n"
        "Use minimal perturbations (e.g. +/- 5% of range) to observe responses.\n"
        "Generate 1-2 probe actions."
    ),
    "preparation": (
        "Goal: Make subtle changes that weaken the system's resilience.\n"
        "Based on reconnaissance results, shift setpoints or actuator values\n"
        "slightly toward less safe regions without triggering alarms.\n"
        "Generate 1-3 preparation actions."
    ),
    "exploitation": (
        "Goal: Execute the main attack payload to achieve the campaign objective.\n"
        "Use knowledge from prior phases to maximize impact while maintaining\n"
        "plausibility. Generate 2-4 exploitation actions."
    ),
    "persistence": (
        "Goal: Maintain the attack effect while minimizing detection risk.\n"
        "Use smaller sustained perturbations rather than large spikes.\n"
        "Generate 1-2 persistence actions."
    ),
}


class CampaignAttacker(BaseAttacker):
    """
    Multi-phase LLM attack campaign planner.

    Generates attack actions across four phases, with each phase
    informed by the outcomes of previous phases. This creates
    strategically coherent attack campaigns that are qualitatively
    different from independent single-step attacks.
    """

    def __init__(
        self,
        config: AttackPolicyConfig,
        *,
        provider: Optional[BaseLLMProvider] = None,
    ) -> None:
        super().__init__(config)

        # Build or accept LLM provider
        if provider is not None:
            self._provider = provider
        else:
            llm_cfg = self._load_llm_config(config)
            self._provider = build_provider(llm_cfg)

        self._validator = ActionSchemaValidator()
        self._max_retries = config.llm_max_retries
        self._campaign_objective = config.parameters.get(
            "campaign_objective",
            "Disrupt the physical process to cause a safety-relevant deviation "
            "while keeping detection probability low."
        )

        # Campaign state
        self._phase_results: Dict[str, Dict[str, Any]] = {}
        self._all_actions: List[AttackAction] = []
        self._campaign_id = str(uuid4())[:8]

        logger.info(
            "CampaignAttacker '%s' ready: provider=%s model=%s campaign=%s",
            self.name, self._provider.provider_name,
            self._provider.model_name, self._campaign_id,
        )

    def generate_actions(self, scene: object) -> List[AttackAction]:
        """
        Generate a full multi-phase campaign.

        Calls the LLM once per phase, passing prior phase results into
        each subsequent prompt. Returns the combined list of all
        campaign actions in phase order.
        """
        profile = getattr(scene, "profile", None)
        if profile is None:
            logger.error("CampaignAttacker: scene has no profile.")
            return []

        attack_surface_str = self._build_attack_surface_str(scene)
        attack_types_str = ", ".join(t.value for t in AttackType)

        all_actions: List[AttackAction] = []
        max_per_phase = max(1, self._config.max_actions // len(CAMPAIGN_PHASES))

        for phase in CAMPAIGN_PHASES:
            logger.info(
                "Campaign '%s' — Phase: %s", self._campaign_id, phase
            )

            system_prompt = _CAMPAIGN_SYSTEM_PROMPT.format(
                scene_name=profile.scene_name,
                scene_description=profile.description,
                attack_surface=attack_surface_str,
                campaign_objective=self._campaign_objective,
                phase=phase.upper(),
                phase_instruction=_PHASE_INSTRUCTIONS[phase],
                attack_types=attack_types_str,
                prior_results=json.dumps(self._phase_results, indent=2)
                if self._phase_results else "None (this is the first phase)",
            )

            user_prompt = (
                f"Generate {phase} actions for this campaign. "
                f"Output ONLY a JSON array of action objects."
            )

            phase_actions = self._call_llm_with_retries(
                system_prompt, user_prompt, scene, max_per_phase
            )

            # Record phase results for next phase's context
            self._phase_results[phase] = {
                "actions_planned": len(phase_actions),
                "targets": [a.target for a in phase_actions],
                "attack_types": [a.attack_type.value for a in phase_actions],
                "rationales": [a.rationale or "" for a in phase_actions],
            }

            # Tag each action with campaign metadata
            for action in phase_actions:
                action.rationale = f"[{phase.upper()}] {action.rationale or ''}"
                action.source = AttackSource.LLM

            all_actions.extend(phase_actions)

        self._all_actions = all_actions
        logger.info(
            "Campaign '%s' complete: %d total actions across %d phases",
            self._campaign_id, len(all_actions), len(CAMPAIGN_PHASES),
        )
        return all_actions[:self._config.max_actions]

    def get_campaign_summary(self) -> Dict[str, Any]:
        """Return metadata about the campaign for artifact logging."""
        return {
            "campaign_id": self._campaign_id,
            "objective": self._campaign_objective,
            "total_actions": len(self._all_actions),
            "phase_results": self._phase_results,
            "phases": CAMPAIGN_PHASES,
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _call_llm_with_retries(
        self,
        system_prompt: str,
        user_prompt: str,
        scene: object,
        max_actions: int,
    ) -> List[AttackAction]:
        """Call LLM with retry logic, returning validated actions."""
        current_prompt = user_prompt
        for attempt in range(self._max_retries):
            try:
                result = self._provider.complete(system_prompt, current_prompt)
                raw_text = result.text

                actions = self._validator.parse_and_validate(raw_text)

                # Validate targets against attack surface
                attack_surface = set()
                profile = getattr(scene, "profile", None)
                if profile and profile.attack_surface:
                    attack_surface = set(profile.attack_surface)

                valid_actions = []
                for action in actions[:max_actions]:
                    if attack_surface and action.target not in attack_surface:
                        logger.warning(
                            "Campaign: LLM proposed invalid target '%s', skipping.",
                            action.target,
                        )
                        continue
                    valid_actions.append(action)

                if valid_actions:
                    return valid_actions

                # No valid actions from this attempt
                current_prompt = (
                    f"{user_prompt}\n\n"
                    f"Your previous response contained no valid targets. "
                    f"Use ONLY these target names: "
                    f"{', '.join(sorted(attack_surface))}"
                )

            except ValidationError as exc:
                logger.warning(
                    "Campaign LLM validation error (attempt %d): %s",
                    attempt + 1, exc.message,
                )
                current_prompt = (
                    f"{user_prompt}\n\n"
                    f"Your previous response was invalid JSON: {exc.message}\n"
                    f"Output ONLY a valid JSON array of attack action objects."
                )
            except Exception as exc:
                logger.warning(
                    "Campaign LLM call failed (attempt %d): %s", attempt + 1, exc
                )

        logger.warning("Campaign: all retries exhausted, returning empty phase.")
        return []

    def _build_attack_surface_str(self, scene: object) -> str:
        """Build human-readable attack surface with tag ranges."""
        profile = getattr(scene, "profile", None)
        if not profile or not profile.attack_surface:
            return "(no writable tags)"

        parts = []
        tags_by_name = {}
        if hasattr(profile, "tags") and profile.tags:
            for tag in profile.tags:
                tags_by_name[tag.name] = tag

        for tag_name in sorted(profile.attack_surface):
            tag = tags_by_name.get(tag_name)
            if tag is None:
                parts.append(f"  - {tag_name}")
                continue

            dtype = tag.data_type.lower() if tag.data_type else "?"
            if dtype == "bool":
                parts.append(f"  - {tag_name} (bool, value: 0 or 1)")
            elif tag.min_value is not None and tag.max_value is not None:
                unit = f" {tag.unit}" if tag.unit else ""
                parts.append(
                    f"  - {tag_name} ({dtype}, range: {tag.min_value}-{tag.max_value}{unit})"
                )
            else:
                parts.append(f"  - {tag_name} ({dtype})")

        return "\n".join(parts)

    def _load_llm_config(self, config: AttackPolicyConfig) -> Any:
        """Load LLM config from the config system."""
        provider_name = config.llm_provider or "local"
        try:
            loader = ConfigLoader()
            return loader.load_llm(provider_name)
        except FileNotFoundError:
            logger.warning(
                "LLM config '%s.yaml' not found under configs/llm/. "
                "Falling back to local_openai_compatible defaults.",
                provider_name,
            )
            from cpsforge.core.config import LLMConfig
            return LLMConfig(
                provider="local_openai_compatible",
                model="qwen2-7b-instruct",
                base_url="http://127.0.0.1:1234/v1",
            )
