"""
static_llm.py — Static (one-shot) LLM attacker for v2 experiments.

StaticLLMAttacker makes a single LLM call at the start of the run with
the initial snapshot (no history, no phase awareness). It generates a
batch of attack proposals and schedules them at fixed intervals.

This is the RQ3 baseline: it demonstrates what a one-shot LLM can do
without the observe-wait-attack loop of the online MITM attacker.

The key difference from OnlineMITMAttacker:
  - ONE LLM call total (not one per decision interval)
  - No history window in context
  - No phase inference
  - Fixed attack schedule (no timing adaptation)

It produces the same AttackDecision schema and integrates with the same
runner, so RQ3 comparisons use identical logging and metrics.
"""

from __future__ import annotations

import json
import logging
import re
import time
import concurrent.futures
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from cpsforge.attacker.schema import (
    AttackDecision,
    AttackDecisionType,
    ATTACK_DECISION_JSON_SCHEMA,
)
from cpsforge.context_builder.builder import ContextBuilder
from cpsforge.context_builder.schema import ContextLevel, ContextPayload
from cpsforge.core.models import (
    AttackAction,
    AttackSource,
    AttackType,
    ExecutionStatus,
    PlantSnapshot,
)
from cpsforge.llm.base_provider import BaseLLMProvider
from cpsforge.observation.history_buffer import HistoryBuffer
from cpsforge.observation.phase_inference import PhaseInferenceEngine
from cpsforge.scenes.base import BaseScene

logger = logging.getLogger(__name__)


class StaticLLMAttacker:
    """One-shot batch LLM attacker for RQ3 baseline.

    Parameters
    ----------
    scene : BaseScene
    llm_provider : BaseLLMProvider
    context_level : ContextLevel
    attack_budget : int
        Number of attacks to request from the LLM (default 10).
    llm_timeout_s : float
        Per-call LLM timeout (default 30s).
    """

    def __init__(
        self,
        scene: BaseScene,
        llm_provider: BaseLLMProvider,
        context_level: ContextLevel,
        history: HistoryBuffer,
        phase_engine: PhaseInferenceEngine,
        attack_budget: int = 10,
        decision_interval: int = 3,
        llm_timeout_s: float = 30.0,
        max_retries: int = 1,
    ) -> None:
        self._scene = scene
        self._provider = llm_provider
        self._context_level = context_level
        self._history = history
        self._phase_engine = phase_engine
        self._attack_budget = attack_budget
        self._decision_interval = decision_interval
        self._timeout = llm_timeout_s
        self._max_retries = max_retries

        # Static attacker always uses MINIMAL context (no history, no phase)
        self._context_builder = ContextBuilder(
            scene=scene,
            phase_engine=phase_engine,
            history=history,
        )

        self._proposals: List[AttackDecision] = []
        self._proposal_idx: int = 0
        self._initial_call_done: bool = False
        self._steps_since_decision: int = 0

    # ------------------------------------------------------------------
    # Public API (matches OnlineMITMAttacker interface)
    # ------------------------------------------------------------------

    def should_call_llm(self) -> bool:
        """Return True if it's time to emit a decision.

        The static attacker calls the LLM once on the first eligible step
        to generate all proposals in batch, then dequeues from the list.
        After the initial batch, it emits one proposal per decision interval.
        """
        self._steps_since_decision += 1
        # Always call on first step to trigger the one-shot batch
        if not self._initial_call_done:
            return True
        if self._steps_since_decision >= self._decision_interval:
            self._steps_since_decision = 0
            return True
        return False

    def decide(self, snapshot: PlantSnapshot) -> AttackDecision:
        """Return the next scheduled attack or WAIT.

        On the first call, makes one LLM call to generate all proposals.
        Subsequent calls dequeue from the pre-generated list.
        """
        if not self._initial_call_done:
            self._initial_call_done = True
            self._proposals = self._generate_batch(snapshot)
            logger.info(
                "StaticLLMAttacker: generated %d proposals in initial batch",
                len(self._proposals),
            )

        # Dequeue next proposal
        if self._proposal_idx < len(self._proposals):
            decision = self._proposals[self._proposal_idx]
            self._proposal_idx += 1
            return decision

        # All proposals exhausted — wait
        return AttackDecision(
            decision=AttackDecisionType.WAIT,
            reasoning="All pre-generated attack proposals exhausted",
            confidence=0.0,
            parse_success=True,
        )

    def record_outcome(self, **kwargs: Any) -> None:
        """No-op for static attacker (no feedback loop)."""
        pass

    def to_attack_action(self, decision: AttackDecision) -> Optional[AttackAction]:
        """Convert AttackDecision to AttackAction for shield evaluation."""
        if decision.decision != AttackDecisionType.ATTACK:
            return None
        if not decision.target_tag or not decision.action_type:
            return None

        attack_type_map = {
            "actuator_override": AttackType.ACTUATOR_OVERRIDE,
            "setpoint_shift": AttackType.SETPOINT_SHIFT,
            "sensor_spoof": AttackType.SENSOR_SPOOF,
            "timing_delay": AttackType.TIMING_DELAY,
            "sequence_perturbation": AttackType.SEQUENCE_PERTURBATION,
        }
        at = attack_type_map.get(decision.action_type, AttackType.ACTUATOR_OVERRIDE)

        return AttackAction(
            attack_type=at,
            target=decision.target_tag,
            value=decision.action_value,
            duration_ms=decision.duration_ms,
            mode="override",
            source=AttackSource.LLM,
            rationale=decision.reasoning or "static_llm_batch",
            confidence=decision.confidence,
            execution_status=ExecutionStatus.PENDING,
        )

    # ------------------------------------------------------------------
    # Internal: batch generation
    # ------------------------------------------------------------------

    def _generate_batch(self, snapshot: PlantSnapshot) -> List[AttackDecision]:
        """Make one LLM call asking for multiple attack proposals."""
        # Build context with MINIMAL-like settings (no history, no phase)
        payload = self._context_builder.build(
            snapshot=snapshot,
            level=ContextLevel.MINIMAL,
        )

        system_prompt, user_prompt = self._context_builder.render(
            payload=payload,
        )

        # Modify prompt to request batch
        user_prompt += (
            f"\n\nGenerate up to {self._attack_budget} attack proposals as a JSON array. "
            f"Each element must have: decision, target_tag, action_type, action_value, "
            f"duration_ms, expected_effect, confidence, reasoning. "
            f"Return ONLY a JSON array of objects."
        )

        raw_output = ""
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    self._provider.complete,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_format={"type": "json_object"},
                )
                result = future.result(timeout=self._timeout)
            raw_output = result.text
        except Exception as exc:
            logger.warning("StaticLLMAttacker batch call failed: %s", exc)
            return []

        return self._parse_batch(raw_output)

    def _parse_batch(self, raw_text: str) -> List[AttackDecision]:
        """Parse a JSON array of attack proposals."""
        text = raw_text.strip()
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```\s*$", "", text)
        text = text.strip()

        logger.debug("StaticLLMAttacker raw output (first 800 chars): %s", text[:800])

        proposals = []
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Try to repair trailing commas
            repaired = re.sub(r",\s*([}\]])", r"\1", text)
            try:
                data = json.loads(repaired)
            except json.JSONDecodeError:
                # Try to salvage truncated array: find last complete object and close the array
                data = None
                last_brace = text.rfind('}')
                if last_brace > 0:
                    arr_start = text.find('[')
                    if arr_start >= 0:
                        truncated = text[arr_start:last_brace + 1] + ']'
                        truncated = re.sub(r",\s*([}\]])", r"\1", truncated)
                        try:
                            data = json.loads(truncated)
                            logger.info("Salvaged truncated batch response (%d chars cut)", len(text) - last_brace)
                        except json.JSONDecodeError:
                            pass
                if data is None:
                    logger.warning("Could not parse batch response. Raw output (first 500): %s", text[:500])
                    return []

        # Handle both array and object-with-array responses
        if isinstance(data, dict):
            # Look for an array field
            for key in ("attacks", "proposals", "actions", "results"):
                if key in data and isinstance(data[key], list):
                    data = data[key]
                    break
            else:
                # Single attack wrapped in object
                data = [data]

        if not isinstance(data, list):
            return []

        attack_surface = self._scene.profile.attack_surface
        for item in data[:self._attack_budget]:
            try:
                decision_str = str(item.get("decision", "attack")).lower()
                if decision_str not in ("attack", "wait"):
                    decision_str = "attack"

                target_tag = item.get("target_tag") or item.get("tag")
                action_type = item.get("action_type") or item.get("attack_type")
                action_value = item.get("action_value") or item.get("value")

                if target_tag and attack_surface and target_tag not in attack_surface:
                    continue

                if action_value is not None:
                    try:
                        action_value = float(action_value)
                    except (TypeError, ValueError):
                        continue

                proposals.append(AttackDecision(
                    decision=AttackDecisionType(decision_str),
                    target_tag=target_tag,
                    action_type=action_type,
                    action_value=action_value,
                    duration_ms=int(item.get("duration_ms", 5000)),
                    expected_effect=str(item.get("expected_effect", "")),
                    confidence=float(item.get("confidence", 0.5)),
                    reasoning=str(item.get("reasoning", "")),
                    parse_success=True,
                    raw_output=raw_text,
                ))
            except Exception as exc:
                logger.debug("Skipping unparseable batch item: %s", exc)
                continue

        return proposals


__all__ = ["StaticLLMAttacker"]
