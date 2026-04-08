"""
online_mitm.py — Core online MITM attacker (Contribution C1).

OnlineMITMAttacker implements the central loop:

  observe → buffer → infer phase → build context → LLM decide → act

This is the component that distinguishes the v2 paper from the v1 testbed.
Unlike the one-shot LLMAttacker (static_llm.py), this attacker:

  1. Runs continuously and observes the live process.
  2. Maintains a rolling history window.
  3. Infers the current operational phase.
  4. Builds a context payload at the configured tier (minimal/partial/full).
  5. Calls the LLM to make an explicit attack-or-wait decision.
  6. Waits if conditions are unfavorable — this is the key MITM behavior.
  7. Executes validated attacks through the safety shield.
  8. Records outcomes for context in subsequent decisions.

Experimental controls
---------------------
The context_level parameter is the independent variable for RQ1.
The llm_provider + model_name are the independent variable for RQ2/RQ3.
All other parameters (scene, shield, budget, duration) are held constant.
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import re
import time
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

# ---------------------------------------------------------------------------
# Decision record — stored in history for context injection
# ---------------------------------------------------------------------------

@dataclass
class DecisionRecord:
    """One cycle's input + output + outcome."""
    step_id: int
    decision: AttackDecisionType
    payload_hash: str
    target_tag: Optional[str] = None
    action_type: Optional[str] = None
    action_value: Optional[float] = None
    shield_approved: Optional[bool] = None
    write_executed: bool = False
    attack_success: Optional[bool] = None
    llm_latency_ms: float = 0.0
    reasoning: str = ""


# ---------------------------------------------------------------------------
# OnlineMITMAttacker
# ---------------------------------------------------------------------------

class OnlineMITMAttacker:
    """Online man-in-the-middle LLM attacker for CPS processes.

    Parameters
    ----------
    scene : BaseScene
        Active Factory I/O scene.
    llm_provider : BaseLLMProvider
        LLM backend (any OpenAI-compatible endpoint including LM Studio).
    context_level : ContextLevel
        Ablation tier: MINIMAL | PARTIAL | FULL.  Independent variable for RQ1.
    history : HistoryBuffer
        Shared rolling window populated by PlcObserver.
    phase_engine : PhaseInferenceEngine
        Phase inference engine for this scene.
    attack_budget : int
        Maximum number of attack proposals per run (default 10).
    decision_interval : int
        Call the LLM every N observation steps (default 3).
    llm_timeout_s : float
        Per-call LLM timeout. On timeout, decision defaults to "wait".
    max_retries : int
        JSON parse retries before giving up on a cycle (default 1).
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
        llm_timeout_s: float = 120.0,
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

        self._context_builder = ContextBuilder(
            scene=scene,
            phase_engine=phase_engine,
            history=history,
        )

        self._decision_history: List[DecisionRecord] = []
        self._attacks_issued: int = 0
        self._steps_since_decision: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def context_level(self) -> ContextLevel:
        return self._context_level

    @property
    def attacks_issued(self) -> int:
        return self._attacks_issued

    @property
    def budget_remaining(self) -> int:
        return max(0, self._attack_budget - self._attacks_issued)

    @property
    def decision_history(self) -> List[DecisionRecord]:
        return list(self._decision_history)

    def should_call_llm(self) -> bool:
        """Return True if it is time to make a decision this step."""
        if self.budget_remaining <= 0:
            return False
        self._steps_since_decision += 1
        if self._steps_since_decision >= self._decision_interval:
            self._steps_since_decision = 0
            return True
        return False

    def decide(self, snapshot: PlantSnapshot) -> AttackDecision:
        """Run one complete MITM decision cycle.

        1. Build context payload at configured tier.
        2. Call LLM (with retry).
        3. Parse + validate response.
        4. Return AttackDecision (attack|wait).
        """
        prior_actions = self._serialize_prior_actions(tail=5)
        payload = self._context_builder.build(
            snapshot=snapshot,
            level=self._context_level,
            prior_actions=prior_actions,
        )
        system_prompt, user_prompt = self._context_builder.render(payload)

        decision = self._call_with_retry(system_prompt, user_prompt, payload, snapshot)

        # Record for subsequent context injection
        self._decision_history.append(
            DecisionRecord(
                step_id=snapshot.step_id,
                decision=decision.decision,
                payload_hash=payload.payload_hash or "",
                target_tag=decision.target_tag,
                action_type=decision.action_type,
                action_value=decision.action_value,
                llm_latency_ms=decision.llm_latency_ms,
                reasoning=decision.reasoning,
            )
        )

        if decision.is_attack():
            self._attacks_issued += 1

        return decision

    def record_outcome(
        self,
        step_id: int,
        shield_approved: bool,
        write_executed: bool,
        attack_success: Optional[bool],
    ) -> None:
        """Update the most recent decision record with execution outcome."""
        for rec in reversed(self._decision_history):
            if rec.step_id == step_id and rec.decision == AttackDecisionType.ATTACK:
                rec.shield_approved = shield_approved
                rec.write_executed = write_executed
                rec.attack_success = attack_success
                return

    def to_attack_action(self, decision: AttackDecision) -> Optional[AttackAction]:
        """Convert an ATTACK decision to an AttackAction for the shield/compiler.

        Returns None if the decision is WAIT or if required fields are missing.
        """
        if not decision.is_attack():
            return None
        if not decision.target_tag or not decision.action_type:
            logger.warning("Attack decision missing target_tag or action_type — treating as wait")
            return None

        try:
            attack_type = AttackType(decision.action_type)
        except ValueError:
            logger.warning(
                "Unknown action_type '%s' in AttackDecision — treating as wait",
                decision.action_type,
            )
            return None

        return AttackAction(
            attack_type=attack_type,
            target=decision.target_tag,
            mode="override",
            value=decision.action_value,
            duration_ms=max(0, min(decision.duration_ms, 30000)),
            rationale=decision.reasoning,
            expected_effect=decision.expected_effect,
            confidence=max(0.0, min(1.0, decision.confidence)),
            source=AttackSource.LLM,
        )

    # ------------------------------------------------------------------
    # Internal: LLM call + retry
    # ------------------------------------------------------------------

    def _call_with_retry(
        self,
        system_prompt: str,
        user_prompt: str,
        payload: ContextPayload,
        snapshot: PlantSnapshot,
    ) -> AttackDecision:
        """Call LLM, parse response, retry once on failure.

        On any unrecoverable failure, returns a WAIT decision.
        """
        raw_output = ""
        latency_ms = 0.0

        for attempt in range(self._max_retries + 1):
            try:
                t0 = time.monotonic()
                # Call LLM directly (no thread pool) — the provider
                # already handles timeouts internally via timeout_s config.
                result = self._provider.complete(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_format={"type": "json_object"},
                )
                latency_ms = (time.monotonic() - t0) * 1000.0
                raw_output = result.text

                decision = _parse_decision(raw_output, self._scene.profile.attack_surface)
                decision.llm_latency_ms = latency_ms
                decision.raw_output = raw_output
                logger.debug(
                    "Step %d: LLM decision=%s target=%s (%.0f ms, attempt %d)",
                    snapshot.step_id,
                    decision.decision.value,
                    decision.target_tag or "—",
                    latency_ms,
                    attempt + 1,
                )
                return decision

            except Exception as exc:
                logger.warning(
                    "Step %d: LLM call/parse failed (attempt %d): %s",
                    snapshot.step_id,
                    attempt + 1,
                    exc,
                )
                # On first failure, add a correction note and retry
                if attempt == 0:
                    attack_surface_str = ", ".join(self._scene.profile.attack_surface)
                    user_prompt = (
                        f"{user_prompt}\n\n"
                        f"[Previous response could not be parsed.  "
                        f"Return ONLY valid JSON with 'decision' and required fields.  "
                        f"Valid target_tag values: {attack_surface_str}]"
                    )

        # All retries exhausted — safe default: wait
        logger.info("Step %d: All LLM retries exhausted — defaulting to WAIT", snapshot.step_id)
        return AttackDecision(
            decision=AttackDecisionType.WAIT,
            reasoning="LLM call failed or produced unparseable output",
            confidence=0.0,
            parse_success=False,
            raw_output=raw_output,
            llm_latency_ms=latency_ms,
        )

    def _serialize_prior_actions(self, tail: int = 5) -> List[Dict[str, Any]]:
        """Extract the last *tail* decisions for injection into FULL context."""
        recent = self._decision_history[-tail:]
        result = []
        for rec in recent:
            result.append({
                "step_id":       rec.step_id,
                "decision":      rec.decision.value,
                "target_tag":    rec.target_tag,
                "action_type":   rec.action_type,
                "action_value":  rec.action_value,
                "shield_approved": rec.shield_approved,
                "attack_success":  rec.attack_success,
                "reasoning":     rec.reasoning,
            })
        return result


# ---------------------------------------------------------------------------
# JSON parsing helper
# ---------------------------------------------------------------------------

def _parse_decision(
    raw_text: str,
    attack_surface: List[str],
) -> AttackDecision:
    """Parse the LLM's raw text response into an AttackDecision.

    Accepts:
    - Clean JSON objects
    - JSON embedded in markdown fences
    - JSON embedded in prose (extracted by depth-counting)
    """
    text = raw_text.strip()

    # Strip markdown fences
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```\s*$",       "", text)
    text = text.strip()

    # Extract first JSON object by depth counting
    obj_text = _extract_first_json_object(text)
    if not obj_text:
        raise ValueError(f"No JSON object found in LLM output: {raw_text[:200]!r}")

    try:
        data = json.loads(obj_text)
    except json.JSONDecodeError:
        # Attempt trailing-comma repair
        repaired = re.sub(r",\s*([}\]])", r"\1", obj_text)
        data = json.loads(repaired)

    # --- Validate decision field ---
    raw_decision = str(data.get("decision", "wait")).lower()
    if raw_decision not in ("attack", "wait"):
        raw_decision = "wait"
    decision_type = AttackDecisionType(raw_decision)

    # --- Extract attack fields ---
    target_tag   = data.get("target_tag") or data.get("tag") or None
    action_type  = data.get("action_type") or data.get("attack_type") or None
    action_value = data.get("action_value") or data.get("value") or None
    duration_ms  = int(data.get("duration_ms") or 5000)
    confidence   = float(data.get("confidence") if data.get("confidence") is not None else 0.5)
    reasoning    = str(data.get("reasoning", ""))
    timing_rat   = str(data.get("timing_rationale", ""))
    effect       = str(data.get("expected_effect", ""))

    # --- Validate target_tag against attack surface ---
    if decision_type == AttackDecisionType.ATTACK:
        if target_tag and attack_surface and target_tag not in attack_surface:
            raise ValueError(
                f"target_tag '{target_tag}' not in attack_surface {attack_surface}"
            )
        if action_value is not None:
            try:
                action_value = float(action_value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"action_value is not numeric: {action_value!r}") from exc

    return AttackDecision(
        decision=decision_type,
        target_tag=target_tag,
        action_type=action_type,
        action_value=action_value,
        duration_ms=min(max(duration_ms, 0), 30000),
        expected_effect=effect,
        confidence=min(max(confidence, 0.0), 1.0),
        reasoning=reasoning,
        timing_rationale=timing_rat,
        parse_success=True,
    )


def _extract_first_json_object(text: str) -> Optional[str]:
    """Extract the first top-level JSON object from *text* using depth counting.

    If the JSON is truncated (e.g. by max_tokens), attempt repair by
    closing open strings, removing trailing commas, and adding closing braces.
    """
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    for i, ch in enumerate(text[start:], start=start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]

    # JSON was truncated — attempt repair
    fragment = text[start:]
    # Close any open string (find last unmatched quote)
    in_string = False
    escaped = False
    for ch in fragment:
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == '"':
            in_string = not in_string
    if in_string:
        fragment += '"'
    # Remove trailing comma after last complete value
    fragment = re.sub(r",\s*$", "", fragment)
    # Close open braces/brackets
    for ch in fragment:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
    # depth was reset above; recalculate
    depth = 0
    for ch in fragment:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
    while depth > 0:
        fragment += "}"
        depth -= 1
    try:
        json.loads(fragment)
        return fragment
    except json.JSONDecodeError:
        return None
