"""
deep_state_mitm.py — Deep State Manipulation MITM attacker (Tier 2).

DeepStateMITMAttacker extends the online MITM concept to target **internal
PLC state variables** that the PLC logic never refreshes — iState, timers,
enable flags, sort thresholds, and classification flags.

Key difference from Tier 1 (I/O MitM):
  - Tier 1 targets I/O tags (sensors, actuators, setpoints) that the PLC
    logic overwrites each scan cycle → requires continuous injection.
  - Tier 2 targets internal state variables that the PLC reads but NEVER
    writes → a single S7 write persists indefinitely, modifying how the
    PLC logic executes without changing the program itself.

This is analogous to Stuxnet's DB890 writes that manipulated VFD frequency
parameters through data blocks rather than code modification.

Attack categories
-----------------
  - threshold_manipulation : Shift sort thresholds (LightThresh, HeavyThresh)
  - state_machine_jump     : Force illegal state transitions (iState)
  - timer_acceleration     : Accelerate or stall timed transitions (DwellTimer)
  - safety_kill_switch     : Disable Enable flag → freeze all actuators
  - decision_flag_spoofing : Override classification flags (IsTall, MeasuredWeight)
  - setpoint_hijack        : Permanently change frozen setpoints (SetpointIn)
  - counter_spoofing       : Falsify production counts
  - mode_manipulation      : Toggle Running/mode flags

The attacker reads the deep_state_attack_surface from the scene YAML config
and builds enhanced LLM context that includes:
  - State machine descriptions and valid transitions
  - Variable persistence characteristics (permanent vs transient)
  - Attack category descriptions and expected effects
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from cpsforge.attacker.schema import (
    AttackDecision,
    AttackDecisionType,
)
from cpsforge.context_builder.builder import ContextBuilder
from cpsforge.context_builder.schema import ContextLevel, ContextPayload
from cpsforge.core.models import (
    AttackAction,
    AttackSource,
    AttackType,
    PlantSnapshot,
)
from cpsforge.llm.base_provider import BaseLLMProvider
from cpsforge.observation.history_buffer import HistoryBuffer
from cpsforge.observation.phase_inference import PhaseInferenceEngine
from cpsforge.scenes.base import BaseScene

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Deep State attack decision schema (extends base AttackDecision)
# ---------------------------------------------------------------------------

DEEP_STATE_JSON_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "decision": {
            "type": "string",
            "enum": ["attack", "wait"],
        },
        "target_tag": {"type": "string"},
        "action_type": {
            "type": "string",
            "enum": [
                "threshold_manipulation",
                "state_machine_jump",
                "timer_acceleration",
                "safety_kill_switch",
                "decision_flag_spoofing",
                "setpoint_hijack",
                "counter_spoofing",
                "mode_manipulation",
            ],
        },
        "action_value": {"type": "number"},
        "persistence": {
            "type": "string",
            "enum": ["permanent", "transient"],
        },
        "expected_effect": {"type": "string"},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "reasoning": {"type": "string"},
        "timing_rationale": {"type": "string"},
    },
    "required": ["decision"],
}


# ---------------------------------------------------------------------------
# Deep State prompt templates
# ---------------------------------------------------------------------------

_DS_SYSTEM_PROMPT = """You are a CPS security researcher testing deep state manipulation attacks on the '{scene_name}' process.

PROCESS DESCRIPTION:
{scene_description}

CONTROL OBJECTIVE:
{control_objective}

DEEP STATE ATTACK CONCEPT:
Unlike standard I/O attacks that overwrite sensor/actuator values (which the PLC
refreshes each scan cycle), deep state attacks target INTERNAL PLC variables that
the PLC logic reads but NEVER writes. A single write to these variables persists
indefinitely, silently modifying how the PLC executes its control logic.

AVAILABLE DEEP STATE TARGETS:
{deep_state_targets}

ATTACK CATEGORIES:
- threshold_manipulation: Change sort thresholds so items route to wrong exits
- state_machine_jump: Force the state machine to skip states or jump backwards
- timer_acceleration: Set timers to high values to force immediate timeout, or 0 to stall
- safety_kill_switch: Set Enable=FALSE to freeze all actuators
- decision_flag_spoofing: Override classification flags (IsTall, MeasuredWeight) to cause missorts
- setpoint_hijack: Change frozen setpoints to push process to dangerous operating point
- counter_spoofing: Falsify production counts to mislead operators
- mode_manipulation: Toggle Running/mode flags to disrupt control logic

STRATEGY:
- Wait until the process is in a vulnerable state (mid-operation, during transitions)
- Choose targets where a single write causes maximum disruption
- Prefer PERMANENT persistence targets — a single write persists across many cycles
- Consider timing: e.g., spoofing IsTall AFTER sensor latch but BEFORE transfer decision

Respond with a JSON object:
{{
  "decision": "attack" or "wait",
  "target_tag": "<deep state target name>",
  "action_type": "<attack category>",
  "action_value": <value to write>,
  "persistence": "permanent" or "transient",
  "expected_effect": "<what happens to the process>",
  "confidence": 0.0-1.0,
  "reasoning": "<why this attack at this time>",
  "timing_rationale": "<why now is the right moment>"
}}
"""

_DS_USER_PROMPT = """CURRENT PROCESS STATE:
{current_values}

INFERRED PHASE: {inferred_phase} (confidence: {phase_confidence})

STATE MACHINE: {state_info}

RECENT HISTORY (last {history_steps} readings):
{history_summary}

{prior_actions_section}

Attacks remaining: {budget_remaining}

Analyze the process state and decide: attack a deep state variable, or wait for a better moment?"""


# ---------------------------------------------------------------------------
# DeepStateMITMAttacker
# ---------------------------------------------------------------------------

class DeepStateMITMAttacker:
    """Online MITM attacker targeting internal PLC state variables.

    Uses the same observe→decide→act loop as OnlineMITMAttacker but with:
    - Enhanced context including state machine descriptions and persistence info
    - Deep state attack surface from scene YAML (instead of I/O attack_surface)
    - Attack category vocabulary specific to internal state manipulation

    Parameters
    ----------
    scene : BaseScene
        Active Factory I/O scene.
    llm_provider : BaseLLMProvider
        LLM backend for decision-making.
    context_level : ContextLevel
        Ablation tier: MINIMAL | PARTIAL | FULL.
    history : HistoryBuffer
        Shared rolling window.
    phase_engine : PhaseInferenceEngine
        Phase inference engine.
    attack_budget : int
        Maximum attacks per run (default 10).
    decision_interval : int
        Call LLM every N observation steps (default 3).
    llm_timeout_s : float
        Per-call LLM timeout (default 120s).
    max_retries : int
        JSON parse retries (default 1).
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

        # Load deep state attack surface from scene config
        self._deep_state_surface = _load_deep_state_surface(scene)
        self._deep_state_tag_names = [t["name"] for t in self._deep_state_surface]

        self._decision_history: List[Dict[str, Any]] = []
        self._attacks_issued: int = 0
        self._steps_since_decision: int = 0

    # ------------------------------------------------------------------
    # Public API (same interface as OnlineMITMAttacker)
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
    def decision_history(self) -> list:
        return list(self._decision_history)

    def should_call_llm(self) -> bool:
        if self.budget_remaining <= 0:
            return False
        self._steps_since_decision += 1
        if self._steps_since_decision >= self._decision_interval:
            self._steps_since_decision = 0
            return True
        return False

    def decide(self, snapshot: PlantSnapshot) -> AttackDecision:
        """Run one deep state decision cycle."""
        system_prompt = self._build_system_prompt()
        user_prompt = self._build_user_prompt(snapshot)

        decision = self._call_with_retry(system_prompt, user_prompt, snapshot)

        self._decision_history.append({
            "step_id": snapshot.step_id,
            "decision": decision.decision.value,
            "target_tag": decision.target_tag,
            "action_type": decision.action_type,
            "action_value": decision.action_value,
            "llm_latency_ms": decision.llm_latency_ms,
            "reasoning": decision.reasoning,
        })

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
        for rec in reversed(self._decision_history):
            if rec["step_id"] == step_id and rec["decision"] == "attack":
                rec["shield_approved"] = shield_approved
                rec["write_executed"] = write_executed
                rec["attack_success"] = attack_success
                return

    def to_attack_action(self, decision: AttackDecision) -> Optional[AttackAction]:
        if not decision.is_attack():
            return None
        if not decision.target_tag or not decision.action_type:
            logger.warning("Deep state decision missing target_tag or action_type — treating as wait")
            return None

        # Map deep state action_type to AttackType enum
        action_type_map = {
            "threshold_manipulation": AttackType.SETPOINT_SHIFT,
            "state_machine_jump": AttackType.SEQUENCE_PERTURBATION,
            "timer_acceleration": AttackType.TIMING_DELAY,
            "safety_kill_switch": AttackType.ACTUATOR_OVERRIDE,
            "decision_flag_spoofing": AttackType.SENSOR_SPOOF,
            "setpoint_hijack": AttackType.SETPOINT_SHIFT,
            "counter_spoofing": AttackType.SENSOR_SPOOF,
            "mode_manipulation": AttackType.ACTUATOR_OVERRIDE,
        }
        try:
            attack_type = action_type_map.get(
                decision.action_type,
                AttackType.ACTUATOR_OVERRIDE,
            )
        except (ValueError, KeyError):
            attack_type = AttackType.ACTUATOR_OVERRIDE

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
    # Prompt construction
    # ------------------------------------------------------------------

    def _build_system_prompt(self) -> str:
        profile = self._scene.profile
        control_obj = getattr(profile, "control_objective", "") or ""
        deep_state_desc = self._format_deep_state_targets()

        return _DS_SYSTEM_PROMPT.format(
            scene_name=profile.scene_name,
            scene_description=profile.description or "",
            control_objective=control_obj,
            deep_state_targets=deep_state_desc,
        )

    def _build_user_prompt(self, snapshot: PlantSnapshot) -> str:
        # Current values
        values: Dict[str, Any] = {}
        for cat in (snapshot.sensors, snapshot.actuators,
                    snapshot.setpoints, snapshot.controller_state):
            values.update(cat)

        # Phase inference
        phase_result = self._phase_engine.infer(
            snapshot, self._history.window(20)
        )

        # State machine info
        state_info = self._get_state_info(values)

        # History summary
        history_tags = self._deep_state_tag_names + list(
            getattr(self._scene.profile, "key_sensors", None) or []
        )
        history_tags = list(dict.fromkeys(history_tags))  # deduplicate
        n_steps = 10 if self._context_level == ContextLevel.FULL else 5
        history_rows = self._history.as_table(tags=history_tags, n=n_steps)
        if history_rows:
            header = list(history_rows[0].keys())
            lines = ["  " + "  ".join(f"{k:<14}" for k in header)]
            for row in history_rows:
                lines.append("  " + "  ".join(f"{str(v):<14}" for v in row.values()))
            history_summary = "\n".join(lines)
        else:
            history_summary = "(no history yet)"

        # Prior actions (for FULL context)
        prior_section = ""
        if self._context_level == ContextLevel.FULL and self._decision_history:
            recent = self._decision_history[-5:]
            prior_section = "PRIOR ACTIONS:\n" + json.dumps(recent, indent=2)

        return _DS_USER_PROMPT.format(
            current_values=json.dumps(values, indent=2),
            inferred_phase=phase_result.phase.value,
            phase_confidence=round(phase_result.confidence, 2),
            state_info=state_info,
            history_steps=n_steps,
            history_summary=history_summary,
            prior_actions_section=prior_section,
            budget_remaining=self.budget_remaining,
        )

    def _format_deep_state_targets(self) -> str:
        """Format deep state targets for the system prompt."""
        lines = []
        for target in self._deep_state_surface:
            lines.append(
                f"  - {target['name']} ({target.get('data_type', '?')}, "
                f"persistence={target.get('persistence', '?')})\n"
                f"    Category: {target.get('attack_category', '?')}\n"
                f"    {target.get('description', '')}\n"
                f"    Effect: {target.get('state_machine_effect', '?')}"
            )
        return "\n".join(lines) if lines else "(no deep state targets configured)"

    def _get_state_info(self, values: Dict[str, Any]) -> str:
        """Extract state machine info from current values."""
        state_parts = []
        for target in self._deep_state_surface:
            name = target["name"]
            if name in values:
                valid_states = target.get("valid_states")
                val = values[name]
                if valid_states and val is not None:
                    state_label = valid_states.get(str(int(val)), f"unknown({val})")
                    state_parts.append(f"{name}={val} ({state_label})")
                else:
                    state_parts.append(f"{name}={val}")
        return ", ".join(state_parts) if state_parts else "(no state info)"

    # ------------------------------------------------------------------
    # LLM call + retry (same pattern as OnlineMITMAttacker)
    # ------------------------------------------------------------------

    def _call_with_retry(
        self,
        system_prompt: str,
        user_prompt: str,
        snapshot: PlantSnapshot,
    ) -> AttackDecision:
        raw_output = ""
        latency_ms = 0.0

        for attempt in range(self._max_retries + 1):
            try:
                t0 = time.monotonic()
                result = self._provider.complete(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_format={"type": "json_object"},
                )
                latency_ms = (time.monotonic() - t0) * 1000.0
                raw_output = result.text

                decision = _parse_deep_state_decision(
                    raw_output, self._deep_state_tag_names,
                )
                decision.llm_latency_ms = latency_ms
                decision.raw_output = raw_output
                logger.debug(
                    "Step %d: Deep state LLM decision=%s target=%s (%.0f ms)",
                    snapshot.step_id,
                    decision.decision.value,
                    decision.target_tag or "—",
                    latency_ms,
                )
                return decision

            except Exception as exc:
                logger.warning(
                    "Step %d: Deep state LLM call/parse failed (attempt %d): %s",
                    snapshot.step_id, attempt + 1, exc,
                )
                if attempt == 0:
                    targets_str = ", ".join(self._deep_state_tag_names)
                    user_prompt = (
                        f"{user_prompt}\n\n"
                        f"[Previous response could not be parsed. "
                        f"Return ONLY valid JSON. "
                        f"Valid target_tag values: {targets_str}]"
                    )

        logger.info("Step %d: All retries exhausted — defaulting to WAIT", snapshot.step_id)
        return AttackDecision(
            decision=AttackDecisionType.WAIT,
            reasoning="LLM call failed or produced unparseable output",
            confidence=0.0,
            parse_success=False,
            raw_output=raw_output,
            llm_latency_ms=latency_ms,
        )


# ---------------------------------------------------------------------------
# Scene config loader
# ---------------------------------------------------------------------------

def _load_deep_state_surface(scene: BaseScene) -> List[Dict[str, Any]]:
    """Load deep_state_attack_surface from scene config YAML."""
    profile = scene.profile
    raw = getattr(profile, "deep_state_attack_surface", None)
    if raw:
        return raw

    # Fallback: try loading from the raw YAML config
    try:
        import yaml
        from pathlib import Path
        config_path = Path("configs/scenes") / f"{profile.scene_name}.yaml"
        if config_path.exists():
            with open(config_path, "r") as f:
                cfg = yaml.safe_load(f)
            return cfg.get("deep_state_attack_surface", [])
    except Exception as exc:
        logger.warning("Could not load deep_state_attack_surface: %s", exc)

    return []


# ---------------------------------------------------------------------------
# JSON parsing (adapted from online_mitm._parse_decision)
# ---------------------------------------------------------------------------

def _parse_deep_state_decision(
    raw_text: str,
    deep_state_tags: List[str],
) -> AttackDecision:
    """Parse LLM JSON into an AttackDecision for deep state attacks."""
    text = raw_text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```\s*$", "", text)
    text = text.strip()

    obj_text = _extract_first_json_object(text)
    if not obj_text:
        raise ValueError(f"No JSON object found in LLM output: {raw_text[:200]!r}")

    try:
        data = json.loads(obj_text)
    except json.JSONDecodeError:
        repaired = re.sub(r",\s*([}\]])", r"\1", obj_text)
        data = json.loads(repaired)

    raw_decision = str(data.get("decision", "wait")).lower()
    if raw_decision not in ("attack", "wait"):
        raw_decision = "wait"
    decision_type = AttackDecisionType(raw_decision)

    target_tag = data.get("target_tag") or data.get("tag") or None
    action_type = data.get("action_type") or data.get("attack_type") or None
    _av = data.get("action_value")
    if _av is None:
        _av = data.get("value")
    action_value = _av  # preserve falsy-but-valid values like 0 / 0.0 / False
    duration_ms = int(data.get("duration_ms") or 5000)
    confidence = float(data.get("confidence") if data.get("confidence") is not None else 0.5)
    reasoning = str(data.get("reasoning", ""))
    timing_rat = str(data.get("timing_rationale", ""))
    effect = str(data.get("expected_effect", ""))

    if decision_type == AttackDecisionType.ATTACK:
        if target_tag and deep_state_tags and target_tag not in deep_state_tags:
            raise ValueError(
                f"target_tag '{target_tag}' not in deep_state_attack_surface {deep_state_tags}"
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
    """Extract the first top-level JSON object with truncation repair."""
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

    # Truncated — attempt repair
    fragment = text[start:]
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
    fragment = re.sub(r",\s*$", "", fragment)
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
