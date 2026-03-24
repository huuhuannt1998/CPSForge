"""Live LLM attacker agent implementation."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from cpsforge.agents.base import BaseAgent
from cpsforge.agents.messages import AgentEventType, RequestKind
from cpsforge.core.models import AttackAction, AttackType, PlantSnapshot
from cpsforge.llm.prompt_builder import PromptBuilder
from cpsforge.llm.schema_validator import ActionSchemaValidator, ValidationError

logger = logging.getLogger(__name__)


class AttackerAgent(BaseAgent):
    """Runtime attacker that adapts actions from live PLC observations."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._validator = ActionSchemaValidator(attack_surface=self._scene.attack_surface)
        self._prompt_builder = PromptBuilder(
            template_version=self._llm.config.prompt_template_version,
        )
        # Build system prompt once (scene context is static per run)
        self._system_prompt = self._prompt_builder.build_attacker_agent_system_prompt(
            scene=self._scene_wrapper,
        )

    @property
    def _scene_wrapper(self) -> object:
        """Expose SceneProfile as an object with a .profile attribute for PromptBuilder."""

        class _W:
            pass

        w = _W()
        w.profile = self._scene  # type: ignore[attr-defined]
        return w

    # ------------------------------------------------------------------
    # JSON schema (structured output) helpers
    # ------------------------------------------------------------------

    def _build_response_format(self) -> Optional[Dict[str, Any]]:
        """
        Build a ``response_format`` JSON-schema dict that constrains the LLM
        token generation to only emit valid attack JSON.

        The ``target`` field is restricted to an enum of the scene's attack
        surface so the model cannot hallucinate arbitrary tag names.
        Returns None when the attack surface is empty (no constraint possible).
        """
        surface = list(self._scene.attack_surface) if self._scene.attack_surface else []
        if not surface:
            return None
        valid_types = [t.value for t in AttackType]
        schema: Dict[str, Any] = {
            "type": "object",
            "properties": {
                "attack_type": {"type": "string", "enum": valid_types},
                "target": {"type": "string", "enum": surface},
                "value": {"type": "number"},
                "duration_ms": {"type": "integer"},
                "rationale": {"type": "string"},
                "expected_effect": {"type": "string"},
                "confidence": {"type": "number"},
            },
            "required": [
                "attack_type", "target", "value", "duration_ms",
                "rationale", "expected_effect", "confidence",
            ],
        }
        return {
            "type": "json_schema",
            "json_schema": {"name": "attack_action", "schema": schema, "strict": False},
        }

    def _build_surface_str_with_ranges(self) -> str:
        """
        Build a human-readable attack surface string that includes each
        tag's data type and safe value range so the LLM can propose
        values that will pass the shield's range checks.

        Example output::

            heavy_thresh (real, range 1.0–15.0 kg), light_thresh (real, range 0.5–10.0 kg),
            send_left (bool, 0 or 1), enable (bool, 0 or 1)
        """
        if not self._scene.attack_surface:
            return ""
        parts: List[str] = []
        for tag_name in sorted(self._scene.attack_surface):
            tag = self._scene.get_tag(tag_name)
            if tag is None:
                parts.append(tag_name)
                continue
            dtype = tag.data_type.lower() if tag.data_type else "?"
            if dtype == "bool":
                hint = f"{tag_name} (bool, value: 0 or 1)"
            elif dtype in ("real", "float", "int", "dint", "word"):
                lo = tag.min_value
                hi = tag.max_value
                unit = f" {tag.unit}" if tag.unit else ""
                if lo is not None and hi is not None:
                    hint = f"{tag_name} ({dtype}, range: {lo}–{hi}{unit})"
                elif lo is not None:
                    hint = f"{tag_name} ({dtype}, min: {lo}{unit})"
                elif hi is not None:
                    hint = f"{tag_name} ({dtype}, max: {hi}{unit})"
                else:
                    hint = f"{tag_name} ({dtype})"
            else:
                hint = f"{tag_name} ({dtype})"
            parts.append(hint)
        return "\n".join(f"  - {p}" for p in parts)

    def reason(self, snapshot: PlantSnapshot) -> Optional[AttackAction]:
        """Generate one adaptive attack action from current runtime state."""
        objective = ""
        if hasattr(self, "_agent_params"):
            objective = self._agent_params.get("objective", "")

        # Limit history to 3 entries to keep prompt within local model context limits
        compact_history = []
        for h in self.history[-3:]:
            result = h.get("result", {})
            entry = {
                "step": h.get("step_id"),
                "action": h.get("action", {}).get("target", "?"),
                "type": h.get("action", {}).get("attack_type", "?"),
                "value": h.get("action", {}).get("value"),
                "approved": result.get("approved"),
                "executed": result.get("executed"),
            }
            if not result.get("approved") and result.get("reason"):
                entry["rejection_reason"] = result.get("reason")
            compact_history.append(entry)
        _surface_str = self._build_surface_str_with_ranges()
        user_prompt = self._prompt_builder.build_attacker_agent_user_prompt(
            snapshot=snapshot,
            prior_actions=compact_history,
            attacker_objective=objective,
            attack_surface=_surface_str,
        )

        # Build JSON schema to constrain target to scene attack surface (LM Studio structured output)
        _response_format = self._build_response_format()

        _MAX_RETRIES = 2
        correction_suffix = ""
        for attempt in range(_MAX_RETRIES + 1):
            prompt = user_prompt + correction_suffix if correction_suffix else user_prompt
            try:
                completion = self._llm.complete(
                    self._system_prompt, prompt, response_format=_response_format
                )
                logger.debug("Attacker LLM raw output (attempt %d): %s", attempt + 1, completion.text[:300])
                actions = self._validator.parse_and_validate(completion.text)
            except ValidationError as exc:
                self.publish_event(AgentEventType.AGENT_ERROR, {"phase": "validate", "error": exc.message})
                if attempt < _MAX_RETRIES:
                    correction_suffix = (
                        f"\n\n---\nYOUR PREVIOUS RESPONSE WAS INVALID.\n"
                        f"{exc.message}\n"
                        f"RETRY: respond with a corrected JSON object. "
                        f"Use ONLY these target names: {_surface_str}. Do not use any other tag name."
                    )
                continue
            except Exception as exc:  # pragma: no cover - runtime resilience
                logger.warning("Attacker LLM call failed: %s", exc)
                self.publish_event(AgentEventType.AGENT_ERROR, {"phase": "llm", "error": str(exc)})
                # If the error may be related to response_format (schema not supported),
                # disable it and fall back to plain completion next time.
                _response_format = None
                return None

            if actions:
                return actions[0]

            # Empty result means the LLM used a target not in attack_surface.
            if attempt < _MAX_RETRIES:
                correction_suffix = (
                    f"\n\n---\nWRONG TARGET — that tag is not on the attack surface.\n"
                    f"You MUST choose 'target' from ONLY these names: {_surface_str}\n"
                    f"Output a corrected JSON object using one of those exact names."
                )

        return None

    def act(self, snapshot: PlantSnapshot, decision: Optional[AttackAction]) -> None:
        """Submit approved attack candidate through coordinator-mediated shield path."""
        if decision is None:
            return

        self.publish_event(
            AgentEventType.ATTACK_SUBMITTED,
            {"action_id": decision.action_id, "target": decision.target},
        )

        result = self.submit_write_request(action=decision, kind=RequestKind.ATTACK)
        if result is None:
            self.publish_event(
                AgentEventType.AGENT_ERROR,
                {"phase": "write_timeout", "action_id": decision.action_id},
            )
            return

        if result.approved:
            self.publish_event(
                AgentEventType.ATTACK_APPROVED,
                {"action_id": decision.action_id, "executed": result.executed},
            )
            if result.executed:
                self.publish_event(
                    AgentEventType.ATTACK_EXECUTED,
                    {"action_id": decision.action_id, "status": result.status},
                )
        else:
            self.publish_event(
                AgentEventType.ATTACK_REJECTED,
                {"action_id": decision.action_id, "reason": result.reason},
            )

        self.add_history(
            {
                "step_id": snapshot.step_id,
                "action": decision.model_dump(mode="json"),
                "result": result.model_dump(mode="json"),
            }
        )
