"""Live LLM attacker agent implementation."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from cpsforge.agents.base import BaseAgent
from cpsforge.agents.messages import AgentEventType, RequestKind
from cpsforge.core.models import AttackAction, PlantSnapshot
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

    def reason(self, snapshot: PlantSnapshot) -> Optional[AttackAction]:
        """Generate one adaptive attack action from current runtime state."""
        objective = ""
        if hasattr(self, "_agent_params"):
            objective = self._agent_params.get("objective", "")

        # Limit history to 3 entries to keep prompt within local model context limits
        compact_history = [
            {"step": h.get("step_id"), "action": h.get("action", {}).get("target", "?"),
             "type": h.get("action", {}).get("attack_type", "?"),
             "approved": h.get("result", {}).get("approved"),
             "executed": h.get("result", {}).get("executed")}
            for h in self.history[-3:]
        ]
        user_prompt = self._prompt_builder.build_attacker_agent_user_prompt(
            snapshot=snapshot,
            prior_actions=compact_history,
            attacker_objective=objective,
        )

        try:
            completion = self._llm.complete(self._system_prompt, user_prompt)
            logger.debug("Attacker LLM raw output: %s", completion.text[:300])
            actions = self._validator.parse_and_validate(completion.text)
        except ValidationError as exc:
            self.publish_event(AgentEventType.AGENT_ERROR, {"phase": "validate", "error": exc.message})
            return None
        except Exception as exc:  # pragma: no cover - runtime resilience
            logger.warning("Attacker LLM call failed: %s", exc)
            self.publish_event(AgentEventType.AGENT_ERROR, {"phase": "llm", "error": str(exc)})
            return None

        if not actions:
            return None
        return actions[0]

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
