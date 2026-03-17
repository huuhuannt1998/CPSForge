"""Live LLM defender agent implementation."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from cpsforge.agents.base import BaseAgent
from cpsforge.agents.messages import AgentEventType, RequestKind
from cpsforge.core.models import AttackAction, AttackSource, AttackType, PlantSnapshot
from cpsforge.defenders.base import BaseDetector
from cpsforge.llm.prompt_builder import PromptBuilder

logger = logging.getLogger(__name__)


@dataclass
class DefenderDecision:
    """Defender decision bundle for one runtime step."""

    summary: str
    confidence: float
    alert_labels: List[str]
    corrective_action: Optional[AttackAction]


class DefenderAgent(BaseAgent):
    """Runtime defender that detects, explains, and optionally corrects state."""

    def __init__(
        self,
        *args: Any,
        detectors: Optional[List[BaseDetector]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._detectors: List[BaseDetector] = detectors or []
        self._prompt_builder = PromptBuilder(
            template_version=self._llm.config.prompt_template_version,
        )
        self._system_prompt = self._prompt_builder.build_defender_agent_system_prompt(
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

    def reason(self, snapshot: PlantSnapshot) -> DefenderDecision:
        """Run fast detectors first, then ask LLM for explanation/corrective plan."""
        events = []
        for detector in self._detectors:
            detector.observe(snapshot)
            events.extend(detector.detect(snapshot))

        labels = [event.label for event in events]
        if not labels:
            return DefenderDecision(summary="normal", confidence=0.0, alert_labels=[], corrective_action=None)

        # Limit history to 3 entries to keep prompt within local model context limits
        compact_history = [
            {"step": h.get("step_id"), "labels": h.get("labels", []),
             "corrective": h.get("corrective") is not None}
            for h in self.history[-3:]
        ]
        user_prompt = self._prompt_builder.build_defender_agent_user_prompt(
            snapshot=snapshot,
            detector_alerts=labels,
            prior_detections=compact_history,
        )

        summary = f"alerts={labels}"
        confidence = min(1.0, 0.5 + 0.1 * len(labels))
        corrective_action: Optional[AttackAction] = None

        try:
            completion = self._llm.complete(self._system_prompt, user_prompt)
            parsed = json.loads(completion.text)
            if isinstance(parsed, dict):
                summary = str(parsed.get("summary", summary))
                confidence = float(parsed.get("confidence", confidence))
                ca = parsed.get("corrective_action")
                if isinstance(ca, dict) and ca.get("target"):
                    target = str(ca["target"])
                    # Validate target is on the attack surface
                    if target in set(self._scene.attack_surface):
                        corrective_action = AttackAction(
                            attack_type=AttackType.ACTUATOR_OVERRIDE,
                            target=target,
                            mode="override",
                            value=float(ca.get("value", 0.0)),
                            duration_ms=int(ca.get("duration_ms", 2000)),
                            rationale=str(ca.get("rationale", "defender corrective action")),
                            source=AttackSource.LLM,
                        )
                    else:
                        logger.warning(
                            "Defender proposed corrective to unknown tag '%s' -- ignored.", target
                        )
        except Exception:
            # Keep detector-backed decision even if LLM output is malformed.
            pass

        return DefenderDecision(
            summary=summary,
            confidence=max(0.0, min(1.0, confidence)),
            alert_labels=labels,
            corrective_action=corrective_action,
        )

    def act(self, snapshot: PlantSnapshot, decision: DefenderDecision) -> None:
        """Emit detection event and submit optional corrective action."""
        if not decision.alert_labels:
            return

        self.publish_event(
            AgentEventType.DETECTION_EMITTED,
            {
                "labels": decision.alert_labels,
                "summary": decision.summary,
                "confidence": decision.confidence,
            },
        )

        if decision.corrective_action is None:
            self.add_history(
                {
                    "step_id": snapshot.step_id,
                    "labels": decision.alert_labels,
                    "summary": decision.summary,
                    "corrective": None,
                }
            )
            return

        self.publish_event(
            AgentEventType.CORRECTIVE_SUBMITTED,
            {
                "action_id": decision.corrective_action.action_id,
                "target": decision.corrective_action.target,
            },
        )

        result = self.submit_write_request(action=decision.corrective_action, kind=RequestKind.CORRECTIVE)
        if result is None:
            self.publish_event(
                AgentEventType.AGENT_ERROR,
                {"phase": "corrective_timeout", "action_id": decision.corrective_action.action_id},
            )
            return

        event_type = AgentEventType.CORRECTIVE_APPROVED if result.approved else AgentEventType.CORRECTIVE_REJECTED
        self.publish_event(
            event_type,
            {
                "action_id": decision.corrective_action.action_id,
                "executed": result.executed,
                "reason": result.reason,
            },
        )

        if result.executed:
            self.publish_event(
                AgentEventType.CORRECTIVE_EXECUTED,
                {"action_id": decision.corrective_action.action_id, "status": result.status},
            )

        self.add_history(
            {
                "step_id": snapshot.step_id,
                "labels": decision.alert_labels,
                "summary": decision.summary,
                "corrective": decision.corrective_action.model_dump(mode="json"),
                "result": result.model_dump(mode="json"),
            }
        )
