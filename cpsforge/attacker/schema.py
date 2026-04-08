"""
schema.py — AttackDecision: the structured output of the online MITM attacker.

The LLM must respond with a JSON object matching this schema every decision
cycle.  The "wait" decision is what distinguishes an online adaptive attacker
from a one-shot generator.

This schema is the independent variable for RQ3.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class AttackDecisionType(str, Enum):
    """Two-valued decision the LLM makes each cycle."""

    ATTACK = "attack"
    WAIT   = "wait"


@dataclass
class AttackDecision:
    """Parsed and validated output of one LLM decision call.

    Raw JSON keys expected from the model
    --------------------------------------
    decision          : "attack" | "wait"
    target_tag        : str  (required if decision == attack)
    action_type       : str  (required if decision == attack)
    action_value      : float (required if decision == attack)
    duration_ms       : int   (required if decision == attack)
    expected_effect   : str   (optional)
    confidence        : float [0, 1]
    reasoning         : str
    timing_rationale  : str   (optional — full context only)
    """

    # --- Always present ---
    decision: AttackDecisionType
    reasoning: str = ""
    confidence: float = 0.5
    timing_rationale: str = ""

    # --- Present when decision == ATTACK ---
    target_tag: Optional[str] = None
    action_type: Optional[str] = None
    action_value: Optional[float] = None
    duration_ms: int = 5000
    expected_effect: str = ""

    # --- Metadata set by the runner (never by LLM) ---
    parse_success: bool = True
    raw_output: str = ""
    llm_latency_ms: float = 0.0

    def is_attack(self) -> bool:
        return self.decision == AttackDecisionType.ATTACK

    def as_dict(self) -> Dict[str, Any]:
        return {
            "decision":         self.decision.value,
            "target_tag":       self.target_tag,
            "action_type":      self.action_type,
            "action_value":     self.action_value,
            "duration_ms":      self.duration_ms,
            "expected_effect":  self.expected_effect,
            "confidence":       self.confidence,
            "reasoning":        self.reasoning,
            "timing_rationale": self.timing_rationale,
            "parse_success":    self.parse_success,
            "llm_latency_ms":   self.llm_latency_ms,
        }


# JSON schema for structured output mode (LM Studio / vLLM constrained decoding)
ATTACK_DECISION_JSON_SCHEMA: Dict[str, Any] = {
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
                "actuator_override",
                "setpoint_shift",
                "sensor_spoof",
                "timing_delay",
                "sequence_perturbation",
            ],
        },
        "action_value":      {"type": "number"},
        "duration_ms":       {"type": "integer", "minimum": 0, "maximum": 30000},
        "expected_effect":   {"type": "string"},
        "confidence":        {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "reasoning":         {"type": "string"},
        "timing_rationale":  {"type": "string"},
    },
    "required": ["decision", "reasoning", "confidence"],
}
