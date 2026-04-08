"""
data_schema.py — Training example format for QLoRA fine-tuning (C3).

Each training example is one (system_prompt, user_prompt, model_output) triple.
The model_output is a JSON string containing the "gold" AttackDecision that was:
  (a) validated by the shield (approved=True), AND
  (b) led to a successful process impact (attack_success=True)

This ensures the fine-tuned model learns to produce high-quality, physically
valid attack decisions; it never learns from failed or rejected attacks.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional


@dataclass
class FinetuneExample:
    """One training example for the attack generation task.

    Stored as a JSONL file; each line is one example.
    """

    # LLM input (the context shown to the model)
    system_prompt: str
    user_prompt: str

    # Gold standard output (what the model should produce)
    gold_output: str              # JSON string — a valid AttackDecision
    gold_decision: str            # "attack" | "wait"
    gold_target_tag: Optional[str] = None
    gold_action_value: Optional[float] = None
    gold_action_type: Optional[str] = None

    # Metadata (for filtering / stratification)
    source_run_id: str = ""
    scene: str = ""
    context_level: str = ""       # "minimal" | "partial" | "full"
    phase_at_step: str = ""
    step_id: int = 0
    shield_approved: bool = True
    attack_success: bool = True

    # Quality indicators
    confidence: float = 1.0
    has_reasoning: bool = False
    has_timing_rationale: bool = False

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_chat_format(self) -> Dict[str, Any]:
        """Return the example in HuggingFace chat-template format.

        Compatible with ``tokenizer.apply_chat_template()``.
        """
        return {
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": self.user_prompt},
                {"role": "assistant", "content": self.gold_output},
            ]
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "FinetuneExample":
        return FinetuneExample(**{k: v for k, v in d.items() if k in FinetuneExample.__dataclass_fields__})
