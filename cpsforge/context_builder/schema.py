"""
schema.py — Data models for the context-ablation framework.

ContextLevel     Enum: MINIMAL | PARTIAL | FULL
TagSummary       Compact tag metadata for partial/full context
ContextPayload   Everything the attacker receives at one decision step
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ContextLevel(str, Enum):
    """The three context tiers used in the ablation study (RQ1)."""

    MINIMAL = "minimal"   # raw values, no semantics, no history
    PARTIAL = "partial"   # values + tag metadata + short history
    FULL    = "full"      # complete description + phase + trend + priors


@dataclass
class TagSummary:
    """Compact tag metadata included in partial/full context."""

    name: str
    unit: Optional[str]
    min_value: Optional[float]
    max_value: Optional[float]
    category: str           # sensor | actuator | setpoint | alarm | ...
    description: str = ""


@dataclass
class ContextPayload:
    """Everything the LLM attacker receives at one decision point.

    Fields present depend on *level*:

    MINIMAL  : level, scene_name, attack_surface, current_values
    PARTIAL  : + tag_metadata, history_table, scene_description,
                 attack_type_descriptions
    FULL     : + inferred_phase, phase_confidence, control_objective,
                 prior_actions, derived_features, shield_rules_summary
    """

    # --- Always present ---
    level: ContextLevel
    scene_name: str
    attack_surface: List[str]                  # tag names the attacker may target
    current_values: Dict[str, Any]             # {tag_name: current_value}

    # --- PARTIAL and FULL ---
    tag_metadata: Optional[List[TagSummary]] = None
    history_table: Optional[List[Dict[str, Any]]] = None   # [{step_id, tag: val, ...}, ...]
    scene_description: Optional[str] = None
    attack_type_descriptions: Optional[Dict[str, str]] = None

    # --- FULL only ---
    inferred_phase: Optional[str] = None
    phase_confidence: Optional[float] = None
    control_objective: Optional[str] = None
    prior_actions: Optional[List[Dict[str, Any]]] = None   # from HistoryBuffer
    derived_features: Optional[Dict[str, float]] = None
    shield_rules_summary: Optional[str] = None

    # --- Metadata (never sent to LLM, used for logging/analysis) ---
    step_id: Optional[int] = None
    run_id: Optional[str] = None
    payload_hash: Optional[str] = None        # sha256 of rendered prompt

    def as_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict of all non-None fields."""
        import dataclasses
        return {
            k: v
            for k, v in dataclasses.asdict(self).items()
            if v is not None
        }
