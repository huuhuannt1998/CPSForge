"""
unified_schema.py — Full per-step log schema for v2 experiments.

Every step in an online MITM run writes one UnifiedStepLog entry.
This is the authoritative record for all paper metrics.

Fields grouped by paper contribution:
  Core identifiers      → run_id, step_id, timestamp, …
  Experimental controls → scene, attacker_type, context_level, model_variant, …
  Observation           → observation_dict, derived_features, inferred_phase, …
  LLM decision          → context_payload_hash, llm_raw_output, parsed_decision, …
  Shield + defense      → shield_decision, phase_shield_blocked, intent_check_blocked, …
  Outcome               → write_executed, process_outcome, attack_success, …
  Detector alerts       → detector_alerts, detection_latency_steps, …
  Performance           → llm_latency_ms, step_latency_ms

All entries are serialisable to JSON/Parquet via .as_dict().
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class UnifiedStepLog:
    """One row of the unified experiment log (one polling step).

    Null / unknown values are stored as None (→ JSON null) so that
    downstream analysis code can distinguish "not present" from 0 or False.
    """

    # ------------------------------------------------------------------ #
    # Core identifiers
    # ------------------------------------------------------------------ #
    timestamp: str                      # ISO-8601, UTC
    run_id: str
    step_id: int

    # ------------------------------------------------------------------ #
    # Experimental controls (vary across experiment matrix)
    # ------------------------------------------------------------------ #
    scene: str
    attacker_type: str                  # "online_mitm" | "static_llm" | "random" | "scripted"
    context_level: str                  # "minimal" | "partial" | "full"
    model_variant: str                  # e.g. "Qwen3.5-4B"
    finetune_status: str                # "base" | "finetuned"
    defense_variant: str                # "none" | "threshold" | "phase_aware" | "intent" | "combined"

    # ------------------------------------------------------------------ #
    # Observation
    # ------------------------------------------------------------------ #
    observation_dict: Dict[str, Any] = field(default_factory=dict)
    derived_features: Dict[str, Any] = field(default_factory=dict)
    inferred_phase: Optional[str] = None
    phase_confidence: Optional[float] = None

    # ------------------------------------------------------------------ #
    # LLM context + decision
    # ------------------------------------------------------------------ #
    context_payload_hash: Optional[str] = None     # SHA-256 of rendered prompts
    llm_raw_output: Optional[str] = None
    parsed_decision: Optional[str] = None          # "attack" | "wait" | None
    parse_success: bool = False
    validation_success: bool = False

    # ------------------------------------------------------------------ #
    # Shield + defense
    # ------------------------------------------------------------------ #
    shield_decision: Optional[str] = None          # "approved" | "blocked"
    phase_shield_blocked: bool = False
    intent_check_blocked: bool = False
    llm_defender_blocked: bool = False

    # ------------------------------------------------------------------ #
    # Outcome
    # ------------------------------------------------------------------ #
    write_executed: bool = False
    process_outcome: Optional[str] = None          # free-text summary
    attack_active: bool = False
    attack_success: Optional[bool] = None

    # Action details (populated when parsed_decision == "attack")
    action_target_tag: Optional[str] = None
    action_type: Optional[str] = None
    action_value: Optional[float] = None
    action_duration_ms: Optional[int] = None

    # ------------------------------------------------------------------ #
    # Detector alerts
    # ------------------------------------------------------------------ #
    detector_alerts: List[str] = field(default_factory=list)  # names of firing detectors
    detection_latency_steps: Optional[int] = None             # steps from attack start → first alert

    # ------------------------------------------------------------------ #
    # Performance
    # ------------------------------------------------------------------ #
    llm_latency_ms: Optional[float] = None
    step_latency_ms: Optional[float] = None

    # ------------------------------------------------------------------ #
    # Serialisation
    # ------------------------------------------------------------------ #

    def as_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict."""
        return asdict(self)

    def to_json_line(self) -> str:
        """Serialise to a single JSON line suitable for JSONL output."""
        return json.dumps(self.as_dict(), default=str)

    @staticmethod
    def hash_prompts(system_prompt: str, user_prompt: str) -> str:
        """SHA-256 fingerprint of the context payload sent to the LLM."""
        combined = system_prompt + "\n\n" + user_prompt
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()[:16]

    @classmethod
    def empty(
        cls,
        *,
        run_id: str,
        step_id: int,
        scene: str,
        attacker_type: str = "online_mitm",
        context_level: str = "full",
        model_variant: str = "unknown",
        finetune_status: str = "base",
        defense_variant: str = "none",
    ) -> "UnifiedStepLog":
        """Create a blank log entry for this step (populated incrementally)."""
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            run_id=run_id,
            step_id=step_id,
            scene=scene,
            attacker_type=attacker_type,
            context_level=context_level,
            model_variant=model_variant,
            finetune_status=finetune_status,
            defense_variant=defense_variant,
        )
