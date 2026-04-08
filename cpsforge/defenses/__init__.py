"""
cpsforge.defenses — v2 defense modules (Contribution C4).

These are the NEW defenses added for the v2 research study.
The existing baseline detectors remain in cpsforge.defenders/

Modules
-------
phase_aware_shield   Blocks writes inconsistent with current operational phase.
intent_checker       Blocks writes opposing the controller's recent trend.
state_consistency    Blocks writes violating state machine consistency (Tier 2 defense).
code_reviewer        LLM-based SCL code review defender (Tier 3 defense).
"""

from cpsforge.defenses.phase_aware_shield import PhaseAwareShield, PhaseWriteRule, PhaseBlockMode
from cpsforge.defenses.intent_checker import IntentConsistencyChecker, ConsistencyResult
from cpsforge.defenses.state_consistency import StateConsistencyChecker, StateConsistencyResult
from cpsforge.defenses.code_reviewer import CodeReviewDefender, ReviewResult

__all__ = [
    "PhaseAwareShield",
    "PhaseWriteRule",
    "PhaseBlockMode",
    "IntentConsistencyChecker",
    "ConsistencyResult",
    "StateConsistencyChecker",
    "StateConsistencyResult",
    "CodeReviewDefender",
    "ReviewResult",
]
