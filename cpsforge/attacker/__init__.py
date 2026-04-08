"""
cpsforge.attacker — v2 attacker modules.

Wraps the new online MITM attacker alongside the static LLM and existing
baseline attackers for use in the experiment matrix.

Exports
-------
OnlineMITMAttacker     Core C1 contribution: observe→phase→context→attack|wait→act
StaticLLMAttacker      Baseline: batch one-shot LLM attack generation (from v1)
DeepStateMITMAttacker  Tier 2: deep state manipulation via S7
LogicMITMAttacker      Tier 3: LLM-generated SCL modifications via TIA Openness
LogicAnalyzer          Tier 3: LLM-based SCL vulnerability analysis
AttackDecision         Structured LLM output schema
AttackDecisionType     ATTACK | WAIT enum
"""

from cpsforge.attacker.online_mitm import OnlineMITMAttacker
from cpsforge.attacker.static_llm import StaticLLMAttacker
from cpsforge.attacker.deep_state_mitm import DeepStateMITMAttacker, DEEP_STATE_JSON_SCHEMA
from cpsforge.attacker.logic_analyzer import LogicAnalyzer, LogicModification, VulnerabilityReport
from cpsforge.attacker.logic_mitm import LogicMITMAttacker, LogicAttackResult, LOGIC_DECISION_JSON_SCHEMA
from cpsforge.attacker.schema import AttackDecision, AttackDecisionType, ATTACK_DECISION_JSON_SCHEMA

__all__ = [
    "OnlineMITMAttacker",
    "StaticLLMAttacker",
    "DeepStateMITMAttacker",
    "LogicMITMAttacker",
    "LogicAnalyzer",
    "LogicModification",
    "LogicAttackResult",
    "VulnerabilityReport",
    "AttackDecision",
    "AttackDecisionType",
    "ATTACK_DECISION_JSON_SCHEMA",
    "DEEP_STATE_JSON_SCHEMA",
    "LOGIC_DECISION_JSON_SCHEMA",
]
