"""
context_builder/ — 3-tier prompt context assembly.

The context builder is the core of the context-ablation framework (C2).
It assembles exactly what the LLM attacker "knows" about the process —
and only that — for each of the three tiers:

  MINIMAL  — raw values only, no semantics, no history
  PARTIAL  — values + tag metadata + short history
  FULL     — complete process description, phase, history, trends, priors

These tiers are the independent variable for RQ1.
"""
from .schema import ContextLevel, ContextPayload, TagSummary
from .builder import ContextBuilder

__all__ = ["ContextLevel", "ContextPayload", "TagSummary", "ContextBuilder"]
