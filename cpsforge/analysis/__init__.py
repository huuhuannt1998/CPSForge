"""
CPSForge Analysis Package
==========================
Paper-ready aggregation, comparison tables, and artifact generation.

This package transforms raw experiment artifacts into publication-quality
tables and statistics that map directly to the evaluation section of the
CPSForge paper.

Main entry points:

* :func:`cross_attacker_table`    → Table 1  (attack-results)
* :func:`shield_analysis_table`   → Table 2  (shield-results)
* :func:`cross_detector_table`    → Table 3  (defender-results)
* :func:`adaptation_round_table`  → Table 4  (adaptation-results)
* :func:`attack_type_breakdown`   → Supplemental attack-type detail
* :func:`latency_distribution`    → Latency percentiles + per-detector
* :func:`hard_case_generalization` → Replay-based generalization analysis
"""

from cpsforge.analysis.tables import (
    cross_attacker_table,
    cross_detector_table,
    cross_model_table,
    shield_analysis_table,
    adaptation_round_table,
    attack_type_breakdown,
    latency_distribution,
    full_paper_export,
)
from cpsforge.analysis.replay_analysis import hard_case_generalization

__all__ = [
    "cross_attacker_table",
    "cross_detector_table",
    "cross_model_table",
    "shield_analysis_table",
    "adaptation_round_table",
    "attack_type_breakdown",
    "latency_distribution",
    "hard_case_generalization",
    "full_paper_export",
]
