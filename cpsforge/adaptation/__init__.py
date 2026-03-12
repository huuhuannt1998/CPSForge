"""
CPSForge Adaptation Package
=============================
Hard-case extraction, replay bank, defender retraining, and closed-loop
adaptation loop.

Phase 5 exports:
  HardCaseBank          -- aggregates hard cases from multiple runs
  SequenceDetectorTrainer -- trains IsolationForest on hard-case windows
  AdaptationLoop        -- multi-round closed-loop experiment runner
  RoundResult           -- per-round outcome record
  RoundSummary          -- per-round metrics for reporting
  write_round_metrics   -- persist round_metrics.csv / round_summary.json
  print_round_table     -- rich comparison table
"""

from cpsforge.adaptation.bank import HardCaseBank
from cpsforge.adaptation.hard_cases import (
    classify_attack_outcome,
    extract_and_write_hard_cases,
    load_hard_cases,
)
from cpsforge.adaptation.replay import RunReplayLoader
from cpsforge.adaptation.adaptation_loop import AdaptationLoop, RoundResult
from cpsforge.adaptation.round_metrics import (
    RoundSummary,
    write_round_metrics,
    print_round_table,
)
from cpsforge.adaptation.trainer import SequenceDetectorTrainer

__all__ = [
    "HardCaseBank",
    "classify_attack_outcome",
    "extract_and_write_hard_cases",
    "load_hard_cases",
    "RunReplayLoader",
    "AdaptationLoop",
    "RoundResult",
    "RoundSummary",
    "write_round_metrics",
    "print_round_table",
    "SequenceDetectorTrainer",
]

