"""
Replay-based analysis utilities.
=================================
Measure how well new/retrained detectors generalize to previously-missed
attacks by systematically replaying hard-case traces.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class GeneralizationResult:
    """Outcome of replaying hard-case traces through a new detector set."""

    total_hard_cases: int = 0
    caught_before: int = 0
    caught_after: int = 0
    still_missed: int = 0
    newly_missed: int = 0  # caught before but not after (regression)
    generalization_rate: float = 0.0
    regression_rate: float = 0.0
    per_case: List[Dict[str, Any]] = field(default_factory=list)

    def summary(self) -> Dict[str, Any]:
        return {
            "total_hard_cases": self.total_hard_cases,
            "caught_before": self.caught_before,
            "caught_after": self.caught_after,
            "still_missed": self.still_missed,
            "newly_missed": self.newly_missed,
            "generalization_rate": round(self.generalization_rate, 4),
            "regression_rate": round(self.regression_rate, 4),
            "net_improvement": self.caught_after - self.caught_before,
        }


def hard_case_generalization(
    bank: Any,  # HardCaseBank
    old_detectors: List[Any],  # List[BaseDetector]
    new_detectors: List[Any],  # List[BaseDetector]
    replay_loader_cls: Optional[type] = None,
) -> GeneralizationResult:
    """
    Replay every hard-case trace through *old_detectors* and *new_detectors*,
    compare detection outcomes.

    Parameters
    ----------
    bank : HardCaseBank
        Must have records already loaded (``load_from_experiment`` called).
    old_detectors : list[BaseDetector]
        Detectors from the round that produced the hard cases.
    new_detectors : list[BaseDetector]
        Retrained / improved detectors to evaluate.
    replay_loader_cls : class, optional
        The ``RunReplayLoader`` class to use.  Imported lazily from
        ``cpsforge.adaptation.replay`` if not supplied.

    Returns
    -------
    GeneralizationResult
        Structured comparison of before/after detection on hard cases.
    """
    if replay_loader_cls is None:
        from cpsforge.adaptation.replay import RunReplayLoader
        replay_loader_cls = RunReplayLoader

    records = bank.get_all() if hasattr(bank, "get_all") else list(getattr(bank, "_records", {}).values())
    if not records:
        logger.warning("HardCaseBank is empty — nothing to replay.")
        return GeneralizationResult()

    result = GeneralizationResult(total_hard_cases=len(records))

    # Group records by run_dir to avoid reloading the same trace
    from collections import defaultdict
    by_run: Dict[str, List] = defaultdict(list)
    for rec in records:
        trace_path = getattr(rec, "trace_path", None) or ""
        # trace_path is relative to data dir root, e.g. "raw/exp/run_id"
        by_run[str(trace_path)].append(rec)

    for trace_rel, cases in by_run.items():
        run_dir = Path(trace_rel)
        if not run_dir.exists():
            # Try resolving relative to bank experiment_dir parent
            exp_dir = getattr(bank, "experiment_dir", None)
            if exp_dir is not None:
                run_dir = Path(exp_dir).parent / trace_rel
            if not run_dir.exists():
                logger.debug("Run dir not found for %s, skipping %d cases.", trace_rel, len(cases))
                for case in cases:
                    result.per_case.append({
                        "record_id": getattr(case, "record_id", "?"),
                        "status": "skipped",
                        "reason": "run_dir_not_found",
                    })
                    result.still_missed += 1
                continue

        try:
            loader = replay_loader_cls(run_dir)
            attack_steps = loader.load_attack_step_range()
        except Exception as e:
            logger.warning("Failed to load run dir %s: %s", run_dir, e)
            for case in cases:
                result.per_case.append({
                    "record_id": getattr(case, "record_id", "?"),
                    "status": "error",
                    "reason": str(e),
                })
                result.still_missed += 1
            continue

        # Replay old detectors
        for det in old_detectors:
            if hasattr(det, "reset"):
                det.reset()
        try:
            old_events = loader.replay_detectors(old_detectors)
        except Exception as e:
            logger.warning("Old detector replay failed for %s: %s", run_dir, e)
            old_events = []

        # Replay new detectors
        for det in new_detectors:
            if hasattr(det, "reset"):
                det.reset()
        try:
            new_events = loader.replay_detectors(new_detectors)
        except Exception as e:
            logger.warning("New detector replay failed for %s: %s", run_dir, e)
            new_events = []

        # Compare per attack_id
        def _get_attr(obj, attr):
            if isinstance(obj, dict):
                return obj.get(attr)
            return getattr(obj, attr, None)

        old_detected_attacks = {
            _get_attr(ev, "attack_action_id")
            for ev in old_events
        }
        new_detected_attacks = {
            _get_attr(ev, "attack_action_id")
            for ev in new_events
        }

        # Use step-based comparison as primary method
        old_det_steps = set()
        for ev in old_events:
            s = _get_attr(ev, "step_id")
            if s is not None:
                old_det_steps.add(int(s))
        new_det_steps = set()
        for ev in new_events:
            s = _get_attr(ev, "step_id")
            if s is not None:
                new_det_steps.add(int(s))

        for case in cases:
            attack_id = getattr(case, "attack_id", None)
            case_id = getattr(case, "record_id", "?")

            # Determine caught-before / caught-after via step overlap with
            # attack steps
            old_caught = bool(old_det_steps & attack_steps) if attack_steps else len(old_events) > 0
            new_caught = bool(new_det_steps & attack_steps) if attack_steps else len(new_events) > 0

            detail: Dict[str, Any] = {
                "record_id": case_id,
                "attack_id": attack_id,
                "failure_mode": str(getattr(case, "failure_mode", "unknown")),
                "old_caught": old_caught,
                "new_caught": new_caught,
            }

            if old_caught:
                result.caught_before += 1
            if new_caught:
                result.caught_after += 1
            if not old_caught and not new_caught:
                result.still_missed += 1
                detail["status"] = "still_missed"
            elif old_caught and not new_caught:
                result.newly_missed += 1
                detail["status"] = "regression"
            elif not old_caught and new_caught:
                detail["status"] = "newly_caught"
            else:
                detail["status"] = "still_caught"

            result.per_case.append(detail)

    # Rates
    t = result.total_hard_cases
    if t > 0:
        result.generalization_rate = result.caught_after / t
        result.regression_rate = result.newly_missed / t

    return result
