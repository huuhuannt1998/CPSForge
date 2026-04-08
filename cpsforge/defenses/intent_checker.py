"""
intent_checker.py — Intent-consistency checker (Contribution C4).

IntentConsistencyChecker detects proposed writes that oppose the
controller's recent trajectory — the defining signature of a context-aware
LLM attacker that knows the process state and deliberately reverses it.

Scientific motivation
---------------------
A smart LLM attacker using full context (RQ1) learns that reversing an
active controller trend is highly disruptive: forcing a valve closed while
the controller is opening it, or shifting a setpoint away from the
controller's target direction.  Standard detectors (threshold, invariant)
only fire AFTER the write causes a process anomaly.  The intent checker
fires BEFORE the write, blocking the action if it opposes the controller
intent inferred from recent history.

Algorithm
---------
For each tag in the action:
  1. Retrieve the last *window* values from HistoryBuffer.
  2. Fit a linear trend (slope) to those values.
  3. Compute intent direction: +1 = controller is increasing, -1 = decreasing, 0 = stable.
  4. Compute proposed direction: sign(action.value - current_value).
  5. If proposed direction opposes intent direction AND the magnitude is
     above *threshold_fraction* of the tag's operational range → block.

The checker is permissive by default (requires both direction reversal AND
significant magnitude) to avoid false positives in genuinely stable states.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from cpsforge.core.models import AttackAction, PlantSnapshot, ShieldDecision
from cpsforge.observation.history_buffer import HistoryBuffer, _get_tag_value

logger = logging.getLogger(__name__)


@dataclass
class ConsistencyResult:
    """Result of one consistency check."""
    consistent: bool
    reason: str
    tag: str
    trend_slope: Optional[float]
    proposed_delta: Optional[float]
    magnitude_fraction: Optional[float]


class IntentConsistencyChecker:
    """Check whether a proposed write is consistent with the controller's intent.

    Parameters
    ----------
    history : HistoryBuffer
        Shared rolling window.
    window_size : int
        How many recent steps to consider for trend estimation (default 10).
    inconsistency_threshold : float
        Minimum |proposed_delta / value_range| that triggers a block.
        Set higher to reduce false positives (default 0.25 = 25% of range).
    min_trend_steps : int
        Minimum data points needed before trend estimation is valid.
        Below this, the checker passes (insufficient history).
    tag_ranges : dict {tag_name: (min, max)}, optional
        Used to normalise proposed delta.  If not provided, a fallback of
        [-10, 10] is assumed.
    """

    def __init__(
        self,
        history: HistoryBuffer,
        window_size: int = 10,
        inconsistency_threshold: float = 0.25,
        min_trend_steps: int = 5,
        tag_ranges: Optional[Dict[str, tuple]] = None,
    ) -> None:
        self._history = history
        self._window = window_size
        self._threshold = inconsistency_threshold
        self._min_steps = min_trend_steps
        self._tag_ranges = tag_ranges or {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(
        self,
        action: AttackAction,
        snapshot: PlantSnapshot,
    ) -> ConsistencyResult:
        """Evaluate whether *action* is consistent with controller intent."""
        tag = action.target
        proposed_value = action.value
        if proposed_value is None:
            return ConsistencyResult(
                consistent=True,
                reason="No action value — cannot assess intent consistency",
                tag=tag,
                trend_slope=None,
                proposed_delta=None,
                magnitude_fraction=None,
            )

        current_value = _get_tag_value(snapshot, tag)
        if current_value is None:
            return ConsistencyResult(
                consistent=True,
                reason=f"Tag '{tag}' not found in current snapshot — skipping check",
                tag=tag,
                trend_slope=None,
                proposed_delta=None,
                magnitude_fraction=None,
            )

        series = self._history.tag_series(tag, self._window)
        series_numeric = [v for v in series if v is not None]
        if len(series_numeric) < self._min_steps:
            return ConsistencyResult(
                consistent=True,
                reason=(
                    f"Insufficient history ({len(series_numeric)} < {self._min_steps} steps) "
                    f"— cannot assess intent"
                ),
                tag=tag,
                trend_slope=None,
                proposed_delta=None,
                magnitude_fraction=None,
            )

        slope = _linear_slope(series_numeric)
        proposed_delta = float(proposed_value) - float(current_value)
        tag_range = self._tag_ranges.get(tag, (-10.0, 10.0))
        value_range = max(abs(tag_range[1] - tag_range[0]), 1e-6)
        magnitude_fraction = abs(proposed_delta) / value_range

        # Intent direction: significant slope matters
        trend_dir = _sign(slope) if abs(slope) > value_range * 0.005 else 0
        proposed_dir = _sign(proposed_delta)

        inconsistent = (
            trend_dir != 0
            and proposed_dir != 0
            and proposed_dir != trend_dir
            and magnitude_fraction >= self._threshold
        )

        if inconsistent:
            reason = (
                f"Proposed write to '{tag}' (Δ={proposed_delta:+.3f}, "
                f"{magnitude_fraction:.0%} of range) opposes controller trend "
                f"(slope={slope:+.4f}/step, direction={'↑' if trend_dir > 0 else '↓'})"
            )
        else:
            reason = (
                f"Write to '{tag}' is consistent with controller intent "
                f"(slope={slope:+.4f}/step, Δ={proposed_delta:+.3f})"
            )

        return ConsistencyResult(
            consistent=not inconsistent,
            reason=reason,
            tag=tag,
            trend_slope=slope,
            proposed_delta=proposed_delta,
            magnitude_fraction=magnitude_fraction,
        )

    def evaluate(
        self,
        action: AttackAction,
        snapshot: PlantSnapshot,
    ) -> ShieldDecision:
        """Return a ShieldDecision for use in the defense pipeline."""
        result = self.check(action, snapshot)

        if result.consistent:
            return ShieldDecision(
                action_id=action.action_id,
                approved=True,
                reasons=[result.reason],
                violated_rules=[],
            )

        logger.info(
            "IntentChecker BLOCKED action on '%s': %s",
            action.target,
            result.reason,
        )
        return ShieldDecision(
            action_id=action.action_id,
            approved=False,
            reasons=[f"[IntentChecker] {result.reason}"],
            violated_rules=["INTENT-CONSISTENCY"],
        )


# ---------------------------------------------------------------------------
# Math helpers
# ---------------------------------------------------------------------------

def _linear_slope(values: List[float]) -> float:
    """Return the ordinary-least-squares slope of *values* vs. step index."""
    n = len(values)
    if n < 2:
        return 0.0
    xs = list(range(n))
    mean_x = (n - 1) / 2.0
    mean_y = sum(values) / n
    num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, values))
    den = sum((x - mean_x) ** 2 for x in xs)
    return num / den if den > 1e-12 else 0.0


def _sign(x: float) -> int:
    if x > 1e-9:
        return 1
    if x < -1e-9:
        return -1
    return 0
