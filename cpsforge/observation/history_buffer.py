"""
history_buffer.py — Sliding window of recent PlantSnapshots.

Maintains a fixed-capacity deque of snapshots that the online MITM
attacker uses to build partial/full context and to run phase inference.
"""

from __future__ import annotations

import threading
from collections import deque
from typing import Deque, Dict, List, Optional, Any

from cpsforge.core.models import PlantSnapshot


class HistoryBuffer:
    """Thread-safe sliding window of PlantSnapshots.

    Parameters
    ----------
    max_size : int
        Maximum number of snapshots retained.  Oldest are discarded when
        the buffer is full.
    """

    def __init__(self, max_size: int = 50) -> None:
        self._max_size = max_size
        self._buffer: Deque[PlantSnapshot] = deque(maxlen=max_size)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def append(self, snapshot: PlantSnapshot) -> None:
        """Append a new snapshot (thread-safe)."""
        with self._lock:
            self._buffer.append(snapshot)

    def clear(self) -> None:
        """Discard all stored snapshots."""
        with self._lock:
            self._buffer.clear()

    # ------------------------------------------------------------------
    # Access
    # ------------------------------------------------------------------

    def latest(self) -> Optional[PlantSnapshot]:
        """Return the most recent snapshot, or None if empty."""
        with self._lock:
            return self._buffer[-1] if self._buffer else None

    def window(self, n: Optional[int] = None) -> List[PlantSnapshot]:
        """Return the last *n* snapshots (oldest first).

        If *n* is None or larger than the buffer contents, all stored
        snapshots are returned.
        """
        with self._lock:
            snaps = list(self._buffer)
        if n is not None and n < len(snaps):
            return snaps[-n:]
        return snaps

    def __len__(self) -> int:
        with self._lock:
            return len(self._buffer)

    # ------------------------------------------------------------------
    # Feature extraction helpers
    # ------------------------------------------------------------------

    def tag_series(self, tag_name: str, n: Optional[int] = None) -> List[Optional[float]]:
        """Return a time-ordered list of values for *tag_name* over the window.

        Values are drawn from the union of sensors, actuators, setpoints,
        controller_state, and alarms dictionaries.  None is returned for
        steps where the tag was absent.
        """
        snaps = self.window(n)
        series: List[Optional[float]] = []
        for snap in snaps:
            val = _get_tag_value(snap, tag_name)
            series.append(val)
        return series

    def as_table(self, tags: List[str], n: Optional[int] = None) -> List[Dict[str, Any]]:
        """Return window as a list of {step_id, tag1, tag2, ...} dicts.

        Convenient for injecting into prompt templates.
        """
        snaps = self.window(n)
        rows = []
        for snap in snaps:
            row: Dict[str, Any] = {"step_id": snap.step_id}
            for tag in tags:
                row[tag] = _get_tag_value(snap, tag)
            rows.append(row)
        return rows

    def trend(self, tag_name: str, n: int = 10) -> Optional[float]:
        """Estimate the linear trend (slope) of *tag_name* over the last *n* steps.

        Returns None if fewer than 2 data points are available.
        """
        series = self.tag_series(tag_name, n)
        values = [(i, v) for i, v in enumerate(series) if v is not None]
        if len(values) < 2:
            return None
        xs = [v[0] for v in values]
        ys = [v[1] for v in values]
        n_pts = len(xs)
        mean_x = sum(xs) / n_pts
        mean_y = sum(ys) / n_pts
        num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
        den = sum((x - mean_x) ** 2 for x in xs)
        if den == 0:
            return 0.0
        return num / den


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_tag_value(snap: PlantSnapshot, tag_name: str) -> Optional[Any]:
    """Extract a tag value from any category in a PlantSnapshot."""
    for category in (
        snap.sensors,
        snap.actuators,
        snap.setpoints,
        snap.controller_state,
        snap.alarms,
        snap.derived_features,
    ):
        if tag_name in category:
            return category[tag_name]
    return None
