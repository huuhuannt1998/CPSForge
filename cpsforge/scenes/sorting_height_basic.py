"""
CPSForge Scene -- Sorting by Height (Basic)
=============================================
Discrete sorting scene for Factory I/O with a Siemens S7 PLC.

Physical process summary:
  - Entry conveyor feeds items onto a loading area.
  - High/Low height sensors classify items:
      - Low sensor only → short → transfer LEFT.
      - High sensor active → tall → transfer RIGHT.
  - 5-state machine: Feed(0) → Load(1) → Transfer(2) → Clear(3) → Finish(4).
  - Left and right exit conveyors carry sorted items.
  - Enable flag is read but never written by PLC logic (attack target).

Derived features computed per snapshot:
  - sort_direction      : -1.0 (left/short), +1.0 (right/tall), 0.0 (idle)
  - state_anomaly       : 1.0 if state outside [0,4]
  - transfer_conflict   : 1.0 if both transf_left and transf_right active
  - load_unload_conflict: 1.0 if both load_act and unload_act active
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from cpsforge.core.models import PlantSnapshot, SceneProfile
from cpsforge.scenes.base import BaseScene

logger = logging.getLogger(__name__)

_VALID_STATES = {0, 1, 2, 3, 4}


class SortingHeightBasicScene(BaseScene):
    """Sorting by Height (Basic) scene implementation."""

    def __init__(self, profile: SceneProfile) -> None:
        super().__init__(profile)
        self._prev_state: Optional[int] = None
        self._prev_item_count: Optional[int] = None

    # ------------------------------------------------------------------
    # Feature extraction
    # ------------------------------------------------------------------

    def extract_derived_features(self, snapshot: PlantSnapshot) -> Dict[str, float]:
        """Compute sorting-specific derived features."""
        features: Dict[str, float] = {}

        is_tall = self._get_tag_value(snapshot, "is_tall")
        state = self._get_tag_value(snapshot, "state")
        transf_left = self._get_tag_value(snapshot, "transf_left")
        transf_right = self._get_tag_value(snapshot, "transf_right")
        load_act = self._get_tag_value(snapshot, "load_act")
        unload_act = self._get_tag_value(snapshot, "unload_act")
        item_count = self._get_tag_value(snapshot, "item_count")

        # Sort direction: which way the current item is going
        if is_tall is not None:
            features["sort_direction"] = 1.0 if is_tall else -1.0
        else:
            features["sort_direction"] = 0.0

        # State anomaly: state outside valid range
        if state is not None:
            try:
                features["state_anomaly"] = 0.0 if int(state) in _VALID_STATES else 1.0
            except (TypeError, ValueError):
                features["state_anomaly"] = 1.0

        # Transfer conflict: mutual exclusion violation
        if transf_left is not None and transf_right is not None:
            features["transfer_conflict"] = 1.0 if (transf_left and transf_right) else 0.0

        # Load/unload conflict
        if load_act is not None and unload_act is not None:
            features["load_unload_conflict"] = 1.0 if (load_act and unload_act) else 0.0

        # State transition detection
        if state is not None and self._prev_state is not None:
            try:
                features["state_changed"] = 1.0 if int(state) != self._prev_state else 0.0
            except (TypeError, ValueError):
                pass
        if state is not None:
            try:
                self._prev_state = int(state)
            except (TypeError, ValueError):
                pass

        # Throughput: items per observation
        if item_count is not None and self._prev_item_count is not None:
            try:
                features["items_since_last"] = float(int(item_count) - self._prev_item_count)
            except (TypeError, ValueError):
                pass
        if item_count is not None:
            try:
                self._prev_item_count = int(item_count)
            except (TypeError, ValueError):
                pass

        snapshot.derived_features.update(features)
        return features

    # ------------------------------------------------------------------
    # Process impact scoring
    # ------------------------------------------------------------------

    def compute_process_impact(
        self, before: PlantSnapshot, after: PlantSnapshot
    ) -> float:
        """
        Compute process-impact score for the sorting scene.

        Impact factors:
          - State machine corruption (out of range)
          - Transfer conflict (both directions active)
          - Load/unload conflict
          - Enable flag toggled off
          - Mis-sort: transfer direction inconsistent with height classification
        """
        impact = 0.0

        state_after = self._get_tag_value(after, "state")
        enable_before = self._get_tag_value(before, "enable")
        enable_after = self._get_tag_value(after, "enable")

        # State out of range → high impact
        if state_after is not None:
            try:
                if int(state_after) not in _VALID_STATES:
                    impact += 1.0
            except (TypeError, ValueError):
                impact += 1.0

        # Transfer conflict (mutual exclusion violation)
        tl = self._get_tag_value(after, "transf_left")
        tr = self._get_tag_value(after, "transf_right")
        if tl and tr:
            impact += 0.8

        # Load/unload conflict
        la = self._get_tag_value(after, "load_act")
        ua = self._get_tag_value(after, "unload_act")
        if la and ua:
            impact += 0.5

        # Enable toggled off unexpectedly
        if enable_before and not enable_after:
            impact += 0.5

        # Mis-sort detection: in Transfer state, direction should match is_tall
        if state_after is not None:
            try:
                if int(state_after) == 2:  # Transfer state
                    is_tall = self._get_tag_value(after, "is_tall")
                    if is_tall is not None:
                        if is_tall and tl and not tr:  # Tall going left = wrong
                            impact += 0.6
                        elif not is_tall and tr and not tl:  # Short going right = wrong
                            impact += 0.6
            except (TypeError, ValueError):
                pass

        return round(impact, 4)
