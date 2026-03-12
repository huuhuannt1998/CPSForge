"""
CPSForge Scene -- From A to B
==============================
Discrete conveyor transport scene for Factory I/O with a Siemens S7 PLC.

Physical process summary:
  - A single conveyor moves items from position A to position B.
  - A sensor detects item presence on the conveyor.
  - The PLC state machine manages: Transport(0) → Arrived(1).
  - Enable flag controls whether the conveyor logic executes.

Derived features computed per snapshot:
  - transport_active   : 1.0 if conveyor on and sensor active, else 0.0
  - state_anomaly      : 1.0 if state value is out of expected range [0,1]
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from cpsforge.core.models import PlantSnapshot, SceneProfile
from cpsforge.scenes.base import BaseScene

logger = logging.getLogger(__name__)

_VALID_STATES = {0, 1}


class FromAtoBScene(BaseScene):
    """From A to B conveyor transport scene implementation."""

    def __init__(self, profile: SceneProfile) -> None:
        super().__init__(profile)
        self._prev_state: Optional[int] = None

    # ------------------------------------------------------------------
    # Feature extraction
    # ------------------------------------------------------------------

    def extract_derived_features(self, snapshot: PlantSnapshot) -> Dict[str, float]:
        """Compute transport-specific derived features."""
        features: Dict[str, float] = {}

        conveyor = self._get_tag_value(snapshot, "conveyor")
        sensor = self._get_tag_value(snapshot, "sensor")
        state = self._get_tag_value(snapshot, "state")

        # Transport active: conveyor running while item present
        if conveyor is not None and sensor is not None:
            features["transport_active"] = 1.0 if (conveyor and sensor) else 0.0

        # State anomaly: state outside valid range
        if state is not None:
            try:
                features["state_anomaly"] = 0.0 if int(state) in _VALID_STATES else 1.0
            except (TypeError, ValueError):
                features["state_anomaly"] = 1.0

        # State transition: did the state change since last observation?
        if state is not None and self._prev_state is not None:
            features["state_changed"] = 1.0 if int(state) != self._prev_state else 0.0
        if state is not None:
            try:
                self._prev_state = int(state)
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
        Compute process-impact score for the discrete transport scene.

        Impact factors:
          - Unexpected conveyor state (running when it shouldn't or stopped when it should)
          - State machine corruption
          - Enable flag toggled off
        """
        impact = 0.0

        state_after = self._get_tag_value(after, "state")
        enable_after = self._get_tag_value(after, "enable")
        enable_before = self._get_tag_value(before, "enable")

        # State out of range → high impact
        if state_after is not None:
            try:
                if int(state_after) not in _VALID_STATES:
                    impact += 1.0
            except (TypeError, ValueError):
                impact += 1.0

        # Enable toggled off unexpectedly
        if enable_before and not enable_after:
            impact += 0.5

        # Conveyor mismatch: conveyor stopped in Transport state or running in Arrived state
        conveyor = self._get_tag_value(after, "conveyor")
        if state_after is not None and conveyor is not None:
            try:
                s = int(state_after)
                if s == 0 and not conveyor:  # Transport but conveyor stopped
                    impact += 0.3
                if s == 1 and conveyor:  # Arrived but conveyor still running
                    impact += 0.3
            except (TypeError, ValueError):
                pass

        return round(impact, 4)
