"""
CPSForge Scene — Generic Config-Driven Scene
=============================================
A general-purpose scene implementation suitable for any Factory I/O scene
whose behaviour can be described entirely by its YAML config (tags, safety
rules, reset procedure).  All 17 new scenes (DB11-DB30, excl. the four
hand-crafted ones) are backed by this class.

Derived features are computed generically:
  - For every REAL sensor tag: normalised value in [0, 1]
  - For every BOOL actuator tag: 0.0 / 1.0
  - For the state tag (if present): normalised by declared max_value
  - enable_off flag (if enable tag present)

Process impact is the mean absolute deviation of numeric tag values between
two consecutive snapshots, normalised by the declared tag range.  This is
intentionally lightweight — scene-specific subclasses can override it.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from cpsforge.core.models import AttackAction, PlantSnapshot, SceneProfile, TagDefinition
from cpsforge.scenes.base import BaseScene

logger = logging.getLogger(__name__)


class GenericScene(BaseScene):
    """
    Config-driven scene implementation.

    Works for any scene whose tag metadata (data_type, min_value, max_value,
    category) is fully specified in the YAML config.  The derived-feature
    vector and process-impact score are computed generically from the profile.
    """

    def __init__(self, profile: SceneProfile) -> None:
        super().__init__(profile)
        # Pre-index tags by category for fast lookup
        self._sensor_tags: List[TagDefinition] = [
            t for t in profile.tags if t.category == "sensor"
        ]
        self._actuator_tags: List[TagDefinition] = [
            t for t in profile.tags if t.category == "actuator"
        ]
        self._setpoint_tags: List[TagDefinition] = [
            t for t in profile.tags if t.category == "setpoint"
        ]
        self._state_tag: Optional[TagDefinition] = next(
            (t for t in profile.tags if t.name in ("state", "i_state")), None
        )
        self._enable_tag: Optional[TagDefinition] = next(
            (t for t in profile.tags if t.name == "enable"), None
        )

    # ------------------------------------------------------------------
    # Feature extraction
    # ------------------------------------------------------------------

    def extract_derived_features(self, snapshot: PlantSnapshot) -> Dict[str, float]:
        features: Dict[str, float] = {}

        # Normalised sensor values
        for t in self._sensor_tags:
            val = self._get_tag_value(snapshot, t.name)
            if val is None:
                continue
            if t.data_type == "bool":
                features[f"{t.name}_active"] = 1.0 if val else 0.0
            elif t.data_type in ("real", "int", "dint"):
                try:
                    fval = float(val)
                    if t.min_value is not None and t.max_value is not None and t.max_value != t.min_value:
                        features[f"{t.name}_norm"] = (fval - float(t.min_value)) / (
                            float(t.max_value) - float(t.min_value)
                        )
                    else:
                        features[f"{t.name}_raw"] = fval
                except (TypeError, ValueError):
                    pass

        # Actuator states
        for t in self._actuator_tags:
            val = self._get_tag_value(snapshot, t.name)
            if val is not None and t.data_type == "bool":
                features[f"{t.name}_on"] = 1.0 if val else 0.0

        # State machine normalisation
        if self._state_tag is not None:
            val = self._get_tag_value(snapshot, self._state_tag.name)
            if val is not None:
                try:
                    fval = float(val)
                    max_v = self._state_tag.max_value
                    features["state_norm"] = (fval / float(max_v)) if max_v else fval
                    # Out-of-range anomaly
                    min_v = self._state_tag.min_value or 0
                    features["state_anomaly"] = (
                        0.0
                        if (float(min_v) <= fval <= float(max_v or fval))
                        else 1.0
                    )
                except (TypeError, ValueError):
                    features["state_anomaly"] = 1.0

        # Enable flag
        if self._enable_tag is not None:
            val = self._get_tag_value(snapshot, "enable")
            if val is not None:
                features["enable_off"] = 0.0 if val else 1.0

        # Setpoint values (normalised)
        for t in self._setpoint_tags:
            val = self._get_tag_value(snapshot, t.name)
            if val is not None and t.data_type in ("real", "int", "dint"):
                try:
                    fval = float(val)
                    if t.min_value is not None and t.max_value is not None and t.max_value != t.min_value:
                        features[f"{t.name}_norm"] = (fval - float(t.min_value)) / (
                            float(t.max_value) - float(t.min_value)
                        )
                    else:
                        features[f"{t.name}_raw"] = fval
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
        Generic process-impact score: mean normalised absolute change across
        all numeric tags between two snapshots.
        """
        total = 0.0
        count = 0

        for t in self._sensor_tags + self._setpoint_tags:
            if t.data_type not in ("real", "int", "dint"):
                continue
            v_before = self._get_tag_value(before, t.name)
            v_after = self._get_tag_value(after, t.name)
            if v_before is None or v_after is None:
                continue
            try:
                diff = abs(float(v_after) - float(v_before))
                # Normalise by range if available
                if t.max_value is not None and t.min_value is not None:
                    span = float(t.max_value) - float(t.min_value)
                    diff = diff / span if span > 0 else diff
                total += diff
                count += 1
            except (TypeError, ValueError):
                pass

        # Penalise enable-flag toggling
        if self._enable_tag is not None:
            v_before = self._get_tag_value(before, "enable")
            v_after = self._get_tag_value(after, "enable")
            if v_before is not None and v_after is not None and bool(v_before) != bool(v_after):
                total += 1.0
                count += 1

        # Penalise actuator changes on writable attack-surface tags
        for tag_name in self._profile.attack_surface:
            t = self.get_tag(tag_name)
            if t is None or t.data_type != "bool":
                continue
            v_before = self._get_tag_value(before, tag_name)
            v_after = self._get_tag_value(after, tag_name)
            if v_before is not None and v_after is not None and bool(v_before) != bool(v_after):
                total += 0.5
                count += 1

        return total / count if count > 0 else 0.0
