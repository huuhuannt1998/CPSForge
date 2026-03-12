"""
CPSForge Scene Base Class
==========================
Abstract base class for all Factory I/O scene implementations.

A Scene wraps a :class:`SceneProfile` (from config) and provides:
  - derived-feature extraction per snapshot
  - feature vector assembly for ML detectors
  - process-impact scoring (deviation from nominal)
  - scene-specific reset logic
  - attack success evaluation

New scenes should subclass :class:`BaseScene` and override the methods
annotated with ``@abstractmethod`` (or leave defaults where appropriate).
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from cpsforge.core.models import (
    AttackAction,
    PlantSnapshot,
    SceneProfile,
    TagDefinition,
)

logger = logging.getLogger(__name__)


class BaseScene(ABC):
    """
    Abstract base class for a CPSForge Factory I/O scene.

    Subclasses must implement :meth:`extract_derived_features` and
    :meth:`compute_process_impact`.
    """

    def __init__(self, profile: SceneProfile) -> None:
        self._profile = profile

    @property
    def profile(self) -> SceneProfile:
        return self._profile

    @property
    def name(self) -> str:
        return self._profile.scene_name

    # ------------------------------------------------------------------
    # Feature extraction
    # ------------------------------------------------------------------

    @abstractmethod
    def extract_derived_features(self, snapshot: PlantSnapshot) -> Dict[str, float]:
        """
        Compute derived process features from a raw plant snapshot.

        Examples: rate-of-change, deviation from setpoint, control error.
        These features are stored in ``snapshot.derived_features`` and used
        by ML-based detectors.
        """

    @abstractmethod
    def compute_process_impact(
        self, before: PlantSnapshot, after: PlantSnapshot
    ) -> float:
        """
        Compute a scalar process-impact score comparing two snapshots.

        Higher score = more physical deviation from normal operation.
        Used to populate ``EvalMetrics.process_impact_score``.
        """

    # ------------------------------------------------------------------
    # Attack success evaluation
    # ------------------------------------------------------------------

    def evaluate_attack_success(
        self,
        action: AttackAction,
        before: PlantSnapshot,
        after: PlantSnapshot,
    ) -> bool:
        """
        Return True if the attack caused a detectable physical change.

        Default implementation checks whether the target tag value changed
        in the expected direction. Subclasses may override for scene-specific logic.
        """
        target = action.target
        before_val = self._get_tag_value(before, target)
        after_val = self._get_tag_value(after, target)
        if before_val is None or after_val is None:
            return False
        if action.value is None:
            return False
        # Success if the tag moved toward the injected value
        try:
            before_dist = abs(float(before_val) - float(action.value))
            after_dist = abs(float(after_val) - float(action.value))
            return after_dist < before_dist
        except (TypeError, ValueError):
            return False

    # ------------------------------------------------------------------
    # Reset information
    # ------------------------------------------------------------------

    def get_reset_writes(self) -> Dict[str, Any]:
        """
        Return a dict of {tag_name: value} required to reset the scene to
        a known safe state. Derived from ``profile.reset_procedure``.
        """
        writes: Dict[str, Any] = {}
        for step in self._profile.reset_procedure:
            writes[step["tag"]] = step["value"]
        return writes

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def get_tag(self, name: str) -> Optional[TagDefinition]:
        return self._profile.get_tag(name)

    def get_all_tags(self) -> List[TagDefinition]:
        return self._profile.tags

    def get_attack_surface(self) -> List[str]:
        return self._profile.attack_surface

    @staticmethod
    def _get_tag_value(snapshot: PlantSnapshot, tag_name: str) -> Optional[Any]:
        """Look up a tag value across all snapshot buckets."""
        for bucket in (
            snapshot.sensors,
            snapshot.actuators,
            snapshot.controller_state,
            snapshot.setpoints,
        ):
            if tag_name in bucket:
                return bucket[tag_name]
        return None
