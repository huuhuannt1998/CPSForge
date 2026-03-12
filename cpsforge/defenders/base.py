"""
CPSForge Detector Base Class
==============================
All detector implementations subclass :class:`BaseDetector`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from cpsforge.core.models import DetectionEvent, PlantSnapshot


class BaseDetector(ABC):
    """Abstract base class for CPSForge anomaly detectors."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable detector name."""

    @abstractmethod
    def observe(self, snapshot: PlantSnapshot) -> None:
        """
        Update the detector's internal state with a new plant snapshot.

        This method is called every polling cycle regardless of whether
        an attack is active.
        """

    @abstractmethod
    def detect(self, snapshot: PlantSnapshot) -> List[DetectionEvent]:
        """
        Evaluate the current snapshot and return any detection events.

        Returns an empty list if no anomaly is detected.
        """

    def reset(self) -> None:
        """Reset the detector's internal state (for replay or retraining)."""

    def export_state(self) -> dict:
        """Export detector state for persistence or inspection."""
        return {}
