"""
CPSForge LLM Explainer Detector -- Phase 4 Stub
=================================================
"""

from __future__ import annotations

import logging
from typing import List

from cpsforge.core.config import DefenderConfig
from cpsforge.core.models import DetectionEvent, PlantSnapshot
from cpsforge.defenders.base import BaseDetector

logger = logging.getLogger(__name__)


class LLMExplainerDetector(BaseDetector):
    """LLM-based explanation module. Full implementation in Phase 4."""

    def __init__(self, config: DefenderConfig) -> None:
        self._config = config
        logger.warning("LLMExplainerDetector is a Phase 4 stub and will not produce detections.")

    @property
    def name(self) -> str:
        return self._config.name

    def observe(self, snapshot: PlantSnapshot) -> None:
        """No-op: LLM explainer does not build running state."""

    def detect(self, snapshot: PlantSnapshot) -> List[DetectionEvent]:
        return []
