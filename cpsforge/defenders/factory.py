"""
CPSForge Defender Factory
===========================
Maps detector_type strings to their implementations.
"""

from __future__ import annotations

import logging

from cpsforge.core.config import DefenderConfig
from cpsforge.defenders.base import BaseDetector
from cpsforge.defenders.threshold import ThresholdDetector
from cpsforge.defenders.invariant import InvariantDetector

logger = logging.getLogger(__name__)


def build_defender(config: DefenderConfig) -> BaseDetector:
    """
    Instantiate a detector from a defender config.

    Raises
    ------
    ValueError
        If the detector_type is unknown.
    """
    t = config.detector_type.lower()

    if t == "threshold":
        return ThresholdDetector(config)
    elif t == "invariant":
        return InvariantDetector(config)
    elif t == "sequence_model":
        # Implemented in Phase 5
        from cpsforge.defenders.sequence_model import SequenceModelDetector
        return SequenceModelDetector(config)
    elif t == "llm_explainer":
        # Implemented in Phase 4
        from cpsforge.defenders.llm_explainer import LLMExplainerDetector
        return LLMExplainerDetector(config)
    elif t == "cusum":
        from cpsforge.defenders.cusum_detector import CUSUMDetector
        return CUSUMDetector(config)
    elif t == "ocsvm":
        from cpsforge.defenders.ocsvm_detector import OCSVMDetector
        return OCSVMDetector(config)
    elif t == "isolation_forest":
        from cpsforge.defenders.iforest_detector import IsolationForestDetector
        return IsolationForestDetector(config)
    elif t == "lstm_ad":
        from cpsforge.defenders.lstm_ad_detector import LSTMADDetector
        return LSTMADDetector(config)
    else:
        raise ValueError(
            f"Unknown detector type: '{config.detector_type}'. "
            "Expected: threshold | invariant | sequence_model | llm_explainer | "
            "cusum | ocsvm | isolation_forest | lstm_ad"
        )
