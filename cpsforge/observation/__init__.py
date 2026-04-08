"""
observation/ — Live PLC state collection, buffering, and phase inference.

Modules
-------
observer       Unified PLC state observer (wraps PollingLoop).
history_buffer Sliding window of recent PlantSnapshots.
phase_inference Rule-based phase detection per scene.
"""

from .observer import PlcObserver
from .history_buffer import HistoryBuffer
from .phase_inference import PhaseInferenceEngine, PhaseLabel, PhaseResult

__all__ = [
    "PlcObserver",
    "HistoryBuffer",
    "PhaseInferenceEngine",
    "PhaseLabel",
    "PhaseResult",
]
