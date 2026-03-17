"""
CPSForge -- Closed-Loop LLM Red-Team/Blue-Team Testbed for Cyber-Physical Systems

Entry-point for the package. Exposes the most commonly used public API.
"""

__version__ = "0.1.0"
__author__ = "CPSForge Research Team"

from cpsforge.core.models import (
    TagDefinition,
    PlantSnapshot,
    AttackAction,
    ShieldDecision,
    DetectionEvent,
    EvalMetrics,
    AgentEvalMetrics,
    SceneProfile,
)
from cpsforge.core.config import ConfigLoader, get_config_loader
from cpsforge.core.config import AgentConfig, AgentRole
from cpsforge.logging.logger import setup_logging

__all__ = [
    "__version__",
    "TagDefinition",
    "PlantSnapshot",
    "AttackAction",
    "ShieldDecision",
    "DetectionEvent",
    "EvalMetrics",
    "AgentEvalMetrics",
    "SceneProfile",
    "ConfigLoader",
    "AgentConfig",
    "AgentRole",
    "get_config_loader",
    "setup_logging",
]
