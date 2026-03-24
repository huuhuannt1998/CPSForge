"""
CPSForge Scene Factory and Registry
=====================================
Maps scene names (from config) to their :class:`BaseScene` implementations.

Usage::

    loader = ConfigLoader()
    scene = load_scene("tank_control", loader)
"""

from __future__ import annotations

import logging
from typing import Dict, Type

from cpsforge.core.config import ConfigLoader
from cpsforge.core.models import SceneProfile, TagDefinition, SafetyRule
from cpsforge.scenes.base import BaseScene
from cpsforge.scenes.from_a_to_b import FromAtoBScene
from cpsforge.scenes.generic import GenericScene
from cpsforge.scenes.level_control import LevelControlScene
from cpsforge.scenes.sorting_height_basic import SortingHeightBasicScene
from cpsforge.scenes.tank_control import TankControlScene

logger = logging.getLogger(__name__)

# Registry of scene_name -> BaseScene subclass
_SCENE_REGISTRY: Dict[str, Type[BaseScene]] = {
    # Hand-crafted implementations
    "tank_control": TankControlScene,
    "from_a_to_b": FromAtoBScene,
    "level_control": LevelControlScene,
    "sorting_height_basic": SortingHeightBasicScene,
    # Generic config-driven implementations for all other Factory I/O scenes
    "from_a_to_b_sr": GenericScene,
    "filling_tank": GenericScene,
    "queue_items": GenericScene,
    "assembler": GenericScene,
    "assembler_analog": GenericScene,
    "warehouse": GenericScene,
    "buffer_station": GenericScene,
    "converge_station": GenericScene,
    "elevator_advanced": GenericScene,
    "elevator_basic": GenericScene,
    "palletizer": GenericScene,
    "pick_place_basic": GenericScene,
    "pick_place_xyz": GenericScene,
    "production_line": GenericScene,
    "separating_station": GenericScene,
    "sorting_height_advanced": GenericScene,
    "sorting_weight": GenericScene,
    "sorting_station": GenericScene,
}


def register_scene(name: str, cls: Type[BaseScene]) -> None:
    """Register a custom scene class under a given name."""
    _SCENE_REGISTRY[name] = cls
    logger.debug("Registered scene: %s -> %s", name, cls.__name__)


def load_scene(scene_name: str, loader: ConfigLoader) -> BaseScene:
    """
    Load a scene config from YAML and return an initialised :class:`BaseScene`.

    Parameters
    ----------
    scene_name:
        Name of the scene (must match a file in ``configs/scenes/<name>.yaml``).
    loader:
        A :class:`ConfigLoader` instance.

    Raises
    ------
    KeyError
        If the scene name is not in the registry.
    FileNotFoundError
        If the config YAML does not exist.
    """
    raw = loader.load_scene_raw(scene_name)
    profile = _parse_scene_profile(raw)

    cls = _SCENE_REGISTRY.get(scene_name)
    if cls is None:
        raise KeyError(
            f"No scene implementation registered for '{scene_name}'. "
            f"Available: {list(_SCENE_REGISTRY.keys())}"
        )
    logger.info("Loaded scene '%s' (%d tags)", scene_name, len(profile.tags))
    return cls(profile)


def _parse_scene_profile(raw: dict) -> SceneProfile:
    """Parse raw YAML dict into a SceneProfile, constructing nested models."""
    tags = [TagDefinition(**t) for t in raw.get("tags", [])]
    rules = [SafetyRule(**r) for r in raw.get("safety_rules", [])]

    return SceneProfile(
        scene_name=raw["scene_name"],
        description=raw.get("description", ""),
        scene_id=raw.get("scene_id"),
        tags=tags,
        writable_tags=raw.get("writable_tags", []),
        safety_rules=rules,
        reset_procedure=raw.get("reset_procedure", []),
        sampling_interval_ms=raw.get("sampling_interval_ms", 500),
        attack_surface=raw.get("attack_surface", []),
    )
