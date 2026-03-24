"""CPSForge scenes package."""
from cpsforge.scenes.base import BaseScene
from cpsforge.scenes.tank_control import TankControlScene
from cpsforge.scenes.factory import load_scene, register_scene
from cpsforge.scenes.generic import GenericScene

__all__ = ["BaseScene", "TankControlScene", "GenericScene", "load_scene", "register_scene"]
