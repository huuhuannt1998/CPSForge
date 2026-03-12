"""
CPSForge Attacker Base Class
==============================
All attacker implementations subclass :class:`BaseAttacker`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from cpsforge.core.config import AttackPolicyConfig
from cpsforge.core.models import AttackAction


class BaseAttacker(ABC):
    """Abstract base class for CPSForge attackers."""

    def __init__(self, config: AttackPolicyConfig) -> None:
        self._config = config

    @property
    def name(self) -> str:
        return self._config.name

    @abstractmethod
    def generate_actions(self, scene: object) -> List[AttackAction]:
        """
        Generate a list of :class:`AttackAction` objects for the given scene.

        Actions are validated by the shield before execution. The attacker
        should not attempt to bypass shield rules.

        Parameters
        ----------
        scene:
            The active :class:`BaseScene` -- provides attack surface and tag info.
        """
