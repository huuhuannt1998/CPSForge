"""
CPSForge Attacker Factory
===========================
Maps attacker_type strings to their implementations.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from cpsforge.attacks.base import BaseAttacker
from cpsforge.attacks.scripted import ScriptedAttacker
from cpsforge.attacks.random_attacker import RandomAttacker
from cpsforge.core.config import AttackPolicyConfig

if TYPE_CHECKING:
    from cpsforge.scenes.base import BaseScene

logger = logging.getLogger(__name__)


def build_attacker(config: AttackPolicyConfig, scene: "BaseScene") -> BaseAttacker:
    """
    Instantiate an attacker from a policy config.

    Parameters
    ----------
    config:
        Loaded :class:`AttackPolicyConfig`.
    scene:
        The active scene (passed for context; some attackers inspect scene tags).

    Raises
    ------
    ValueError
        If the attacker_type is unknown.
    """
    t = config.attacker_type.lower()

    if t == "scripted":
        return ScriptedAttacker(config)
    elif t == "random":
        return RandomAttacker(config)
    elif t == "llm":
        # LLM attacker is implemented in Phase 4
        from cpsforge.llm.attacker import LLMAttacker
        return LLMAttacker(config)
    elif t == "campaign":
        from cpsforge.attacks.campaign_attacker import CampaignAttacker
        return CampaignAttacker(config)
    else:
        raise ValueError(
            f"Unknown attacker type: '{config.attacker_type}'. "
            "Expected: scripted | random | llm | campaign"
        )
