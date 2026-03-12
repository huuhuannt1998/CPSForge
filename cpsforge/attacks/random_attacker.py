"""
CPSForge Random Attacker
==========================
Generates randomised attack actions within the scene's configured attack surface
and the allowed attack types from the policy config.

Randomisation is seeded for reproducibility. Each generated action selects:
  - a random target tag from the attack surface
  - a random attack type from the policy whitelist
  - a random value bounded by the tag's min/max
  - a random duration within [500ms, policy.max_duration_ms]
"""

from __future__ import annotations

import logging
import random
from typing import List, Optional

from cpsforge.attacks.base import BaseAttacker
from cpsforge.core.config import AttackPolicyConfig
from cpsforge.core.models import AttackAction, AttackSource, AttackType, TagDefinition

logger = logging.getLogger(__name__)

_MAX_DURATION_MS = 20000  # hard cap for random durations


class RandomAttacker(BaseAttacker):
    """
    Generates bounded-random attack actions within the scene attack surface.

    Reproducible when ``config.random_seed`` is set.
    """

    def __init__(self, config: AttackPolicyConfig) -> None:
        super().__init__(config)
        self._rng = random.Random(config.random_seed)

    def generate_actions(self, scene: object) -> List[AttackAction]:
        scene_name = getattr(scene, "name", "unknown")
        attack_surface = getattr(scene, "get_attack_surface", lambda: [])()
        tags_by_name = {t.name: t for t in getattr(scene, "get_all_tags", lambda: [])()}

        if not attack_surface:
            logger.warning("RandomAttacker: no attack surface defined for scene '%s'.", scene_name)
            return []

        # Filter to allowed attack types
        allowed_types = [AttackType(t) for t in self._config.attack_types]
        if not allowed_types:
            allowed_types = list(AttackType)

        actions: List[AttackAction] = []
        for _ in range(self._config.max_actions):
            target = self._rng.choice(attack_surface)
            attack_type = self._rng.choice(allowed_types)
            tag_def: Optional[TagDefinition] = tags_by_name.get(target)
            value = self._sample_value(tag_def)
            duration_ms = self._rng.randint(1000, min(_MAX_DURATION_MS, 15000))

            action = AttackAction(
                attack_type=attack_type,
                target=target,
                mode="override",
                value=value,
                duration_ms=duration_ms,
                rationale=f"Random {attack_type.value} on {target}",
                expected_effect="Unknown -- random perturbation",
                confidence=round(self._rng.uniform(0.3, 0.8), 2),
                source=AttackSource.RANDOM,
            )
            actions.append(action)

        logger.info(
            "RandomAttacker '%s' generated %d actions (seed=%s).",
            self.name,
            len(actions),
            self._config.random_seed,
        )
        return actions

    def _sample_value(self, tag: Optional[TagDefinition]) -> Any:
        """Sample a random value within the tag's allowed range."""
        # Boolean tags get True/False, not a float
        if tag is not None and tag.data_type.value == "bool":
            return self._rng.choice([True, False])

        lo = 0.0
        hi = 100.0
        if tag is not None:
            if tag.min_value is not None:
                lo = float(tag.min_value)
            if tag.max_value is not None:
                hi = float(tag.max_value)
        val = self._rng.uniform(lo, hi)
        # Apply optional noise perturbation
        noise = self._rng.gauss(0, self._config.value_noise_std * (hi - lo))
        val = max(lo, min(hi, val + noise))
        return round(val, 3)
