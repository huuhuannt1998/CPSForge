"""
CPSForge Scene Resetter
========================
Restores a Factory I/O scene to a known safe operating state after an
adversarial experiment run by writing the scene's ``reset_procedure`` tags
back to the PLC through the safety shield.

Usage
-----
Typically called automatically by the orchestrator when
``ExperimentConfig.reset_after_run`` is True for a live run::

    from cpsforge.plc.reset import SceneResetter
    resetter = SceneResetter()
    result = resetter.reset(plc_client, scene, shield, dry_run=False)

Or invoked from the CLI::

    cpsforge run reset --scene tank_control

Safety
------
All writes are routed through the ShieldEngine even during reset.
If the shield rejects a reset write (e.g. a cooldown has not expired),
the rejection is logged but the resetter continues with remaining tags.
Set ``force_unsafe=True`` only when you are certain it is safe to bypass
cooldown constraints (never bypass range or invariant rules).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from cpsforge.core.models import AttackAction, AttackSource, AttackType

logger = logging.getLogger(__name__)


class SceneResetter:
    """
    Writes the scene's ``reset_procedure`` tag list back to the PLC.

    All writes are submitted through the :class:`~cpsforge.shield.engine.ShieldEngine`
    so that safety invariants are respected even during reset.
    """

    def reset(
        self,
        plc_client: Any,
        scene: Any,
        shield: Any,
        snapshot: Optional[Any] = None,
        dry_run: bool = True,
        force_cooldown_bypass: bool = False,
    ) -> Dict[str, bool]:
        """
        Execute the reset procedure for *scene*.

        Parameters
        ----------
        plc_client:
            A connected :class:`~cpsforge.plc.client.PlcClient`.  Ignored
            when *dry_run* is True.
        scene:
            The active :class:`~cpsforge.scenes.base.BaseScene` whose
            ``reset_procedure`` defines the target values.
        shield:
            The active :class:`~cpsforge.shield.engine.ShieldEngine`.
        snapshot:
            Optional current :class:`~cpsforge.core.models.PlantSnapshot`
            used by the shield for context-aware rule checks (interlock,
            mode_gate).  Pass None if no snapshot is available.
        dry_run:
            If *True*, log what would be written but do not call
            :meth:`~cpsforge.plc.client.PlcClient.write_tag`.
        force_cooldown_bypass:
            If *True*, temporarily disable cooldown rules by evaluating the
            action with ``duration_ms=0`` so cooldown checks pass.  Never
            use this flag to bypass range or invariant limits.

        Returns
        -------
        Dict[str, bool]
            Mapping of ``tag_name -> success``.  A value of True means the write
            was approved and either executed (live) or logged (dry-run).
        """
        reset_writes = scene.get_reset_writes()
        if not reset_writes:
            logger.warning(
                "SceneResetter: scene '%s' has no reset_procedure. Nothing to reset.",
                scene.name,
            )
            return {}

        logger.info(
            "SceneResetter: resetting scene '%s' (%d tags, dry_run=%s).",
            scene.name,
            len(reset_writes),
            dry_run,
        )

        results: Dict[str, bool] = {}
        rejected: List[Tuple[str, List[str]]] = []

        for tag_name, value in reset_writes.items():
            # Build a minimal AttackAction representing the reset write.
            # Use duration_ms=0 so cooldown bypass takes effect when requested.
            numeric_value: Optional[float]
            if isinstance(value, bool):
                numeric_value = 1.0 if value else 0.0
            elif value is None:
                logger.warning("Reset: tag '%s' has no value in reset_procedure -- skipping.", tag_name)
                results[tag_name] = False
                continue
            else:
                try:
                    numeric_value = float(value)
                except (TypeError, ValueError):
                    logger.warning("Reset: cannot convert value %r for '%s' -- skipping.", value, tag_name)
                    results[tag_name] = False
                    continue

            action = AttackAction(
                attack_type=AttackType.ACTUATOR_OVERRIDE,
                target=tag_name,
                mode="override",
                value=numeric_value,
                duration_ms=0,
                rationale="Scene reset after experiment run",
                source=AttackSource.SCRIPTED,
                confidence=1.0,
            )

            decision = shield.evaluate(action, snapshot)

            if not decision.approved:
                # If the only violated rule is a cooldown and bypass is allowed, retry
                if force_cooldown_bypass and decision.violated_rules == ["cooldown"]:
                    logger.debug(
                        "Reset: cooldown bypass for '%s' (force_cooldown_bypass=True).", tag_name
                    )
                else:
                    logger.warning(
                        "Reset: write to '%s' rejected by shield: %s",
                        tag_name,
                        decision.reasons,
                    )
                    rejected.append((tag_name, decision.reasons))
                    results[tag_name] = False
                    continue

            if dry_run:
                logger.info("DRY-RUN reset: would write %s = %r", tag_name, value)
                results[tag_name] = True
            else:
                tag_def = scene.get_tag(tag_name)
                if tag_def is None:
                    logger.error(
                        "Reset: tag definition for '%s' not found in scene profile.", tag_name
                    )
                    results[tag_name] = False
                    continue
                ok = plc_client.write_tag(tag_def, value)
                if ok:
                    logger.info("Reset: wrote %s = %r", tag_name, value)
                else:
                    logger.error("Reset: PLC write FAILED for %s = %r", tag_name, value)
                results[tag_name] = ok

        success_count = sum(1 for v in results.values() if v)
        logger.info(
            "SceneResetter done: %d/%d tags written successfully.",
            success_count, len(results),
        )
        if rejected:
            logger.warning(
                "SceneResetter: %d tag(s) rejected by shield: %s",
                len(rejected),
                [t for t, _ in rejected],
            )
        return results
