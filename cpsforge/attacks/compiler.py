"""
CPSForge Attack Action Compiler
==================================
Translates an abstract :class:`AttackAction` into a concrete dict of
``{tag_name: value}`` writes to send to the PLC.

The compiler is the bridge between the attacker's high-level intent and
the physical PLC tag writes. It must be called AFTER shield approval.

Attack modes supported:
  - override  : write the specified value directly
  - offset    : add value as an offset to the current reading
  - freeze    : use snapshot's current value (write same value back repeatedly)
  - zero      : force the tag to 0 / False

Note: The compiler does NOT check shield rules -- that is the shield's job.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from cpsforge.core.models import AttackAction, AttackType

logger = logging.getLogger(__name__)


def compile_action(
    action: AttackAction,
    scene: Any,  # BaseScene
    current_snapshot: Any = None,  # Optional PlantSnapshot
) -> Dict[str, Any]:
    """
    Compile an :class:`AttackAction` into a ``{tag_name: value}`` write dict.

    Parameters
    ----------
    action:
        The approved attack action to compile.
    scene:
        The active :class:`BaseScene` (for tag lookup).
    current_snapshot:
        Optional current plant snapshot (needed for 'offset' and 'freeze' modes).

    Returns
    -------
    Dict of tag_name -> value to write.
    """
    writes: Dict[str, Any] = {}
    target = action.target

    if action.mode == "override":
        if action.value is not None:
            writes[target] = action.value

    elif action.mode == "offset":
        current = _get_current(current_snapshot, target)
        if current is not None and action.value is not None:
            writes[target] = float(current) + float(action.value)
        elif action.value is not None:
            writes[target] = action.value

    elif action.mode == "freeze":
        current = _get_current(current_snapshot, target)
        if current is not None:
            writes[target] = current

    elif action.mode == "zero":
        tag = scene.get_tag(target) if scene else None
        if tag and tag.data_type.value == "bool":
            writes[target] = False
        else:
            writes[target] = 0.0

    else:
        # Default: treat as override
        if action.value is not None:
            writes[target] = action.value

    if not writes:
        logger.warning("Compiler produced no writes for action %s (target=%s, mode=%s)",
                       action.action_id[:8], target, action.mode)

    return writes


def _get_current(snapshot: Any, tag_name: str) -> Optional[Any]:
    """Extract current tag value from snapshot across all buckets."""
    if snapshot is None:
        return None
    for bucket in (
        snapshot.sensors,
        snapshot.actuators,
        snapshot.controller_state,
        snapshot.setpoints,
    ):
        if tag_name in bucket:
            return bucket[tag_name]
    return None
