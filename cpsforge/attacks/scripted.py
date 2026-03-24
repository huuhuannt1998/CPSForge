"""
CPSForge Scripted Attacker
============================
Executes a deterministic, pre-defined sequence of attack actions.

Attack templates are loaded from a JSON file (``script_file`` in config)
or from a hardcoded default sequence if no file is specified.

Scripted attacks are fully reproducible and suitable for repeatable experiments.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List

from cpsforge.attacks.base import BaseAttacker
from cpsforge.core.config import AttackPolicyConfig
from cpsforge.core.models import AttackAction, AttackSource, AttackType

logger = logging.getLogger(__name__)

# Default scripted sequences per scene when no script_file is provided
_DEFAULT_SCRIPTS: dict[str, list[dict]] = {
    "tank_control": [
        {
            "attack_type": "actuator_override",
            "target": "pump_speed",
            "mode": "override",
            "value": 0.0,
            "duration_ms": 8000,
            "rationale": "Stop pump to cause level drop",
            "expected_effect": "Tank level decreases below setpoint",
            "confidence": 0.9,
        },
        {
            "attack_type": "setpoint_shift",
            "target": "level_setpoint",
            "mode": "override",
            "value": 85.0,
            "duration_ms": 10000,
            "rationale": "Shift setpoint high to cause overflow risk",
            "expected_effect": "PID drives pump to fill tank excessively",
            "confidence": 0.85,
        },
        {
            "attack_type": "actuator_override",
            "target": "drain_valve_position",
            "mode": "override",
            "value": 100.0,
            "duration_ms": 6000,
            "rationale": "Fully open drain to rapidly empty tank",
            "expected_effect": "Tank level drops rapidly",
            "confidence": 0.9,
        },
    ],
    "from_a_to_b": [
        {
            "attack_type": "actuator_override",
            "target": "conveyor",
            "mode": "override",
            "value": False,
            "duration_ms": 10000,
            "rationale": "Stop conveyor to halt transport during Transport state",
            "expected_effect": "Box stalls on conveyor; state remains 0 indefinitely",
            "confidence": 0.9,
        },
        {
            "attack_type": "actuator_override",
            "target": "enable",
            "mode": "override",
            "value": False,
            "duration_ms": 15000,
            "rationale": "Disable system enable flag to freeze entire operation",
            "expected_effect": "PLC logic stops executing; conveyor and sensor inactive",
            "confidence": 0.85,
        },
        {
            "attack_type": "actuator_override",
            "target": "conveyor",
            "mode": "override",
            "value": True,
            "duration_ms": 8000,
            "rationale": "Force conveyor on when system should be idle in Arrived state",
            "expected_effect": "Conveyor runs unnecessarily; box already removed",
            "confidence": 0.8,
        },
    ],
    "level_control": [
        {
            "attack_type": "setpoint_shift",
            "target": "setpoint_in",
            "mode": "override",
            "value": 9.5,
            "duration_ms": 12000,
            "rationale": "Shift setpoint near maximum to drive fill valve high",
            "expected_effect": "Level rises toward overflow; high-level alarm risk",
            "confidence": 0.9,
        },
        {
            "attack_type": "actuator_override",
            "target": "fill_valve",
            "mode": "override",
            "value": 10.0,
            "duration_ms": 8000,
            "rationale": "Force fill valve fully open to flood tank",
            "expected_effect": "Tank fills rapidly regardless of setpoint",
            "confidence": 0.85,
        },
        {
            "attack_type": "actuator_override",
            "target": "discharge_valve",
            "mode": "override",
            "value": 10.0,
            "duration_ms": 10000,
            "rationale": "Force discharge valve fully open to drain tank",
            "expected_effect": "Level drops below setpoint; low-level alarm risk",
            "confidence": 0.85,
        },
        {
            "attack_type": "actuator_override",
            "target": "enable",
            "mode": "override",
            "value": False,
            "duration_ms": 15000,
            "rationale": "Disable system to interrupt control loop",
            "expected_effect": "PID loop stops; valves freeze in last state",
            "confidence": 0.8,
        },
    ],
    "sorting_height_basic": [
        {
            "attack_type": "actuator_override",
            "target": "conveyor_entry",
            "mode": "override",
            "value": False,
            "duration_ms": 10000,
            "rationale": "Stop entry conveyor to block item feed",
            "expected_effect": "Items cannot enter sorting area; throughput drops",
            "confidence": 0.9,
        },
        {
            "attack_type": "actuator_override",
            "target": "transf_left",
            "mode": "override",
            "value": True,
            "duration_ms": 8000,
            "rationale": "Force left transfer on to mis-sort items",
            "expected_effect": "All items sent left regardless of height",
            "confidence": 0.85,
        },
        {
            "attack_type": "actuator_override",
            "target": "transf_right",
            "mode": "override",
            "value": True,
            "duration_ms": 8000,
            "rationale": "Force right transfer on simultaneously",
            "expected_effect": "Transfer conflict; safety violation",
            "confidence": 0.8,
        },
        {
            "attack_type": "actuator_override",
            "target": "enable",
            "mode": "override",
            "value": False,
            "duration_ms": 15000,
            "rationale": "Disable system to halt sorting operation",
            "expected_effect": "Entire sorter stops; items stuck on conveyor",
            "confidence": 0.85,
        },
    ],
    "filling_tank": [
        {
            "attack_type": "actuator_override",
            "target": "fill_valve",
            "mode": "override",
            "value": False,
            "duration_ms": 12000,
            "rationale": "Close fill valve during fill phase to stall cycle",
            "expected_effect": "Tank never fills; process stuck indefinitely",
            "confidence": 0.9,
        },
        {
            "attack_type": "actuator_override",
            "target": "drain_valve",
            "mode": "override",
            "value": True,
            "duration_ms": 10000,
            "rationale": "Force drain valve open during fill phase",
            "expected_effect": "Simultaneous fill/drain; violates mutual exclusion",
            "confidence": 0.85,
        },
        {
            "attack_type": "actuator_override",
            "target": "enable",
            "mode": "override",
            "value": False,
            "duration_ms": 15000,
            "rationale": "Disable system to freeze all valve outputs",
            "expected_effect": "All outputs off; tank level unchanged",
            "confidence": 0.85,
        },
    ],
    "sorting_weight": [
        {
            "attack_type": "setpoint_shift",
            "target": "light_thresh",
            "mode": "override",
            "value": 8.0,
            "duration_ms": 15000,
            "rationale": "Shift light threshold high so most boxes go left",
            "expected_effect": "Medium and some heavy boxes mis-sorted to left",
            "confidence": 0.9,
        },
        {
            "attack_type": "setpoint_shift",
            "target": "heavy_thresh",
            "mode": "override",
            "value": 2.0,
            "duration_ms": 15000,
            "rationale": "Lower heavy threshold so most boxes go right",
            "expected_effect": "Medium and light boxes mis-sorted to right",
            "confidence": 0.85,
        },
        {
            "attack_type": "actuator_override",
            "target": "send_left",
            "mode": "override",
            "value": True,
            "duration_ms": 8000,
            "rationale": "Force left diverter on during idle or forward send",
            "expected_effect": "Box routed left regardless of weight",
            "confidence": 0.8,
        },
        {
            "attack_type": "actuator_override",
            "target": "entry_conveyor",
            "mode": "override",
            "value": False,
            "duration_ms": 12000,
            "rationale": "Stop entry conveyor to starve scale of boxes",
            "expected_effect": "No boxes reach scale; throughput drops to zero",
            "confidence": 0.9,
        },
        {
            "attack_type": "actuator_override",
            "target": "enable",
            "mode": "override",
            "value": False,
            "duration_ms": 15000,
            "rationale": "Disable system to freeze all outputs",
            "expected_effect": "Entire sorter stops; boxes stuck on conveyors",
            "confidence": 0.85,
        },
    ],
}


class ScriptedAttacker(BaseAttacker):
    """
    Deterministic attacker that executes a pre-defined attack script.

    The script can be loaded from ``config.script_file`` (JSON array of
    action dicts) or falls back to the built-in default for the scene.
    """

    def generate_actions(self, scene: object) -> List[AttackAction]:
        scene_name = getattr(scene, "name", "unknown")
        script = self._load_script(scene_name)

        actions: List[AttackAction] = []
        for i, entry in enumerate(script[: self._config.max_actions]):
            try:
                action = AttackAction(
                    attack_type=AttackType(entry["attack_type"]),
                    target=entry["target"],
                    mode=entry.get("mode", "override"),
                    value=entry.get("value"),
                    duration_ms=entry.get("duration_ms", 5000),
                    rationale=entry.get("rationale", ""),
                    expected_effect=entry.get("expected_effect", ""),
                    confidence=entry.get("confidence", 0.5),
                    source=AttackSource.SCRIPTED,
                )
                actions.append(action)
            except Exception as exc:
                logger.warning("Could not parse script entry %d: %s -- skipping.", i, exc)

        logger.info("ScriptedAttacker '%s' loaded %d actions.", self.name, len(actions))
        return actions

    def _load_script(self, scene_name: str) -> list:
        if self._config.script_file:
            path = Path(self._config.script_file)
            if path.exists():
                with path.open() as fh:
                    data = json.load(fh)
                if isinstance(data, list):
                    return data
                logger.warning("Script file %s is not a JSON array -- using default.", path)
        default = _DEFAULT_SCRIPTS.get(scene_name, [])
        if not default:
            logger.warning("No default script for scene '%s'. No attacks will run.", scene_name)
        return default
