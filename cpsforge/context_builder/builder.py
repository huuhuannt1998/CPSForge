"""
builder.py — 3-tier context builder for the online MITM attacker.

ContextBuilder.build() is called every LLM decision cycle.  It assembles
a ContextPayload and renders it into (system_prompt, user_prompt) strings
ready for the LLM provider.

The ONLY thing that changes across context levels is the ContextPayload
content — model, temperature, max_tokens, scene, and defense are all held
constant.  This guarantees a fair ablation study (RQ1).
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from cpsforge.context_builder.schema import (
    ContextLevel,
    ContextPayload,
    TagSummary,
)
from cpsforge.core.models import PlantSnapshot
from cpsforge.observation.history_buffer import HistoryBuffer
from cpsforge.observation.phase_inference import PhaseInferenceEngine, PhaseLabel
from cpsforge.scenes.base import BaseScene

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"


class ContextBuilder:
    """Build 3-tier attacker context from live PLC observations.

    Parameters
    ----------
    scene : BaseScene
        The active Factory I/O scene (provides tag metadata + description).
    phase_engine : PhaseInferenceEngine
        Pre-configured phase inference engine for this scene.
    history : HistoryBuffer
        Rolling window of recent PlantSnapshots.
    partial_history_steps : int
        Number of history steps included in PARTIAL context (default 5).
    full_history_steps : int
        Number of history steps included in FULL context (default 10).
    template_dir : Path, optional
        Directory containing minimal.md / partial.md / full.md templates.
        Defaults to the bundled templates/ subdirectory.
    """

    def __init__(
        self,
        scene: BaseScene,
        phase_engine: PhaseInferenceEngine,
        history: HistoryBuffer,
        partial_history_steps: int = 5,
        full_history_steps: int = 10,
        template_dir: Optional[Path] = None,
    ) -> None:
        self._scene = scene
        self._phase_engine = phase_engine
        self._history = history
        self._partial_steps = partial_history_steps
        self._full_steps = full_history_steps
        self._tpl_dir = template_dir or _TEMPLATES_DIR
        self._templates = self._load_templates()

    # ------------------------------------------------------------------
    # Primary API
    # ------------------------------------------------------------------

    def build(
        self,
        snapshot: PlantSnapshot,
        level: ContextLevel,
        prior_actions: Optional[List[Dict[str, Any]]] = None,
    ) -> ContextPayload:
        """Assemble a ContextPayload for *level* from *snapshot*.

        Parameters
        ----------
        snapshot : PlantSnapshot
            Current state of the process.
        level : ContextLevel
            Which context tier to build (MINIMAL / PARTIAL / FULL).
        prior_actions : list, optional
            Previous attack proposals with outcomes (FULL context only).
        """
        profile = self._scene.profile
        attack_surface = profile.attack_surface
        current_values = self._extract_current_values(snapshot)

        payload = ContextPayload(
            level=level,
            scene_name=profile.scene_name,
            attack_surface=attack_surface,
            current_values=current_values,
            step_id=snapshot.step_id,
            run_id=snapshot.run_id,
        )

        if level in (ContextLevel.PARTIAL, ContextLevel.FULL):
            payload.tag_metadata = self._build_tag_metadata()
            # Limit history to attack-surface tags + key sensors to keep
            # prompt size manageable (especially for scenes with 30+ tags).
            # Key sensors are loaded from scene YAML config (key_sensors field),
            # falling back to attack surface only if not configured.
            key_sensor_names = set(getattr(profile, "key_sensors", None) or [])
            history_tags = list(dict.fromkeys(
                attack_surface
                + [k for k in current_values if k in key_sensor_names]
            ))
            payload.history_table = self._history.as_table(
                tags=history_tags,
                n=self._partial_steps if level == ContextLevel.PARTIAL else self._full_steps,
            )
            payload.scene_description = profile.description or ""
            payload.attack_type_descriptions = _ATTACK_TYPE_DESCRIPTIONS

        if level == ContextLevel.FULL:
            phase_result = self._phase_engine.infer(snapshot, self._history.window(self._full_steps))
            payload.inferred_phase = phase_result.phase.value
            payload.phase_confidence = round(phase_result.confidence, 2)
            payload.control_objective = (
                getattr(profile, "control_objective", None)
                or _CONTROL_OBJECTIVES.get(profile.scene_name, "")
            )
            payload.prior_actions = prior_actions or []
            payload.derived_features = dict(snapshot.derived_features)
            payload.shield_rules_summary = self._build_shield_summary()

        payload.payload_hash = self._hash_payload(payload)
        return payload

    def render(
        self,
        payload: ContextPayload,
    ) -> tuple[str, str]:
        """Render *payload* into (system_prompt, user_prompt) strings.

        Returns
        -------
        system_prompt : str
        user_prompt   : str
        """
        tpl = self._templates.get(payload.level.value, "")
        if not tpl:
            logger.warning("No template found for level %s; using fallback", payload.level)
            return _fallback_system(payload), _fallback_user(payload)

        # Split template on the ===USER=== marker
        if "===USER===" in tpl:
            sys_part, usr_part = tpl.split("===USER===", 1)
        else:
            sys_part = tpl
            usr_part = ""

        fmt = _build_format_map(payload)
        try:
            system = sys_part.strip().format_map(fmt)
            user   = usr_part.strip().format_map(fmt)
        except KeyError as exc:
            logger.error("Template placeholder %s not found in context payload", exc)
            system = _fallback_system(payload)
            user   = _fallback_user(payload)
        return system, user

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_current_values(self, snapshot: PlantSnapshot) -> Dict[str, Any]:
        """Return a flat dict of all tag values from the snapshot."""
        values: Dict[str, Any] = {}
        for cat in (
            snapshot.sensors,
            snapshot.actuators,
            snapshot.setpoints,
            snapshot.controller_state,
            snapshot.alarms,
        ):
            values.update(cat)
        return values

    def _build_tag_metadata(self) -> List[TagSummary]:
        # Only include attack-surface tags + key sensors to keep prompt compact.
        # Key sensors loaded from scene config (key_sensors field in YAML).
        attack_tags = set(self._scene.profile.attack_surface)
        key_sensors = set(getattr(self._scene.profile, "key_sensors", None) or [])
        summaries = []
        for tag in self._scene.profile.tags:
            if tag.name not in attack_tags and tag.name not in key_sensors:
                continue
            summaries.append(
                TagSummary(
                    name=tag.name,
                    unit=tag.unit,
                    min_value=tag.min_value,
                    max_value=tag.max_value,
                    category=tag.category.value,
                    description=tag.description,
                )
            )
        return summaries

    def _build_shield_summary(self) -> str:
        """Summarise safety rules in plain English for the full context."""
        rules = self._scene.profile.safety_rules
        if not rules:
            return "No explicit safety rules configured."
        lines = []
        for rule in rules:
            if rule.enabled:
                lines.append(f"- [{rule.rule_id}] {rule.description}")
        return "\n".join(lines) if lines else "No enabled safety rules."

    def _load_templates(self) -> Dict[str, str]:
        templates: Dict[str, str] = {}
        for level in ContextLevel:
            path = self._tpl_dir / f"{level.value}.md"
            if path.exists():
                templates[level.value] = path.read_text(encoding="utf-8")
            else:
                logger.debug("Template not found at %s; will use fallback", path)
        return templates

    @staticmethod
    def _hash_payload(payload: ContextPayload) -> str:
        raw = json.dumps(payload.as_dict(), sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Format-map builder
# ---------------------------------------------------------------------------

def _build_format_map(payload: ContextPayload) -> Dict[str, str]:
    """Build a {placeholder: value} dict for template string substitution."""
    m: Dict[str, str] = {
        "scene_name":         payload.scene_name,
        "attack_surface":     ", ".join(payload.attack_surface),
        "current_values":     json.dumps(payload.current_values, indent=2),
        "step_id":            str(payload.step_id or "?"),
    }

    if payload.tag_metadata:
        rows = []
        for t in payload.tag_metadata:
            rng = ""
            if t.min_value is not None and t.max_value is not None:
                rng = f"[{t.min_value}, {t.max_value}]"
            unit = t.unit or ""
            rows.append(f"  {t.name:<28} {t.category:<12} {unit:<8} {rng:<20} {t.description}")
        m["tag_table"] = "\n".join(rows)
    else:
        m["tag_table"] = "(not provided)"

    if payload.history_table:
        header_keys = list(payload.history_table[0].keys()) if payload.history_table else []
        hdr = "  " + "  ".join(f"{k:<14}" for k in header_keys)
        rows_txt = []
        for row in payload.history_table:
            rows_txt.append("  " + "  ".join(f"{str(v):<14}" for v in row.values()))
        m["history_table"] = "\n".join([hdr] + rows_txt)
    else:
        m["history_table"] = "(not provided)"

    m["scene_description"]        = payload.scene_description or "(not provided)"
    m["attack_type_descriptions"] = (
        "\n".join(f"  {k}: {v}" for k, v in (payload.attack_type_descriptions or {}).items())
    )
    m["inferred_phase"]    = payload.inferred_phase or "unknown"
    m["phase_confidence"]  = str(int((payload.phase_confidence or 0.0) * 100)) + "%"
    m["control_objective"] = payload.control_objective or "(not provided)"
    m["prior_actions"]     = json.dumps(payload.prior_actions or [], indent=2)
    m["derived_features"]  = json.dumps(payload.derived_features or {}, indent=2)
    m["shield_rules"]      = payload.shield_rules_summary or "(not provided)"
    return m


def _fallback_system(payload: ContextPayload) -> str:
    return (
        f"You are a CPS security researcher testing the '{payload.scene_name}' process.\n"
        f"You may target these tags: {', '.join(payload.attack_surface)}.\n"
        "Respond only with valid JSON matching the AttackDecision schema."
    )


def _fallback_user(payload: ContextPayload) -> str:
    vals = json.dumps(payload.current_values, indent=2)
    return f"Current process state:\n{vals}\n\nDecide: attack or wait?"


# ---------------------------------------------------------------------------
# Shared metadata constants
# ---------------------------------------------------------------------------

_ATTACK_TYPE_DESCRIPTIONS: Dict[str, str] = {
    "actuator_override":    "Force an actuator (valve, pump, conveyor) to a specific value.",
    "setpoint_shift":       "Move a controller setpoint to an unsafe target value.",
    "sensor_spoof":         "Inject a false sensor reading to mislead the controller.",
    "timing_delay":         "Delay an actuator operation to cause a process fault.",
    "sequence_perturbation":"Disrupt the normal order of discrete control operations.",
}

_CONTROL_OBJECTIVES: Dict[str, str] = {
    "level_control":    "Maintain liquid level at the configured setpoint (default ~5.25 V). "
                         "Controller opens fill or discharge valve as needed.",
    "filling_tank":     "Fill the tank to a target level then hold. Overflow sensor triggers shutdown.",
    "sorting_weight":   (
        "3-way weight sort: weight<light_thresh(2.0)→LEFT, weight≥heavy_thresh(5.0)→RIGHT, else→FORWARD.\n"
        "ATTACKS: Shift light_thresh/heavy_thresh within [0.5-10.0]/[1.0-15.0] to missort boxes. "
        "Force wrong diverter (send_left/send_right/send_forward) to jam. "
        "Set entry_conveyor=False to stall. Best timing: attack thresholds when at_scale=True."
    ),
    "from_a_to_b":      "Transport items from station A to station B using a series of conveyors.",
    "tank_control":     "Regulate tank level via pump speed. PID tracks the configured setpoint.",
    "sorting_height_basic": (
        "2-way height sort: short items (low_sensor only)→LEFT, tall items (high_sensor)→RIGHT.\n"
        "ATTACKS: Force wrong transfer (transf_left/transf_right) to missort. "
        "Stop conveyor_entry or load_act to stall. Set enable=False to halt. "
        "Best timing: attack transfers when item is on load area (low_sensor=True)."
    ),
}
