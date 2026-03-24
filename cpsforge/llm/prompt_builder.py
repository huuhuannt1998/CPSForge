"""
CPSForge LLM Prompt Builder
=============================
Constructs the system and user prompts sent to the LLM attacker from:

1. A *versioned template pair* loaded from disk:
   ``configs/llm/prompts/v{version}/attacker_system.md``
   ``configs/llm/prompts/v{version}/attacker_user.md``

2. Runtime data injected via Python `str.format_map()`:
   - ``{scene_name}``          -- name of the active Factory I/O scene
   - ``{scene_description}``   -- prose description from the scene profile
   - ``{tag_summary}``         -- formatted table of readable/writable tags
   - ``{attack_surface}``      -- comma-separated list of attackable tag names
   - ``{valid_attack_types}``  -- comma-separated valid AttackType enum values
   - ``{max_actions}``         -- max number of actions to generate
   - ``{scene_state}``         -- JSON serialisation of the latest PlantSnapshot
   - ``{step_id}``             -- current step number
   - ``{prior_actions}``       -- JSON of previously generated actions (multi-step)
   - ``{attacker_objective}``  -- optional objective string from config
   - ``{notes}``               -- optional guidance appended to the user prompt

Template files are plain Markdown / text with ``{placeholder}`` tokens.
Missing keys are silently replaced with an empty string.

Template versioning:
  The active version is controlled by ``LLMConfig.prompt_template_version``
  (default ``"v1"``).  New templates can be added in a new ``v2/`` folder
  without breaking existing configs.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from cpsforge.core.models import AttackAction, AttackType, PlantSnapshot, SceneProfile

logger = logging.getLogger(__name__)

# Resolve the repo root once at module load time
_REPO_ROOT = Path(__file__).parent.parent.parent
_PROMPTS_ROOT = _REPO_ROOT / "configs" / "llm" / "prompts"

# Provided as a fallback when the template files are absent, so the attacker
# can still run without disk I/O in unit tests.
_FALLBACK_SYSTEM = """\
You are an expert Cyber-Physical Systems (CPS) security researcher conducting
authorised red-team testing on a Factory I/O simulation connected to a real
Siemens S7 PLC.

Scene: {scene_name}
Description: {scene_description}

Attack surface (tag names you may target):
{attack_surface}

Valid attack types: {valid_attack_types}

STRICT OUTPUT RULES:
1. Respond with ONLY a valid JSON array of attack action objects.
2. Each object must have: attack_type, target, value, duration_ms,
   rationale, expected_effect, confidence.
3. Target must be a tag NAME from the attack surface list above --
   NEVER a raw PLC memory address (e.g. DB1,REAL4 or MW10).
4. Value must be a numeric literal.
5. Confidence must be between 0.0 and 1.0.
6. Maximum {max_actions} actions per response.
7. No explanatory text -- JSON array only.
"""

_FALLBACK_USER = """\
Current plant state (step {step_id}):
{scene_state}

{notes}
Generate {max_actions} attack actions targeting this scene.
"""

# Human-readable descriptions of each attack type, injected into prompts via
# {valid_attack_types_detail} so the LLM can reason about which type suits the
# current physical process state.
_ATTACK_TYPE_DESCRIPTIONS: Dict[str, str] = {
    "actuator_override": "force an actuator to a specific fixed output value, bypassing the controller",
    "setpoint_shift": "shift the controller setpoint to drive the process toward a physical limit",
    "sensor_spoof": "inject a false sensor reading to mislead the feedback control loop",
    "timing_delay": "introduce a control-signal delay (value = delay in milliseconds)",
    "sequence_perturbation": "disrupt the order or timing of a discrete sequential process step",
}


class PromptBuilder:
    """
    Builds versioned LLM attacker prompts from disk templates.

    Parameters
    ----------
    template_version:
        Sub-folder name inside ``configs/llm/prompts/`` to load from.
        Defaults to ``"v1"``.
    prompts_root:
        Override the default ``configs/llm/prompts/`` directory
        (useful for testing).
    """

    def __init__(
        self,
        template_version: str = "v1",
        prompts_root: Optional[Path] = None,
    ) -> None:
        self._version = template_version
        self._root = prompts_root or _PROMPTS_ROOT
        self._system_template: Optional[str] = None
        self._user_template: Optional[str] = None
        # Agent-mode templates (loaded lazily)
        self._attacker_agent_system: Optional[str] = None
        self._attacker_agent_user: Optional[str] = None
        self._defender_agent_system: Optional[str] = None
        self._defender_agent_user: Optional[str] = None
        self._load_templates()

    # ------------------------------------------------------------------
    # Template loading
    # ------------------------------------------------------------------

    @property
    def version(self) -> str:
        """Active template version string."""
        return self._version

    def _load_templates(self) -> None:
        """Load system and user templates from disk; fall back to built-ins."""
        version_dir = self._root / self._version
        sys_path = version_dir / "attacker_system.md"
        usr_path = version_dir / "attacker_user.md"

        if sys_path.exists():
            self._system_template = sys_path.read_text(encoding="utf-8")
            logger.debug("Loaded system template from %s", sys_path)
        else:
            logger.warning(
                "System prompt template not found at %s -- using built-in fallback.", sys_path
            )
            self._system_template = _FALLBACK_SYSTEM

        if usr_path.exists():
            self._user_template = usr_path.read_text(encoding="utf-8")
            logger.debug("Loaded user template from %s", usr_path)
        else:
            logger.warning(
                "User prompt template not found at %s -- using built-in fallback.", usr_path
            )
            self._user_template = _FALLBACK_USER

        # Agent-mode templates (optional; fall back to batch templates)
        for attr, filename, fallback_attr in [
            ("_attacker_agent_system", "attacker_agent_system.md", "_system_template"),
            ("_attacker_agent_user", "attacker_agent_user.md", "_user_template"),
            ("_defender_agent_system", "defender_agent_system.md", "_system_template"),
            ("_defender_agent_user", "defender_agent_user.md", "_user_template"),
        ]:
            path = version_dir / filename
            if path.exists():
                setattr(self, attr, path.read_text(encoding="utf-8"))
                logger.debug("Loaded agent template from %s", path)
            else:
                setattr(self, attr, getattr(self, fallback_attr))

    def reload(self, version: Optional[str] = None) -> None:
        """
        Hot-reload templates from disk, optionally switching to a new version.

        Useful when iterating on prompt design without restarting the process.
        """
        if version is not None:
            self._version = version
        self._load_templates()

    # ------------------------------------------------------------------
    # Prompt assembly
    # ------------------------------------------------------------------

    def build_system_prompt(
        self,
        scene: object,
        max_actions: int = 5,
    ) -> str:
        """
        Render the system prompt for the LLM attacker.

        Parameters
        ----------
        scene:
            Active :class:`BaseScene` (provides profile, tags, attack surface).
        max_actions:
            Maximum number of attack actions the model should produce.

        Returns
        -------
        str
            Fully rendered system prompt string.
        """
        profile: Optional[SceneProfile] = getattr(scene, "profile", None)
        context = self._build_scene_context(profile, max_actions)
        return self._render(self._system_template, context)

    def build_user_prompt(
        self,
        snapshot: Optional[PlantSnapshot],
        max_actions: int = 5,
        prior_actions: Optional[List[AttackAction]] = None,
        attacker_objective: str = "",
        notes: str = "",
    ) -> str:
        """
        Render the user (turn-level) prompt.

        Parameters
        ----------
        snapshot:
            Most recent :class:`PlantSnapshot`; serialised to JSON for the model.
        max_actions:
            Maximum number of attack actions to request.
        prior_actions:
            Previously generated actions for multi-step chain reasoning.
        attacker_objective:
            High-level attack goal provided via config.
        notes:
            Extra freeform guidance (e.g. "focus on tank overflow").

        Returns
        -------
        str
            Fully rendered user prompt string.
        """
        step_id = snapshot.step_id if snapshot else 0
        scene_state = self._snapshot_to_str(snapshot)
        prior_str = self._prior_actions_to_str(prior_actions)

        parts = []
        if attacker_objective:
            parts.append(f"Attacker objective: {attacker_objective}")
        if notes:
            parts.append(notes)
        notes_combined = "\n".join(parts)

        context: Dict[str, Any] = {
            "step_id": step_id,
            "scene_state": scene_state,
            "max_actions": max_actions,
            "prior_actions": prior_str,
            "attacker_objective": attacker_objective,
            "notes": notes_combined,
        }
        return self._render(self._user_template, context)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_scene_context(
        self, profile: Optional[SceneProfile], max_actions: int
    ) -> Dict[str, Any]:
        if profile is None:
            return {
                "scene_name": "unknown",
                "scene_description": "",
                "tag_summary": "No tags available",
                "attack_surface": "none",
                "valid_attack_types": ", ".join(t.value for t in AttackType),
                "max_actions": max_actions,
            }

        tag_lines: List[str] = []
        for tag in profile.tags:
            rw = tag.access.value if hasattr(tag.access, "value") else str(tag.access)
            tag_lines.append(
                f"  {tag.name:<30s} [{rw:10s}] {tag.category.value:<12s} "
                f"{tag.min_value or '?'} - {tag.max_value or '?'} {tag.unit or ''}"
            )
        tag_summary = "\n".join(tag_lines) if tag_lines else "  (no tags defined)"

        attack_surface_str = ", ".join(profile.attack_surface) if profile.attack_surface else "none"

        return {
            "scene_name": profile.scene_name,
            "scene_description": profile.description,
            "tag_summary": tag_summary,
            "attack_surface": attack_surface_str,
            "attack_surface_detail": self._build_attack_surface_detail(profile),
            "valid_attack_types": ", ".join(t.value for t in AttackType),
            "valid_attack_types_detail": "\n".join(
                f"  {k:<25s} -- {v}" for k, v in _ATTACK_TYPE_DESCRIPTIONS.items()
            ),
            "max_actions": max_actions,
        }

    @staticmethod
    def _build_attack_surface_detail(profile: Optional[SceneProfile]) -> str:
        """
        Build a per-tag reference table for tags on the attack surface.

        Includes the value range, unit, and category for each writable tag so
        the LLM can choose physically plausible attack values without guessing.
        """
        if profile is None:
            return "  (no attack surface defined)"

        surface_set = set(profile.attack_surface) if profile.attack_surface else set()
        lines: List[str] = []
        for tag in profile.tags:
            if tag.name not in surface_set:
                continue
            lo = tag.min_value if tag.min_value is not None else "?"
            hi = tag.max_value if tag.max_value is not None else "?"
            unit = tag.unit or ""
            cat = tag.category.value if hasattr(tag.category, "value") else str(tag.category)
            lines.append(
                f"  {tag.name:<30s}  range: {lo} -- {hi} {unit:<6s}  category: {cat}"
            )

        return "\n".join(lines) if lines else "  (no writable tags found on attack surface)"

    @staticmethod
    def _snapshot_to_str(snapshot: Optional[PlantSnapshot]) -> str:
        """Serialise a PlantSnapshot to a compact JSON string for the prompt."""
        if snapshot is None:
            return "{}"
        data: Dict[str, Any] = {"step": snapshot.step_id}
        # Only include non-empty sections to minimise prompt token usage
        if snapshot.sensors:
            data["sensors"] = snapshot.sensors
        if snapshot.actuators:
            data["actuators"] = snapshot.actuators
        if snapshot.setpoints:
            data["setpoints"] = snapshot.setpoints
        if snapshot.alarms:
            data["alarms"] = {k: v for k, v in snapshot.alarms.items() if v}
        # Omit derived_features to save tokens (rarely needed for LLM reasoning)
        return json.dumps(data, separators=(",", ":"), default=str)

    @staticmethod
    def _prior_actions_to_str(actions: Optional[List[AttackAction]]) -> str:
        if not actions:
            return "[]"
        items = [
            {
                "attack_type": a.attack_type.value,
                "target": a.target,
                "value": a.value,
                "approved": a.approved_by_shield,
                "status": a.execution_status.value if a.execution_status else "unknown",
                "rationale": a.rationale,
            }
            for a in actions
        ]
        return json.dumps(items, indent=2)

    @staticmethod
    def _render(template: str, context: Dict[str, Any]) -> str:
        """
        Render a template string with format_map, silently filling missing keys
        with an empty string.
        """
        class _DefaultDict(dict):
            def __missing__(self, key: str) -> str:
                return ""

        return template.format_map(_DefaultDict(context))

    def build_correction_prompt(
        self,
        validation_error: Any,
        scene: object = None,
    ) -> str:
        """
        Build a context-aware correction prompt after a schema validation failure.

        Extracts the writable attack-surface tag names from *scene* so the
        correction message can list legal targets for the LLM to choose from.

        Parameters
        ----------
        validation_error:
            A :class:`~cpsforge.llm.schema_validator.ValidationError` instance
            raised during action parsing.
        scene:
            Active scene object (provides a ``profile`` attribute with
            ``attack_surface`` list).  May be None.

        Returns
        -------
        str
            A correction prompt ready to be sent as the next user turn.
        """
        profile: Optional[SceneProfile] = getattr(scene, "profile", None) if scene else None
        attack_surface: List[str] = (
            list(profile.attack_surface)
            if (profile is not None and profile.attack_surface)
            else []
        )
        return validation_error.correction_prompt(attack_surface=attack_surface)

    # ------------------------------------------------------------------
    # Agent-mode prompt assembly
    # ------------------------------------------------------------------

    def build_attacker_agent_system_prompt(
        self,
        scene: object,
    ) -> str:
        """Render the system prompt for the live attacker agent."""
        profile: Optional[SceneProfile] = getattr(scene, "profile", None)
        context = self._build_scene_context(profile, max_actions=1)
        return self._render(self._attacker_agent_system, context)

    def build_attacker_agent_user_prompt(
        self,
        snapshot: Optional[PlantSnapshot],
        prior_actions: Optional[List[Dict[str, Any]]] = None,
        attacker_objective: str = "",
        notes: str = "",
        attack_surface: str = "",
    ) -> str:
        """Render the per-cycle user prompt for the live attacker agent."""
        step_id = snapshot.step_id if snapshot else 0
        scene_state = self._snapshot_to_str(snapshot)
        prior_str = json.dumps(prior_actions or [], indent=2, default=str)

        parts = []
        if attacker_objective:
            parts.append(f"Attacker objective: {attacker_objective}")
        if notes:
            parts.append(notes)

        context: Dict[str, Any] = {
            "step_id": step_id,
            "scene_state": scene_state,
            "prior_actions": prior_str,
            "attacker_objective": attacker_objective,
            "notes": "\n".join(parts),
            "attack_surface": attack_surface or "(see system prompt)",
        }
        return self._render(self._attacker_agent_user, context)

    def build_defender_agent_system_prompt(
        self,
        scene: object,
    ) -> str:
        """Render the system prompt for the live defender agent."""
        profile: Optional[SceneProfile] = getattr(scene, "profile", None)
        context = self._build_scene_context(profile, max_actions=1)
        return self._render(self._defender_agent_system, context)

    def build_defender_agent_user_prompt(
        self,
        snapshot: Optional[PlantSnapshot],
        detector_alerts: Optional[List[str]] = None,
        prior_detections: Optional[List[Dict[str, Any]]] = None,
        notes: str = "",
    ) -> str:
        """Render the per-cycle user prompt for the live defender agent."""
        step_id = snapshot.step_id if snapshot else 0
        scene_state = self._snapshot_to_str(snapshot)

        context: Dict[str, Any] = {
            "step_id": step_id,
            "scene_state": scene_state,
            "detector_alerts": json.dumps(detector_alerts or [], indent=2),
            "prior_detections": json.dumps(prior_detections or [], indent=2, default=str),
            "notes": notes,
        }
        return self._render(self._defender_agent_user, context)
