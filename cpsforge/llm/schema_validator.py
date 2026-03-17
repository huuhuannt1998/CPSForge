"""
CPSForge LLM Schema Validator
================================
Parses and validates the raw JSON text produced by an LLM provider and
converts it into a list of validated :class:`AttackAction` objects.

Safety rules enforced here (not in the shield -- the shield provides a
second independent layer):

1. The LLM output must be valid JSON.
2. The JSON must be a list of action objects (or a single object, which is
   wrapped in a list for convenience).
3. Each action object must contain the required keys.
4. ``attack_type`` must be a valid :class:`AttackType` enum value.
5. ``target`` must be a *tag name*, not a raw PLC address.  A tag name
   passes the check if it appears in the scene's ``attack_surface`` list.
   Raw S7 address patterns (e.g. "DB1,REAL4", "MW10", "QW0") are
   explicitly rejected even if the scene check is skipped.
6. ``value`` must be a finite number (no strings, no PLC encoding).
7. ``confidence`` must be in [0, 1].

Retry guidance is returned via :exc:`ValidationError` so the attacker can
send a corrective follow-up prompt to the LLM.
"""

from __future__ import annotations

import json
import logging
import math
import re
from typing import Any, Dict, List, Optional

from cpsforge.core.models import AttackAction, AttackSource, AttackType

logger = logging.getLogger(__name__)

# Regex patterns that identify raw Siemens S7 memory addresses.
# If a target matches any of these, it is rejected unconditionally.
_S7_ADDRESS_PATTERNS = [
    re.compile(r"^DB\d+[,.]", re.IGNORECASE),      # DB1,REAL4 / DB1.DBD4
    re.compile(r"^[IMQ][BWDX]\d+", re.IGNORECASE), # IB0, MW10, QW0, QX0.0
    re.compile(r"^[IMQ]\d+\.\d+", re.IGNORECASE),   # I0.0, M1.2, Q2.3
    re.compile(r"^[IMQ]\d+$", re.IGNORECASE),        # I0, M10, Q5
]

_REQUIRED_KEYS = {"attack_type", "target"}
_OPTIONAL_DEFAULTS = {
    "mode": "override",
    "value": None,
    "duration_ms": 5000,
    "rationale": "",
    "expected_effect": "",
    "confidence": 0.5,
}

# Attack mode values accepted without error; unrecognised modes default to "override"
_VALID_MODES = {"override", "offset", "freeze", "replay", "noise"}

# Hard cap on single-action duration; values exceeding this are clamped, not rejected
_MAX_DURATION_MS = 120_000  # 2 minutes

# --- Key and value normalization for smaller LLMs ---
# Maps common alternative key names to our canonical keys
_KEY_ALIASES: Dict[str, str] = {
    "target_sensor": "target",
    "target_tag": "target",
    "sensor": "target",
    "actuator": "target",
    "tag": "target",
    "tag_name": "target",
    "new_value": "value",
    "set_value": "value",
    "override_value": "value",
    "reasoning": "rationale",
    "reason": "rationale",
    "explanation": "rationale",
    "expected_outcome": "expected_effect",
    "impact": "expected_effect",
    "duration": "duration_ms",
    "timeout_ms": "duration_ms",
}

# Maps common alternative attack_type names to valid AttackType enum values
_ATTACK_TYPE_ALIASES: Dict[str, str] = {
    "alter_sensor_reading": "sensor_spoof",
    "sensor_override": "sensor_spoof",
    "spoof_sensor": "sensor_spoof",
    "spoof": "sensor_spoof",
    "override_actuator": "actuator_override",
    "actuator_control": "actuator_override",
    "override": "actuator_override",
    "shift_setpoint": "setpoint_shift",
    "modify_setpoint": "setpoint_shift",
    "change_setpoint": "setpoint_shift",
    "delay": "timing_delay",
    "add_delay": "timing_delay",
    "perturb_sequence": "sequence_perturbation",
    "sequence_attack": "sequence_perturbation",
}


def _normalize_keys(item: Dict[str, Any]) -> Dict[str, Any]:
    """Map alternative key names to canonical keys expected by the schema.

    Also handles nested structures like ``{"attack_action": {"sensor": {"water_level": 95}}}``
    which some smaller LLMs produce.
    """
    # Unwrap common nested wrappers
    for wrapper_key in ("attack_action", "action", "attack"):
        if wrapper_key in item and isinstance(item[wrapper_key], dict):
            inner = item.pop(wrapper_key)
            # Merge inner keys into outer (outer takes precedence)
            for k, v in inner.items():
                if k not in item:
                    item[k] = v

    out: Dict[str, Any] = {}
    for k, v in item.items():
        canonical = _KEY_ALIASES.get(k, k)
        # Don't overwrite an existing canonical key
        if canonical not in out:
            out[canonical] = v
    # Normalize attack_type value aliases
    if "attack_type" in out:
        raw = str(out["attack_type"]).lower().strip()
        out["attack_type"] = _ATTACK_TYPE_ALIASES.get(raw, raw)

    # Infer attack_type from context if missing but target is present
    if "attack_type" not in out and "target" in out:
        out["attack_type"] = "sensor_spoof"  # safe default

    return out


class ValidationError(ValueError):
    """
    Raised when the LLM output does not conform to the expected schema.

    The ``message`` attribute is designed to be used verbatim as a
    corrective instruction in a follow-up LLM prompt.
    """

    def __init__(self, message: str, raw_text: str = "", partial_index: int = -1) -> None:
        super().__init__(message)
        self.message = message
        self.raw_text = raw_text
        self.partial_index = partial_index  # index of the failing action (-1 = global)

    def correction_prompt(self, attack_surface: Optional[List[str]] = None) -> str:
        """
        Return a repair instruction suitable for a follow-up LLM prompt.

        Parameters
        ----------
        attack_surface:
            When provided, the correction prompt lists the permitted tag names
            explicitly so the model can self-correct a wrong-target error.
        """
        if attack_surface:
            surface_lines = "\n".join(f"    - {t}" for t in sorted(attack_surface))
            surface_hint = (
                f"Permitted targets (tag names from the scene attack surface):\n"
                f"{surface_lines}"
            )
        else:
            surface_hint = (
                "Target must be a symbolic tag name from the scene's attack surface "
                "(NOT a raw PLC address like DB1,REAL4 or MW10)."
            )

        example = (
            '[\n'
            '  {\n'
            '    "attack_type": "actuator_override",\n'
            '    "target": "<tag name from the list above>",\n'
            '    "value": 10.0,\n'
            '    "duration_ms": 8000,\n'
            '    "rationale": "brief explanation",\n'
            '    "expected_effect": "expected physical impact",\n'
            '    "confidence": 0.8\n'
            '  }\n'
            ']'
        )

        return (
            "Your previous response did not conform to the required JSON schema.\n\n"
            f"Error: {self.message}\n\n"
            "REQUIREMENTS:\n"
            "1. Respond with ONLY a raw JSON array -- no markdown fences (```), "
            "no explanatory text.\n"
            "2. Start your response with '[' and end with ']'.\n"
            "3. Each object must have: attack_type, target, value, duration_ms, "
            "rationale, expected_effect, confidence.\n"
            "4. attack_type must be one of: "
            + ", ".join(t.value for t in AttackType)
            + ".\n"
            "5. value must be a numeric literal (e.g. 45.0), NOT a string.\n"
            "6. duration_ms must be an integer (0 – 120000).\n"
            "7. confidence must be a float between 0.0 and 1.0.\n\n"
            + surface_hint
            + "\n\nExample of a valid response:\n"
            + example
        )


def _is_raw_s7_address(target: str) -> bool:
    """Return True if *target* looks like a raw S7 memory address."""
    return any(pat.search(target) for pat in _S7_ADDRESS_PATTERNS)


def _repair_trailing_commas(text: str) -> str:
    """Remove trailing commas before closing braces and brackets (common LLM error)."""
    return re.sub(r",\s*([}\]])", r"\1", text)


def _repair_truncated_values(text: str) -> str:
    """Fix common LLM output errors: truncated numbers, garbage after values.

    Examples fixed:
    - ``"confidence":0ayer`` → ``"confidence":0``
    - ``"confidence":0.9}extra text`` → ``"confidence":0.9}``
    """
    # Fix numbers followed by non-JSON chars: digits then letters before , or }
    text = re.sub(r':\s*(\d+(?:\.\d+)?)\s*[a-zA-Z_][a-zA-Z0-9_ ]*([,}])', r': \1\2', text)
    return text


def _find_outermost(text: str, open_ch: str, close_ch: str) -> Optional[str]:
    """
    Find the outermost delimited substring using depth counting.

    More robust than a greedy regex: correctly handles nested structures.
    Returns the matched substring, or None if not found.
    """
    start = text.find(open_ch)
    if start == -1:
        return None
    depth = 0
    for i, ch in enumerate(text[start:], start):
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _try_loads(text: str) -> Optional[Any]:
    """
    Try ``json.loads`` on *text*, then with increasing repair.

    Returns the parsed object on success, or None without raising.
    """
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        return json.loads(_repair_trailing_commas(text))
    except json.JSONDecodeError:
        pass
    try:
        return json.loads(_repair_truncated_values(_repair_trailing_commas(text)))
    except json.JSONDecodeError:
        return None


def _parse_json_from_text(text: str) -> Any:
    """
    Extract and parse JSON from LLM output that may contain surrounding prose.

    Attempts in priority order:

    1. Strip markdown code fences (``\`\`\`json...\`\`\`` or ``\`\`\`...\`\`\``),
       then parse (with and without trailing-comma repair).
    2. Direct parse of the full text.
    3. Depth-count to find the outermost ``[...]`` and parse.
    4. Depth-count to find the outermost ``{...}`` and wrap in a list.

    Each attempt includes trailing-comma repair so minor formatting errors
    produced by LLMs are handled gracefully.

    Raises
    ------
    ValidationError
        If no valid JSON can be extracted after all attempts.
    """
    text = text.strip()

    # -- Step 1: strip markdown code fences (very common LLM mistake) ----------
    fence_match = re.search(
        r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL | re.IGNORECASE
    )
    if fence_match:
        candidate = fence_match.group(1).strip()
        result = _try_loads(candidate)
        if result is not None:
            return result

    # -- Step 2: direct parse of full text ------------------------------------
    result = _try_loads(text)
    if result is not None:
        return result

    # -- Step 3: outermost [...] by depth counting ----------------------------
    array_str = _find_outermost(text, "[", "]")
    if array_str:
        result = _try_loads(array_str)
        if result is not None:
            return result

    # -- Step 4: outermost {...} wrapped in a list ----------------------------
    obj_str = _find_outermost(text, "{", "}")
    if obj_str:
        result = _try_loads(obj_str)
        if result is not None:
            return [result]

    raise ValidationError(
        "Could not parse valid JSON from the model response.\n"
        "Ensure the output is a raw JSON array (starting with '[' and ending with ']').\n"
        "Do NOT wrap the JSON in markdown fences (```json ... ```) or add explanatory text.\n"
        f"Received (first 300 chars): {text[:300]}",
        raw_text=text,
    )


class ActionSchemaValidator:
    """
    Validates raw LLM JSON output and converts it to :class:`AttackAction` objects.

    Parameters
    ----------
    attack_surface:
        Optional list of tag names the LLM is permitted to target.
        When provided, any ``target`` not in this list is rejected.
        When None, only the raw S7 address pattern check is applied.
    source:
        :class:`AttackSource` to stamp on created actions (default: LLM).
    """

    def __init__(
        self,
        attack_surface: Optional[List[str]] = None,
        source: AttackSource = AttackSource.LLM,
    ) -> None:
        self._attack_surface = set(attack_surface) if attack_surface else None
        self._source = source

    def parse_and_validate(
        self, raw_text: str, scene: Optional[object] = None
    ) -> List[AttackAction]:
        """
        Parse *raw_text* and return a list of validated :class:`AttackAction`.

        Parameters
        ----------
        raw_text:
            Raw string output from an LLM completion call.
        scene:
            Optional :class:`BaseScene` whose ``attack_surface`` overrides
            the instance-level surface if provided.

        Returns
        -------
        List[AttackAction]
            Validated actions stamped with ``source=LLM``.

        Raises
        ------
        ValidationError
            On JSON parse failure or schema violation.
        """
        # Resolve attack surface: scene wins if available
        attack_surface: Optional[set] = self._attack_surface
        if scene is not None:
            surface_list = getattr(
                getattr(scene, "profile", None), "attack_surface", None
            )
            if surface_list:
                attack_surface = set(surface_list)

        data = _parse_json_from_text(raw_text)

        # Normalise to a list
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            raise ValidationError(
                f"Expected a JSON array of actions, got {type(data).__name__}.",
                raw_text=raw_text,
            )
        if len(data) == 0:
            raise ValidationError(
                "JSON array is empty -- at least one action is required.",
                raw_text=raw_text,
            )

        actions: List[AttackAction] = []
        parse_errors: List[ValidationError] = []

        for i, item in enumerate(data):
            try:
                action = self._validate_single(item, i, attack_surface, raw_text)
                actions.append(action)
            except ValidationError as exc:
                parse_errors.append(exc)
                logger.warning(
                    "LLM output: skipping action[%d] -- %s", i, exc.message
                )

        if not actions:
            # All items failed -- surface the first (most informative) error
            raise parse_errors[0]

        if parse_errors:
            logger.info(
                "Partial parse: %d/%d action(s) accepted, %d rejected by schema.",
                len(actions),
                len(data),
                len(parse_errors),
            )

        return actions

    # ------------------------------------------------------------------
    # Internal validation
    # ------------------------------------------------------------------

    def _validate_single(
        self,
        item: Any,
        index: int,
        attack_surface: Optional[set],
        raw_text: str,
    ) -> AttackAction:
        if not isinstance(item, dict):
            raise ValidationError(
                f"Action[{index}] is not a JSON object (got {type(item).__name__}).",
                raw_text=raw_text,
                partial_index=index,
            )

        # --- Normalise common alternative keys from smaller LLMs ---
        item = _normalize_keys(item)

        # Check required keys
        missing = _REQUIRED_KEYS - item.keys()
        if missing:
            raise ValidationError(
                f"Action[{index}] is missing required keys: {sorted(missing)}.",
                raw_text=raw_text,
                partial_index=index,
            )

        # --- attack_type ---
        raw_type = item.get("attack_type", "")
        try:
            attack_type = AttackType(str(raw_type).lower())
        except ValueError:
            valid = [t.value for t in AttackType]
            raise ValidationError(
                f"Action[{index}].attack_type '{raw_type}' is not valid. "
                f"Must be one of: {valid}.",
                raw_text=raw_text,
                partial_index=index,
            )

        # --- target: reject raw S7 addresses immediately ---
        target = str(item.get("target", "")).strip()
        if not target:
            raise ValidationError(
                f"Action[{index}].target is empty.",
                raw_text=raw_text,
                partial_index=index,
            )
        if _is_raw_s7_address(target):
            raise ValidationError(
                f"Action[{index}].target '{target}' looks like a raw PLC memory "
                "address. Use the tag name from the attack surface instead "
                "(e.g. 'pump_speed', not 'DB1,REAL4').",
                raw_text=raw_text,
                partial_index=index,
            )
        # Check against known attack surface
        if attack_surface is not None and target not in attack_surface:
            raise ValidationError(
                f"Action[{index}].target '{target}' is not in the scene's attack "
                f"surface. Permitted targets: {sorted(attack_surface)}.",
                raw_text=raw_text,
                partial_index=index,
            )

        # --- value: must be a finite number ---
        raw_value = item.get("value", _OPTIONAL_DEFAULTS["value"])
        if raw_value is not None:
            if isinstance(raw_value, str):
                # Reject any string value -- could be a PLC address
                raise ValidationError(
                    f"Action[{index}].value is a string '{raw_value}'. "
                    "Value must be a numeric literal.",
                    raw_text=raw_text,
                    partial_index=index,
                )
            try:
                v_float = float(raw_value)
            except (TypeError, ValueError) as exc:
                raise ValidationError(
                    f"Action[{index}].value cannot be converted to float: {raw_value}.",
                    raw_text=raw_text,
                    partial_index=index,
                ) from exc
            if not math.isfinite(v_float):
                raise ValidationError(
                    f"Action[{index}].value must be finite, got {raw_value}.",
                    raw_text=raw_text,
                    partial_index=index,
                )
            value: Optional[float] = v_float
        else:
            value = None

        # --- duration_ms ---
        raw_dur = item.get("duration_ms", _OPTIONAL_DEFAULTS["duration_ms"])
        try:
            duration_ms = int(raw_dur)
        except (TypeError, ValueError) as exc:
            raise ValidationError(
                f"Action[{index}].duration_ms is not an integer: {raw_dur}.",
                raw_text=raw_text,
                partial_index=index,
            ) from exc
        if duration_ms < 0:
            raise ValidationError(
                f"Action[{index}].duration_ms must be >= 0, got {duration_ms}.",
                raw_text=raw_text,
                partial_index=index,
            )
        if duration_ms > _MAX_DURATION_MS:
            logger.debug(
                "Action[%d].duration_ms %d exceeds cap %d -- clamping.",
                index,
                duration_ms,
                _MAX_DURATION_MS,
            )
            duration_ms = _MAX_DURATION_MS

        # --- mode: lenient -- unrecognised values default to "override" ------
        raw_mode = str(item.get("mode", _OPTIONAL_DEFAULTS["mode"])).strip().lower()
        if raw_mode not in _VALID_MODES:
            logger.debug(
                "Action[%d].mode '%s' is not recognised; defaulting to 'override'.",
                index,
                raw_mode,
            )
            raw_mode = "override"

        # --- confidence ---
        raw_conf = item.get("confidence", _OPTIONAL_DEFAULTS["confidence"])
        try:
            confidence = float(raw_conf)
        except (TypeError, ValueError):
            confidence = 0.5
        confidence = max(0.0, min(1.0, confidence))

        return AttackAction(
            attack_type=attack_type,
            target=target,
            mode=raw_mode,
            value=value,
            duration_ms=duration_ms,
            rationale=str(item.get("rationale", "")),
            expected_effect=str(item.get("expected_effect", "")),
            confidence=confidence,
            source=self._source,
        )
