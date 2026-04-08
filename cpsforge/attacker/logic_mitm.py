"""
logic_mitm.py — Logic-level MITM attacker via TIA Portal Openness.

LogicMITMAttacker uses the LLM to analyze PLC control logic (SCL source),
generate adversarial modifications, and deploy them to the PLC through
TIA Portal Openness.  This models an attacker with engineering workstation
access — the Stuxnet-class threat model.

Unlike the online MITM (Tier 1) which writes I/O values each scan cycle,
the logic attacker modifies the PLC PROGRAM ITSELF.  A single successful
modification persists indefinitely until the code is restored.

Three context tiers control how much the LLM knows:
  - MINIMAL: SCL source only, no tag semantics or process description
  - PARTIAL: SCL + tag descriptions + process summary
  - FULL:    SCL + tags + process + live state + phase + vulnerabilities

Pipeline per attack attempt:
  1. Load original SCL source
  2. Build context at configured tier
  3. LLM generates LogicModification proposal
  4. Validate: original_code exists in source (exact match)
  5. Apply modification (string replacement)
  6. Deploy via TIA Openness (import → compile)
  7. If compilation fails, log and revert
  8. Record result

This is NOT a polling-loop attacker — it makes ONE modification per run,
then the runner observes the physical effect over time.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cpsforge.attacker.logic_analyzer import LogicModification, _parse_json_response
from cpsforge.context_builder.schema import ContextLevel
from cpsforge.core.models import PlantSnapshot
from cpsforge.llm.base_provider import BaseLLMProvider
from cpsforge.observation.history_buffer import HistoryBuffer
from cpsforge.observation.phase_inference import PhaseInferenceEngine
from cpsforge.scenes.base import BaseScene

logger = logging.getLogger(__name__)

# SCL file name mapping
_SCL_NAMES: Dict[str, str] = {
    "level_control": "FB_LevelControl.scl",
    "sorting_weight": "FB_SortingWeight.scl",
    "sorting_height_basic": "FB_SortingHeightBasic.scl",
    "sorting_height_advanced": "FB_SortingHeightAdvanced.scl",
    "filling_tank": "FB_FillingTank.scl",
    "assembler": "FB_Assembler.scl",
    "production_line": "FB_ProductionLine.scl",
}

_BLOCK_NAMES: Dict[str, str] = {
    "level_control": "FB_LevelControl",
    "sorting_weight": "FB_SortingWeight",
    "sorting_height_basic": "FB_SortingHeightBasic",
    "sorting_height_advanced": "FB_SortingHeightAdvanced",
    "filling_tank": "FB_FillingTank",
    "assembler": "FB_Assembler",
    "production_line": "FB_ProductionLine",
}

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "context_builder" / "templates"


# ---------------------------------------------------------------------------
# Logic modification decision (LLM output schema)
# ---------------------------------------------------------------------------

LOGIC_DECISION_JSON_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "decision": {"type": "string", "enum": ["modify", "skip"]},
        "target_block": {"type": "string"},
        "modification_type": {
            "type": "string",
            "enum": [
                "comparison_inversion",
                "sensor_clamping",
                "interlock_removal",
                "gradual_drift",
                "dead_code_injection",
                "timer_alteration",
                "state_shortcut",
            ],
        },
        "vulnerability_description": {"type": "string"},
        "original_code": {"type": "string"},
        "modified_code": {"type": "string"},
        "expected_effect": {"type": "string"},
        "stealth_assessment": {"type": "string"},
        "detection_difficulty": {"type": "number"},
        "requires_restart": {"type": "boolean"},
        "confidence": {"type": "number"},
        "reasoning": {"type": "string"},
    },
    "required": ["decision", "original_code", "modified_code"],
}


@dataclass
class LogicAttackResult:
    """Result of one logic-level attack attempt."""
    success: bool
    modification: Optional[LogicModification] = None
    compilation_ok: bool = False
    compilation_message: str = ""
    original_code_matched: bool = False
    scl_deployed: bool = False
    llm_latency_ms: float = 0.0
    parse_success: bool = False
    error: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "modification": self.modification.as_dict() if self.modification else None,
            "compilation_ok": self.compilation_ok,
            "compilation_message": self.compilation_message,
            "original_code_matched": self.original_code_matched,
            "scl_deployed": self.scl_deployed,
            "llm_latency_ms": self.llm_latency_ms,
            "parse_success": self.parse_success,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# LogicMITMAttacker
# ---------------------------------------------------------------------------

class LogicMITMAttacker:
    """Logic-level attacker: LLM generates SCL modifications, deploys via TIA Openness.

    Parameters
    ----------
    scene : BaseScene
        Active Factory I/O scene.
    llm_provider : BaseLLMProvider
        LLM for code analysis and modification generation.
    context_level : ContextLevel
        MINIMAL | PARTIAL | FULL — controls what context the LLM receives.
    history : HistoryBuffer
        Rolling window for live state (used in FULL context).
    phase_engine : PhaseInferenceEngine
        Phase inference (used in FULL context).
    scl_dir : Path
        Directory containing original SCL files.
    max_retries : int
        JSON parse retries per LLM call.
    llm_timeout_s : float
        Per-call LLM timeout.
    """

    def __init__(
        self,
        scene: BaseScene,
        llm_provider: BaseLLMProvider,
        context_level: ContextLevel,
        history: HistoryBuffer,
        phase_engine: PhaseInferenceEngine,
        scl_dir: Optional[Path] = None,
        max_retries: int = 2,
        llm_timeout_s: float = 120.0,
    ) -> None:
        self._scene = scene
        self._provider = llm_provider
        self._context_level = context_level
        self._history = history
        self._phase_engine = phase_engine
        self._scl_dir = scl_dir or Path("factoryio_scenes")
        self._max_retries = max_retries
        self._timeout_s = llm_timeout_s
        self._templates = self._load_templates()

    # ------------------------------------------------------------------
    # Primary API
    # ------------------------------------------------------------------

    def generate_attack(
        self,
        snapshot: Optional[PlantSnapshot] = None,
    ) -> LogicAttackResult:
        """Generate an adversarial SCL modification using the LLM.

        Parameters
        ----------
        snapshot : PlantSnapshot, optional
            Current PLC state (used for FULL context tier).

        Returns
        -------
        LogicAttackResult with the modification proposal and validation status.
        """
        scene_name = self._scene.profile.scene_name
        scl_source = self._load_scl(scene_name)
        if not scl_source:
            return LogicAttackResult(
                success=False,
                error=f"No SCL source found for scene '{scene_name}'",
            )

        # Build prompts from template
        system_prompt, user_prompt = self._build_prompts(
            scene_name=scene_name,
            scl_source=scl_source,
            snapshot=snapshot,
        )

        # Call LLM
        raw_output = ""
        latency_ms = 0.0
        for attempt in range(self._max_retries + 1):
            try:
                t0 = time.monotonic()
                result = self._provider.complete(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_format={"type": "json_object"},
                )
                latency_ms = (time.monotonic() - t0) * 1000.0
                raw_output = result.text

                data = _parse_json_response(raw_output)

                if data.get("decision") == "skip":
                    return LogicAttackResult(
                        success=False,
                        llm_latency_ms=latency_ms,
                        parse_success=True,
                        error="LLM chose to skip (no modification).",
                    )

                # Build LogicModification
                mod = LogicModification(
                    target_block=str(data.get("target_block", _BLOCK_NAMES.get(scene_name, ""))),
                    modification_type=str(data.get("modification_type", "unknown")),
                    vulnerability_description=str(data.get("vulnerability_description", "")),
                    original_code=str(data.get("original_code", "")),
                    modified_code=str(data.get("modified_code", "")),
                    expected_effect=str(data.get("expected_effect", "")),
                    stealth_assessment=str(data.get("stealth_assessment", "")),
                    detection_difficulty=float(data.get("detection_difficulty", 0.5)),
                    requires_restart=bool(data.get("requires_restart", False)),
                    reasoning=str(data.get("reasoning", "")),
                    compilation_note=str(data.get("compilation_note", "")),
                    raw_output=raw_output,
                    llm_latency_ms=latency_ms,
                    parse_success=True,
                )

                # Validate: does original_code exist in the SCL?
                matched = mod.original_code.strip() in scl_source
                if not matched:
                    # Try with normalized whitespace
                    matched = _normalize_ws(mod.original_code) in _normalize_ws(scl_source)
                if not matched:
                    # Try line-based fuzzy match
                    matched = self._line_based_replace(
                        scl_source, mod.original_code, mod.modified_code,
                    ) is not None
                if not matched:
                    # For injection attacks (sensor_clamping, gradual_drift, dead_code_injection),
                    # the LLM may propose inserting NEW code rather than replacing existing code.
                    # In that case, try to find a suitable anchor point in the source.
                    injection_types = {"sensor_clamping", "gradual_drift", "dead_code_injection"}
                    if mod.modification_type in injection_types:
                        anchor = self._find_injection_anchor(scl_source, mod)
                        if anchor:
                            mod.original_code = anchor
                            matched = True
                            logger.info("Injection anchor found for %s", mod.modification_type)

                if not matched:
                    logger.warning(
                        "original_code matching failed. LLM proposed:\n---\n%s\n---",
                        mod.original_code[:500],
                    )

                return LogicAttackResult(
                    success=matched,
                    modification=mod,
                    original_code_matched=matched,
                    llm_latency_ms=latency_ms,
                    parse_success=True,
                    error="" if matched else "original_code does not match SCL source",
                )

            except Exception as exc:
                logger.warning(
                    "Logic attack generation failed (attempt %d): %s",
                    attempt + 1, exc,
                )
                if attempt < self._max_retries:
                    user_prompt += (
                        "\n\n[Previous response was invalid JSON. "
                        "Return ONLY a valid JSON object with all required fields. "
                        "The original_code field MUST match the exact source code.]"
                    )

        return LogicAttackResult(
            success=False,
            llm_latency_ms=latency_ms,
            parse_success=False,
            error=f"All {self._max_retries + 1} attempts failed. Last output: {raw_output[:200]}",
        )

    def apply_modification(
        self,
        scl_source: str,
        modification: LogicModification,
    ) -> Optional[str]:
        """Apply a LogicModification to the SCL source.

        Returns the modified SCL string, or None if original_code not found.
        Handles both replacement and injection-style modifications.
        """
        original = modification.original_code.strip()
        modified = modification.modified_code.strip()

        # Direct match — standard replacement
        if original in scl_source:
            return scl_source.replace(original, modified, 1)

        # Try normalized whitespace match
        norm_source = _normalize_ws(scl_source)
        norm_original = _normalize_ws(original)
        if norm_original in norm_source:
            result = self._line_based_replace(scl_source, original, modified)
            if result:
                return result

        # Line-based fuzzy match
        result = self._line_based_replace(scl_source, original, modified)
        if result:
            return result

        # Injection-style: if original is a single line anchor,
        # prepend modified code before the anchor
        injection_types = {"sensor_clamping", "gradual_drift", "dead_code_injection"}
        if modification.modification_type in injection_types:
            # Check if original is a single line that exists in source
            orig_stripped = original.strip()
            for i, line in enumerate(scl_source.splitlines()):
                if line.strip() == orig_stripped:
                    lines = scl_source.splitlines()
                    indent = len(line) - len(line.lstrip())
                    indent_str = line[:indent]
                    injection_lines = []
                    for ml in modified.splitlines():
                        if ml.strip():
                            injection_lines.append(indent_str + ml.strip())
                        else:
                            injection_lines.append("")
                    # Insert modified code, keeping the original anchor line
                    lines[i:i+1] = injection_lines
                    return "\n".join(lines)

        return None

    def get_scl_source(self, scene_name: Optional[str] = None) -> Optional[str]:
        """Load the original SCL source for the scene."""
        return self._load_scl(scene_name or self._scene.profile.scene_name)

    # ------------------------------------------------------------------
    # Context building
    # ------------------------------------------------------------------

    def _build_prompts(
        self,
        scene_name: str,
        scl_source: str,
        snapshot: Optional[PlantSnapshot] = None,
    ) -> Tuple[str, str]:
        """Build (system_prompt, user_prompt) for the configured context level."""
        level = self._context_level
        template_key = f"logic_{level.value}"
        tpl = self._templates.get(template_key, "")

        if not tpl:
            logger.warning("No template for %s; using minimal", template_key)
            tpl = self._templates.get("logic_minimal", "")

        fmt = self._build_format_map(scene_name, scl_source, snapshot)

        if "===USER===" in tpl:
            sys_part, usr_part = tpl.split("===USER===", 1)
        else:
            sys_part = tpl
            usr_part = ""

        try:
            system = sys_part.strip().format_map(fmt)
            user = usr_part.strip().format_map(fmt)
        except KeyError as exc:
            logger.error("Template placeholder %s not found", exc)
            system = f"You are a CPS security researcher. Modify the SCL for '{scene_name}'."
            user = f"```scl\n{scl_source}\n```\nGenerate adversarial modification as JSON."

        return system, user

    def _build_format_map(
        self,
        scene_name: str,
        scl_source: str,
        snapshot: Optional[PlantSnapshot] = None,
    ) -> Dict[str, str]:
        """Build template substitution map."""
        profile = self._scene.profile
        block_name = _BLOCK_NAMES.get(scene_name, f"FB_{scene_name}")

        m: Dict[str, str] = {
            "scene_name": scene_name,
            "target_block": block_name,
            "scl_source": scl_source,
        }

        # Partial + Full: tag table, scene description
        if self._context_level in (ContextLevel.PARTIAL, ContextLevel.FULL):
            attack_tags = set(profile.attack_surface)
            key_sensors = set(getattr(profile, "key_sensors", None) or [])
            rows = []
            for tag in profile.tags:
                if tag.name not in attack_tags and tag.name not in key_sensors:
                    continue
                rng = ""
                if tag.min_value is not None and tag.max_value is not None:
                    rng = f"[{tag.min_value}, {tag.max_value}]"
                unit = tag.unit or ""
                rows.append(f"  {tag.name:<28} {tag.category.value:<12} {unit:<8} {rng:<20} {tag.description or ''}")
            m["tag_table"] = "\n".join(rows) or "(no tags)"
            m["scene_description"] = profile.description or "(no description)"

        # Full: live state, phase, control objective, shield rules, vulnerabilities
        if self._context_level == ContextLevel.FULL:
            m["control_objective"] = (
                getattr(profile, "control_objective", None) or "(not provided)"
            )
            m["shield_rules"] = self._build_shield_summary()
            m["known_vulnerabilities"] = self._build_vulnerability_hints(scene_name)

            if snapshot:
                values = {}
                for cat in (snapshot.sensors, snapshot.actuators, snapshot.setpoints,
                            snapshot.controller_state, snapshot.alarms):
                    values.update(cat)
                m["current_values"] = json.dumps(values, indent=2)

                phase_result = self._phase_engine.infer(
                    snapshot, self._history.window(10)
                )
                m["inferred_phase"] = phase_result.phase.value
                m["phase_confidence"] = f"{int(phase_result.confidence * 100)}%"
            else:
                m["current_values"] = "(not available — offline analysis)"
                m["inferred_phase"] = "unknown"
                m["phase_confidence"] = "0%"

        return m

    def _build_shield_summary(self) -> str:
        rules = self._scene.profile.safety_rules
        if not rules:
            return "No explicit safety rules configured."
        lines = []
        for rule in rules:
            if rule.enabled:
                lines.append(f"- [{rule.rule_id}] {rule.description}")
        return "\n".join(lines) if lines else "No enabled safety rules."

    def _build_vulnerability_hints(self, scene_name: str) -> str:
        hints = _VULN_HINTS.get(scene_name)
        if not hints:
            return "No known vulnerabilities documented."
        return "\n".join(f"- {h}" for h in hints)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _load_scl(self, scene_name: str) -> Optional[str]:
        filename = _SCL_NAMES.get(scene_name)
        if not filename:
            return None
        path = self._scl_dir / filename
        if not path.exists():
            logger.error("SCL file not found: %s", path)
            return None
        return path.read_text(encoding="utf-8")

    def _load_templates(self) -> Dict[str, str]:
        templates: Dict[str, str] = {}
        for level in ("minimal", "partial", "full"):
            key = f"logic_{level}"
            path = _TEMPLATES_DIR / f"{key}.md"
            if path.exists():
                templates[key] = path.read_text(encoding="utf-8")
            else:
                logger.debug("Template not found: %s", path)
        return templates

    def _line_based_replace(
        self,
        source: str,
        original: str,
        replacement: str,
    ) -> Optional[str]:
        """Try to match original code by line content (ignoring whitespace and comments).

        The LLM often omits SCL comments (// ...) present in the real source.
        This matcher skips comment-only lines when finding the match region,
        then replaces the entire matched region (including comments).
        """
        orig_lines = [l.strip() for l in original.strip().splitlines() if l.strip()]
        source_lines = source.splitlines()

        # First try: exact line-for-line match (no comment skipping)
        for i in range(len(source_lines) - len(orig_lines) + 1):
            match = True
            for j, orig_line in enumerate(orig_lines):
                if source_lines[i + j].strip() != orig_line:
                    match = False
                    break
            if match:
                before = source_lines[:i]
                after = source_lines[i + len(orig_lines):]
                indent = len(source_lines[i]) - len(source_lines[i].lstrip())
                indent_str = source_lines[i][:indent]
                mod_lines = []
                for line in replacement.strip().splitlines():
                    if line.strip():
                        mod_lines.append(indent_str + line.strip())
                    else:
                        mod_lines.append("")
                return "\n".join(before + mod_lines + after)

        # Second try: match skipping comment-only lines in source
        # Build list of (source_idx, stripped_content) for non-comment lines
        def _is_comment(line: str) -> bool:
            s = line.strip()
            return s.startswith("//") or s == ""

        for start in range(len(source_lines)):
            src_idx = start
            matched_count = 0
            matched_range_end = start  # track last matched source line

            for orig_line in orig_lines:
                # Skip comment lines in source
                while src_idx < len(source_lines) and _is_comment(source_lines[src_idx]):
                    src_idx += 1
                if src_idx >= len(source_lines):
                    break
                if source_lines[src_idx].strip() == orig_line:
                    matched_count += 1
                    matched_range_end = src_idx + 1
                    src_idx += 1
                else:
                    break

            if matched_count == len(orig_lines):
                # Replace source_lines[start:matched_range_end] with replacement
                before = source_lines[:start]
                after = source_lines[matched_range_end:]
                indent = len(source_lines[start]) - len(source_lines[start].lstrip())
                indent_str = source_lines[start][:indent]
                mod_lines = []
                for line in replacement.strip().splitlines():
                    if line.strip():
                        mod_lines.append(indent_str + line.strip())
                    else:
                        mod_lines.append("")
                return "\n".join(before + mod_lines + after)

        # Third try: subsequence match — every LLM line exists in order in the source,
        # but the source may have extra lines (comments, clamping, etc.) between them.
        # This handles the case where the LLM "summarizes" the code by omitting lines.
        # Also strips trailing SCL comments (// ...) for comparison.
        def _strip_comment(line: str) -> str:
            """Strip trailing // comment from a code line."""
            # Only strip if not inside a string (simple heuristic: no quotes before //)
            idx = line.find("//")
            if idx >= 0:
                return line[:idx].strip()
            return line.strip()

        for start in range(len(source_lines)):
            src_idx = start
            matched_positions: list[int] = []

            for orig_line in orig_lines:
                while src_idx < len(source_lines):
                    src_stripped = source_lines[src_idx].strip()
                    src_no_comment = _strip_comment(source_lines[src_idx])
                    if src_stripped == orig_line or src_no_comment == orig_line:
                        matched_positions.append(src_idx)
                        src_idx += 1
                        break
                    src_idx += 1
                else:
                    break  # Ran out of source lines

            if len(matched_positions) == len(orig_lines):
                # All LLM lines found in order. Replace the full contiguous region
                # from first match to last match (inclusive).
                region_start = matched_positions[0]
                region_end = matched_positions[-1] + 1
                before = source_lines[:region_start]
                after = source_lines[region_end:]
                indent = len(source_lines[region_start]) - len(source_lines[region_start].lstrip())
                indent_str = source_lines[region_start][:indent]
                mod_lines = []
                for line in replacement.strip().splitlines():
                    if line.strip():
                        mod_lines.append(indent_str + line.strip())
                    else:
                        mod_lines.append("")
                logger.info(
                    "Subsequence match: LLM %d lines → source region [%d:%d] (%d lines)",
                    len(orig_lines), region_start, region_end, region_end - region_start,
                )
                return "\n".join(before + mod_lines + after)

        # Fourth try: token-based matching — the LLM condensed multi-line SCL
        # into fewer lines (e.g. "IF IsTall THEN TransfRight := TRUE ELSE TransfLeft := TRUE;"
        # for what is actually a 6-line IF/ELSE block).  Extract key identifier
        # tokens from original, find the source region that contains all of them
        # in order, and replace that region.
        import re as _re

        def _extract_tokens(code: str) -> list[str]:
            """Extract assignment and conditional tokens from SCL code."""
            tokens = []
            # Find assignment targets: <var> := <value>
            for m in _re.finditer(r'(\w+)\s*:=\s*(\w+[\.\d]*)', code):
                tokens.append((m.group(1), m.group(2)))
            return tokens

        def _extract_tokens_replacement(code: str) -> list[str]:
            """Same for replacement — find what changed."""
            tokens = []
            for m in _re.finditer(r'(\w+)\s*:=\s*(\w+[\.\d]*)', code):
                tokens.append((m.group(1), m.group(2)))
            return tokens

        orig_tokens = _extract_tokens(original)
        repl_tokens = _extract_tokens_replacement(replacement)

        # Extract the IF condition variable from LLM's original code
        # e.g. "IF IsTall THEN ..." → "IsTall"
        _cond_match = _re.search(r'\bIF\s+(?:NOT\s+)?(\w+)\b', original.strip())
        _cond_var = _cond_match.group(1) if _cond_match else None

        if len(orig_tokens) >= 2 and len(repl_tokens) >= 2:
            # Find the source IF block that:
            # 1) Has the same condition variable as the LLM's code
            # 2) Contains ALL the original assignment tokens (var+value)

            # Build set of unique (var, value) pairs from original
            orig_assign_set = set(orig_tokens)

            # Find IF/ELSE/END_IF block boundaries containing these assignments
            for start in range(len(source_lines)):
                line_s = source_lines[start].strip()
                # Look for the IF keyword that starts this block
                if not (line_s.startswith("IF ") or line_s.startswith("ELSIF ")):
                    continue

                # Check condition variable matches LLM's target
                if _cond_var:
                    src_cond_match = _re.search(r'\bIF\s+(?:NOT\s+)?(\w+)\b', line_s)
                    if src_cond_match and src_cond_match.group(1) != _cond_var:
                        continue  # Wrong IF block — different condition variable

                # Scan the block to find END_IF and check ALL assignments
                found_assigns = set()
                end_idx = start
                for j in range(start, min(start + 20, len(source_lines))):
                    src_s = _strip_comment(source_lines[j])
                    # Check each original assignment token
                    for var, val in orig_assign_set:
                        if var in src_s and ":=" in src_s and val in src_s:
                            found_assigns.add((var, val))
                    if "END_IF" in src_s:
                        end_idx = j
                        break

                if found_assigns == orig_assign_set:
                    region_start = start
                    region_end = end_idx + 1
                    before = source_lines[:region_start]
                    after = source_lines[region_end:]
                    indent = len(source_lines[region_start]) - len(source_lines[region_start].lstrip())
                    indent_str = source_lines[region_start][:indent]

                    # Build replacement: re-expand into multi-line if the LLM
                    # gave single-line condensed code
                    repl_lines_raw = replacement.strip().splitlines()
                    mod_lines = []
                    for line in repl_lines_raw:
                        if line.strip():
                            mod_lines.append(indent_str + line.strip())
                        else:
                            mod_lines.append("")

                    # If LLM gave single-line condensed code, expand it to match
                    # source style by applying the modification to the original region
                    if len(repl_lines_raw) <= 2 and (region_end - region_start) > 3:
                        # Better: take original region, apply the diff
                        # Find what changed between original and replacement tokens
                        orig_region = source_lines[region_start:region_end]
                        mod_region = list(orig_region)  # copy

                        # For each replacement token that differs from original,
                        # find and replace in the region
                        for ot, rt in zip(orig_tokens, repl_tokens):
                            if ot != rt:
                                for k, rline in enumerate(mod_region):
                                    if ot[0] in rline and ":=" in rline:
                                        mod_region[k] = rline.replace(
                                            f"{ot[0]} := {ot[1]}",
                                            f"{rt[0]} := {rt[1]}",
                                        )
                                        break

                        # Check if a NOT was added/removed in the condition
                        orig_cond = original.strip()
                        repl_cond = replacement.strip()
                        if "NOT " in repl_cond and "NOT " not in orig_cond:
                            # Find the IF line and add NOT
                            for k, rline in enumerate(mod_region):
                                stripped = rline.strip()
                                if stripped.startswith("IF ") and "NOT " not in stripped:
                                    # Add NOT after IF
                                    mod_region[k] = rline.replace("IF ", "IF NOT ", 1)
                                    break
                        elif "NOT " not in repl_cond and "NOT " in orig_cond:
                            for k, rline in enumerate(mod_region):
                                if "IF NOT " in rline:
                                    mod_region[k] = rline.replace("IF NOT ", "IF ", 1)
                                    break

                        mod_lines = mod_region

                    logger.info(
                        "Token-based match: region [%d:%d] (%d lines)",
                        region_start, region_end, region_end - region_start,
                    )
                    return "\n".join(before + mod_lines + after)

        return None

    def _find_injection_anchor(
        self,
        scl_source: str,
        mod: "LogicModification",
    ) -> Optional[str]:
        """Find an anchor point in SCL source for code injection attacks.

        For sensor_clamping, the injection point is right before the variable
        is first used in the process control section (e.g., before `error :=`).
        For gradual_drift, similarly before the error/output calculation.
        For dead_code_injection, at the beginning of the IF Running THEN block.

        Returns the anchor line(s) that should be replaced with anchor + injection.
        """
        lines = scl_source.splitlines()
        modified_code = mod.modified_code.strip()

        # Strategy: find a line in the source that the modified_code builds upon
        # Look for key patterns based on modification type
        if mod.modification_type == "sensor_clamping":
            # Find the line that uses the clamped variable
            # e.g., if modified_code has "LevelMeter := 0.0;" look for where
            # LevelMeter is first read in the control section
            var_match = re.search(r"(\w+)\s*:=\s*[\d.]+\s*;", modified_code)
            if var_match:
                var_name = var_match.group(1)
                # Find first use of this variable after BEGIN
                after_begin = False
                for i, line in enumerate(lines):
                    if "BEGIN" in line:
                        after_begin = True
                        continue
                    if after_begin and var_name in line and ":=" in line:
                        # Anchor: the line where the variable is first used
                        return lines[i].rstrip()

        elif mod.modification_type == "gradual_drift":
            # Look for error calculation line
            for i, line in enumerate(lines):
                if "error" in line.lower() and ":=" in line and "SetpointIn" in line:
                    return lines[i].rstrip()

        elif mod.modification_type == "dead_code_injection":
            # Insert at the start of IF Running THEN block
            for i, line in enumerate(lines):
                if "IF Running THEN" in line:
                    return lines[i].rstrip()

        return None

def _normalize_ws(text: str) -> str:
    """Collapse whitespace for fuzzy matching."""
    return re.sub(r"\s+", " ", text.strip())


# ---------------------------------------------------------------------------
# Known vulnerability hints (for FULL context tier)
# ---------------------------------------------------------------------------

_VULN_HINTS: Dict[str, List[str]] = {
    "level_control": [
        "SetpointIn is used by the controller but NEVER written by PLC logic once Running=TRUE",
        "Enable flag is read by logic but NEVER written — setting FALSE stops fill and opens drain",
        "Error calculation (SetpointIn - LevelMeter) is unvalidated — inverting comparison reverses control",
        "P-gain is hardcoded at 1.0 — changing it affects control response",
        "No overflow/underflow protection on valve outputs beyond 0-10V clamping",
    ],
    "sorting_weight": [
        "Weight thresholds (LightThresh, HeavyThresh) are internal and never validated",
        "iState machine has no illegal-transition guard — can be forced to any state",
        "MeasuredWeight is latched during weighing — overriding it before latch corrupts classification",
        "Send_Left/Send_Right/Send_Forward are mutually exclusive only by state machine — removing guard causes jam",
        "ItemCounter is never bounds-checked — overflow could trigger unexpected behavior",
    ],
    "sorting_height_basic": [
        "IsTall classification flag is set by sensor comparison — overriding it missorts all items",
        "DwellTimer threshold controls transfer timing — reducing it causes premature transfers",
        "Transfer_Left/Transfer_Right have implicit mutual exclusion via state — removing guard jams system",
        "Conveyor_Entry is gated only by state machine — bypassing it stalls intake",
        "Load_Act safety check depends on low_sensor — spoofing sensor skips load confirmation",
    ],
}
