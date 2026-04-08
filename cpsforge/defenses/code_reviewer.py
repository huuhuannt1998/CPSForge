"""
code_reviewer.py — LLM-based SCL code review defender.

The CodeReviewDefender is the symmetric defense counterpart to
LogicAnalyzer. Given an original SCL program and a proposed
modification (diff), the LLM evaluates whether the change is:
  - benign (bug fix, optimization, feature addition)
  - suspicious (could disrupt the process)

This mirrors real-world ICS code review workflows where security
engineers review PLC program changes before deployment.

Usage
-----
    reviewer = CodeReviewDefender(llm_provider)
    result = reviewer.review(
        original_scl="...",
        modified_scl="...",
        scene_name="level_control",
        change_description="Updated PID parameters",
    )
    # result.decision in {"approve", "reject"}
"""

from __future__ import annotations

import difflib
import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cpsforge.llm.base_provider import BaseLLMProvider

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ReviewResult:
    """Structured review verdict from the LLM."""
    decision: str  # "approve" | "reject"
    suspicion_score: float  # 0.0 (benign) to 1.0 (clearly malicious)
    reasoning: str
    identified_risks: str
    recommendation: str
    diff_summary: str
    raw_output: str = ""
    llm_latency_ms: float = 0.0
    parse_success: bool = True

    def as_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "suspicion_score": self.suspicion_score,
            "reasoning": self.reasoning,
            "identified_risks": self.identified_risks,
            "recommendation": self.recommendation,
            "diff_summary": self.diff_summary,
            "llm_latency_ms": self.llm_latency_ms,
            "parse_success": self.parse_success,
        }


# ---------------------------------------------------------------------------
# Prompt template
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are a senior ICS security engineer reviewing PLC code changes.

You are given:
1. The original SCL (Structured Control Language) source code
2. A unified diff showing proposed modifications
3. The scene/process description

Your task: determine whether this code change is SAFE or MALICIOUS.

Red flags to look for:
- Safety interlock removal or weakening
- Comparison operator changes (< to >, AND to OR, = to <>)
- Timing constant modifications (especially reductions)
- New branches triggered by counters or rare conditions (dead code injection)
- Sensor reading overrides (clamping)
- State machine shortcutting (jumping states)
- Cumulative variable modifications (drift attacks)
- Removal of bounds checking
- Variables being set to hardcoded values instead of sensor readings

Respond with a JSON object:
{{
  "decision": "approve" or "reject",
  "suspicion_score": 0.0-1.0,
  "reasoning": "<detailed explanation>",
  "identified_risks": "<specific risky code changes found, or 'none'>",
  "recommendation": "<what you recommend: approve as-is, request changes, or reject>"
}}"""

_USER_PROMPT = """SCENE: {scene_name}
PROCESS: {scene_description}
SUBMITTED CHANGE DESCRIPTION: {change_description}

UNIFIED DIFF:
```diff
{unified_diff}
```

FULL ORIGINAL CODE:
```scl
{original_scl}
```

Review this change. Respond with JSON only."""


# ---------------------------------------------------------------------------
# CodeReviewDefender
# ---------------------------------------------------------------------------

class CodeReviewDefender:
    """LLM-based SCL code review for detecting adversarial modifications.

    Parameters
    ----------
    llm_provider : BaseLLMProvider
        LLM for code review.
    rejection_threshold : float
        Minimum suspicion_score to reject (default: 0.5).
    max_retries : int
        Parse retries per call.
    """

    def __init__(
        self,
        llm_provider: BaseLLMProvider,
        rejection_threshold: float = 0.5,
        max_retries: int = 1,
    ) -> None:
        self._provider = llm_provider
        self._threshold = rejection_threshold
        self._max_retries = max_retries
        self._call_count = 0
        self._reject_count = 0

    def review(
        self,
        original_scl: str,
        modified_scl: str,
        scene_name: str,
        scene_description: str = "",
        change_description: str = "Code update",
    ) -> ReviewResult:
        """Review a proposed SCL modification."""
        self._call_count += 1

        # Generate unified diff
        diff_lines = list(difflib.unified_diff(
            original_scl.splitlines(keepends=True),
            modified_scl.splitlines(keepends=True),
            fromfile="original.scl",
            tofile="modified.scl",
            lineterm="",
        ))
        unified_diff = "\n".join(diff_lines)
        diff_summary = f"{sum(1 for l in diff_lines if l.startswith('+') and not l.startswith('+++'))} additions, " \
                        f"{sum(1 for l in diff_lines if l.startswith('-') and not l.startswith('---'))} deletions"

        if not diff_lines:
            return ReviewResult(
                decision="approve",
                suspicion_score=0.0,
                reasoning="No code differences found",
                identified_risks="none",
                recommendation="No changes to review",
                diff_summary="0 additions, 0 deletions",
            )

        user_prompt = _USER_PROMPT.format(
            scene_name=scene_name,
            scene_description=scene_description,
            change_description=change_description,
            unified_diff=unified_diff,
            original_scl=original_scl,
        )

        raw_output = ""
        latency_ms = 0.0

        for attempt in range(self._max_retries + 1):
            try:
                t0 = time.monotonic()
                result = self._provider.complete(
                    system_prompt=_SYSTEM_PROMPT,
                    user_prompt=user_prompt,
                    response_format={"type": "json_object"},
                )
                latency_ms = (time.monotonic() - t0) * 1000.0
                raw_output = result.text

                data = _parse_json(raw_output)
                decision = str(data.get("decision", "approve")).lower()
                suspicion = float(data.get("suspicion_score", 0.0))

                # Override: if score exceeds threshold, force reject
                if suspicion >= self._threshold and decision == "approve":
                    decision = "reject"

                if decision == "reject":
                    self._reject_count += 1

                return ReviewResult(
                    decision=decision,
                    suspicion_score=suspicion,
                    reasoning=str(data.get("reasoning", "")),
                    identified_risks=str(data.get("identified_risks", "")),
                    recommendation=str(data.get("recommendation", "")),
                    diff_summary=diff_summary,
                    raw_output=raw_output,
                    llm_latency_ms=latency_ms,
                    parse_success=True,
                )

            except Exception as exc:
                logger.warning(
                    "Code review parse failed (attempt %d): %s", attempt + 1, exc,
                )
                if attempt == 0:
                    user_prompt += (
                        "\n\n[Previous response was invalid. "
                        "Return ONLY a valid JSON object.]"
                    )

        # Default: approve on parse failure (don't block legitimate changes)
        return ReviewResult(
            decision="approve",
            suspicion_score=0.0,
            reasoning="LLM parse failure — defaulting to approve",
            identified_risks="",
            recommendation="Manual review recommended",
            diff_summary=diff_summary,
            raw_output=raw_output,
            llm_latency_ms=latency_ms,
            parse_success=False,
        )

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "total_reviews": self._call_count,
            "total_rejects": self._reject_count,
            "reject_rate": self._reject_count / max(1, self._call_count),
        }


# ---------------------------------------------------------------------------
# JSON parsing helper
# ---------------------------------------------------------------------------

def _parse_json(raw_text: str) -> Dict[str, Any]:
    """Parse JSON from LLM response."""
    text = raw_text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```\s*$", "", text)
    text = text.strip()

    start = text.find("{")
    if start == -1:
        raise ValueError(f"No JSON object found: {raw_text[:200]!r}")

    depth = 0
    for i, ch in enumerate(text[start:], start=start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i + 1])

    # Truncated — try repair
    fragment = text[start:]
    while fragment.count("{") > fragment.count("}"):
        fragment += "}"
    return json.loads(fragment)
