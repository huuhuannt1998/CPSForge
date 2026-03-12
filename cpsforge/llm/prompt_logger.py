"""
CPSForge LLM Prompt Logger
=============================
Structured, append-only logging of every LLM request/response pair to a
JSONL file alongside the run's other artifacts.

Each log entry is a single JSON object on one line, containing:
- Metadata always logged (model, provider, latency, tokens, success flag)
- Prompt/response text logged only when ``log_prompts=True`` in config
- Optional redaction of the full prompt/response when ``redact_prompts=True``

Security note:
- API keys are NEVER written to log entries.
- The ``log_prompts=False`` (default) mode records only metadata, which is
  safe to commit or share for performance analysis.
- ``log_prompts=True`` records full prompts; only enable when you understand
  the privacy implications (prompts contain plant state / attack objectives).

Log file location: ``{log_dir}/{experiment}/{run_id}/llm_log.jsonl``
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from cpsforge.llm.base_provider import CompletionResult

logger = logging.getLogger(__name__)

_REDACT_MARKER = "[REDACTED]"


class PromptLogger:
    """
    Append-only structured logger for LLM prompt/response pairs.

    Parameters
    ----------
    log_dir:
        Directory where ``llm_log.jsonl`` is written.  Created if needed.
    log_prompts:
        When True, full system and user prompt text is written to the log.
        When False (default), only telemetry metadata is logged.
    redact_prompts:
        When True AND ``log_prompts=True``, prompt/response text is replaced
        with the marker ``[REDACTED]``.  Intended as a safety override for
        shared environments.
    run_id:
        Optional run identifier stamped onto every log entry.
    provider_name:
        Optional provider name stamped onto every log entry.
    model_name:
        Optional model name stamped onto every log entry.
    """

    def __init__(
        self,
        log_dir: Path,
        log_prompts: bool = False,
        redact_prompts: bool = False,
        run_id: str = "",
        provider_name: str = "",
        model_name: str = "",
    ) -> None:
        self._log_dir = Path(log_dir)
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._log_file = self._log_dir / "llm_log.jsonl"
        self._log_prompts = log_prompts
        self._redact_prompts = redact_prompts
        self._run_id = run_id
        self._provider_name = provider_name
        self._model_name = model_name
        self._entries_written = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log_attempt(
        self,
        *,
        attempt: int,
        system_prompt: str,
        user_prompt: str,
        raw_text: Optional[str] = None,
        result: Optional[CompletionResult] = None,
        error: Optional[Exception] = None,
        validation_error: Optional[str] = None,
        actions_count: int = 0,
    ) -> None:
        """
        Write one log entry for a single LLM completion attempt.

        Parameters
        ----------
        attempt:
            Zero-based retry attempt index.
        system_prompt / user_prompt:
            Prompts sent to the provider.  Included in log only when
            ``log_prompts=True`` and ``redact_prompts=False``.
        raw_text:
            Raw model response text.
        result:
            :class:`CompletionResult` from the provider (carries telemetry).
        error:
            Provider-level exception if the call failed.
        validation_error:
            Schema validation failure message if parsing failed.
        actions_count:
            Number of valid actions extracted on this attempt.
        """
        entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id": self._run_id,
            "provider": self._provider_name or (result.model if result else ""),
            "model": self._model_name or (result.model if result else ""),
            "attempt": attempt,
            "success": error is None and validation_error is None,
            "actions_count": actions_count,
        }

        # Telemetry (always logged when a result is available)
        if result is not None:
            entry["input_tokens"] = result.input_tokens
            entry["output_tokens"] = result.output_tokens
            entry["latency_ms"] = round(result.latency_ms, 2) if result.latency_ms else None
            entry["finish_reason"] = result.finish_reason

        # Error metadata
        if error is not None:
            entry["error_type"] = type(error).__name__
            entry["error_message"] = str(error)[:500]

        if validation_error is not None:
            entry["validation_error"] = validation_error[:500]

        # Prompt/response text (opt-in, with optional redaction)
        if self._log_prompts:
            if self._redact_prompts:
                entry["system_prompt"] = _REDACT_MARKER
                entry["user_prompt"] = _REDACT_MARKER
                entry["response"] = _REDACT_MARKER
            else:
                entry["system_prompt"] = system_prompt
                entry["user_prompt"] = user_prompt
                entry["response"] = raw_text or ""

        self._write(entry)

    def log_run_summary(
        self,
        *,
        total_attempts: int,
        actions_generated: int,
        exhausted_retries: bool,
    ) -> None:
        """Write a summary entry at the end of a generate_actions() call."""
        entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id": self._run_id,
            "type": "run_summary",
            "total_attempts": total_attempts,
            "actions_generated": actions_generated,
            "exhausted_retries": exhausted_retries,
        }
        self._write(entry)

    @property
    def log_file_path(self) -> Path:
        return self._log_file

    @property
    def entries_written(self) -> int:
        return self._entries_written

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _write(self, entry: Dict[str, Any]) -> None:
        try:
            line = json.dumps(entry, default=str, ensure_ascii=False)
            with self._log_file.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            self._entries_written += 1
        except OSError as exc:
            logger.error("PromptLogger: failed to write log entry: %s", exc)


class NullPromptLogger(PromptLogger):
    """
    A no-op prompt logger that discards all entries.

    Used when no log_dir is available (e.g. in dry-run unit tests where
    no run artifact directory has been created yet).
    """

    def __init__(self) -> None:
        # Don't call super().__init__ -- we want no file I/O at all.
        self._log_prompts = False
        self._redact_prompts = False
        self._run_id = ""
        self._provider_name = ""
        self._model_name = ""
        self._entries_written = 0

    def _write(self, entry: Dict[str, Any]) -> None:
        self._entries_written += 1  # count in memory, don't write

    @property
    def log_file_path(self) -> Path:
        return Path("/dev/null")
