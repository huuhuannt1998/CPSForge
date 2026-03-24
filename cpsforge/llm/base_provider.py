"""
CPSForge LLM Provider Interface
=================================
Abstract base class that every concrete LLM provider must implement.

All providers receive a :class:`LLMConfig` and expose a single
``complete(system_prompt, user_prompt) -> str`` call.  The LLMAttacker
drives providers through this interface; callers never need to know
which vendor is behind the curtain.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from cpsforge.core.config import LLMConfig

logger = logging.getLogger(__name__)


@dataclass
class CompletionResult:
    """
    Return value of a single LLM completion call.

    Carries both the raw text and lightweight token/latency telemetry
    needed for prompt logging and cost tracking.
    """

    text: str
    """The model's raw text response."""

    input_tokens: Optional[int] = None
    """Number of prompt tokens consumed (if reported by the API)."""

    output_tokens: Optional[int] = None
    """Number of completion tokens generated (if reported by the API)."""

    latency_ms: Optional[float] = None
    """Wall-clock time for the API call, in milliseconds."""

    model: str = ""
    """Model identifier as echoed by the API response."""

    finish_reason: str = ""
    """Stop reason, e.g. 'stop', 'max_tokens', 'error'."""

    raw_metadata: dict = field(default_factory=dict)
    """Vendor-specific response metadata for debugging."""


class BaseLLMProvider(ABC):
    """
    Abstract LLM provider.

    Concrete subclasses (e.g. :class:`LocalOpenAICompatibleProvider`)
    must implement :meth:`complete` and :meth:`provider_name`.

    All API key handling is delegated to :class:`LLMConfig`, which reads
    from environment variables at runtime -- never from hardcoded strings.
    """

    def __init__(self, config: LLMConfig) -> None:
        self._config = config

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Short vendor name, e.g. ``'anthropic'``, ``'openai'``, ``'local'``."""

    @property
    def model_name(self) -> str:
        """Model identifier used for API calls."""
        return self._config.model

    @property
    def config(self) -> LLMConfig:
        """Read-only access to the underlying config."""
        return self._config

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    @abstractmethod
    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: Optional[Dict[str, Any]] = None,
    ) -> CompletionResult:
        """
        Send a chat/completion request and block until a response is received.

        Parameters
        ----------
        system_prompt:
            The model-level instruction that establishes role and constraints.
            For the LLM attacker this includes safety rules and output schema.
        user_prompt:
            The turn-level prompt containing the current plant state and
            attack objective.
        response_format:
            Optional structured-output specification forwarded to the API.
            Supported by LM Studio / llama.cpp via
            ``{"type": "json_schema", "json_schema": {...}}``.
            When provided, the server constrains token generation to the schema.

        Returns
        -------
        CompletionResult
            Structured response including raw text and optional telemetry.

        Raises
        ------
        ProviderError
            On API-level failures (auth, rate limit, timeout, etc.).
        """

    # ------------------------------------------------------------------
    # Health check (optional override)
    # ------------------------------------------------------------------

    def health_check(self) -> bool:
        """
        Optional lightweight validation that the provider is reachable.

        Default implementation returns True (subclasses may override to
        ping the real API).
        """
        return True

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(model={self._config.model!r})"


class ProviderError(RuntimeError):
    """
    Raised when a provider call fails in a way that is not retryable at
    the schema-correction level (e.g. authentication error, hard timeout).
    """
