"""
CPSForge Local OpenAI-Compatible Provider
==========================================
LLM provider for any server that exposes an **OpenAI-compatible**
``/v1/chat/completions`` endpoint.  Primary target: **LM Studio**.

Key differences from the old Ollama-specific LocalProvider:
  - Uses the OpenAI REST dialect (``/v1/chat/completions``), not ``/api/chat``.
  - Parses the standard ``choices[0].message.content`` response path.
  - Health-checks via ``GET /v1/models``.
  - No API key required by default (LM Studio does not use one).

Configuration example (``configs/llm/local.yaml``)::

    provider: local_openai_compatible
    model: qwen2-7b-instruct
    base_url: http://127.0.0.1:1234/v1
    max_tokens: 1024
    temperature: 0.2
    timeout_s: 120.0

Dependencies: ``httpx`` (already in CPSForge base requirements).
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, Optional

import httpx

from cpsforge.core.config import LLMConfig
from cpsforge.llm.base_provider import BaseLLMProvider, CompletionResult, ProviderError

logger = logging.getLogger(__name__)

_DEFAULT_BASE_URL = "http://127.0.0.1:1234/v1"


class LocalOpenAICompatibleProvider(BaseLLMProvider):
    """
    LLM provider targeting any local server with an OpenAI-compatible API.

    Sends ``POST {base_url}/chat/completions`` using the standard OpenAI
    message format (system + user messages). Parses the standard
    ``choices[0].message.content`` response.

    Primary target: **LM Studio** running at ``http://127.0.0.1:1234/v1``.

    Also compatible with:
      - vLLM (``--served-model-name <model>``)
      - llama.cpp server (``--api-like-OAI``)
      - text-generation-webui with OpenAI extension
      - Ollama (v0.1.24+ also exposes ``/v1/chat/completions``)
    """

    def __init__(self, config: LLMConfig) -> None:
        super().__init__(config)
        self._base_url = (config.base_url or _DEFAULT_BASE_URL).rstrip("/")
        self._http = httpx.Client(timeout=config.timeout_s)

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    @property
    def provider_name(self) -> str:  # noqa: D401
        return "local_openai_compatible"

    # ------------------------------------------------------------------
    # Core completion
    # ------------------------------------------------------------------

    def complete(self, system_prompt: str, user_prompt: str) -> CompletionResult:
        """
        Call the local model server via the OpenAI chat-completions endpoint.

        Returns
        -------
        CompletionResult
            Text response plus token usage and latency metadata.

        Raises
        ------
        ProviderError
            On network errors, non-200 HTTP responses, or malformed JSON.
        """
        endpoint = f"{self._base_url}/chat/completions"
        payload: Dict[str, Any] = {
            "model": self._config.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": self._config.temperature,
            "max_tokens": self._config.max_tokens,
            "stream": False,
        }

        t0 = time.monotonic()
        try:
            resp = self._http.post(endpoint, json=payload)
        except httpx.TimeoutException as exc:
            raise ProviderError(
                f"Local model server timed out after {self._config.timeout_s}s. "
                f"Is the server running at {self._base_url}?"
            ) from exc
        except httpx.ConnectError as exc:
            raise ProviderError(
                f"Cannot connect to local model server at {self._base_url}. "
                "Start LM Studio and enable the local server."
            ) from exc
        except httpx.RequestError as exc:
            raise ProviderError(f"Local provider network error: {exc}") from exc

        latency_ms = (time.monotonic() - t0) * 1000.0

        if resp.status_code != 200:
            raise ProviderError(
                f"Local model server returned HTTP {resp.status_code}: "
                f"{resp.text[:300]}"
            )

        try:
            data = resp.json()
        except json.JSONDecodeError as exc:
            raise ProviderError(
                f"Local model server returned non-JSON: {resp.text[:300]}"
            ) from exc

        # ------------------------------------------------------------------
        # Parse OpenAI-compatible response
        # ------------------------------------------------------------------
        # Expected shape:
        # {
        #   "id": "...",
        #   "object": "chat.completion",
        #   "choices": [
        #     {
        #       "index": 0,
        #       "message": {"role": "assistant", "content": "..."},
        #       "finish_reason": "stop"
        #     }
        #   ],
        #   "usage": {
        #     "prompt_tokens": N,
        #     "completion_tokens": N,
        #     "total_tokens": N
        #   }
        # }
        choices = data.get("choices", [])
        if not choices:
            raise ProviderError(
                "Local model server returned an empty 'choices' array. "
                f"Raw response keys: {list(data.keys())}"
            )

        text = choices[0].get("message", {}).get("content", "")
        finish_reason = choices[0].get("finish_reason", "")

        usage = data.get("usage") or {}
        input_tokens = usage.get("prompt_tokens")
        output_tokens = usage.get("completion_tokens")

        model_echo = data.get("model", self._config.model)

        return CompletionResult(
            text=text,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
            model=model_echo,
            finish_reason=finish_reason,
            raw_metadata={
                "id": data.get("id"),
                "object": data.get("object"),
                "system_fingerprint": data.get("system_fingerprint"),
            },
        )

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    def health_check(self) -> bool:
        """Ping the server's ``/models`` endpoint to verify it is alive."""
        try:
            resp = self._http.get(f"{self._base_url}/models", timeout=5.0)
            if resp.status_code == 200:
                return True
            logger.warning(
                "LocalOpenAICompatibleProvider health_check: "
                "server returned HTTP %s",
                resp.status_code,
            )
            return False
        except httpx.RequestError as exc:
            logger.warning(
                "LocalOpenAICompatibleProvider health_check FAILED: %s", exc
            )
            return False

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Explicitly close the underlying HTTP client."""
        self._http.close()

    def __del__(self) -> None:
        try:
            self._http.close()
        except Exception:  # noqa: BLE001
            pass
