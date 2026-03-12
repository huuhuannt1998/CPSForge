"""
CPSForge LLM Provider Factory
================================
Maps the ``provider`` string from :class:`LLMConfig` to the concrete
:class:`BaseLLMProvider` implementation.

Usage::

    from cpsforge.core.config import ConfigLoader
    from cpsforge.llm.factory import build_provider

    llm_cfg = ConfigLoader().load_llm("local")
    provider = build_provider(llm_cfg)
    result = provider.complete(system_prompt, user_prompt)

Provider names (``LLMConfig.provider``):
- ``"local_openai_compatible"`` -- :class:`LocalOpenAICompatibleProvider`
  (uses ``httpx``; targets LM Studio / vLLM / any OpenAI-compatible endpoint)
"""

from __future__ import annotations

import logging

from cpsforge.core.config import LLMConfig
from cpsforge.llm.base_provider import BaseLLMProvider

logger = logging.getLogger(__name__)

_PROVIDER_REGISTRY: dict[str, str] = {
    "local_openai_compatible": (
        "cpsforge.llm.local_openai_provider.LocalOpenAICompatibleProvider"
    ),
}


def build_provider(config: LLMConfig) -> BaseLLMProvider:
    """
    Instantiate an LLM provider from a :class:`LLMConfig`.

    Parameters
    ----------
    config:
        Loaded and validated :class:`LLMConfig` (from ``configs/llm/*.yaml``).

    Returns
    -------
    BaseLLMProvider
        Ready-to-use provider instance.

    Raises
    ------
    ValueError
        If ``config.provider`` is not a recognised provider name.
    ImportError
        If the optional package for the requested provider is not installed.
    """
    provider_key = config.provider.lower().strip()
    class_path = _PROVIDER_REGISTRY.get(provider_key)

    if class_path is None:
        valid = ", ".join(sorted(_PROVIDER_REGISTRY.keys()))
        raise ValueError(
            f"Unknown LLM provider: '{config.provider}'. "
            f"Valid providers: {valid}"
        )

    # Lazy import -- avoids importing anthropic/openai at module load time
    module_path, class_name = class_path.rsplit(".", 1)
    try:
        import importlib
        module = importlib.import_module(module_path)
        cls = getattr(module, class_name)
    except ImportError as exc:
        raise ImportError(
            f"Failed to import provider '{provider_key}' ({class_path}): {exc}"
        ) from exc

    provider: BaseLLMProvider = cls(config)
    logger.info(
        "Built LLM provider: %s (model=%s)", provider.provider_name, provider.model_name
    )
    return provider


def list_providers() -> list[str]:
    """Return the list of registered provider names."""
    return sorted(_PROVIDER_REGISTRY.keys())
