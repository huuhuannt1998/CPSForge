"""
CPSForge LLM Package
======================
Provides the LLM provider abstraction, prompt building, schema validation,
prompt logging, and the LLMAttacker implementation.

Quick-start example::

    from cpsforge.core.config import ConfigLoader
    from cpsforge.llm import build_provider, LLMAttacker
    from cpsforge.core.config import AttackPolicyConfig

    # Load provider config from configs/llm/local.yaml
    llm_cfg = ConfigLoader().load_llm("local")
    provider = build_provider(llm_cfg)

    # Or use the LLMAttacker directly via the attack factory
    pol = ConfigLoader().load_attack_policy("llm_tank_control")
    attacker = LLMAttacker(pol)
    actions = attacker.generate_actions(scene)
"""

from cpsforge.llm.attacker import LLMAttacker
from cpsforge.llm.base_provider import BaseLLMProvider, CompletionResult, ProviderError
from cpsforge.llm.factory import build_provider, list_providers
from cpsforge.llm.local_openai_provider import LocalOpenAICompatibleProvider
from cpsforge.llm.prompt_builder import PromptBuilder
from cpsforge.llm.prompt_logger import NullPromptLogger, PromptLogger
from cpsforge.llm.schema_validator import ActionSchemaValidator, ValidationError

__all__ = [
    # Attacker
    "LLMAttacker",
    # Provider abstraction
    "BaseLLMProvider",
    "CompletionResult",
    "ProviderError",
    # Concrete provider
    "LocalOpenAICompatibleProvider",
    # Factory
    "build_provider",
    "list_providers",
    # Prompt building
    "PromptBuilder",
    # Logging
    "PromptLogger",
    "NullPromptLogger",
    # Validation
    "ActionSchemaValidator",
    "ValidationError",
]

