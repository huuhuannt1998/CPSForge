"""
CPSForge HuggingFace Provider
================================
LLM provider that loads a model directly via ``transformers`` + ``bitsandbytes``
for in-process inference on a local GPU.  Eliminates the need for an external
inference server (LM Studio, vLLM, etc.).

Primary use: Qwen3.5-4B for both **baseline** (base weights) and **fine-tuned**
(base + LoRA adapter) experiments on the same hardware.

Configuration example (``configs/llm/huggingface.yaml``)::

    provider: huggingface
    model: Qwen/Qwen3.5-4B          # HF Hub name or local path
    adapter_path: null               # set for fine-tuned runs
    load_in_4bit: true
    max_tokens: 1024
    temperature: 0.2
    timeout_s: 120.0

Requirements (install separately, not in core requirements.txt)::

    pip install transformers>=4.48 accelerate bitsandbytes>=0.43 peft>=0.14

GPU VRAM: Qwen3.5-4B in 4-bit NF4 uses ~3 GB.  An RTX A4000 (16 GB) handles
inference comfortably with room for training batches.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

from cpsforge.core.config import LLMConfig
from cpsforge.llm.base_provider import BaseLLMProvider, CompletionResult, ProviderError

logger = logging.getLogger(__name__)


class HuggingFaceProvider(BaseLLMProvider):
    """
    In-process LLM provider using HuggingFace ``transformers``.

    Loads the model (optionally quantised to 4-bit NF4 via bitsandbytes)
    on first use, and keeps it resident in GPU memory for the lifetime of
    the experiment.  Optionally loads a LoRA adapter on top for fine-tuned
    inference.

    Designed for Qwen3.5-4B but works with any ``AutoModelForCausalLM``-
    compatible model.
    """

    def __init__(self, config: LLMConfig) -> None:
        super().__init__(config)
        self._model = None
        self._tokenizer = None
        self._loaded = False

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    @property
    def provider_name(self) -> str:  # noqa: D401
        return "huggingface"

    # ------------------------------------------------------------------
    # Lazy model loading
    # ------------------------------------------------------------------

    def _ensure_loaded(self) -> None:
        """Load model + tokenizer on first use."""
        if self._loaded:
            return

        try:
            import torch
            from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
        except ImportError as exc:
            raise ProviderError(
                "HuggingFace provider requires: "
                "pip install transformers>=4.48 accelerate bitsandbytes>=0.43 peft>=0.14"
            ) from exc

        cfg = self._config
        model_name = cfg.model
        adapter_path = getattr(cfg, "adapter_path", None)
        load_in_4bit = getattr(cfg, "load_in_4bit", True)

        logger.info("Loading model: %s (4-bit=%s, adapter=%s)",
                     model_name, load_in_4bit, adapter_path or "none")

        t0 = time.monotonic()

        # Tokenizer
        self._tokenizer = AutoTokenizer.from_pretrained(
            model_name, trust_remote_code=True,
        )
        if self._tokenizer.pad_token is None:
            self._tokenizer.pad_token = self._tokenizer.eos_token

        # Model
        load_kwargs: Dict[str, Any] = {
            "device_map": "auto",
            "trust_remote_code": True,
        }
        if load_in_4bit:
            load_kwargs["quantization_config"] = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_use_double_quant=True,
                bnb_4bit_compute_dtype=torch.bfloat16,
            )
        else:
            load_kwargs["torch_dtype"] = torch.bfloat16

        self._model = AutoModelForCausalLM.from_pretrained(
            model_name, **load_kwargs,
        )

        # Load LoRA adapter for fine-tuned variant
        if adapter_path:
            import os
            if not os.path.isfile(os.path.join(adapter_path, "adapter_config.json")):
                raise ProviderError(
                    f"LoRA adapter not found at '{adapter_path}'. "
                    "Run RQ2 fine-tuning before executing finetuned cells."
                )
            try:
                from peft import PeftModel
            except ImportError as exc:
                raise ProviderError(
                    "Loading a LoRA adapter requires: pip install peft>=0.14"
                ) from exc
            logger.info("Loading LoRA adapter from %s", adapter_path)
            self._model = PeftModel.from_pretrained(self._model, adapter_path)
            # Optional: merge for faster inference (no adapter overhead)
            # self._model = self._model.merge_and_unload()

        self._model.eval()
        elapsed = time.monotonic() - t0
        logger.info("Model loaded in %.1f s", elapsed)
        self._loaded = True

    # ------------------------------------------------------------------
    # Core completion
    # ------------------------------------------------------------------

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: Optional[Dict[str, Any]] = None,
    ) -> CompletionResult:
        """
        Generate a completion using the locally loaded model.

        Parameters
        ----------
        system_prompt:
            Model-level instruction with role/constraints.
        user_prompt:
            Turn-level prompt with current plant state / objective.
        response_format:
            Accepted for interface compatibility but not enforced at the
            token-generation level.  The caller (online_mitm) relies on
            prompt instructions + retry logic for JSON conformance.

        Returns
        -------
        CompletionResult

        Raises
        ------
        ProviderError
            On model loading failures or generation errors.
        """
        import torch

        self._ensure_loaded()

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        # Apply chat template — disable Qwen3.5 thinking mode for
        # deterministic JSON output.
        try:
            input_text = self._tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
                enable_thinking=False,
            )
        except TypeError:
            # Fallback for models whose chat template doesn't accept enable_thinking
            input_text = self._tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
            )

        inputs = self._tokenizer(
            input_text, return_tensors="pt",
        ).to(self._model.device)
        input_len = inputs["input_ids"].shape[1]

        t0 = time.monotonic()
        with torch.no_grad():
            gen_kwargs: Dict[str, Any] = {
                "max_new_tokens": self._config.max_tokens,
            }
            if self._config.temperature > 0:
                gen_kwargs["do_sample"] = True
                gen_kwargs["temperature"] = self._config.temperature
                gen_kwargs["top_p"] = 0.9
            else:
                gen_kwargs["do_sample"] = False

            outputs = self._model.generate(**inputs, **gen_kwargs)

        latency_ms = (time.monotonic() - t0) * 1000.0

        # Decode only the new tokens (skip the prompt)
        new_tokens = outputs[0][input_len:]
        text = self._tokenizer.decode(new_tokens, skip_special_tokens=True)

        output_tokens = len(new_tokens)

        return CompletionResult(
            text=text,
            input_tokens=input_len,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
            model=self._config.model,
            finish_reason="stop",
            raw_metadata={
                "adapter": getattr(self._config, "adapter_path", None),
                "quantized_4bit": getattr(self._config, "load_in_4bit", True),
            },
        )

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    def health_check(self) -> bool:
        """Return True if model is loaded or loadable."""
        if self._loaded:
            return True
        try:
            self._ensure_loaded()
            return True
        except Exception:
            return False
