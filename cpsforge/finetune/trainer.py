"""
trainer.py — QLoRA fine-tuning pipeline for Qwen3.5-4B (C3).

This module wraps the ``transformers`` + ``peft`` + ``trl`` libraries to run
a QLoRA fine-tune on the attack-generation dataset produced by DataGenerator.

Architecture
------------
  Base model : Qwen/Qwen3.5-4B (4-bit NF4 via bitsandbytes)
  PEFT       : LoRA (rank=16, alpha=32, auto-detected target modules)
  Training   : SFTTrainer (causal LM on "messages" chat format)
  Epochs     : default 3
  LR         : 2e-4 with cosine schedule

Note: Qwen3.5 uses a hybrid Gated-DeltaNet + Gated-Attention architecture.
LoRA target modules are auto-detected from the loaded model to ensure
compatibility with this novel architecture.

Output: an adapter saved to finetune/adapters/<run_tag>/
        optional GGUF export via finetune/export.py

Requirements (install separately, not in core requirements.txt):
  pip install transformers>=4.48 peft>=0.14 trl>=0.8 bitsandbytes>=0.43 accelerate
  # For GGUF export:
  pip install llama-cpp-python  # OR use llama.cpp CLI

Usage (CLI)
-----------
  python -m cpsforge.finetune.trainer \\
      --dataset data/processed/finetune/finetune_examples.jsonl \\
      --output  finetune/adapters/qwen35_4b_cps_v1 \\
      --model   Qwen/Qwen3.5-4B
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

_REQUIRED_LIBS = ["transformers", "peft", "trl", "bitsandbytes", "accelerate"]


@dataclass
class TrainingConfig:
    """Configuration for QLoRA fine-tuning."""

    # Model
    base_model_name: str = "Qwen/Qwen3.5-4B"

    # Dataset
    dataset_path: str = "data/processed/finetune/finetune_examples.jsonl"

    # Output
    output_dir: str = "finetune/adapters/qwen35_4b_cps_v1"
    run_tag: str = "qwen35_4b_cps_v1"

    # QLoRA parameters
    lora_rank: int = 16
    lora_alpha: int = 32
    lora_dropout: float = 0.05
    # Qwen3.5 uses hybrid Gated-DeltaNet + Gated-Attention.
    # Set to None to auto-detect linear layers from the loaded model,
    # which is the safest approach for novel architectures.
    target_modules: Optional[List[str]] = None

    # Training hyperparameters
    num_epochs: int = 3
    per_device_train_batch_size: int = 1
    gradient_accumulation_steps: int = 8
    learning_rate: float = 2e-4
    warmup_ratio: float = 0.05
    lr_scheduler_type: str = "cosine"
    max_seq_length: int = 2048

    # Quantisation
    load_in_4bit: bool = True
    bnb_4bit_quant_type: str = "nf4"
    bnb_4bit_use_double_quant: bool = True

    # Misc
    logging_steps: int = 10
    save_steps: int = 50
    seed: int = 42
    fp16: bool = False
    bf16: bool = True              # Requires Ampere+ GPU (A100/3090)


class QLoRATrainer:
    """Fine-tune Qwen3.5-4B on CPS attack generation data.

    Parameters
    ----------
    config : TrainingConfig
    """

    def __init__(self, config: Optional[TrainingConfig] = None) -> None:
        self._cfg = config or TrainingConfig()
        self._check_dependencies()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def train(self) -> Path:
        """Run fine-tuning. Returns path to saved adapter."""
        # Late imports — training libraries may not be installed in eval environment
        import torch
        from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
        from trl import SFTTrainer, SFTConfig
        from datasets import Dataset

        cfg = self._cfg
        output_dir = Path(cfg.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        logger.info("Loading base model: %s", cfg.base_model_name)
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=cfg.load_in_4bit,
            bnb_4bit_quant_type=cfg.bnb_4bit_quant_type,
            bnb_4bit_use_double_quant=cfg.bnb_4bit_use_double_quant,
            bnb_4bit_compute_dtype=torch.bfloat16,
        )

        tokenizer = AutoTokenizer.from_pretrained(cfg.base_model_name, trust_remote_code=True)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token

        model = AutoModelForCausalLM.from_pretrained(
            cfg.base_model_name,
            quantization_config=bnb_config,
            device_map="auto",
            trust_remote_code=True,
        )
        model = prepare_model_for_kbit_training(model)

        # Resolve target modules: auto-detect all linear layers if not specified.
        # This is the safest approach for Qwen3.5's hybrid Gated-DeltaNet +
        # Gated-Attention architecture, where projection names differ from
        # standard transformers.
        target_modules = cfg.target_modules
        if target_modules is None:
            target_modules = "all-linear"
            logger.info("target_modules=None → using peft 'all-linear' auto-detection")

        lora_config = LoraConfig(
            r=cfg.lora_rank,
            lora_alpha=cfg.lora_alpha,
            lora_dropout=cfg.lora_dropout,
            target_modules=target_modules,
            bias="none",
            task_type="CAUSAL_LM",
        )
        model = get_peft_model(model, lora_config)
        model.print_trainable_parameters()

        # Load dataset
        logger.info("Loading dataset from %s", cfg.dataset_path)
        dataset = _load_jsonl_as_dataset(cfg.dataset_path)
        logger.info("Dataset size: %d examples", len(dataset))

        # Format as chat messages and apply template
        def format_example(example):
            messages = [
                {"role": "system", "content": example["system_prompt"]},
                {"role": "user",   "content": example["user_prompt"]},
                {"role": "assistant", "content": example["gold_output"]},
            ]
            text = tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=False
            )
            return {"text": text}

        formatted = dataset.map(format_example, remove_columns=dataset.column_names)

        # SFTTrainer
        training_args = SFTConfig(
            output_dir=str(output_dir),
            num_train_epochs=cfg.num_epochs,
            per_device_train_batch_size=cfg.per_device_train_batch_size,
            gradient_accumulation_steps=cfg.gradient_accumulation_steps,
            learning_rate=cfg.learning_rate,
            warmup_steps=max(1, int(cfg.warmup_ratio * 228)),  # ~10% of estimated total steps
            lr_scheduler_type=cfg.lr_scheduler_type,
            max_length=cfg.max_seq_length,
            logging_steps=cfg.logging_steps,
            save_steps=cfg.save_steps,
            seed=cfg.seed,
            fp16=cfg.fp16,
            bf16=cfg.bf16,
            report_to="none",
            dataset_text_field="text",
        )

        trainer = SFTTrainer(
            model=model,
            processing_class=tokenizer,
            train_dataset=formatted,
            args=training_args,
        )

        logger.info("Starting fine-tuning (epochs=%d)…", cfg.num_epochs)
        trainer.train()

        adapter_path = output_dir / "final_adapter"
        model.save_pretrained(str(adapter_path))
        tokenizer.save_pretrained(str(adapter_path))
        logger.info("Adapter saved to %s", adapter_path)

        # Save config for reproducibility
        with open(output_dir / "training_config.json", "w") as f:
            json.dump(
                {k: v for k, v in vars(cfg).items() if not callable(v)},
                f,
                indent=2,
            )

        return adapter_path

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _check_dependencies() -> None:
        missing = []
        for lib in _REQUIRED_LIBS:
            try:
                __import__(lib.replace("-", "_"))
            except ImportError:
                missing.append(lib)
        if missing:
            logger.warning(
                "QLoRA training dependencies not installed: %s\n"
                "Run: pip install %s",
                missing,
                " ".join(missing),
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_jsonl_as_dataset(path: str):
    """Load a JSONL file as a HuggingFace Dataset."""
    from datasets import Dataset
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return Dataset.from_list(records)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    parser = argparse.ArgumentParser(description="QLoRA fine-tune Qwen3.5-4B for CPS attack generation")
    parser.add_argument("--dataset", default="data/processed/finetune/finetune_examples.jsonl")
    parser.add_argument("--output", default="finetune/adapters/qwen35_4b_cps_v1")
    parser.add_argument("--model", default="Qwen/Qwen3.5-4B")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--rank", type=int, default=16)
    args = parser.parse_args()

    cfg = TrainingConfig(
        base_model_name=args.model,
        dataset_path=args.dataset,
        output_dir=args.output,
        num_epochs=args.epochs,
        lora_rank=args.rank,
    )
    trainer = QLoRATrainer(cfg)
    adapter_path = trainer.train()
    print(f"Done. Adapter saved to: {adapter_path}")
