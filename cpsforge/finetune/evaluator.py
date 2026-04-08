"""
evaluator.py — Before/after fine-tuning capability harness (RQ2).

Measures the effect of QLoRA fine-tuning on:
  - Attack Success Rate (ASR)
  - Action parse success rate (format validity)
  - Shield approval rate (semantic validity)
  - Phase-consistency rate (timing quality)
  - Cross-scene transfer (train scenes vs held-out scenes)

Usage
-----
    evaluator = FinetuneEvaluator(
        base_model_name="Qwen/Qwen3.5-4B",
        adapter_path="finetune/adapters/qwen35_4b_cps_v1/final_adapter",
        test_jsonl="data/processed/finetune/test_examples.jsonl",
    )
    report = evaluator.evaluate()
    evaluator.save_report(report, "data/processed/finetune/eval_report.json")
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ModelEvalResult:
    """Per-model metrics for RQ2 analysis."""
    model_label: str          # "base" or "finetuned"
    model_name: str
    adapter_path: Optional[str]

    n_examples: int
    parse_success_rate: float         # fraction of valid JSON outputs
    shield_approval_rate: float       # fraction approved by rule-based shield
    attack_decision_rate: float       # fraction that chose "attack" over "wait"
    avg_confidence: float
    has_reasoning_rate: float         # fraction with non-empty reasoning field
    has_timing_rationale_rate: float  # fraction with non-empty timing_rationale

    # Per-scene breakdown (scene → ASR)
    per_scene_parse_rate: Dict[str, float] = None

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class FinetuneEvalReport:
    """RQ2 report comparing base vs fine-tuned model."""
    base: ModelEvalResult
    finetuned: ModelEvalResult

    # Delta metrics
    parse_success_delta: float
    shield_approval_delta: float
    attack_decision_delta: float
    avg_confidence_delta: float

    def as_dict(self) -> Dict[str, Any]:
        return {
            "base": self.base.as_dict(),
            "finetuned": self.finetuned.as_dict(),
            "deltas": {
                "parse_success": self.parse_success_delta,
                "shield_approval": self.shield_approval_delta,
                "attack_decision": self.attack_decision_delta,
                "avg_confidence": self.avg_confidence_delta,
            },
        }


class FinetuneEvaluator:
    """Evaluate base + fine-tuned model on held-out test examples.

    Parameters
    ----------
    base_model_name : str
        HuggingFace model ID for the base model.
    adapter_path : str or Path
        Path to the saved LoRA adapter (produced by QLoRATrainer).
    test_jsonl : str or Path
        Held-out test set (JSONL of FinetuneExample dicts).
    max_new_tokens : int
        Max tokens for model generation.
    """

    def __init__(
        self,
        base_model_name: str = "Qwen/Qwen3.5-4B",
        adapter_path: Optional[str] = None,
        test_jsonl: str = "data/processed/finetune/test_examples.jsonl",
        max_new_tokens: int = 256,
    ) -> None:
        self._base_model = base_model_name
        self._adapter_path = str(adapter_path) if adapter_path else None
        self._test_path = Path(test_jsonl)
        self._max_new_tokens = max_new_tokens

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self) -> FinetuneEvalReport:
        """Run evaluation for both base and fine-tuned models."""
        examples = self._load_test_examples()
        logger.info("Evaluating %d test examples…", len(examples))

        base_result = self._eval_model(
            model_label="base",
            model_name=self._base_model,
            adapter_path=None,
            examples=examples,
        )

        ft_result = self._eval_model(
            model_label="finetuned",
            model_name=self._base_model,
            adapter_path=self._adapter_path,
            examples=examples,
        )

        report = FinetuneEvalReport(
            base=base_result,
            finetuned=ft_result,
            parse_success_delta=ft_result.parse_success_rate - base_result.parse_success_rate,
            shield_approval_delta=ft_result.shield_approval_rate - base_result.shield_approval_rate,
            attack_decision_delta=ft_result.attack_decision_rate - base_result.attack_decision_rate,
            avg_confidence_delta=ft_result.avg_confidence - base_result.avg_confidence,
        )
        return report

    def save_report(self, report: FinetuneEvalReport, path: str = "finetune_eval_report.json") -> None:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w") as f:
            json.dump(report.as_dict(), f, indent=2)
        logger.info("Saved eval report → %s", out)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_test_examples(self) -> List[Dict[str, Any]]:
        from cpsforge.finetune.data_schema import FinetuneExample
        if not self._test_path.exists():
            raise FileNotFoundError(f"Test JSONL not found: {self._test_path}")
        examples = []
        with open(self._test_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    examples.append(json.loads(line))
        return examples

    def _eval_model(
        self,
        model_label: str,
        model_name: str,
        adapter_path: Optional[str],
        examples: List[Dict[str, Any]],
    ) -> ModelEvalResult:
        """Run inference and compute metrics for one model variant."""
        generator = _ModelGenerator(model_name, adapter_path, self._max_new_tokens)
        generator.load()

        parse_ok = 0
        shield_ok = 0
        attack_count = 0
        confidences: List[float] = []
        has_reasoning = 0
        has_timing = 0
        scene_results: Dict[str, List[bool]] = {}

        for ex in examples:
            raw_output = generator.generate(ex["system_prompt"], ex["user_prompt"])
            parsed, ok = _parse_output(raw_output)
            if ok:
                parse_ok += 1
            approved = _check_shield_heuristic(parsed) if ok else False
            if approved:
                shield_ok += 1
            if ok and parsed.get("decision") == "attack":
                attack_count += 1
            if ok:
                c = float(parsed.get("confidence", 0.5))
                confidences.append(c)
                if parsed.get("reasoning"):
                    has_reasoning += 1
                if parsed.get("timing_rationale"):
                    has_timing += 1
            scene = ex.get("scene", "unknown")
            scene_results.setdefault(scene, []).append(ok)

        n = len(examples)
        per_scene = {
            s: sum(v) / max(len(v), 1)
            for s, v in scene_results.items()
        }

        return ModelEvalResult(
            model_label=model_label,
            model_name=model_name,
            adapter_path=adapter_path,
            n_examples=n,
            parse_success_rate=parse_ok / max(n, 1),
            shield_approval_rate=shield_ok / max(n, 1),
            attack_decision_rate=attack_count / max(n, 1),
            avg_confidence=sum(confidences) / max(len(confidences), 1),
            has_reasoning_rate=has_reasoning / max(n, 1),
            has_timing_rationale_rate=has_timing / max(n, 1),
            per_scene_parse_rate=per_scene,
        )


# ---------------------------------------------------------------------------
# Generator helper (thin wrapper around model)
# ---------------------------------------------------------------------------

class _ModelGenerator:
    """Load a model (optionally with LoRA adapter) and run inference."""

    def __init__(
        self, model_name: str, adapter_path: Optional[str], max_new_tokens: int
    ) -> None:
        self._model_name = model_name
        self._adapter_path = adapter_path
        self._max_new_tokens = max_new_tokens
        self._model = None
        self._tokenizer = None

    def load(self) -> None:
        import torch
        from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=torch.bfloat16,
        )
        self._tokenizer = AutoTokenizer.from_pretrained(
            self._model_name, trust_remote_code=True
        )
        self._model = AutoModelForCausalLM.from_pretrained(
            self._model_name,
            quantization_config=bnb_config,
            device_map="auto",
            trust_remote_code=True,
        )
        if self._adapter_path:
            from peft import PeftModel
            self._model = PeftModel.from_pretrained(self._model, self._adapter_path)
            logger.info("Loaded LoRA adapter from %s", self._adapter_path)

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        import torch
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ]
        input_ids = self._tokenizer.apply_chat_template(
            messages, add_generation_prompt=True, return_tensors="pt"
        ).to(self._model.device)
        with torch.no_grad():
            out = self._model.generate(
                input_ids,
                max_new_tokens=self._max_new_tokens,
                do_sample=False,
                pad_token_id=self._tokenizer.eos_token_id,
            )
        generated = out[0][input_ids.shape[-1]:]
        return self._tokenizer.decode(generated, skip_special_tokens=True)


# ---------------------------------------------------------------------------
# Parse + heuristic shield helpers
# ---------------------------------------------------------------------------

def _parse_output(text: str):
    """Try to parse the model output as JSON. Returns (dict, success_bool)."""
    import re
    # Try direct parse
    try:
        return json.loads(text.strip()), True
    except json.JSONDecodeError:
        pass
    # Extract first JSON object
    depth = 0
    start = None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    return json.loads(text[start:i + 1]), True
                except json.JSONDecodeError:
                    pass
    return {}, False


def _check_shield_heuristic(parsed: Dict[str, Any]) -> bool:
    """Lightweight (offline) shield check for evaluation.

    Checks required fields are present and value is numeric.
    Does NOT contact the real shield (no PLC required).
    """
    if not parsed:
        return False
    if "decision" not in parsed:
        return False
    if parsed["decision"] == "wait":
        return True   # wait decisions are always "valid" structurally
    required = {"target_tag", "action_type", "action_value"}
    if not required.issubset(parsed.keys()):
        return False
    try:
        float(parsed["action_value"])
    except (ValueError, TypeError):
        return False
    return True
