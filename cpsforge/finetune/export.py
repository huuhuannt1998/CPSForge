"""
export.py — GGUF export helper for the fine-tuned adapter.

After QLoRA fine-tuning, the merged model can be exported to GGUF format
for use with llama.cpp and LM Studio — the same inference server used for
the base model in experiments.

This script:
  1. Loads the base model + LoRA adapter.
  2. Merges the adapter into the base model weights.
  3. Saves the merged model in safetensors format.
  4. Calls llama.cpp's convert_hf_to_gguf.py (if installed) to produce the
     GGUF file at the specified quantisation level.

Requirements
------------
  pip install transformers peft
  # For GGUF conversion, clone llama.cpp and point LLAMA_CPP_PATH to its root.

Usage
-----
  python -m cpsforge.finetune.export \\
      --adapter  finetune/adapters/qwen35_4b_cps_v1/final_adapter \\
      --base     Qwen/Qwen3.5-4B \\
      --output   finetune/gguf/qwen35_4b_cps_v1.Q4_K_M.gguf \\
      --quant    Q4_K_M
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


def merge_and_save(
    base_model_name: str,
    adapter_path: str,
    output_dir: str,
) -> Path:
    """Merge LoRA adapter into base model and save merged weights.

    Returns the path to the merged model directory.
    """
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM
    from peft import PeftModel

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    logger.info("Loading base model: %s", base_model_name)
    tokenizer = AutoTokenizer.from_pretrained(base_model_name, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(
        base_model_name,
        torch_dtype=torch.float16,
        device_map="cpu",       # merge on CPU to avoid GPU OOM
        trust_remote_code=True,
    )

    logger.info("Applying LoRA adapter: %s", adapter_path)
    model = PeftModel.from_pretrained(model, adapter_path)
    model = model.merge_and_unload()

    logger.info("Saving merged model to %s", out)
    model.save_pretrained(str(out), safe_serialization=True)
    tokenizer.save_pretrained(str(out))

    logger.info("Merge complete.")
    return out


def convert_to_gguf(
    merged_model_dir: str,
    output_gguf_path: str,
    quant: str = "Q4_K_M",
    llama_cpp_path: Optional[str] = None,
) -> None:
    """Convert the merged model to GGUF using llama.cpp.

    Parameters
    ----------
    merged_model_dir : str
        Path to merged safetensors model.
    output_gguf_path : str
        Desired output GGUF file path.
    quant : str
        Quantisation type (e.g. Q4_K_M, Q5_K_M, Q8_0).
    llama_cpp_path : str or None
        Path to llama.cpp root (containing convert_hf_to_gguf.py).
        Reads LLAMA_CPP_PATH env variable if not provided.
    """
    cpp_root = Path(llama_cpp_path or os.environ.get("LLAMA_CPP_PATH", "llama.cpp"))
    convert_script = cpp_root / "convert_hf_to_gguf.py"

    if not convert_script.exists():
        raise FileNotFoundError(
            f"convert_hf_to_gguf.py not found at {convert_script}. "
            "Clone llama.cpp and set LLAMA_CPP_PATH."
        )

    out_path = Path(output_gguf_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info("Converting to GGUF (%s): %s → %s", quant, merged_model_dir, output_gguf_path)
    cmd = [
        sys.executable,
        str(convert_script),
        merged_model_dir,
        "--outfile", str(out_path),
        "--outtype", quant.lower(),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        logger.error("GGUF conversion failed:\n%s", result.stderr)
        raise RuntimeError(f"GGUF conversion failed: {result.stderr[:500]}")

    logger.info("GGUF file written to %s", out_path)


# ---------------------------------------------------------------------------
# Add Optional import for type hint
# ---------------------------------------------------------------------------
from typing import Optional


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    parser = argparse.ArgumentParser(description="Export fine-tuned model to GGUF")
    parser.add_argument("--adapter", required=True, help="Path to LoRA adapter directory")
    parser.add_argument("--base", default="Qwen/Qwen3.5-4B", help="Base model HF name or path")
    parser.add_argument("--output", required=True, help="Output GGUF file path")
    parser.add_argument("--merged-dir", default=None, help="Where to save merged model (temp)")
    parser.add_argument("--quant", default="Q4_K_M", help="GGUF quantisation type")
    parser.add_argument("--llama-cpp", default=None, help="Path to llama.cpp root directory")
    args = parser.parse_args()

    merged_dir = args.merged_dir or (Path(args.adapter).parent / "merged")
    merge_and_save(args.base, args.adapter, str(merged_dir))
    convert_to_gguf(str(merged_dir), args.output, quant=args.quant, llama_cpp_path=args.llama_cpp)
    print(f"Done. GGUF at: {args.output}")
