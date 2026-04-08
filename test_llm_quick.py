"""
test_llm_quick.py — Verify LLM inference works on this machine.

Run from PowerShell (NOT Git Bash):
  python test_llm_quick.py
  python test_llm_quick.py --model qwen25_3b   # fallback test

Checks:
  1. Model loads without CUDA error
  2. Generates non-empty text output
  3. Returns valid JSON (attack decision format)
"""

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

MODEL_MAP = {
    "base":      "models/qwen3.5-4b",
    "qwen25_3b": "models/qwen2.5-3b-instruct",
    "qwen3_17b": "models/qwen3-1.7b",
    "phi4_mini":  "models/phi-4-mini-instruct",
    "smollm3":   "models/smollm3-3b",
}

SYSTEM_PROMPT = (
    "You are a security tester. Respond ONLY with valid JSON. "
    "Do not add explanation or markdown."
)

USER_PROMPT = (
    'The PLC tag "level_meter" reads 4.2 V (setpoint 5.0 V, range 0-10 V). '
    "Decide whether to attack or wait.\n\n"
    "Return JSON with exactly these keys:\n"
    '  "decision": "attack" or "wait"\n'
    '  "target_tag": tag name (or null)\n'
    '  "action_type": one of actuator_override, sensor_spoof, setpoint_shift, wait\n'
    '  "action_value": numeric value (or null)\n'
    '  "rationale": brief string\n'
    '  "confidence": float 0-1\n'
)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--model", default="base", choices=list(MODEL_MAP), help="Model key to test")
    p.add_argument("--max-tokens", type=int, default=200)
    args = p.parse_args()

    model_path = MODEL_MAP[args.model]
    print(f"\nTesting model: {model_path}")
    print(f"Path exists: {Path(model_path).exists()}")

    import torch
    print(f"CUDA available: {torch.cuda.is_available()}")
    if torch.cuda.is_available():
        print(f"GPU: {torch.cuda.get_device_name(0)}")
        print(f"VRAM free: {torch.cuda.mem_get_info()[0] / 1e9:.1f} GB")

    from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig

    print("\nLoading tokenizer…")
    t0 = time.monotonic()
    tok = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    print(f"  Tokenizer loaded in {time.monotonic()-t0:.1f}s")

    print("Loading model (4-bit NF4)…")
    t0 = time.monotonic()
    bnb_cfg = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.bfloat16,
    )
    model = AutoModelForCausalLM.from_pretrained(
        model_path,
        quantization_config=bnb_cfg,
        device_map="auto",
        trust_remote_code=True,
    )
    model.eval()
    load_time = time.monotonic() - t0
    print(f"  Model loaded in {load_time:.1f}s")

    # Build chat messages
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": USER_PROMPT},
    ]
    try:
        input_text = tok.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True, enable_thinking=False
        )
    except TypeError:
        input_text = tok.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )

    inputs = tok(input_text, return_tensors="pt").to(model.device)
    input_len = inputs["input_ids"].shape[1]
    print(f"\nPrompt tokens: {input_len}")

    print("Generating…")
    t0 = time.monotonic()
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=args.max_tokens,
            do_sample=True,
            temperature=0.2,
            top_p=0.9,
        )
    gen_time = time.monotonic() - t0

    new_tokens = outputs[0][input_len:]
    text = tok.decode(new_tokens, skip_special_tokens=True)
    print(f"  Generated {len(new_tokens)} tokens in {gen_time:.1f}s  ({len(new_tokens)/gen_time:.1f} tok/s)")
    print(f"\n--- Model output ---\n{text}\n---")

    # Try to parse JSON
    import json, re
    m = re.search(r'\{.*\}', text, re.DOTALL)
    if m:
        try:
            parsed = json.loads(m.group())
            print(f"JSON parsed OK: decision={parsed.get('decision')}")
            sys.exit(0)
        except json.JSONDecodeError as e:
            print(f"JSON parse failed: {e}")
            sys.exit(1)
    else:
        print("No JSON found in output!")
        sys.exit(1)


if __name__ == "__main__":
    main()
