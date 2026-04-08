"""Quick test: verify HuggingFace provider can generate text."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cpsforge.core.config import ConfigLoader
from cpsforge.llm.factory import build_provider

loader = ConfigLoader(configs_dir=Path("configs"))
cfg = loader.load_llm("huggingface")
print(f"Model: {cfg.model}, Provider: {cfg.provider}")
provider = build_provider(cfg)

try:
    result = provider.complete(
        system_prompt="You are a security analyst. Respond with JSON only.",
        user_prompt='Identify one vulnerability: {"id": "VULN-001", "description": "..."}',
    )
    print(f"Result ({result.latency_ms:.0f}ms): {result.text[:300]}")
except Exception as e:
    print(f"ERROR: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()
