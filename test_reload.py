"""Test loading HuggingFace model twice in same process."""
import sys, time, gc
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import torch

from cpsforge.core.config import ConfigLoader
loader = ConfigLoader(configs_dir=Path("configs"))
llm_cfg = loader.load_llm("huggingface")
from cpsforge.llm.huggingface_provider import HuggingFaceProvider

print("First load...", flush=True)
t0 = time.monotonic()
p1 = HuggingFaceProvider(llm_cfg)
p1._ensure_loaded()
print(f"First load OK: {time.monotonic()-t0:.1f}s", flush=True)

# Cleanup
del p1._model
del p1._tokenizer
del p1
gc.collect()
torch.cuda.empty_cache()
print("Cache cleared", flush=True)

print("Second load...", flush=True)
t0 = time.monotonic()
p2 = HuggingFaceProvider(llm_cfg)
p2._ensure_loaded()
print(f"Second load OK: {time.monotonic()-t0:.1f}s", flush=True)
print("PASS")
