"""Dump all ablation metrics in a readable table."""
import json
import glob

fields = [
    "attack_success_rate", "detector_precision", "detector_recall",
    "detector_f1", "false_positives", "false_negatives", "total_steps"
]

paths = sorted(glob.glob(r"data/raw/ablation_*/*/metrics.json"))
for p in paths:
    parts = p.replace("\\", "/").split("/")
    exp = parts[-3]
    m = json.load(open(p))
    vals = "  ".join(f"{k}={m.get(k, '?')}" for k in fields)
    print(f"{exp}")
    print(f"  {vals}")
    print()
