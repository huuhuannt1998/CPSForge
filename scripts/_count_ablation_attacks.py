"""Count ablation attack types to update paper totals."""
import glob
import json
from collections import Counter

tc = Counter()
for p in sorted(glob.glob(r"data/raw/ablation_*/*/attacks.json")):
    data = json.load(open(p))
    if isinstance(data, list):
        for a in data:
            tc[a.get("attack_type", "unknown")] += 1

print(f"Ablation attack types: {dict(tc)}")
print(f"Ablation total: {sum(tc.values())}")
print()
ao = tc.get("actuator_override", 0)
ss = tc.get("setpoint_shift", 0)
sp = tc.get("sequence_perturbation", 0)
print(f"  actuator_override: 119 + {ao} = {119 + ao}")
print(f"  setpoint_shift: 31 + {ss} = {31 + ss}")
print(f"  sequence_perturbation: 21 + {sp} = {21 + sp}")
print(f"  Grand total: {171 + sum(tc.values())}")
