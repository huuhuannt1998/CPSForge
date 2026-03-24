"""Quick check of eval_run flags across all live experiments."""
import json
from pathlib import Path

raw = Path("data/raw")
for exp_dir in sorted(raw.iterdir()):
    if not exp_dir.is_dir() or not exp_dir.name.startswith("live_"):
        continue
    for rd in sorted(exp_dir.iterdir()):
        if not rd.is_dir():
            continue
        mp = rd / "metrics.json"
        if not mp.exists():
            continue
        m = json.loads(mp.read_text())
        ev = m.get("eval_run", "MISSING")
        asr = m.get("attack_success_rate", "?")
        print(f"{exp_dir.name}/{rd.name}: eval_run={ev}, ASR={asr}")
