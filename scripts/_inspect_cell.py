"""Quick inspection of an experiment run cell."""
import json, sys
from pathlib import Path

if len(sys.argv) < 2:
    # Find most recent run
    base = Path("data/raw")
    runs = sorted(base.rglob("metadata.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not runs:
        print("No runs found")
        sys.exit(1)
    run_dir = runs[0].parent
else:
    run_dir = Path(sys.argv[1])

print(f"=== Run: {run_dir.name}")

# Metadata
meta = json.loads((run_dir / "metadata.json").read_text())
for k, v in meta.items():
    print(f"  {k}: {v}")

# Attacks
attacks = json.loads((run_dir / "attacks.json").read_text())
print(f"\nAttacks: {len(attacks)}")
for i, a in enumerate(attacks):
    status = a.get("execution_status", "?")
    approved = a.get("approved_by_shield", "?")
    target = a.get("target", "?")
    atype = a.get("attack_type", "?")
    value = a.get("value", "?")
    print(f"  [{i+1}] {atype:20s} -> {target:15s} val={value}  shield={approved}  exec={status}")

# Shield events
shield = json.loads((run_dir / "shield_events.json").read_text())
print(f"\nShield events: {len(shield)}")
for s in shield[:5]:
    print(f"  {s.get('action', '?')}: {s.get('result', '?')} - {s.get('violations', [])}")

# Parquet summary
try:
    import pandas as pd
    df = pd.read_parquet(run_dir / "unified_steps.parquet")
    print(f"\nSteps: {len(df)} rows, {len(df.columns)} columns")
    print(f"Columns: {list(df.columns[:15])}...")
except Exception as e:
    print(f"\nParquet: {e}")
