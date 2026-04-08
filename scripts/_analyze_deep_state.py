"""Analyze deep state MITM experiment results."""
import json
import sys
from pathlib import Path

run_dir = Path("data/raw/v2_online_mitm_level_control/20260407T015532Z_0fdda58c")

# Metadata
meta = json.load(open(run_dir / "metadata.json"))
print("=" * 70)
print(f"RUN: {meta['run_id']}")
print(f"Scene: {meta['scene_name']}  Attacker: {meta['attacker_name']}")
print(f"Context: {meta['context_level']}  Defense: {meta['defense_variant']}")
print(f"Steps: {meta['total_steps']}  Attacks: {meta['total_attacks']}")
print("=" * 70)

# Attacks
attacks = json.load(open(run_dir / "attacks.json"))
print(f"\n--- ATTACKS ({len(attacks)} total) ---\n")
for i, a in enumerate(attacks):
    print(f"  {i+1:2d}. target={a['target']:15s}  type={a['attack_type']:25s}  "
          f"val={str(a['value']):8s}  conf={a['confidence']:.1f}  "
          f"status={a['execution_status']}")
    print(f"      effect: {a['expected_effect'][:90]}")
    print(f"      reason: {a['rationale'][:90]}")
    print()

# Shield events
shield = json.load(open(run_dir / "shield_events.json"))
print(f"--- SHIELD EVENTS ({len(shield)} total) ---\n")
for s in shield:
    print(f"  target={s.get('target','?'):15s}  action={s.get('action','?'):10s}  "
          f"value={str(s.get('value','?')):8s}  result={s.get('result','?')}")

# Capture file
cap_path = Path("data/captures/20260407T015532Z_0fdda58c_plc_events.jsonl")
if cap_path.exists() and cap_path.stat().st_size > 0:
    events = [json.loads(line) for line in open(cap_path)]
    event_types = {}
    for e in events:
        t = e.get("event_type", "unknown")
        event_types[t] = event_types.get(t, 0) + 1
    print(f"\n--- PLC CAPTURE ({len(events)} events) ---\n")
    for t, c in sorted(event_types.items()):
        print(f"  {t}: {c}")
    # Show attack_write events
    writes = [e for e in events if e.get("event_type") == "attack_write"]
    if writes:
        print(f"\n  Attack writes executed on PLC:")
        for w in writes:
            print(f"    tag={w.get('tag','?'):15s}  value={w.get('value','?')}  "
                  f"addr={w.get('address','?')}")

# Parquet summary
try:
    import pandas as pd
    df = pd.read_parquet(run_dir / "unified_steps.parquet")
    print(f"\n--- STEP TRACE ({len(df)} rows) ---\n")
    print(f"  Columns: {list(df.columns)}")
    # Show setpoint and level evolution
    if "setpoint_in" in df.columns and "level" in df.columns:
        print(f"\n  Level/Setpoint evolution:")
        for _, row in df.iterrows():
            step = int(row.get("step", 0))
            lvl = row.get("level", 0)
            sp = row.get("setpoint_in", 0)
            dec = row.get("decision", "?")
            if step % 5 == 0 or dec == "attack":
                print(f"    step={step:3d}  level={lvl:5.2f}  setpoint={sp:5.2f}  decision={dec}")
except ImportError:
    print("\n  (pandas not available for parquet analysis)")
except Exception as e:
    print(f"\n  Parquet error: {e}")
