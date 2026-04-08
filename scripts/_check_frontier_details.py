"""Check attack details for FRONTIER runs."""
import json, pathlib

# Check a minimal context cell
run_dir = pathlib.Path('data/raw/v2_online_mitm_level_control/20260407T223231Z_556bfe57')
attacks = json.load(open(run_dir / 'attacks.json'))
print(f"=== Minimal context run: {len(attacks)} proposals ===")
for i, atk in enumerate(attacks):
    print(f"  {i}: target={atk['target']:15s} value={str(atk.get('value','?')):8s} "
          f"status={atk.get('execution_status','?')} shield={atk.get('approved_by_shield','?')}")

# Check parquet for write_executed, attack_success columns
import pandas as pd
df = pd.read_parquet(run_dir / 'unified_steps.parquet')
print(f"\nParquet columns: {list(df.columns)}")
attack_cols = [c for c in df.columns if 'attack' in c.lower() or 'write' in c.lower() or 'shield' in c.lower() or 'block' in c.lower()]
print(f"Attack-related columns: {attack_cols}")

# Show steps with attack decisions
if 'llm_decision' in df.columns:
    attack_steps = df[df['llm_decision'] == 'attack']
    print(f"\nSteps with llm_decision='attack': {len(attack_steps)}")
    if len(attack_steps) > 0:
        print(attack_steps[['step', 'llm_decision'] + [c for c in attack_cols if c in df.columns]].head(5).to_string())

# Check defense cell
print("\n\n=== LLM Defender cell ===")
def_dir = pathlib.Path('data/raw/v2_online_mitm_level_control/20260407T224215Z_cbc4fe1a')
def_attacks = json.load(open(def_dir / 'attacks.json'))
print(f"Proposals in attacks.json: {len(def_attacks)}")
def_df = pd.read_parquet(def_dir / 'unified_steps.parquet')
if 'llm_decision' in def_df.columns:
    att_steps = def_df[def_df['llm_decision'] == 'attack']
    print(f"Steps with llm_decision='attack': {len(att_steps)}")

# Check shield_events
shield_f = def_dir / 'shield_events.json'
if shield_f.exists():
    shields = json.load(open(shield_f))
    print(f"Shield events: {len(shields)}")
    if shields:
        print(json.dumps(shields[0], indent=2, default=str))

# Check detections
det_f = def_dir / 'detections.json'
if det_f.exists():
    dets = json.load(open(det_f))
    print(f"Detections: {len(dets)}")
    if dets:
        print(json.dumps(dets[0], indent=2, default=str))
