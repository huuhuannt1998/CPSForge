"""Quick analysis of FRONTIER Level Control results."""
import pandas as pd, json, pathlib

raw = pathlib.Path('data/raw/v2_online_mitm_level_control')
frontier_runs = []
for d in sorted(raw.iterdir()):
    meta_f = d / 'metadata.json'
    if not meta_f.exists():
        continue
    meta = json.load(open(meta_f))
    cell_id = meta.get('cell_id', '')
    model_variant = meta.get('model_variant', '')
    if model_variant != 'gpt4o_mini':
        continue
    pq_f = d / 'unified_steps.parquet'
    df = pd.read_parquet(pq_f) if pq_f.exists() else pd.DataFrame()
    attacks_f = d / 'attacks.json'
    attacks = json.load(open(attacks_f)) if attacks_f.exists() else []
    n_proposals = len(attacks)
    n_success = sum(1 for a in attacks if a.get('attack_success', False))
    n_valid = sum(1 for a in attacks if a.get('write_executed', False))
    ctx = meta.get('context_level', 'unknown')
    defense = meta.get('defense_variant', 'none')
    cell_id = f"FRONTIER_{ctx}_{defense}_{d.name[:15]}"
    repeat = '?'
    frontier_runs.append({
        'cell_id': cell_id,
        'run_id': d.name,
        'context': ctx,
        'defense': defense,
        'repeat': repeat,
        'proposals': n_proposals,
        'valid': n_valid,
        'success': n_success,
        'steps': len(df),
    })

print("=" * 80)
print("FRONTIER (GPT-4o-mini) — Level Control Results")
print("=" * 80)
print(f"{'Cell':45s}  {'Ctx':8s} {'Def':12s} Props Valid Succ")
print("-" * 80)
for r in frontier_runs:
    print(f"{r['cell_id']:45s}  {r['context']:8s} {r['defense']:12s} {r['proposals']:5d} {r['valid']:5d} {r['success']:4d}")

# Aggregate by condition
print("\n" + "=" * 80)
print("AGGREGATED BY CONDITION")
print("=" * 80)
from collections import defaultdict
agg = defaultdict(lambda: {'proposals': [], 'valid': [], 'success': []})
for r in frontier_runs:
    key = f"{r['context']}_{r['defense']}"
    agg[key]['proposals'].append(r['proposals'])
    agg[key]['valid'].append(r['valid'])
    agg[key]['success'].append(r['success'])

print(f"{'Condition':25s}  {'Avg Props':>9s} {'Avg Valid':>9s} {'Avg Succ':>8s} {'ASR':>5s} {'VAR':>5s}")
print("-" * 70)
for key in sorted(agg.keys()):
    v = agg[key]
    avg_p = sum(v['proposals']) / len(v['proposals'])
    avg_v = sum(v['valid']) / len(v['valid'])
    avg_s = sum(v['success']) / len(v['success'])
    asr = f"{avg_s/10*100:.1f}%" if avg_p > 0 else "N/A"
    var = f"{avg_v/avg_p*100:.1f}%" if avg_p > 0 else "N/A"
    print(f"{key:25s}  {avg_p:9.1f} {avg_v:9.1f} {avg_s:8.1f} {asr:>5s} {var:>5s}")

# Compare with Qwen2.5-3B baseline (if available)
print("\n" + "=" * 80)
print("COMPARISON: GPT-4o-mini vs Qwen2.5-3B (Level Control)")
print("=" * 80)
print("Qwen2.5-3B baseline: 0 proposals on minimal context (self-deterrence)")
print("GPT-4o-mini: See above — likely 10 proposals per cell (max aggressive)")
