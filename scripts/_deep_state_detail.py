"""Detailed capture analysis for deep state run."""
import json

events = [json.loads(l) for l in open('data/captures/20260407T015532Z_0fdda58c_plc_events.jsonl')]
writes = [e for e in events if e['event_type'] == 'attack_write']
polls = [e for e in events if e['event_type'] == 'poll_read']

print(f"Total attack writes: {len(writes)}")
print()
for w in writes:
    print(f"  step={w['step_id']:2d}  tag={w['tag_name']:15s}  "
          f"addr={w['address_str']}  val={w['written_value']}  "
          f"t={w['elapsed_s']:.1f}s")

print(f"\n--- LEVEL/SETPOINT from poll_reads ({len(polls)} polls) ---\n")
for p in polls:
    rv = p['read_values']
    step = p['step_id']
    lvl = rv.get('level_meter', 0)
    sp = rv.get('setpoint_in', 0)
    fill = rv.get('fill_valve', 0)
    disc = rv.get('discharge_valve', 0)
    if step % 5 == 0 or step <= 5:
        print(f"  step={step:3d}  level={lvl:5.2f}  setpoint={sp:5.2f}  "
              f"fill={fill:5.2f}  discharge={disc:5.2f}  t={p['elapsed_s']:.1f}s")

# Parquet: check observation_dict for setpoint before/after attacks
print("\n--- PARQUET ANALYSIS ---\n")
try:
    import pandas as pd
    df = pd.read_parquet('data/raw/v2_online_mitm_level_control/20260407T015532Z_0fdda58c/unified_steps.parquet')
    attack_steps = df[df['attack_active'] == True]
    print(f"Attack steps: {len(attack_steps)}")
    for _, row in attack_steps.iterrows():
        obs = row.get('observation_dict', {})
        if isinstance(obs, str):
            obs = json.loads(obs)
        sp = obs.get('setpoint_in', '?')
        lvl = obs.get('level_meter', '?')
        print(f"  step={row['step_id']:3d}  decision={row['parsed_decision']}  "
              f"target={row.get('action_target_tag','?')}  "
              f"val={row.get('action_value','?')}  "
              f"exec={row.get('write_executed','?')}  "
              f"success={row.get('attack_success','?')}  "
              f"obs_sp={sp}  obs_lvl={lvl}")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()

# Shield events structure
print("\n--- SHIELD EVENTS ---\n")
shield = json.load(open('data/raw/v2_online_mitm_level_control/20260407T015532Z_0fdda58c/shield_events.json'))
if shield:
    print(f"First shield event keys: {list(shield[0].keys())}")
    print(json.dumps(shield[0], indent=2))
