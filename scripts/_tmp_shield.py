import json
d = json.load(open(r'data\raw\v2_online_mitm_level_control\20260406T234616Z_b4c63465\shield_events.json'))
approved = [s for s in d if s['approved']]
blocked = [s for s in d if not s['approved']]
print(f'Total: {len(d)}, Approved: {len(approved)}, Blocked: {len(blocked)}')
for s in blocked:
    print(f'  BLOCKED: {s["reasons"]}')
for s in approved:
    print(f'  APPROVED: val={s.get("normalized_value","?")} tag={s.get("target_tag","?")}')
