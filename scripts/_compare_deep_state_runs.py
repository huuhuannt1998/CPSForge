"""Compare deep state MITM runs: with vs without TankSimulator."""
import json
import pandas as pd
from pathlib import Path

runs = {
    "Run 1 (TankSim ON)":  "data/raw/v2_online_mitm_level_control/20260407T015532Z_0fdda58c",
    "Run 2 (TankSim OFF)": "data/raw/v2_online_mitm_level_control/20260407T020726Z_93a652a8",
}

for label, run_dir in runs.items():
    rd = Path(run_dir)
    print("=" * 70)
    print(f"  {label}")
    print(f"  Run dir: {run_dir}")
    print("=" * 70)

    # Metadata
    meta = json.load(open(rd / "metadata.json"))
    print(f"  Steps={meta['total_steps']}  Attacks={meta['total_attacks']}")

    # Capture events
    cap_path = Path(f"data/captures/{rd.name}_plc_events.jsonl")
    events = [json.loads(l) for l in open(cap_path)]
    writes = [e for e in events if e['event_type'] == 'attack_write']
    polls = [e for e in events if e['event_type'] == 'poll_read']

    # Attack summary
    targets = {}
    for w in writes:
        t = w['tag_name']
        targets[t] = targets.get(t, 0) + 1
    print(f"  Attack writes: {len(writes)} ({len(writes)//2} unique attacks)")
    print(f"  Targets: {targets}")

    # Physical effect from polls
    levels = [p['read_values'].get('level_meter', 0) for p in polls]
    setpoints = [p['read_values'].get('setpoint_in', 0) for p in polls]
    fills = [p['read_values'].get('fill_valve', 0) for p in polls]
    discharges = [p['read_values'].get('discharge_valve', 0) for p in polls]

    print(f"\n  Level:     min={min(levels):.2f}  max={max(levels):.2f}  "
          f"mean={sum(levels)/len(levels):.2f}  range={max(levels)-min(levels):.2f}")
    print(f"  Setpoint:  min={min(setpoints):.2f}  max={max(setpoints):.2f}")
    print(f"  FillValve: max={max(fills):.2f}")
    print(f"  DischValve: max={max(discharges):.2f}")

    # Count how many polls saw non-baseline values
    baseline_sp = 4.33
    sp_deviated = sum(1 for s in setpoints if abs(s - baseline_sp) > 0.05)
    lvl_deviated = sum(1 for l in levels if abs(l - baseline_sp) > 0.2)
    print(f"\n  Polls where setpoint != baseline: {sp_deviated}/{len(polls)}")
    print(f"  Polls where level deviated >0.2:   {lvl_deviated}/{len(polls)}")

    # Attack success metric: did level move toward attack target (6.0)?
    attack_target = 6.0
    polls_above_5 = sum(1 for l in levels if l > 5.0)
    polls_above_55 = sum(1 for l in levels if l > 5.5)
    print(f"  Polls with level > 5.0: {polls_above_5}/{len(polls)}")
    print(f"  Polls with level > 5.5: {polls_above_55}/{len(polls)}")

    # Duration
    t_start = polls[0]['elapsed_s']
    t_end = polls[-1]['elapsed_s']
    print(f"\n  Duration: {t_end - t_start:.1f}s")
    print()
