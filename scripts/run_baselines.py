"""
CPSForge Baseline + Normal Trace Runner
=========================================
Runs baseline (no-attack) traces for scenes that need normal data.
Also runs scripted/random baselines if needed.

Usage:
  python scripts/run_baselines.py
"""

import json
import signal
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cpsforge.core.config import ConfigLoader, ExperimentConfig
from cpsforge.core.orchestrator import ExperimentOrchestrator
from cpsforge.logging.logger import setup_logging

setup_logging()

interrupted = False


def _sigint_handler(signum, frame):
    global interrupted
    if interrupted:
        sys.exit(1)
    interrupted = True
    print("\nInterrupt received. Will finish current experiment and exit.")


signal.signal(signal.SIGINT, _sigint_handler)

EXPERIMENTS = [
    {
        "name": f"baseline_{scene}",
        "scene": scene,
        "attackers": [],
        "defenders": [],
        "max_steps": 100,
    }
    for scene in [
        "from_a_to_b",
        "from_a_to_b_sr",
        "filling_tank",
        "queue_items",
        "assembler",
        "assembler_analog",
        "warehouse",
        "buffer_station",
        "converge_station",
        "elevator_advanced",
        "elevator_basic",
        "level_control",
        "palletizer",
        "pick_place_basic",
        "pick_place_xyz",
        "production_line",
        "separating_station",
        "sorting_height_advanced",
        "sorting_height_basic",
        "sorting_weight",
        "sorting_station",
    ]
]

# ---------------------------------------------------------------------------
# Factory I/O driver configuration hints per scene
# ---------------------------------------------------------------------------
# Used to guide the user when switching scenes in Factory I/O.
#
# Key:  scene_name
# Value:
#   scene_id:  OB_Main CASE value (CPSForge writes this to DB_Config automatically)
#   fio_name:  Factory I/O scene filename description
#   bool_in_start:  Factory I/O Bool Inputs → Start Number (byte address)
#   bool_in_count:  Factory I/O Bool Inputs → Count
#   bool_out_start: Factory I/O Bool Outputs → Start Number (byte address)
#   bool_out_count: Factory I/O Bool Outputs → Count
#   has_analog: True if scene uses DWORD analog I/O (%ID100/%QD100+)
#   notes: extra reminders
_FACTORY_IO_HINTS = {
    #                                                          ┌─── I/O Points (Factory I/O driver panel) ───────────────────────────────────┐
    #  scene_name                  scene_id  fio_name            Bool In         Bool Out        DWORD In        DWORD Out
    #                                                           Offset Count    Offset Count    Offset Count    Offset Count
    #  NOTE: ALL scenes use Bool Inputs Offset = 10 to avoid S7-1200 built-in DI module at %IB0.
    "from_a_to_b":            {"scene_id": 1,  "fio_name": "From A to B",              "bi_off": 10, "bi_cnt": 1,  "bo_off": 0, "bo_cnt": 1,  "di_off": 100, "di_cnt": 0, "do_off": 100, "do_cnt": 0},
    "from_a_to_b_sr":         {"scene_id": 2,  "fio_name": "From A to B (SR)",         "bi_off": 10, "bi_cnt": 2,  "bo_off": 0, "bo_cnt": 1,  "di_off": 100, "di_cnt": 0, "do_off": 100, "do_cnt": 0},
    "filling_tank":           {"scene_id": 3,  "fio_name": "Filling Tank (Timers)",     "bi_off": 10, "bi_cnt": 2,  "bo_off": 0, "bo_cnt": 2,  "di_off": 100, "di_cnt": 0, "do_off": 100, "do_cnt": 0},
    "queue_items":            {"scene_id": 4,  "fio_name": "Queue of Items",            "bi_off": 10, "bi_cnt": 2,  "bo_off": 0, "bo_cnt": 3,  "di_off": 100, "di_cnt": 0, "do_off": 100, "do_cnt": 0},
    "assembler":              {"scene_id": 5,  "fio_name": "Assembler",                 "bi_off": 10, "bi_cnt": 6,  "bo_off": 0, "bo_cnt": 9,  "di_off": 100, "di_cnt": 0, "do_off": 100, "do_cnt": 0},
    "assembler_analog":       {"scene_id": 6,  "fio_name": "Assembler (Analog)",        "bi_off": 10, "bi_cnt": 4,  "bo_off": 0, "bo_cnt": 5,  "di_off": 100, "di_cnt": 2, "do_off": 100, "do_cnt": 2},
    "warehouse":              {"scene_id": 7,  "fio_name": "Automated Warehouse",       "bi_off": 10, "bi_cnt": 3,  "bo_off": 0, "bo_cnt": 5,  "di_off": 100, "di_cnt": 2, "do_off": 100, "do_cnt": 2},
    "buffer_station":         {"scene_id": 8,  "fio_name": "Buffer Station",            "bi_off": 10, "bi_cnt": 6,  "bo_off": 0, "bo_cnt": 5,  "di_off": 100, "di_cnt": 0, "do_off": 100, "do_cnt": 0},
    "converge_station":       {"scene_id": 9,  "fio_name": "Converge Station",          "bi_off": 10, "bi_cnt": 4,  "bo_off": 0, "bo_cnt": 6,  "di_off": 100, "di_cnt": 0, "do_off": 100, "do_cnt": 0},
    "elevator_advanced":      {"scene_id": 10, "fio_name": "Elevator (Advanced)",       "bi_off": 10, "bi_cnt": 19, "bo_off": 0, "bo_cnt": 26, "di_off": 100, "di_cnt": 0, "do_off": 100, "do_cnt": 1},
    "elevator_basic":         {"scene_id": 11, "fio_name": "Elevator (Basic)",          "bi_off": 10, "bi_cnt": 29, "bo_off": 0, "bo_cnt": 29, "di_off": 100, "di_cnt": 0, "do_off": 100, "do_cnt": 0},
    "level_control":          {"scene_id": 12, "fio_name": "Level Control",             "bi_off": 10, "bi_cnt": 3,  "bo_off": 0, "bo_cnt": 3,  "di_off": 100, "di_cnt": 3, "do_off": 100, "do_cnt": 4},
    "palletizer":             {"scene_id": 13, "fio_name": "Palletizer",                "bi_off": 10, "bi_cnt": 5,  "bo_off": 0, "bo_cnt": 4,  "di_off": 100, "di_cnt": 2, "do_off": 100, "do_cnt": 2},
    "pick_place_basic":       {"scene_id": 14, "fio_name": "Pick & Place (Basic)",      "bi_off": 10, "bi_cnt": 5,  "bo_off": 0, "bo_cnt": 7,  "di_off": 100, "di_cnt": 0, "do_off": 100, "do_cnt": 0},
    "pick_place_xyz":         {"scene_id": 15, "fio_name": "Pick & Place XYZ",          "bi_off": 10, "bi_cnt": 3,  "bo_off": 0, "bo_cnt": 4,  "di_off": 100, "di_cnt": 3, "do_off": 100, "do_cnt": 3},
    "production_line":        {"scene_id": 16, "fio_name": "Production Line",           "bi_off": 10, "bi_cnt": 4,  "bo_off": 0, "bo_cnt": 6,  "di_off": 100, "di_cnt": 0, "do_off": 100, "do_cnt": 0},
    "separating_station":     {"scene_id": 17, "fio_name": "Separating Station",        "bi_off": 10, "bi_cnt": 4,  "bo_off": 0, "bo_cnt": 7,  "di_off": 100, "di_cnt": 0, "do_off": 100, "do_cnt": 0},
    "sorting_height_advanced":{"scene_id": 18, "fio_name": "Sorting Height (Advanced)", "bi_off": 10, "bi_cnt": 16, "bo_off": 0, "bo_cnt": 13, "di_off": 100, "di_cnt": 0, "do_off": 100, "do_cnt": 1},
    "sorting_height_basic":   {"scene_id": 19, "fio_name": "Sorting Height (Basic)",    "bi_off": 10, "bi_cnt": 13, "bo_off": 0, "bo_cnt": 10, "di_off": 100, "di_cnt": 0, "do_off": 100, "do_cnt": 1},
    "sorting_weight":         {"scene_id": 20, "fio_name": "Sorting by Weight",         "bi_off": 10, "bi_cnt": 4,  "bo_off": 0, "bo_cnt": 6,  "di_off": 100, "di_cnt": 2, "do_off": 100, "do_cnt": 0},
    "sorting_station":        {"scene_id": 21, "fio_name": "Sorting Station",           "bi_off": 10, "bi_cnt": 4,  "bo_off": 0, "bo_cnt": 7,  "di_off": 100, "di_cnt": 0, "do_off": 100, "do_cnt": 0},
}



def run_experiment(exp_def: dict) -> dict:
    loader = ConfigLoader()
    exp_cfg = ExperimentConfig(
        name=exp_def["name"],
        scene_config=f"scenes/{exp_def['scene']}.yaml",
        attackers=exp_def["attackers"],
        defenders=exp_def["defenders"],
        dry_run=False,
        live_writes_enabled=True,  # needed for dry_run=False; no writes will happen (no attackers)
        eval_run=True,
        max_steps=exp_def["max_steps"],
    )

    print(f"\n{'='*60}")
    print(f"  Running: {exp_def['name']}")
    print(f"  Scene: {exp_def['scene']} | Steps: {exp_def['max_steps']}")
    print(f"{'='*60}")

    orchestrator = ExperimentOrchestrator(exp_cfg, loader)
    run_id = orchestrator.run()

    metrics_path = Path(f"data/raw/{exp_def['name']}/{run_id}/metrics.json")
    if metrics_path.exists():
        with open(metrics_path) as f:
            metrics = json.load(f)
        print(f"  Run ID: {run_id}")
        print(f"  Total steps: {metrics.get('total_steps', '?')}")
        return metrics
    else:
        print(f"  Run ID: {run_id} (baseline, no metrics)")
        return {"run_id": run_id, "total_steps": exp_def["max_steps"]}


def main():
    results = {}
    last_scene = None
    for exp_def in EXPERIMENTS:
        if interrupted:
            print(f"\nSkipping {exp_def['name']} (interrupted)")
            continue

        # Prompt user to load the correct Factory I/O scene
        scene = exp_def["scene"]
        if scene != last_scene:
            h = _FACTORY_IO_HINTS.get(scene, {})
            sid = h.get("scene_id", "?")
            fio = h.get("fio_name", scene)

            print(f"\n{'='*70}")
            print(f"  >>> SWITCH FACTORY I/O SCENE")
            print(f"{'='*70}")
            print(f"  Scene:  {fio}  (ID #{sid})")
            print()
            print(f"  Factory I/O  >  File  >  Drivers  >  S7 COMM  >  I/O Points")
            print(f"  ┌──────────────────┬──────────┬──────────┐")
            print(f"  │                  │  Offset  │  Count   │")
            print(f"  ├──────────────────┼──────────┼──────────┤")
            print(f"  │  Bool Inputs     │  {h.get('bi_off',0):>5}   │  {h.get('bi_cnt','?'):>5}   │")
            print(f"  │  Bool Outputs    │  {h.get('bo_off',0):>5}   │  {h.get('bo_cnt','?'):>5}   │")
            print(f"  │  DWORD Inputs    │  {h.get('di_off',100):>5}   │  {h.get('di_cnt',0):>5}   │")
            print(f"  │  DWORD Outputs   │  {h.get('do_off',100):>5}   │  {h.get('do_cnt',0):>5}   │")
            print(f"  └──────────────────┴──────────┴──────────┘")
            print()
            print(f"  Steps:")
            print(f"    1. Open Factory I/O -> load scene '{fio}'")
            print(f"    2. File -> Drivers -> S7 COMM -> set I/O Points as above")
            print(f"    3. Click CONNECT in the driver, then PLAY (green arrow)")
            print(f"    4. Press Enter here (CPSForge auto-writes ActiveScene to DB2)")
            print(f"{'='*70}")
            input("  Press Enter when Factory I/O is running... ")
            last_scene = scene

        try:
            metrics = run_experiment(exp_def)
            results[exp_def["name"]] = metrics
        except Exception as e:
            print(f"\n  ERROR in {exp_def['name']}: {e}")
            results[exp_def["name"]] = {"error": str(e)}

    summary_path = Path("data/processed/baseline_summary.json")
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with open(summary_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n{'='*60}")
    print(f"  All baseline experiments complete.")
    print(f"  Summary: {summary_path}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
