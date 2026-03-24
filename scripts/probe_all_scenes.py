#!/usr/bin/env python3
"""
Quick probe script for all 21 Factory I/O scenes.

For each scene:
  1. Write ActiveScene to DB2
  2. Wait for user to load the scene in Factory I/O
  3. Read the scene's DB and all mapped I/O
  4. Print a summary of all tag values

Usage:
  python scripts/probe_all_scenes.py                   # interactive, all scenes
  python scripts/probe_all_scenes.py --scene 1         # single scene
  python scripts/probe_all_scenes.py --scene 1 --loop  # read scene 1 in a loop
"""

import argparse
import snap7
import struct
import time
import sys
import io

PLC_IP = "192.168.0.1"
RACK, SLOT = 0, 1

# Log file handle — set in main()
_log_file = None

def log(msg=""):
    """Print to stdout and optionally to log file."""
    print(msg)
    if _log_file:
        _log_file.write(msg + "\n")
        _log_file.flush()

# Scene definitions: scene_id, name, db_number, db_size, fields
# Fields: (name, byte_offset, type)  type: 'bool', 'int', 'real', 'byte'
SCENES = {
    1: {
        "name": "From A to B",
        "db": 3, "size": 6,
        "fields": [
            ("Sensor",   0, "bool"),
            ("Conveyor", 2, "bool"),
            ("Enable",   4, "bool"),
        ],
        "bi_cnt": 1, "bo_cnt": 1,
    },
    2: {
        "name": "From A to B (SR)",
        "db": 4, "size": 12,
        "fields": [
            ("SensorA",         0, "bool"),
            ("SensorB",         2, "bool"),
            ("FIO_Running",      4, "bool"),
            ("Conveyor",         6, "bool"),
            ("ConveyorRunning",  8, "bool"),
            ("Enable",          10, "bool"),
        ],
        "bi_cnt": 3, "bo_cnt": 1,
    },
    3: {
        "name": "Filling Tank",
        "db": 5, "size": 18,
        "fields": [
            ("SensorFill",   0, "bool"),
            ("SensorDrain",  2, "bool"),
            ("FIO_Running",  4, "bool"),
            ("FillValve",    6, "bool"),
            ("Filling",      8, "bool"),
            ("DrainValve",  10, "bool"),
            ("Discharging", 12, "bool"),
            ("IsFilling",   14, "bool"),
            ("Enable",      16, "bool"),
        ],
        "bi_cnt": 3, "bo_cnt": 4,
    },
    4: {
        "name": "Queue of Items",
        "db": 6, "size": 24,
        "fields": [
            ("AtEntry",     0, "bool"),
            ("AtExit",      2, "bool"),
            ("Conveyor",    4, "bool"),
            ("Emitter",     6, "bool"),
            ("Remover",     8, "bool"),
            ("BoxCount",   10, "int"),
            ("MaxCount",   12, "int"),
            ("iState",     14, "int"),
            ("EntryPrev",  16, "bool"),
            ("ExitPrev",   18, "bool"),
            ("EmitTimer",  20, "int"),
            ("Enable",     22, "bool"),
        ],
        "bi_cnt": 2, "bo_cnt": 3,
    },
    5: {
        "name": "Assembler",
        "db": 7, "size": 26,
        "fields": [
            ("PartAtPickup", 0, "bool"),
            ("PartAtPlace",  2, "bool"),
            ("LidAtPickup",  4, "bool"),
            ("ClampSensor",  6, "bool"),
            ("MovingX",      8, "bool"),
            ("MovingZ",     10, "bool"),
            ("ConveyorBase",12, "bool"),
            ("ConveyorLid", 14, "bool"),
            ("ConveyorOut", 16, "bool"),
            ("MoveX",      18, "bool"),
            ("MoveZ",      20, "bool"),
            ("Clamp",      22, "bool"),
            ("Emitter",    24, "bool"),
        ],
        "bi_cnt": 6, "bo_cnt": 9,
    },
    6: {
        "name": "Assembler Analog",
        "db": 8, "size": 36,
        "fields": [
            ("PartAtPickup", 0, "bool"),
            ("PartAtPlace",  2, "bool"),
            ("LidAtPickup",  4, "bool"),
            ("ClampSensor",  6, "bool"),
            ("PosX",         8, "real"),
            ("PosZ",        12, "real"),
            ("ConveyorBase",16, "bool"),
            ("ConveyorLid", 18, "bool"),
            ("ConveyorOut", 20, "bool"),
            ("Clamp",       22, "bool"),
            ("Emitter",     24, "bool"),
            ("SetpointX",   26, "real"),
            ("SetpointZ",   30, "real"),
            ("iState",      34, "int"),
        ],
        "bi_cnt": 4, "bo_cnt": 5, "di_cnt": 2, "do_cnt": 2,
    },
    7: {
        "name": "Automated Warehouse",
        "db": 9, "size": 34,
        "fields": [
            ("AtEntry",      0, "bool"),
            ("AtExit",       2, "bool"),
            ("CraneFork",    4, "bool"),
            ("CraneX",       6, "real"),
            ("CraneZ",      10, "real"),
            ("ConveyorIn",  14, "bool"),
            ("ConveyorOut", 16, "bool"),
            ("ForkExtend",  18, "bool"),
            ("ForkRetract", 20, "bool"),
            ("Emitter",     22, "bool"),
            ("CraneMoveX",  24, "real"),
            ("CraneMoveZ",  28, "real"),
            ("iState",      32, "int"),
        ],
        "bi_cnt": 3, "bo_cnt": 5, "di_cnt": 2, "do_cnt": 2,
    },
    8: {
        "name": "Buffer Station",
        "db": 10, "size": 28,
        "fields": [
            ("Sensor1",    0, "bool"),
            ("Sensor2",    2, "bool"),
            ("Sensor3",    4, "bool"),
            ("Sensor4",    6, "bool"),
            ("Sensor5",    8, "bool"),
            ("AtExit",    10, "bool"),
            ("Conveyor",  12, "bool"),
            ("Stopper1",  14, "bool"),
            ("Stopper2",  16, "bool"),
            ("Emitter",   18, "bool"),
            ("Remover",   20, "bool"),
            ("iState",    22, "int"),
            ("BoxCount",  24, "int"),
            ("BufferMax", 26, "int"),
        ],
        "bi_cnt": 6, "bo_cnt": 5,
    },
    9: {
        "name": "Converge Station",
        "db": 11, "size": 22,
        "fields": [
            ("SensorLeft",    0, "bool"),
            ("SensorRight",   2, "bool"),
            ("SensorMerge",   4, "bool"),
            ("AtExit",        6, "bool"),
            ("ConveyorLeft",  8, "bool"),
            ("ConveyorRight",10, "bool"),
            ("ConveyorOut",  12, "bool"),
            ("Emitter1",    14, "bool"),
            ("Emitter2",    16, "bool"),
            ("Remover",     18, "bool"),
            ("Priority",    20, "bool"),
        ],
        "bi_cnt": 4, "bo_cnt": 6,
    },
    10: {
        "name": "Elevator Advanced",
        "db": 12, "size": 110,
        "fields": [
            ("At1",           0, "bool"),
            ("At2",           2, "bool"),
            ("At3",           4, "bool"),
            ("AtElevator",    6, "bool"),
            ("AtEntry",       8, "bool"),
            ("AtExit",       10, "bool"),
            ("iState",       96, "int"),
            ("Enable",      104, "bool"),
        ],
        "bi_cnt": 19, "bo_cnt": 26,
    },
    11: {
        "name": "Elevator Basic",
        "db": 13, "size": 128,
        "fields": [
            ("AtEntry",      0, "bool"),
            ("LeftState",   98, "int"),
            ("RightState", 100, "int"),
            ("Enable",     126, "bool"),
        ],
        "bi_cnt": 29, "bo_cnt": 29,
    },
    12: {
        "name": "Level Control",
        "db": 14, "size": 44,
        "fields": [
            ("Start",         0, "bool"),
            ("Reset",         2, "bool"),
            ("Stop",          4, "bool"),
            ("LevelMeter",    6, "real"),
            ("FlowMeter",    10, "real"),
            ("SetpointIn",   14, "real"),
            ("Running",      18, "bool"),
            ("FillValve",    20, "real"),
            ("DischargeValve",24,"real"),
            ("Setpoint",     28, "real"),
            ("Error",        32, "real"),
            ("SP_Display",   36, "int"),   # actually DINT
            ("PV_Display",   40, "int"),   # actually DINT
        ],
        "bi_cnt": 3, "bo_cnt": 3, "di_cnt": 3, "do_cnt": 4,
    },
    13: {
        "name": "Palletizer",
        "db": 15, "size": 34,
        "fields": [
            ("BoxAtEntry",    0, "bool"),
            ("BoxAtPickup",   2, "bool"),
            ("PalletReady",   4, "bool"),
            ("LayerComplete", 6, "bool"),
            ("ClampSensor",   8, "bool"),
            ("ConveyorIn",   10, "bool"),
            ("Clamp",        12, "bool"),
            ("ConveyorOut",  14, "bool"),
            ("Emitter",      16, "bool"),
            ("iState",       32, "int"),
        ],
        "bi_cnt": 5, "bo_cnt": 4, "di_cnt": 2, "do_cnt": 2,
    },
    14: {
        "name": "Pick & Place Basic",
        "db": 16, "size": 24,
        "fields": [
            ("ItemAtPick",    0, "bool"),
            ("ItemAtPlace",   2, "bool"),
            ("GripperClosed", 4, "bool"),
            ("ArmAtPick",     6, "bool"),
            ("ArmAtPlace",    8, "bool"),
            ("ConveyorIn",   10, "bool"),
            ("ConveyorOut",  12, "bool"),
            ("Gripper",      14, "bool"),
            ("ArmRotate",    16, "bool"),
            ("ArmUp",        18, "bool"),
            ("ArmDown",      20, "bool"),
            ("Emitter",      22, "bool"),
        ],
        "bi_cnt": 5, "bo_cnt": 7,
    },
    15: {
        "name": "Pick & Place XYZ",
        "db": 17, "size": 38,
        "fields": [
            ("BoxAtPick",     0, "bool"),
            ("PalletReady",   2, "bool"),
            ("GripperClosed", 4, "bool"),
            ("Gripper",       6, "bool"),
            ("ConveyorIn",    8, "bool"),
            ("ConveyorPallet",10, "bool"),
            ("Emitter",      12, "bool"),
            ("iState",       36, "int"),
        ],
        "bi_cnt": 3, "bo_cnt": 4, "di_cnt": 3, "do_cnt": 3,
    },
    16: {
        "name": "Production Line",
        "db": 18, "size": 24,
        "fields": [
            ("LidReady",      0, "bool"),
            ("BaseReady",     2, "bool"),
            ("LidAtAssembly", 4, "bool"),
            ("BaseAtAssembly",6, "bool"),
            ("LidMachine",    8, "bool"),
            ("BaseMachine",  10, "bool"),
            ("ConveyorLid",  12, "bool"),
            ("ConveyorBase", 14, "bool"),
            ("ConveyorOut",  16, "bool"),
            ("Emitter",      18, "bool"),
            ("LidCount",     20, "int"),
            ("BaseCount",    22, "int"),
        ],
        "bi_cnt": 4, "bo_cnt": 6,
    },
    17: {
        "name": "Separating Station",
        "db": 19, "size": 26,
        "fields": [
            ("PartAtEntry",   0, "bool"),
            ("VisionSensor",  2, "int"),
            ("AtDiverter",    4, "bool"),
            ("AtExitLeft",    6, "bool"),
            ("AtExitRight",   8, "bool"),
            ("ConveyorIn",   10, "bool"),
            ("ConveyorLeft", 12, "bool"),
            ("ConveyorRight",14, "bool"),
            ("Diverter",     16, "bool"),
            ("Emitter",      18, "bool"),
            ("RemoverLeft",  20, "bool"),
            ("RemoverRight", 22, "bool"),
            ("DetectedColor",24, "int"),
        ],
        "bi_cnt": 4, "bo_cnt": 7,
    },
    18: {
        "name": "Sorting Height Advanced",
        "db": 20, "size": 76,
        "fields": [
            ("AtEntry",          0, "bool"),
            ("LowBox",           2, "bool"),
            ("HighBox",          4, "bool"),
            ("AtTurntableEntry", 6, "bool"),
            ("iState",          56, "int"),
            ("Enable",          72, "bool"),
        ],
        "bi_cnt": 16, "bo_cnt": 13,
    },
    19: {
        "name": "Sorting Height Basic",
        "db": 21, "size": 62,
        "fields": [
            ("HighSensor",     0, "bool"),
            ("LowSensor",     2, "bool"),
            ("PalletSensor",   4, "bool"),
            ("Loaded",         6, "bool"),
            ("iState",        48, "int"),
            ("Enable",        60, "bool"),
        ],
        "bi_cnt": 13, "bo_cnt": 10,
    },
    20: {
        "name": "Sorting by Weight",
        "db": 22, "size": 86,
        "fields": [
            ("AtScaleEntry",    0, "bool"),
            ("AtScale",         2, "bool"),
            ("AtScaleExit",     4, "bool"),
            ("AtLeftEntry",     6, "bool"),
            ("AtExitLeft",      8, "bool"),
            ("AtForwardEntry", 10, "bool"),
            ("AtExitFront",    12, "bool"),
            ("AtRightEntry",   14, "bool"),
            ("AtExitRight",    16, "bool"),
            ("BtnStart",       18, "bool"),
            ("BtnReset",       20, "bool"),
            ("BtnStop",        22, "bool"),
            ("BtnAuto",        24, "bool"),
            ("FIO_Running",    26, "bool"),
            ("Weight",         28, "real"),
            ("EntryConveyor",  32, "bool"),
            ("LoadScale",      34, "bool"),
            ("SendLeft",       36, "bool"),
            ("LeftConveyor",   38, "bool"),
            ("SendRight",      40, "bool"),
            ("RightConveyor",  42, "bool"),
            ("SendForward",    44, "bool"),
            ("FrontConveyor",  46, "bool"),
            ("StartLight",     48, "bool"),
            ("ResetLight",     50, "bool"),
            ("StopLight",      52, "bool"),
            ("LeftCount",      54, "dint"),
            ("ForwardCount",   58, "dint"),
            ("RightCount",     62, "dint"),
            ("WeightDisplay",  66, "dint"),
            ("MeasuredWeight", 70, "real"),
            ("LightThresh",    74, "real"),
            ("HeavyThresh",    78, "real"),
            ("iState",         82, "int"),
            ("Enable",         84, "bool"),
        ],
        "bi_cnt": 14, "bo_cnt": 11, "di_cnt": 1, "do_cnt": 4,
    },
    21: {
        "name": "Sorting Station",
        "db": 23, "size": 26,
        "fields": [
            ("ItemAtEntry",   0, "bool"),
            ("VisionColor",   2, "int"),
            ("AtDiverter",    4, "bool"),
            ("AtExitGreen",   6, "bool"),
            ("AtExitBlue",    8, "bool"),
            ("ConveyorIn",   10, "bool"),
            ("ConveyorGreen",12, "bool"),
            ("ConveyorBlue", 14, "bool"),
            ("Diverter",     16, "bool"),
            ("Emitter",      18, "bool"),
            ("RemoverGreen", 20, "bool"),
            ("RemoverBlue",  22, "bool"),
            ("DetectedColor",24, "int"),
        ],
        "bi_cnt": 4, "bo_cnt": 7,
    },
}


def read_field(data: bytearray, offset: int, ftype: str):
    if ftype == "bool":
        return bool(data[offset] & 1)
    elif ftype == "int":
        return struct.unpack(">h", data[offset:offset+2])[0]
    elif ftype == "real":
        return struct.unpack(">f", data[offset:offset+4])[0]
    elif ftype == "dint":
        return struct.unpack(">i", data[offset:offset+4])[0]
    elif ftype == "byte":
        return data[offset]
    return None


def probe_scene(client, scene_id: int, loop: bool = False):
    scene = SCENES[scene_id]
    log(f"\n{'='*60}")
    log(f"  Scene {scene_id}: {scene['name']}")
    log(f"  DB{scene['db']}, {scene['size']} bytes")
    log(f"{'='*60}")

    # Set ActiveScene
    data = bytearray(2)
    struct.pack_into(">h", data, 0, scene_id)
    client.db_write(2, 0, data)
    time.sleep(0.3)

    iterations = 0
    while True:
        try:
            db = client.db_read(scene["db"], 0, scene["size"])
        except Exception as e:
            log(f"  ERROR reading DB{scene['db']}: {e}")
            log(f"  DB size may differ from expected {scene['size']} bytes.")
            log(f"  Try reducing size or check TIA Portal.")
            return

        # Read physical I/O
        i10 = client.read_area(snap7.Area.PE, 0, 10, 4)  # IB10-IB13
        q0 = client.read_area(snap7.Area.PA, 0, 0, 4)    # QB0-QB3

        log(f"\n  --- Sample {iterations} ---")
        for fname, foff, ftype in scene["fields"]:
            val = read_field(db, foff, ftype)
            if ftype == "real":
                log(f"    {fname:20s} = {val:8.2f}  (byte {foff})")
            else:
                log(f"    {fname:20s} = {str(val):8s}  (byte {foff})")

        # Show raw I/O bytes
        log(f"    {'--- Physical I/O ---':20s}")
        for b in range(min(4, (scene.get("bi_cnt", 0) + 7) // 8)):
            log(f"    IB{10+b:2d}               = {i10[b]:08b}")
        for b in range(min(4, (scene.get("bo_cnt", 0) + 7) // 8)):
            log(f"    QB{b:2d}                = {q0[b]:08b}")

        iterations += 1
        if not loop:
            break
        time.sleep(1)
        if iterations >= 30:
            break


def main():
    global _log_file
    parser = argparse.ArgumentParser(description="Probe Factory I/O scenes on PLC")
    parser.add_argument("--scene", type=int, help="Scene ID (1-21) to probe")
    parser.add_argument("--loop", action="store_true", help="Read in a loop (30 samples)")
    parser.add_argument("--all", action="store_true", help="Probe all scenes sequentially")
    parser.add_argument("--log", type=str, default="data/probe_log.txt",
                        help="Log file path (default: data/probe_log.txt)")
    args = parser.parse_args()

    _log_file = open(args.log, "w", encoding="utf-8")
    log(f"Probe log started at {time.strftime('%Y-%m-%d %H:%M:%S')}")

    client = snap7.client.Client()
    client.connect(PLC_IP, RACK, SLOT)
    log(f"Connected to PLC at {PLC_IP}")

    try:
        if args.scene:
            if args.scene not in SCENES:
                log(f"Unknown scene {args.scene}. Valid: 1-21")
                return
            probe_scene(client, args.scene, loop=args.loop)
        elif args.all:
            for sid in sorted(SCENES.keys()):
                input(f"\n  Load scene '{SCENES[sid]['name']}' in Factory I/O, click Start, press Enter...")
                probe_scene(client, sid)
        else:
            # Default: ask which scene
            print("\nAvailable scenes:")
            for sid in sorted(SCENES.keys()):
                print(f"  {sid:2d}: {SCENES[sid]['name']}")
            choice = input("\nEnter scene ID (1-21): ").strip()
            if choice.isdigit() and int(choice) in SCENES:
                probe_scene(client, int(choice), loop=args.loop)
            else:
                print("Invalid selection.")
    except KeyboardInterrupt:
        log("\nInterrupted.")
    finally:
        client.disconnect()
        log("Disconnected.")
        if _log_file:
            _log_file.close()
        print(f"\nLog saved to: {args.log}")


if __name__ == "__main__":
    main()
