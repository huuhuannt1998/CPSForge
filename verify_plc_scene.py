"""
verify_plc_scene.py — Read live PLC tags from a loaded Factory I/O scene.

Run from PowerShell BEFORE starting experiments to confirm:
  1. The PLC is connected and responding
  2. The correct scene is loaded in Factory I/O
  3. Tag values are non-zero (process is running)

Usage:
  python verify_plc_scene.py --scene level_control
  python verify_plc_scene.py --scene sorting_weight
  python verify_plc_scene.py --scene filling_tank
  python verify_plc_scene.py --scene from_a_to_b
  python verify_plc_scene.py --scene sorting_height_basic
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--scene", required=True, help="Scene name to verify")
    p.add_argument("--steps", type=int, default=10, help="Steps to poll (default: 10)")
    args = p.parse_args()

    from cpsforge.core.config import ConfigLoader
    from cpsforge.scenes.factory import load_scene
    from cpsforge.plc.client import PlcClient

    loader = ConfigLoader(configs_dir=Path("configs"))
    scene = load_scene(args.scene, loader)
    plc_cfg = loader.load_plc()
    plc_cfg.live_writes_enabled = False  # read-only verify

    print(f"\nScene: {args.scene}")
    print(f"Tags: {len(scene.profile.tags)}")
    print(f"Connecting to PLC at {plc_cfg.host}...")

    client = PlcClient(plc_cfg)
    client.connect()
    print(f"PLC connected: {client.is_connected()}\n")

    import time

    for step in range(args.steps):
        try:
            raw = client.read_many(scene.profile.tags)
        except Exception as exc:
            print(f"Step {step}: READ ERROR: {exc}")
            time.sleep(0.5)
            continue

        print(f"Step {step:3d} | ", end="")
        # Print first 6 tags for quick sanity check
        preview = list(raw.items())[:6]
        for name, val in preview:
            if isinstance(val, float):
                print(f"{name}={val:.2f}", end="  ")
            else:
                print(f"{name}={val}", end="  ")
        print()
        time.sleep(0.5)

    client.disconnect()
    print("\nDone. If you see non-None, non-zero values, the scene is loaded correctly.")


if __name__ == "__main__":
    main()
