#!/usr/bin/env python3
"""
CPSForge — Standalone PLC Probe Script
========================================
Tests the TCP/IP connection to a real Siemens S7 PLC and optionally reads
all tags from a scene. Equivalent to ``cpsforge plc probe`` but works as a
plain script without the full CLI installed.

Usage
-----
  python scripts/probe_plc.py
  python scripts/probe_plc.py --host 192.168.0.1 --rack 0 --slot 1
  python scripts/probe_plc.py --scene tank_control --read-tags

Arguments
---------
  --host       PLC IP address (default: 192.168.0.1)
  --rack       PLC rack number (default: 0)
  --slot       PLC slot number (default: 1, S7-1200/1500; use 2 for S7-300/400)
  --port       TCP port (default: 102)
  --scene      If specified, read all tags from this scene after connecting
  --read-tags  Read all scene tags and print their current values
  --timeout    Connection timeout in seconds (default: 5.0)

Exit codes
----------
  0  PLC reachable (and health check passed)
  1  Connection failed
  2  Connected but health check failed
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure the project root is importable when run from any directory.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _probe(host: str, rack: int, slot: int, port: int, timeout: float) -> int:
    """
    Attempt a PLC connection and health check.

    Returns an exit code (0 = OK, 1 = failed to connect, 2 = no health data).
    """
    from cpsforge.core.config import PLCConfig
    from cpsforge.plc.client import PlcClient, PLCConnectionError

    cfg = PLCConfig(
        host=host,
        rack=rack,
        slot=slot,
        port=port,
        connect_timeout_s=timeout,
        live_writes_enabled=False,  # probe never writes
    )
    client = PlcClient(cfg)
    print(f"\nProbing PLC at {host}:{port}  (rack={rack}, slot={slot}) ...")

    try:
        client.connect()
    except PLCConnectionError as exc:
        print(f"  FAILED  Could not connect: {exc}")
        return 1
    except ImportError as exc:
        print(f"  ERROR   {exc}")
        print("  Hint: install python-snap7 and ensure snap7.dll / libsnap7.so is on PATH.")
        return 1

    try:
        if client.health_check():
            print("  OK      PLC is reachable and responding to CPU-info request.")
            return 0
        else:
            print("  WARNING Connected but health_check returned no CPU info.")
            return 2
    finally:
        client.disconnect()
        print("  Disconnected.")


def _read_scene_tags(host: str, rack: int, slot: int, port: int, scene_name: str) -> int:
    """Connect and read all tags from the named scene."""
    from cpsforge.core.config import ConfigLoader, PLCConfig
    from cpsforge.plc.client import PlcClient, PLCConnectionError
    from cpsforge.scenes.factory import load_scene

    loader = ConfigLoader()
    cfg = PLCConfig(host=host, rack=rack, slot=slot, port=port, live_writes_enabled=False)
    client = PlcClient(cfg)

    try:
        scene = load_scene(scene_name, loader)
    except FileNotFoundError:
        print(f"  ERROR   Scene config not found: {scene_name}")
        return 1

    print(f"\nConnecting to {host} and reading tags from '{scene_name}' ...")
    try:
        client.connect()
    except PLCConnectionError as exc:
        print(f"  FAILED  {exc}")
        return 1

    try:
        results = client.read_many(scene.get_all_tags())
    except Exception as exc:
        print(f"  ERROR   read_many failed: {exc}")
        return 1
    finally:
        client.disconnect()

    print(f"\n{'Tag':<30}  {'Value':<15}  {'Unit':<8}  Category")
    print("-" * 70)
    for tag in scene.get_all_tags():
        val = results.get(tag.name)
        val_str = f"{val:.4f}" if isinstance(val, float) else str(val)
        print(f"  {tag.name:<28}  {val_str:<15}  {tag.unit or '':<8}  {tag.category.value}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Standalone probe for a Siemens S7 PLC. "
            "Default target: 192.168.0.1."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--host", default="192.168.0.1", help="PLC IP address")
    parser.add_argument("--rack", type=int, default=0, help="PLC rack number")
    parser.add_argument("--slot", type=int, default=1, help="PLC slot number")
    parser.add_argument("--port", type=int, default=102, help="ISO-on-TCP port")
    parser.add_argument("--timeout", type=float, default=5.0, help="Connection timeout (s)")
    parser.add_argument(
        "--scene", default=None,
        help="Scene name to read tags from (e.g. tank_control). Requires --read-tags.",
    )
    parser.add_argument(
        "--read-tags", action="store_true",
        help="After connecting, read and print all tags from --scene.",
    )
    args = parser.parse_args()

    if args.read_tags and args.scene:
        rc = _read_scene_tags(args.host, args.rack, args.slot, args.port, args.scene)
    else:
        rc = _probe(args.host, args.rack, args.slot, args.port, args.timeout)

    sys.exit(rc)


if __name__ == "__main__":
    main()
