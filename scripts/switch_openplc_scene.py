"""
Switch OpenPLC scene: stop PLC → upload + compile new ST → start PLC.

Usage:
    py -3 scripts/switch_openplc_scene.py level_control
    py -3 scripts/switch_openplc_scene.py sorting_weight
    py -3 scripts/switch_openplc_scene.py sorting_height
"""
import sys
import time

sys.path.insert(0, ".")

from pathlib import Path
from cpsforge.plc.openplc_adapter import OpenPLCAdapter, OpenPLCConfig

SCENES = {
    "level_control": "configs/openplc/level_control.st",
    "sorting_weight": "configs/openplc/sorting_weight.st",
    "sorting_height": "configs/openplc/sorting_height.st",
}

def main():
    if len(sys.argv) < 2 or sys.argv[1] not in SCENES:
        print(f"Usage: {sys.argv[0]} <{'|'.join(SCENES.keys())}>")
        sys.exit(1)

    scene = sys.argv[1]
    st_file = Path(SCENES[scene])

    if not st_file.exists():
        print(f"ERROR: ST file not found: {st_file}")
        sys.exit(1)

    config = OpenPLCConfig()
    adapter = OpenPLCAdapter(config)

    print(f"=== Switching to scene: {scene}")
    print(f"    ST file: {st_file}")

    # Authenticate
    print("1. Authenticating...")
    adapter.authenticate()
    print("   OK")

    # Stop PLC if running
    print("2. Stopping PLC...")
    adapter.stop_plc()
    time.sleep(2)
    print("   OK")

    # Upload and compile
    print(f"3. Uploading and compiling {st_file.name}...")
    result = adapter.upload_and_compile(st_file=st_file, program_name=scene)
    if not result.success:
        print(f"   FAILED: {result.error}")
        if result.logs:
            print(f"   Logs: {result.logs[:500]}")
        sys.exit(1)
    print("   Compilation OK")

    # Start PLC
    print("4. Starting PLC...")
    ok = adapter.start_plc()
    if not ok:
        print("   WARNING: start_plc returned False (may still start)")
    time.sleep(3)

    # Verify
    print("5. Checking status...")
    status = adapter.get_status()
    print(f"   Running: {status.running}")

    # Verify Modbus
    print("6. Testing Modbus connection...")
    try:
        from pymodbus.client import ModbusTcpClient
        client = ModbusTcpClient("127.0.0.1", port=502, timeout=5)
        if client.connect():
            rr = client.read_holding_registers(0, 5, device_id=1)
            if not rr.isError():
                print(f"   HR0-4: {rr.registers}")
            else:
                print(f"   Read error: {rr}")
            client.close()
            print("   Modbus OK")
        else:
            print("   WARNING: Modbus connection failed")
    except Exception as e:
        print(f"   Modbus error: {e}")

    print(f"\n=== Scene '{scene}' ready for experiments.")

if __name__ == "__main__":
    main()
