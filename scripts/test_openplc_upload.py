"""Quick test: upload ST → compile → start → check Modbus."""
import sys
import time

sys.path.insert(0, ".")

from pathlib import Path
from cpsforge.plc.openplc_adapter import OpenPLCAdapter, OpenPLCConfig

config = OpenPLCConfig()
adapter = OpenPLCAdapter(config)

print("=== Authenticating...")
adapter.authenticate()
print("OK - authenticated")

print("=== Uploading level_control.st...")
result = adapter.upload_and_compile(
    st_file=Path("configs/openplc/level_control.st")
)
print(f"Compilation success: {result.success}")
if result.logs:
    print(f"Logs (first 500 chars): {result.logs[:500]}")
if result.error:
    print(f"Error: {result.error[:500]}")

if not result.success:
    print("Compilation failed — stopping.")
    sys.exit(1)

print("=== Starting PLC...")
ok = adapter.start_plc()
print(f"Start result: {ok}")

time.sleep(3)

print("=== Getting status...")
status = adapter.get_status()
print(f"Running: {status.running}")
print(f"Raw: {status.raw}")

# Try Modbus connection
print("=== Testing Modbus connection...")
try:
    from pymodbus.client import ModbusTcpClient
    client = ModbusTcpClient("127.0.0.1", port=502, timeout=5)
    connected = client.connect()
    print(f"Modbus connected: {connected}")
    if connected:
        # Read HR0-HR12 (holding registers)
        rr = client.read_holding_registers(0, 13, device_id=1)
        if not rr.isError():
            print(f"HR0-HR12: {rr.registers}")
        else:
            print(f"Read error: {rr}")
        
        # Read COIL0-1
        cr = client.read_coils(0, 2, device_id=1)
        if not cr.isError():
            print(f"COIL0-1: {cr.bits[:2]}")
        else:
            print(f"Coil read error: {cr}")
        
        # Write HR12 (setpoint = 500 = 5.0V)
        wr = client.write_register(12, 500, device_id=1)
        print(f"Write HR12=500: {wr}")
        
        client.close()
except Exception as exc:
    print(f"Modbus error: {exc}")

print("=== Done.")
