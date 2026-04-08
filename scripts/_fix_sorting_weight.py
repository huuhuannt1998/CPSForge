"""Fix corrupted Sorting by Weight thresholds in DB22."""
import snap7
import struct

c = snap7.client.Client()
c.connect('192.168.0.1', 0, 1)
print("Connected to PLC")

# Read current state
data = c.db_read(22, 0, 86)
lt_cur = struct.unpack('>f', data[74:78])[0]
ht_cur = struct.unpack('>f', data[78:82])[0]
state_cur = struct.unpack('>h', data[82:84])[0]
print(f"BEFORE: LightThresh={lt_cur:.2f}  HeavyThresh={ht_cur:.2f}  iState={state_cur}")

# Fix LightThresh at byte 74 (REAL) -> 2.0
c.db_write(22, 74, struct.pack('>f', 2.0))
# Fix HeavyThresh at byte 78 (REAL) -> 5.0
c.db_write(22, 78, struct.pack('>f', 5.0))
# Reset state machine at byte 82 (INT) -> 0
c.db_write(22, 82, struct.pack('>h', 0))

# Verify
data = c.db_read(22, 0, 86)
lt_new = struct.unpack('>f', data[74:78])[0]
ht_new = struct.unpack('>f', data[78:82])[0]
state_new = struct.unpack('>h', data[82:84])[0]
print(f"AFTER:  LightThresh={lt_new:.2f}  HeavyThresh={ht_new:.2f}  iState={state_new}")

c.disconnect()
print("Fixed. Scene should resume normal sorting.")
