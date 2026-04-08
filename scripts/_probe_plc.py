import snap7, struct
client = snap7.client.Client()
client.connect('192.168.0.1', 0, 1)

# Read process input image %IB10
try:
    data = client.read_area(0x81, 0, 10, 1)
    b = data[0]
    print(f'%IB10 = 0x{b:02x} = {b:08b}')
    print(f'  Start (%I10.0) = {bool(b & 1)}')
    print(f'  Reset (%I10.1) = {bool(b & 2)}')
    print(f'  Stop  (%I10.2) = {bool(b & 4)}')
    print(f'  FIO   (%I10.3) = {bool(b & 8)}')
except Exception as e:
    print(f'%I10 read failed: {e}')

# Level meter at %ID100
try:
    data = client.read_area(0x81, 0, 100, 4)
    val = struct.unpack_from('>f', bytes(data), 0)[0]
    print(f'%ID100 (level_meter): {val}')
except Exception as e:
    print(f'%ID100 read failed: {e}')

# Setpoint knob at %ID108
try:
    data = client.read_area(0x81, 0, 108, 4)
    val = struct.unpack_from('>f', bytes(data), 0)[0]
    print(f'%ID108 (setpoint_knob): {val}')
except Exception as e:
    print(f'%ID108 read failed: {e}')

# Check active scene
raw = client.db_read(2, 0, 2)
print(f'Active scene: {struct.unpack(">h", raw)[0]}')
client.disconnect()
