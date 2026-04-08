"""Test: rotate wheels first for a longer time, then push."""
import snap7, struct, time

c = snap7.client.Client()
c.connect('192.168.0.1', 0, 1)

def hold_state():
    c.db_write(22, 82, struct.pack('>h', 99))

def set_outputs(ec=0, ls=0, sl=0, sr=0, sf=0):
    data = c.db_read(22, 32, 14)
    data[0] = ec; data[2] = ls; data[4] = sl; data[8] = sr; data[12] = sf
    c.db_write(22, 32, data)
    hold_state()

def read_sensors():
    data = c.db_read(22, 0, 32)
    w = struct.unpack('>f', data[28:32])[0]
    return {
        'AtScale': bool(data[2]), 'AtScaleExit': bool(data[4]),
        'AtLeftEntry': bool(data[6]), 'AtForwardEntry': bool(data[10]),
        'AtRightEntry': bool(data[14]), 'Weight': w,
    }

hold_state()
set_outputs()
time.sleep(1)

# Feed box
print("Feeding box...")
set_outputs(ec=1, ls=1)
for i in range(60):
    s = read_sensors()
    hold_state()
    if s['AtScale'] and s['Weight'] > 0.5:
        print(f"  Box on scale! W={s['Weight']:.2f}")
        break
    time.sleep(0.5)

# Stop and settle
set_outputs()
time.sleep(2)
s = read_sensors()
print(f"Settled: AtScale={s['AtScale']} W={s['Weight']:.2f}")

# Test sequence of individual outputs to see what each does visually
tests = [
    ("SendRight ONLY", dict(sr=1)),
    ("SendLeft ONLY", dict(sl=1)),
    ("SendForward ONLY", dict(sf=1)),
    ("LoadScale ONLY", dict(ls=1)),
]

for name, kwargs in tests:
    print(f"\n--- {name} for 5s (WATCH Factory I/O) ---")
    set_outputs(**kwargs)
    time.sleep(5)
    s = read_sensors()
    print(f"  AtScale={s['AtScale']} Exit={s['AtScaleExit']} L={s['AtLeftEntry']} F={s['AtForwardEntry']} R={s['AtRightEntry']} W={s['Weight']:.2f}")
    set_outputs()  # all off
    time.sleep(1)

# Cleanup
c.db_write(22, 82, struct.pack('>h', 0))
set_outputs()
print("\nDone. Restored state=0")
c.disconnect()
