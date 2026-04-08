"""Test ONLY the right diverter."""
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
        'AtScaleEntry': bool(data[0]), 'AtScale': bool(data[2]),
        'AtScaleExit': bool(data[4]), 'AtLeftEntry': bool(data[6]),
        'AtForwardEntry': bool(data[10]), 'AtRightEntry': bool(data[14]),
        'Weight': w,
    }

# Hold PLC
hold_state()
set_outputs()
time.sleep(1)

# Feed box
print("Feeding box...")
set_outputs(ec=1, ls=1)
for i in range(60):
    s = read_sensors()
    hold_state()
    print(f"  feed t={i}: Entry={s['AtScaleEntry']} Scale={s['AtScale']} W={s['Weight']:.2f}")
    if s['AtScale'] and s['Weight'] > 0.5:
        print(f"  >>> Box on scale! W={s['Weight']:.2f}")
        break
    time.sleep(0.5)

# Stop and settle
set_outputs()
time.sleep(2)
s = read_sensors()
print(f"Settled: AtScale={s['AtScale']} W={s['Weight']:.2f}")

# Send RIGHT
print("\nSendRight + LoadScale ON...")
set_outputs(ls=1, sr=1)
for i in range(40):
    s = read_sensors()
    hold_state()
    print(f"  t={i:2d}: Scale={s['AtScale']} Exit={s['AtScaleExit']} RightEntry={s['AtRightEntry']} W={s['Weight']:.2f}")
    if s['AtRightEntry']:
        print("  >>> Box reached AtRightEntry!")
        break
    if i > 5 and not s['AtScale'] and not s['AtScaleExit']:
        print("  Box has left scale area but hasn't reached right entry")
    time.sleep(0.5)
else:
    print("  FAIL: never reached AtRightEntry in 20s")

# Cleanup
set_outputs()
c.db_write(22, 82, struct.pack('>h', 0))
print("\nRestored state=0")
c.disconnect()
