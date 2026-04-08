"""Manual test of Factory I/O Sorting by Weight diverters."""
import snap7, struct, time

c = snap7.client.Client()
c.connect('192.168.0.1', 0, 1)

def hold_state():
    c.db_write(22, 82, struct.pack('>h', 99))

def set_outputs(ec=0, ls=0, sl=0, sr=0, sf=0):
    data = c.db_read(22, 32, 14)  # bytes 32-45
    data[0] = ec   # EntryConveyor (32)
    data[2] = ls   # LoadScale (34)
    data[4] = sl   # SendLeft (36)
    data[8] = sr   # SendRight (40)
    data[12] = sf  # SendForward (44)
    c.db_write(22, 32, data)
    hold_state()

def read_sensors():
    data = c.db_read(22, 0, 32)
    w = struct.unpack('>f', data[28:32])[0]
    return {
        'AtScaleEntry': bool(data[0]),
        'AtScale': bool(data[2]),
        'AtScaleExit': bool(data[4]),
        'AtLeftEntry': bool(data[6]),
        'AtExitLeft': bool(data[8]),
        'AtForwardEntry': bool(data[10]),
        'AtExitFront': bool(data[12]),
        'AtRightEntry': bool(data[14]),
        'AtExitRight': bool(data[16]),
        'Weight': w,
    }

def feed_box():
    """Feed a box onto the scale, wait for it to settle, and stop."""
    set_outputs(ec=1, ls=1)
    # Wait for box to arrive at scale
    for i in range(60):
        s = read_sensors()
        hold_state()
        if s['AtScale'] and s['Weight'] > 0.5:
            print(f"  [feed] Box detected: AtScale=True, Weight={s['Weight']:.2f}")
            break
        time.sleep(0.5)
    else:
        print("  [feed] WARNING: no box reached scale in 30s")
        set_outputs()
        return 0.0
    # Stop belts, let weight settle
    set_outputs()  # all off
    time.sleep(1.5)
    s = read_sensors()
    if not s['AtScale']:
        print(f"  [feed] WARNING: box left scale during settle! AtScale={s['AtScale']}")
    return s['Weight']

def test_diverter(name, send_kwarg, entry_key):
    print(f"\n=== TEST {name} ===")
    w = feed_box()
    if w < 0.5:
        print(f"SKIP: no box on scale (weight={w:.2f})")
        return
    print(f"Box on scale, weight={w:.2f} kg")
    
    # Verify box is still on scale
    s = read_sensors()
    if not s['AtScale']:
        print("SKIP: box left scale before diverter test")
        return
    
    set_outputs(ls=1, **{send_kwarg: 1})
    for i in range(40):
        s = read_sensors()
        hold_state()
        print(f"  t={i:2d}: Scale={s['AtScale']} Exit={s['AtScaleExit']} {entry_key}={s[entry_key]} W={s['Weight']:.2f}")
        if s[entry_key]:
            print(f"  >>> Box reached {entry_key}!")
            break
        time.sleep(0.5)
    else:
        print(f"  FAIL: box did not reach {entry_key} in 20s")
    
    set_outputs()  # all off
    time.sleep(5)  # wait for box to clear before next test

# Hold PLC in dummy state
hold_state()

test_diverter("SendForward", "sf", "AtForwardEntry")
test_diverter("SendRight", "sr", "AtRightEntry")
test_diverter("SendLeft", "sl", "AtLeftEntry")

# Restore normal operation
c.db_write(22, 82, struct.pack('>h', 0))
set_outputs()
print("\nDone. Restored state=0")
c.disconnect()
