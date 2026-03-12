# Hardware Deployment Guide

How to set up CPSForge with a real Siemens PLC and Factory I/O for live experiments.

---

## Overview

```
┌──────────────┐     Ethernet      ┌──────────────────┐
│  Factory I/O │ ←── physical I/O ──→  Siemens S7 PLC  │
│  (plant sim) │                    │  192.168.0.1      │
└──────────────┘                    └────────┬─────────┘
                                             │ TCP/IP (port 102)
                                    ┌────────▼─────────┐
                                    │  Bridge Machine   │
                                    │  (CPSForge)       │
                                    └──────────────────┘
```

**Bridge machine**: the PC or laptop running CPSForge. It must be on the same subnet as the PLC.

---

## 1. PLC Setup

### Requirements

- Siemens S7-1200 or S7-1500 PLC
- TIA Portal v17 installed on an engineering workstation
- PLC IP configured to `192.168.0.1`

### TIA Portal Configuration

1. Open your TIA Portal project.
2. In **Device & Networks**, set the PLC IP to `192.168.0.1`.
3. Under **PLC Properties → Protection & Security**:
   - Enable **Full access (no protection)** or **PUT/GET access** for S7 communication.
   - For S7-1200/1500: enable **Permit access with PUT/GET** in the PLC properties.
4. Compile and download the project to the PLC.
5. Set the PLC to **RUN** mode.

### Rack and Slot

| PLC Family | Rack | Slot |
|-----------|------|------|
| S7-1200 | 0 | 1 |
| S7-1500 | 0 | 1 |
| S7-300 | 0 | 2 |
| S7-400 | 0 | 2 |

These are configured in `configs/system/plc.yaml`.

---

## 2. Factory I/O Setup

1. Install Factory I/O on the same machine as the PLC or with a direct connection.
2. Open or create your scene (e.g., "Level Control" or "Tank").
3. In Factory I/O, set the **Driver** to **Siemens S7-PLCSIM** or **Siemens S7-1200/1500** depending on your setup.
4. Map Factory I/O I/O points to the PLC data blocks defined in your TIA Portal project.
5. Start the Factory I/O simulation.

---

## 3. Network Configuration

### Bridge Machine

The bridge machine (running CPSForge) must reach the PLC:

```bash
# Verify connectivity
ping 192.168.0.1

# Verify S7 port is open (should connect)
python -c "import socket; s=socket.socket(); s.settimeout(3); s.connect(('192.168.0.1', 102)); print('OK'); s.close()"
```

If using a USB-to-Ethernet adapter or a separate NIC, ensure the bridge machine's interface is configured on the `192.168.0.x` subnet.

### Firewall

- Allow outbound TCP to `192.168.0.1:102`
- The PLC does not initiate connections back to the bridge machine

---

## 4. Install python-snap7

CPSForge uses `python-snap7` for S7 communication.

```bash
pip install python-snap7
```

**Windows**: `python-snap7` bundles the Snap7 DLL.

**Linux**: you may need to install the Snap7 shared library:
```bash
sudo apt-get install libsnap7-dev    # Debian/Ubuntu
# or build from source: https://snap7.sourceforge.net/
```

---

## 5. CPSForge PLC Configuration

### Default config: `configs/system/plc.yaml`

```yaml
host: 192.168.0.1
rack: 0
slot: 1
port: 102
connect_timeout_s: 5.0
read_timeout_s: 2.0
live_writes_enabled: false    # ← SAFE DEFAULT
reconnect_delay_s: 3.0
max_reconnect_attempts: 5
```

### Environment override

```bash
# .env
CPSFORGE_PLC_HOST=192.168.0.1
CPSFORGE_LIVE_WRITES=false
```

---

## 6. Test the Connection

```bash
# Using the CLI
cpsforge plc probe

# Using the standalone script
python scripts/probe_plc.py --host 192.168.0.1
```

Expected output:
```
Probing PLC at 192.168.0.1 (rack=0, slot=1)
OK PLC is reachable and responding.
```

### Read tags

```bash
cpsforge plc read --scene tank_control --tag tank_level
```

---

## 7. Run a Live Experiment

### Step 1: Dry-run first (ALWAYS)

```bash
cpsforge run attack --scene tank_control --attacker scripted --dry-run --max-steps 50
```

Verify the attack plan, shield decisions, and detector outputs look correct.

### Step 2: Enable live writes

Edit `.env`:
```bash
CPSFORGE_LIVE_WRITES=true
```

### Step 3: Run with `--no-dry-run`

```bash
cpsforge run attack --scene tank_control --attacker scripted --no-dry-run --eval-run --max-steps 200
```

The CLI will ask for confirmation before issuing real PLC writes.

### Step 4: Monitor Factory I/O

Watch the Factory I/O visualization while the experiment runs. The safety shield constrains all writes, but always be prepared to switch the PLC to STOP mode if needed.

---

## 8. Tag Address Mapping

CPSForge uses S7-style addressing. Example from `tank_control.yaml`:

```yaml
tags:
  - name: tank_level
    address: "DB1,REAL0"      # DB1 offset 0, REAL (4 bytes)
    data_type: real
    access: read
    category: sensor

  - name: pump_speed
    address: "DB1,REAL4"      # DB1 offset 4
    data_type: real
    access: read_write
    category: actuator
```

Address formats supported:
- `DB<n>,<type><offset>` — Data block access (e.g., `DB1,REAL4`)
- `MW<n>` — Memory word
- `IW<n>` — Input word
- `QW<n>` — Output word
- `M<n>.<bit>` — Memory bit

Ensure these addresses match your TIA Portal project.

---

## 9. Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `PLCConnectionError: connect failed` | PLC unreachable | Check IP, subnet, firewall |
| `Connection refused on port 102` | S7 communication disabled | Enable PUT/GET in TIA Portal |
| Wrong values read | Address mismatch | Verify DB offsets match TIA Portal |
| `snap7 not found` | Missing native library | Install `libsnap7-dev` (Linux) |
| Writes have no effect | `live_writes_enabled=false` | Set `CPSFORGE_LIVE_WRITES=true` in `.env` |
| Shield rejects all writes | Overly restrictive rules | Review safety rules in scene config |
