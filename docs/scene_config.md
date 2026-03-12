# Scene Configuration Guide

Scenes define the Factory I/O environment that CPSForge operates on. Each scene specifies the PLC tag map, safety rules, attack surface, and reset behavior.

---

## Scene Config File

Scene configs live in `configs/scenes/<scene_name>.yaml`. The reference scene is `tank_control.yaml`.

### Minimal Structure

```yaml
scene_name: tank_control
description: "Water tank level control system with PID controller."
sampling_interval_ms: 500

tags:
  - name: tank_level
    address: "DB1,REAL0"
    data_type: real
    access: read
    unit: "%"
    min_value: 0.0
    max_value: 100.0
    description: "Current tank water level"
    category: sensor

  - name: pump_speed
    address: "DB1,REAL4"
    data_type: real
    access: read_write
    unit: "%"
    min_value: 0.0
    max_value: 100.0
    description: "Pump motor speed setpoint"
    category: actuator

writable_tags:
  - pump_speed
  - supply_valve_open
  - level_setpoint

attack_surface:
  - tag: pump_speed
    allowed_types: [actuator_override, timing_delay]
  - tag: level_setpoint
    allowed_types: [setpoint_shift]

safety_rules:
  - rule_id: range_pump_speed
    description: "Pump speed must stay within 0–100%"
    rule_type: range
    tags: [pump_speed]
    parameters:
      min: 0.0
      max: 100.0

reset_procedure:
  steps:
    - write: {tag: pump_speed, value: 0.0}
    - write: {tag: supply_valve_open, value: false}
    - wait_ms: 2000
```

---

## Tag Definitions

Each tag requires these fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Unique identifier (used throughout the codebase) |
| `address` | string | yes | S7 PLC address (`DB1,REAL4`, `MW10`, `IW2`, `QW0`) |
| `data_type` | enum | yes | `bool`, `int`, `dint`, `real`, `word`, `dword`, `byte` |
| `access` | enum | yes | `read`, `write`, `read_write` |
| `unit` | string | no | Display unit (e.g., `%`, `°C`, `m³/h`) |
| `min_value` | float | no | Physical minimum (used by shield range checks) |
| `max_value` | float | no | Physical maximum |
| `description` | string | no | Human-readable description |
| `category` | enum | yes | `sensor`, `actuator`, `mode_bit`, `alarm`, `setpoint`, `internal` |

### Categories

- **sensor** — Read-only measurements (tank level, flow rate, temperature)
- **actuator** — Controllable outputs (pump speed, valve position)
- **setpoint** — Target values for PID controllers
- **mode_bit** — Auto/manual mode flags
- **alarm** — PLC alarm outputs
- **internal** — Controller state variables

---

## Writable Tags

The `writable_tags` list defines which tags the attack framework is allowed to write. Tags not in this list are blocked by the shield even if the PLC address is read_write.

```yaml
writable_tags:
  - pump_speed
  - supply_valve_open
  - level_setpoint
```

**Principle of least privilege**: only include tags required for the experiment.

---

## Attack Surface

The `attack_surface` section maps each writable tag to the attack types it supports:

```yaml
attack_surface:
  - tag: pump_speed
    allowed_types:
      - actuator_override
      - timing_delay
  - tag: level_setpoint
    allowed_types:
      - setpoint_shift
  - tag: supply_valve_open
    allowed_types:
      - actuator_override
      - sequence_perturbation
```

Available attack types: `sensor_spoof`, `actuator_override`, `setpoint_shift`, `timing_delay`, `sequence_perturbation`.

---

## Safety Rules

Safety rules are enforced by the shield on every proposed write. See [Safety Notes](safety_notes.md) for the full rule reference.

### Rule Types

| Type | Parameters | Purpose |
|------|-----------|---------|
| `range` | `min`, `max` | Value must be within bounds |
| `duration` | `max_duration_ms` | Maximum override duration |
| `cooldown` | `cooldown_ms` | Minimum time between writes to same tag |
| `mutual_exclusion` | `forbidden_pairs` | Tags that must not be overridden simultaneously |
| `mode_gate` | `required_mode`, `mode_tag` | Write only allowed in a specific mode |
| `invariant` | `condition` | Boolean expression over tags that must remain true |
| `interlock` | `condition`, `dependent_tag` | Conditional write permission |

### Example Rules

```yaml
safety_rules:
  - rule_id: range_pump_speed
    rule_type: range
    tags: [pump_speed]
    parameters: {min: 0.0, max: 100.0}

  - rule_id: interlock_pump_valve
    rule_type: interlock
    tags: [pump_speed, supply_valve_open]
    parameters:
      condition: "pump_speed > 50 implies supply_valve_open"

  - rule_id: cooldown_setpoint
    rule_type: cooldown
    tags: [level_setpoint]
    parameters: {cooldown_ms: 10000}

  - rule_id: duration_override
    rule_type: duration
    tags: [pump_speed, supply_valve_open]
    parameters: {max_duration_ms: 30000}
```

---

## Reset Procedure

Defines how to return the plant to a safe initial state after an experiment:

```yaml
reset_procedure:
  steps:
    - write: {tag: pump_speed, value: 0.0}
    - write: {tag: supply_valve_open, value: false}
    - write: {tag: level_setpoint, value: 50.0}
    - wait_ms: 2000
```

---

## Sampling Interval

```yaml
sampling_interval_ms: 500    # Poll PLC tags every 500ms
```

Adjust based on process dynamics. Fast processes (sorting, pick-and-place) may need 100–200ms. Slow processes (tank filling) work fine at 500–1000ms.

---

## Derived Features

Scenes can define derived features that are computed from raw tag values and included in the trace:

```yaml
derived_features:
  - name: level_error
    expression: "level_setpoint - tank_level"
  - name: pump_active
    expression: "pump_speed > 0"
```

---

## Validating a Scene

```bash
cpsforge scene validate --scene tank_control
cpsforge scene info --scene tank_control
```

The validator checks:
- All required fields are present
- Tag names are unique
- Writable tags reference valid tag names
- Attack surface tags are in the writable list
- Safety rule tags reference valid tag names
- Address formats are parseable
