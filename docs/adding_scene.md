# Adding a New Scene

This guide walks through adding a new Factory I/O scene to CPSForge.

---

## 1. Create the Scene Config

Create `configs/scenes/<scene_name>.yaml`:

```yaml
scene_name: sorting_by_height
description: "Sorting station that routes parts by measured height."
sampling_interval_ms: 200

tags:
  - name: part_detected
    address: "DB2,X0.0"
    data_type: bool
    access: read
    description: "Part presence sensor at entry"
    category: sensor

  - name: part_height
    address: "DB2,REAL2"
    data_type: real
    access: read
    unit: "mm"
    min_value: 0.0
    max_value: 200.0
    description: "Measured part height"
    category: sensor

  - name: conveyor_speed
    address: "DB2,REAL6"
    data_type: real
    access: read_write
    unit: "%"
    min_value: 0.0
    max_value: 100.0
    description: "Conveyor belt speed"
    category: actuator

  - name: diverter_position
    address: "DB2,INT10"
    data_type: int
    access: read_write
    min_value: 0
    max_value: 2
    description: "Diverter gate selection (0=straight, 1=left, 2=right)"
    category: actuator

  - name: sort_mode
    address: "DB2,X12.0"
    data_type: bool
    access: read
    description: "Auto sort mode active"
    category: mode_bit

writable_tags:
  - conveyor_speed
  - diverter_position

attack_surface:
  - tag: conveyor_speed
    allowed_types: [actuator_override, timing_delay]
  - tag: diverter_position
    allowed_types: [actuator_override, sequence_perturbation]

safety_rules:
  - rule_id: range_conveyor
    rule_type: range
    tags: [conveyor_speed]
    parameters: {min: 0.0, max: 100.0}

  - rule_id: range_diverter
    rule_type: range
    tags: [diverter_position]
    parameters: {min: 0, max: 2}

  - rule_id: cooldown_diverter
    rule_type: cooldown
    tags: [diverter_position]
    parameters: {cooldown_ms: 1000}

reset_procedure:
  steps:
    - write: {tag: conveyor_speed, value: 0.0}
    - write: {tag: diverter_position, value: 0}
    - wait_ms: 1000
```

Tag address formats for Siemens S7:
- `DB<n>,REAL<offset>` — REAL in data block
- `DB<n>,INT<offset>` — INT in data block
- `DB<n>,X<byte>.<bit>` — BOOL in data block
- `MW<offset>` — Merker word
- `IW<offset>` — Input word
- `QW<offset>` — Output word

---

## 2. Create the Scene Class

Create `cpsforge/scenes/sorting_by_height.py`:

```python
"""CPSForge Scene — Sorting by Height."""

from __future__ import annotations

import logging
from typing import Dict

from cpsforge.core.models import PlantSnapshot, SceneProfile
from cpsforge.scenes.base import BaseScene

logger = logging.getLogger(__name__)


class SortingByHeightScene(BaseScene):
    """Sorting station scene for Factory I/O."""

    def __init__(self, profile: SceneProfile) -> None:
        super().__init__(profile)
        self._prev_diverter: int | None = None
        self._sort_count: int = 0

    def extract_derived_features(self, snapshot: PlantSnapshot) -> Dict[str, float]:
        features: Dict[str, float] = {}

        height = snapshot.sensors.get("part_height")
        detected = snapshot.sensors.get("part_detected")
        diverter = snapshot.actuators.get("diverter_position")

        features["part_present"] = 1.0 if detected else 0.0

        if height is not None:
            features["height_bin"] = 0.0 if height < 80 else (1.0 if height < 140 else 2.0)

        if diverter is not None and self._prev_diverter is not None:
            features["diverter_changed"] = float(diverter != self._prev_diverter)
        else:
            features["diverter_changed"] = 0.0

        if diverter is not None:
            self._prev_diverter = int(diverter)

        snapshot.derived_features = features
        return features

    def compute_process_impact(
        self, before: PlantSnapshot, after: PlantSnapshot
    ) -> float:
        # Impact: wrong sort = diverter changed when no part, or part sorted to wrong bin
        diverter_before = before.actuators.get("diverter_position", 0)
        diverter_after = after.actuators.get("diverter_position", 0)
        height = after.sensors.get("part_height", 0.0)

        if diverter_before == diverter_after:
            return 0.0

        # Check if diverter matches expected bin for height
        expected = 0 if height < 80 else (1 if height < 140 else 2)
        if diverter_after != expected:
            return 1.0
        return 0.0
```

### Required Methods

| Method | Purpose |
|--------|---------|
| `extract_derived_features(snapshot)` | Compute derived features; store in `snapshot.derived_features` |
| `compute_process_impact(before, after)` | Return scalar impact score (0.0 = no effect, 1.0 = full impact) |

Optional overrides:
- `evaluate_attack_success(action, before, after)` — custom success criterion
- `get_reset_writes()` — custom reset logic (default reads from config)

---

## 3. Register in the Factory

Edit `cpsforge/scenes/factory.py`:

```python
from cpsforge.scenes.sorting_by_height import SortingByHeightScene

_SCENE_REGISTRY: Dict[str, Type[BaseScene]] = {
    "tank_control": TankControlScene,
    "sorting_by_height": SortingByHeightScene,
}
```

---

## 4. Create Attacker and Defender Configs

Scene-specific attacker config (`configs/attacks/scripted_sorting.yaml`):

```yaml
name: scripted_sorting
attacker_type: scripted
scene_name: sorting_by_height
max_actions: 5
inter_attack_delay_ms: 1000
attack_types:
  - actuator_override
  - sequence_perturbation
```

Scene-specific defender config (`configs/defenders/threshold_sorting.yaml`):

```yaml
name: threshold_sorting
detector_type: threshold
scene_name: sorting_by_height
enabled: true
thresholds:
  - tag: conveyor_speed
    operator: "<"
    value: 5.0
    severity: medium
    label: "conveyor_stopped"
```

---

## 5. Validate and Run

```bash
# Validate the scene config
cpsforge scene validate --scene sorting_by_height

# Run a dry-run experiment
cpsforge run attack --scene sorting_by_height --attacker scripted
```

---

## Scene Design Considerations

### Continuous vs Discrete Processes

- **Continuous** (e.g., tank_control): Tags vary smoothly; derived features include rates, errors
- **Discrete** (e.g., sorting): Tags change in steps; derived features include state transitions, counts

Design `extract_derived_features()` accordingly. Discrete scenes benefit from counting transitions and tracking sequences rather than computing rates.

### Safety Rules

Consider the specific hazards of each scene:
- Tank: overflow, pump cavitation
- Sorting: parts misrouted, collisions, conveyor jam
- Elevator: door/motor interlocks, limit switches

### Attack Surface

Only include tags that are meaningful to attack. For sorting, manipulating the diverter is interesting; forcing it to the wrong position causes missorts. Manipulating the conveyor speed disrupts timing.

---

## Checklist

1. [ ] Create scene config YAML in `configs/scenes/`
2. [ ] Create scene class in `cpsforge/scenes/` subclassing `BaseScene`
3. [ ] Implement `extract_derived_features()` and `compute_process_impact()`
4. [ ] Register in `cpsforge/scenes/factory.py`
5. [ ] Create matching attacker + defender configs
6. [ ] Validate: `cpsforge scene validate --scene <name>`
7. [ ] Test: `cpsforge run attack --scene <name> --attacker scripted`
