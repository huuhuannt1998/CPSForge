# Adding a New Detector

This guide walks through adding a custom anomaly detector to CPSForge.

---

## 1. Create the Detector Class

Create a new file in `cpsforge/defenders/`, e.g., `cpsforge/defenders/cusum.py`:

```python
"""CUSUM change-point detector for CPSForge."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict, List

from cpsforge.core.config import DefenderConfig
from cpsforge.core.models import DetectionEvent, DetectionSeverity, PlantSnapshot
from cpsforge.defenders.base import BaseDetector

logger = logging.getLogger(__name__)


class CusumDetector(BaseDetector):
    """
    Cumulative sum (CUSUM) detector.

    Monitors selected tags for sustained shifts in mean value.
    """

    def __init__(self, config: DefenderConfig) -> None:
        self._config = config
        self._name = config.name
        self._cusum_params: List[Dict] = config.extra.get("cusum_rules", [])
        # Internal state: cumulative sums per tag
        self._cusum_pos: Dict[str, float] = {}
        self._cusum_neg: Dict[str, float] = {}
        for rule in self._cusum_params:
            tag = rule["tag"]
            self._cusum_pos[tag] = 0.0
            self._cusum_neg[tag] = 0.0

    @property
    def name(self) -> str:
        return self._name

    def observe(self, snapshot: PlantSnapshot) -> None:
        """Update CUSUM accumulators with new observation."""
        for rule in self._cusum_params:
            tag = rule["tag"]
            target = rule.get("target_mean", 50.0)
            slack = rule.get("slack", 0.5)
            value = snapshot.sensors.get(tag)
            if value is None:
                continue
            diff = float(value) - target
            self._cusum_pos[tag] = max(0.0, self._cusum_pos[tag] + diff - slack)
            self._cusum_neg[tag] = max(0.0, self._cusum_neg[tag] - diff - slack)

    def detect(self, snapshot: PlantSnapshot) -> List[DetectionEvent]:
        events: List[DetectionEvent] = []
        for rule in self._cusum_params:
            tag = rule["tag"]
            threshold = rule.get("threshold", 10.0)
            severity = DetectionSeverity(rule.get("severity", "medium"))

            if self._cusum_pos[tag] > threshold or self._cusum_neg[tag] > threshold:
                direction = "positive" if self._cusum_pos[tag] > threshold else "negative"
                events.append(DetectionEvent(
                    detector_name=self._name,
                    severity=severity,
                    label="cusum_shift",
                    confidence=min(1.0, max(self._cusum_pos[tag], self._cusum_neg[tag]) / (2 * threshold)),
                    explanation=f"CUSUM {direction} shift detected on {tag}",
                    affected_tags=[tag],
                ))
        return events

    def reset(self) -> None:
        for tag in self._cusum_pos:
            self._cusum_pos[tag] = 0.0
            self._cusum_neg[tag] = 0.0

    def export_state(self) -> dict:
        return {
            "cusum_pos": dict(self._cusum_pos),
            "cusum_neg": dict(self._cusum_neg),
        }
```

### Key Points

- Subclass `BaseDetector`
- Implement `name` (property), `observe()`, `detect()`
- Optionally override `reset()` and `export_state()`
- `observe()` updates internal state; `detect()` returns zero or more `DetectionEvent` objects

---

## 2. Register in the Factory

Edit `cpsforge/defenders/factory.py`:

```python
elif t == "cusum":
    from cpsforge.defenders.cusum import CusumDetector
    return CusumDetector(config)
```

---

## 3. Create a Config File

Create `configs/defenders/cusum_tank_control.yaml`:

```yaml
name: cusum_tank_control
detector_type: cusum
scene_name: tank_control
enabled: true

extra:
  cusum_rules:
    - tag: tank_level
      target_mean: 50.0
      slack: 0.5
      threshold: 10.0
      severity: medium
    - tag: pump_speed
      target_mean: 50.0
      slack: 1.0
      threshold: 15.0
      severity: medium
```

---

## 4. Run It

```bash
cpsforge run attack --scene tank_control --attacker scripted
```

Detectors are loaded from configs matching the scene. To use only specific detectors, reference them in the experiment config.

---

## Interface Reference

### BaseDetector

```python
class BaseDetector(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def observe(self, snapshot: PlantSnapshot) -> None: ...

    @abstractmethod
    def detect(self, snapshot: PlantSnapshot) -> List[DetectionEvent]: ...

    def reset(self) -> None: ...
    def export_state(self) -> dict: ...
```

### Method Lifecycle

1. **Every polling cycle**: `observe(snapshot)` is called first to update state
2. **Every polling cycle**: `detect(snapshot)` is called to check for anomalies
3. **Between runs**: `reset()` clears internal state

### DetectionEvent Fields

| Field | Type | Description |
|-------|------|-------------|
| `detector_name` | str | Name of the detector that fired |
| `severity` | DetectionSeverity | `low`, `medium`, `high`, `critical` |
| `label` | str | Short label for the detection type |
| `confidence` | float | Detector confidence (0–1) |
| `explanation` | str | Human-readable explanation |
| `affected_tags` | list[str] | Tags involved in the anomaly |

### DefenderConfig Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | str | Config identifier |
| `detector_type` | str | Type key used by factory |
| `scene_name` | str | Target scene |
| `enabled` | bool | Whether the detector is active |
| `thresholds` | list[dict] | Threshold rules (for ThresholdDetector) |
| `invariants` | list[dict] | Invariant rules (for InvariantDetector) |
| `extra` | dict | Arbitrary extra parameters |

### Stateful vs Stateless Patterns

- **Stateless** (e.g., ThresholdDetector): `observe()` is a no-op; `detect()` evaluates only the current snapshot
- **Stateful** (e.g., SequenceModelDetector, CusumDetector): `observe()` accumulates a window; `detect()` uses historical context

---

## Checklist

1. [ ] Create `cpsforge/defenders/<name>.py` subclassing `BaseDetector`
2. [ ] Implement `name`, `observe()`, `detect()`
3. [ ] Add branch in `cpsforge/defenders/factory.py`
4. [ ] Create config YAML in `configs/defenders/`
5. [ ] (Optional) Override `reset()` and `export_state()`
6. [ ] Test with: `cpsforge run attack --scene <scene> --attacker scripted`
