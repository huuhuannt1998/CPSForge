# Adding a New Attacker

This guide walks through adding a custom attacker to CPSForge.

---

## 1. Create the Attacker Class

Create a new file in `cpsforge/attacks/`, e.g., `cpsforge/attacks/replay_attacker.py`:

```python
"""Replay attacker — replays attack traces from previous runs."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List

from cpsforge.attacks.base import BaseAttacker
from cpsforge.core.config import AttackPolicyConfig
from cpsforge.core.models import AttackAction, AttackSource, AttackType

logger = logging.getLogger(__name__)


class ReplayAttacker(BaseAttacker):
    """Replays a sequence of attack actions loaded from a run's attacks.json."""

    def generate_actions(self, scene: object) -> List[AttackAction]:
        replay_file = self._config.extra.get("replay_file")
        if not replay_file:
            raise ValueError("ReplayAttacker requires 'replay_file' in config extra")

        path = Path(replay_file)
        if not path.exists():
            raise FileNotFoundError(f"Replay file not found: {path}")

        raw_actions = json.loads(path.read_text())
        actions: List[AttackAction] = []
        for i, entry in enumerate(raw_actions[: self._config.max_actions]):
            action = AttackAction(
                attack_type=AttackType(entry["attack_type"]),
                target=entry["target"],
                mode=entry.get("mode", "override"),
                value=entry.get("value"),
                duration_ms=entry.get("duration_ms", 5000),
                rationale=entry.get("rationale", "replayed action"),
                expected_effect=entry.get("expected_effect", ""),
                confidence=entry.get("confidence", 1.0),
                source=AttackSource.SCRIPTED,
            )
            actions.append(action)
            logger.info("Replay action %d: %s -> %s", i, action.attack_type, action.target)

        return actions
```

### Key Points

- Subclass `BaseAttacker`
- Implement `generate_actions(self, scene) -> List[AttackAction]`
- Access config via `self._config` (an `AttackPolicyConfig`)
- Return a list of `AttackAction` objects — the shield validates them before execution

---

## 2. Register in the Factory

Edit `cpsforge/attacks/factory.py` and add a branch:

```python
elif t == "replay":
    from cpsforge.attacks.replay_attacker import ReplayAttacker
    return ReplayAttacker(config)
```

---

## 3. Create a Config File

Create `configs/attacks/replay_tank_control.yaml`:

```yaml
name: replay_tank_control
attacker_type: replay
scene_name: tank_control
max_actions: 10
inter_attack_delay_ms: 2000
attack_types:
  - actuator_override
  - setpoint_shift
extra:
  replay_file: "data/raw/eval_tank_scripted/run_001/attacks.json"
```

---

## 4. Run It

```bash
cpsforge run attack --scene tank_control --attacker replay
```

---

## Interface Reference

### BaseAttacker

```python
class BaseAttacker(ABC):
    def __init__(self, config: AttackPolicyConfig) -> None:
        self._config = config

    @property
    def name(self) -> str:
        return self._config.name

    @abstractmethod
    def generate_actions(self, scene: object) -> List[AttackAction]:
        ...
```

### AttackAction Fields

| Field | Type | Description |
|-------|------|-------------|
| `attack_type` | AttackType | `sensor_spoof`, `actuator_override`, `setpoint_shift`, `timing_delay`, `sequence_perturbation` |
| `target` | str | Tag name (not raw PLC address) |
| `mode` | str | `override`, `bias`, `freeze` |
| `value` | float/bool/None | Value to inject |
| `duration_ms` | int | How long the override lasts |
| `rationale` | str | Why this attack was chosen |
| `expected_effect` | str | What the attacker expects to happen |
| `confidence` | float | Attacker's confidence (0–1) |
| `source` | AttackSource | `scripted`, `random`, `llm` |

### AttackPolicyConfig Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | str | Config identifier |
| `attacker_type` | str | Type key used by factory |
| `scene_name` | str | Target scene |
| `max_actions` | int | Cap on actions per run |
| `inter_attack_delay_ms` | int | Delay between actions |
| `attack_types` | list[str] | Allowed attack types |
| `script_file` | str | Path to script JSON (scripted attacker) |
| `extra` | dict | Arbitrary extra parameters |

---

## Checklist

1. [ ] Create `cpsforge/attacks/<name>.py` subclassing `BaseAttacker`
2. [ ] Implement `generate_actions()` returning `List[AttackAction]`
3. [ ] Add branch in `cpsforge/attacks/factory.py`
4. [ ] Create config YAML in `configs/attacks/`
5. [ ] Test: `cpsforge run attack --scene <scene> --attacker <name>`
