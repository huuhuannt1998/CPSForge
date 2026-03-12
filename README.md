# CPSForge

**CPSForge: A Closed-Loop LLM Red-Team / Blue-Team Testbed for Cyber-Physical Systems**

A modular, hardware-in-the-loop CPS security framework that connects to a **real Siemens PLC** and **Factory I/O** scene, enables structured LLM-driven attack planning, enforces a runtime safety shield, evaluates classical and learned defenders, and supports closed-loop defender adaptation from failed detections.

> **Default PLC target:** `192.168.0.1` — All commands default to dry-run (no live PLC writes).

---

## Key Features

| Layer | Capability |
|-------|-----------|
| **PLC Interface** | Siemens S7 via `python-snap7`, configurable polling, DB/I/Q/M addressing |
| **Attack Framework** | Scripted, random, and LLM-based attackers with structured action schema (LM Studio / OpenAI-compatible) |
| **Safety Shield** | Mandatory validation of every write — whitelist, range, duration, interlock, rollback |
| **Defender Stack** | Threshold, invariant, and sequence-model detectors with plug-in interface |
| **Adaptation Loop** | Hard-case extraction → replay bank → retraining → round-over-round evaluation |
| **Experiment Engine** | Config-driven runs, eval-run labeling, structured artifact output |
| **Analysis Pipeline** | Paper-ready tables, cross-attacker/detector comparisons, latency distributions |

---

## Quick Start

```bash
# Clone and install
git clone <repo-url> && cd CPSForge
pip install -e ".[dev]"

# Validate scene config (no PLC needed)
cpsforge scene validate --scene tank_control

# Dry-run attack experiment (no PLC writes)
cpsforge run attack --scene tank_control --attacker scripted --dry-run --max-steps 50

# Generate paper-ready tables from an experiment
cpsforge report export-all --experiment my_experiment
```

See [docs/quickstart.md](docs/quickstart.md) for the full setup guide.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Factory I/O (plant simulation)                         │
└───────────────────────┬─────────────────────────────────┘
                        │ physical I/O
┌───────────────────────▼─────────────────────────────────┐
│  Siemens S7 PLC (TIA Portal v17)   192.168.0.1         │
└───────────────────────┬─────────────────────────────────┘
                        │ python-snap7
┌───────────────────────▼─────────────────────────────────┐
│  CPSForge Middleware (bridge machine)                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  │
│  │ Attacker │→ │  Shield  │→ │   PLC    │→ │ Poller │  │
│  │ (LLM /   │  │ (rules + │  │ (write)  │  │ (read) │  │
│  │ scripted/│  │ rollback)│  │          │  │        │  │
│  │ random)  │  └──────────┘  └──────────┘  └───┬────┘  │
│  └──────────┘                                   │       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐      │       │
│  │ Defender │← │ Trace    │← │ Snapshot │←─────┘       │
│  │ Stack    │  │ Logger   │  │ Builder  │               │
│  └────┬─────┘  └──────────┘  └──────────┘               │
│       │                                                  │
│  ┌────▼─────────────────────────────────┐               │
│  │ Adaptation: hard cases → retrain     │               │
│  └──────────────────────────────────────┘               │
└──────────────────────────────────────────────────────────┘
```

### Layers

1. **Physical Execution** — PLC runs control logic; Factory I/O renders the plant.
2. **Observation & Logging** — Cyclic tag polling, timestamped snapshots, structured trace storage.
3. **Attack** — Structured actions (sensor spoof, actuator override, setpoint shift, timing delay, sequence perturbation) compiled to concrete PLC writes.
4. **Safety Shield** — Validates every action against configurable rules (range, duration, cooldown, interlock, invariant, mode-gate). Rejects or normalizes unsafe writes.
5. **Defender** — Threshold, invariant, and ML-based detectors score every snapshot.
6. **Adaptation** — Missed/late detections stored as hard cases; sequence detector retrained iteratively.

---

## Project Structure

```
CPSForge/
├── pyproject.toml              # Package metadata, dependencies, entry point
├── requirements.txt            # Pip-installable dependency list
├── .env.example                # Environment variable template
├── configs/
│   ├── system/                 # PLC connection, logging
│   │   ├── plc.yaml
│   │   └── logging.yaml
│   ├── scenes/                 # Factory I/O scene profiles
│   │   ├── tank_control.yaml
│   │   ├── from_a_to_b.yaml
│   │   ├── level_control.yaml
│   │   └── sorting_height_basic.yaml
│   ├── attacks/                # Attacker configurations
│   │   ├── scripted_tank_control.yaml
│   │   ├── random_tank_control.yaml
│   │   └── llm_tank_control.yaml
│   ├── defenders/              # Detector configurations
│   │   ├── threshold_tank_control.yaml
│   │   ├── invariant_tank_control.yaml
│   │   └── sequence_model_tank_control.yaml
│   ├── experiments/            # Experiment presets
│   │   ├── phase1_baseline.yaml
│   │   ├── phase2_dry_run.yaml
│   │   ├── phase2_live_run.yaml
│   │   ├── phase3_baseline.yaml
│   │   ├── phase3_eval_run.yaml
│   │   └── phase5_adaptation.yaml
│   └── llm/                    # LLM provider configs + prompt templates
│       ├── local.yaml          # LM Studio / OpenAI-compatible endpoint
│       └── prompts/
│           ├── v1/
│           └── v2/
├── cpsforge/                   # Main Python package
│   ├── cli/                    # Typer CLI (scene, plc, run, report, adapt)
│   ├── core/                   # Models, config loader, orchestrator
│   ├── plc/                    # PLC client, poller, address parser
│   ├── scenes/                 # Scene abstraction + 4 implemented scenes
│   ├── attacks/                # Scripted, random attackers + compiler
│   ├── shield/                 # Safety shield engine
│   ├── defenders/              # Threshold, invariant, sequence, LLM explainer
│   ├── adaptation/             # Hard-case bank, trainer, adaptation loop
│   ├── analysis/               # Paper-ready table generation
│   ├── llm/                    # LLM providers, attacker, prompt builder
│   ├── logging/                # Trace recorder, artifact writer, logger
│   ├── api/                    # FastAPI status endpoints (stub)
│   ├── utils/                  # Shared utilities
│   └── tests/                  # Test suites (phase 1–6 + validation)
├── scripts/                    # Standalone scripts (probe_plc.py)
├── data/
│   ├── raw/                    # Per-run artifacts
│   ├── processed/              # Aggregate experiment summaries
│   └── replays/                # Replay data
├── docs/                       # Guides and documentation
│   ├── quickstart.md
│   ├── hardware_deployment.md
│   ├── scene_config.md
│   ├── safety_notes.md
│   ├── evaluation_workflow.md
│   ├── metrics_guide.md
│   ├── adding_attacker.md
│   ├── adding_detector.md
│   └── adding_scene.md
└── examples/                   # Example scripts and configs
```

---

## CLI Reference

### Scene Management

```bash
cpsforge scene validate --scene tank_control     # Validate scene YAML
cpsforge scene info --scene tank_control          # Print tag table
```

### PLC Connectivity

```bash
cpsforge plc probe                                # Test PLC connection
cpsforge plc read --scene tank_control --tag tank_level   # Read a tag
```

### Experiment Execution

```bash
# Dry-run (no PLC writes — safe for development)
cpsforge run baseline --scene tank_control --dry-run
cpsforge run attack --scene tank_control --attacker scripted --dry-run
cpsforge run attack --scene tank_control --attacker random --dry-run
cpsforge run attack --scene tank_control --attacker llm --dry-run

# Live eval run (requires PLC + --no-dry-run + CPSFORGE_LIVE_WRITES=true)
cpsforge run attack --scene tank_control --attacker scripted --no-dry-run --eval-run

# Closed-loop adaptation (multi-round attack → detect → retrain)
cpsforge run closed-loop --scene tank_control --rounds 3 --dry-run

# Replay saved trace through detectors (no PLC needed)
cpsforge run detect-replay --experiment my_exp --run-id <run_id>
```

### Reporting & Analysis

```bash
cpsforge report summarize --experiment my_exp       # Aggregate metrics
cpsforge report metrics --experiment my_exp          # Show per-run table

# Paper-ready tables
cpsforge report cross-attacker --experiment my_exp   # Table 1: attacker comparison
cpsforge report shield-analysis --experiment my_exp  # Table 2: shield effectiveness
cpsforge report cross-detector --experiment my_exp   # Table 3: detector comparison
cpsforge report adaptation --experiment my_exp       # Table 4: round-over-round

cpsforge report attack-types --experiment my_exp     # Supplemental: by attack type
cpsforge report cross-model --experiment my_exp      # Cross-model LLM comparison
cpsforge report export-all --experiment my_exp       # Batch export all tables
```

### Adaptation

```bash
cpsforge adapt list-hard-cases --experiment my_exp
cpsforge adapt train --experiment my_exp --scene tank_control
cpsforge adapt run-rounds --experiment my_exp --rounds 5
cpsforge adapt round-summary --experiment my_exp
```

---

## Run Artifacts

Each run produces a folder under `data/raw/<experiment>/<run_id>/`:

| File | Contents |
|------|----------|
| `trace.parquet` | Timestamped plant snapshots (sensors, actuators, alarms, attack context) |
| `attacks.json` | All proposed attack actions with shield approval status |
| `detections.json` | All detector events with severity, confidence, step ID |
| `shield_events.json` | Every shield decision (approved/rejected, violated rules, rollback) |
| `hard_cases.json` | Missed or late detections classified by failure mode |
| `metrics.json` | Per-run `EvalMetrics` (attack rates, shield rates, detector P/R/F1, latency) |
| `metadata.json` | Config snapshot and run parameters |

Experiment summaries go to `data/processed/<experiment>/`:

| File | Contents |
|------|----------|
| `run_index.csv` | Index of all runs with key metadata |
| `aggregate_metrics.csv` | Mean/std of all EvalMetrics fields |
| `summary.json` | Machine-readable experiment summary |
| `paper/` | Publication-ready CSVs and manifest (from `report export-all`) |

---

## Configuration

All behavior is config-driven via YAML files under `configs/`. See:

- [Scene Config Guide](docs/scene_config.md) — Tag definitions, safety rules, attack surface
- [Hardware Deployment Guide](docs/hardware_deployment.md) — PLC + Factory I/O setup
- [Safety Notes](docs/safety_notes.md) — Shield rules, dry-run mode, live-write controls

---

## Extending CPSForge

- [Adding a New Attacker](docs/adding_attacker.md)
- [Adding a New Detector](docs/adding_detector.md)
- [Adding a New Scene](docs/adding_scene.md)

---

## Metrics & Evaluation

All paper metrics are collected during explicitly labeled **eval runs** on the real PLC.

| Category | Metrics |
|----------|---------|
| **Attack** | action validity rate, execution success rate, attack success rate, process impact |
| **Shield** | approval rate, rejection rate, unsafe block rate, per-rule breakdown |
| **Detector** | precision, recall, F1, detection latency (mean, p50, p90, p99) |
| **Adaptation** | F1 improvement across rounds, hard-case reduction, generalization rate |

See [Evaluation Workflow](docs/evaluation_workflow.md) and [Metrics Guide](docs/metrics_guide.md).

---

## Testing

```bash
pip install -e ".[dev]"
python -m pytest cpsforge/tests/ -q
```

318 tests across phases 1–6 + LLM provider and scene tests covering: schema validation, attack compilation, shield logic, detector interfaces, adaptation loop, CLI commands, LLM provider integration, scene logic, cross-model reporting, and paper-ready analysis.

---

## Safety

CPSForge is a **CPS security research framework**, not malware.

- **Dry-run by default** — no PLC writes unless `--no-dry-run` + `CPSFORGE_LIVE_WRITES=true`
- **Mandatory shield** — every write is validated against scene safety rules
- **No raw PLC writes from LLM** — actions are structured and compiled after validation
- **Auditable** — every action, decision, and detection is logged
- **Rollback support** — shield generates rollback plans for approved writes

See [Safety Notes](docs/safety_notes.md) for full details.

---

## License

MIT