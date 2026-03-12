# Quick Start Guide

This guide gets you from zero to running your first CPSForge experiment.

---

## Prerequisites

- **Python 3.11+** (3.12 or 3.13 also work)
- **pip** (or conda)
- **Git**
- For live PLC runs: a Siemens S7 PLC at `192.168.0.1` with Factory I/O

---

## 1. Install CPSForge

```bash
git clone <repo-url>
cd CPSForge

# Editable install with dev dependencies
pip install -e ".[dev]"

# Verify installation
cpsforge --help
```

### Optional dependencies

```bash
# All extras including PyTorch (for learned detectors)
pip install -e ".[all]"
```

### LLM attacker prerequisites

The LLM attacker uses a local **LM Studio** server (or any OpenAI-compatible endpoint).
No cloud API keys are required.

1. Download [LM Studio](https://lmstudio.ai/) and load a model (e.g., `qwen2-7b-instruct`).
2. Start the local server (default: `http://127.0.0.1:1234/v1`).
3. The provider config is in `configs/llm/local.yaml`.

---

## 2. Configure Environment

```bash
# Copy the example env file
cp .env.example .env
```

Edit `.env` if needed. The defaults are safe (dry-run mode, no live writes).

Key settings:
```bash
CPSFORGE_PLC_HOST=192.168.0.1       # PLC IP address
CPSFORGE_LIVE_WRITES=false           # MUST be explicitly set true for live writes
```

---

## 3. Validate Setup (No PLC Required)

### Validate a scene configuration

```bash
cpsforge scene validate --scene tank_control
```

Expected output:
```
OK Scene 'tank_control' is valid.
  Tags        : 11
  Writable    : 3
  Safety rules: 7
```

### Inspect scene tags

```bash
cpsforge scene info --scene tank_control
```

---

## 4. Run a Dry-Run Experiment

Dry-run mode exercises the full pipeline (attacker → shield → defender) with simulated PLC values. No PLC connection needed.

### Baseline (polling only)

```bash
cpsforge run baseline --scene tank_control --dry-run --max-steps 20
```

### Scripted attack

```bash
cpsforge run attack --scene tank_control --attacker scripted --dry-run --max-steps 50
```

### Random attack

```bash
cpsforge run attack --scene tank_control --attacker random --dry-run --max-steps 50
```

### Where are the outputs?

Artifacts are written to `data/raw/<experiment_name>/<run_id>/`:
```
data/raw/scripted_tank_control_attack/20260311T.../
├── trace.parquet
├── attacks.json
├── detections.json
├── shield_events.json
├── hard_cases.json
├── metrics.json
└── metadata.json
```

---

## 5. View Results

### Per-run metrics table

```bash
cpsforge report metrics --experiment scripted_tank_control_attack
```

### Aggregate summary

```bash
cpsforge report summarize --experiment scripted_tank_control_attack
```

---

## 6. Next Steps

| Goal | Guide |
|------|-------|
| Connect to the real PLC | [Hardware Deployment](hardware_deployment.md) |
| Run a live eval experiment | [Evaluation Workflow](evaluation_workflow.md) |
| Use the LLM attacker | Start LM Studio, then `cpsforge run attack --attacker llm` |
| Run multi-round adaptation | `cpsforge run closed-loop --scene tank_control --rounds 3` |
| Generate paper tables | `cpsforge report export-all --experiment <name>` |
| Add a new scene | [Adding a Scene](adding_scene.md) |
| Add a new detector | [Adding a Detector](adding_detector.md) |
| Understand safety controls | [Safety Notes](safety_notes.md) |
