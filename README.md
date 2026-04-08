# CPSForge

**CPSForge: Online Context-Aware LLM Man-in-the-Middle Attacks on Cyber-Physical Systems — Capability, Fine-Tuning, and Defense**

A general-purpose PLC-in-the-loop framework that places a local LLM as a man-in-the-middle agent in the communication between a PLC and its connected machines, automating both **red team (attack)** and **blue team (defense)** analysis of the control-plane communication stream. Evaluated on a **real Siemens S7-1200 PLC** with **Factory I/O** across **333 experiment runs** and **6 research questions**.

> **Anonymous artifact repository:** <https://anonymous.4open.science/r/CPSForge-4ED6>

> **Default PLC target:** `192.168.0.1` — All commands default to dry-run (no live PLC writes).

---

## Key Features

| Layer | Capability |
|-------|------------|
| **PLC Interface** | Siemens S7 via `python-snap7`, configurable polling (500 ms), DB/I/Q/M addressing |
| **Online MITM Attacker** | Observe → infer phase → build context → decide (attack\|wait) → act — every 3 steps |
| **Context Builder** | 3-tier context ablation (minimal / partial / full) for controlled experiments (RQ1) |
| **Multi-Model LLM** | Qwen2.5-3B-Instruct (base + QLoRA), Qwen3-1.7B, SmolLM3-3B, GPT-4o-mini — in-process via HuggingFace transformers + OpenAI API |
| **Attack Framework** | Random, static LLM, and online MITM attackers with structured JSON action schema |
| **Safety Shield** | Mandatory validation of every write — whitelist, range, duration, interlock, invariant |
| **Defense Chain** | Safety Shield → PhaseAwareShield → IntentConsistencyChecker → LLM Defender (7 variants) |
| **LLM Defender** | Symmetric LLM-vs-LLM: same model and context pipeline serves both red and blue team |
| **Fine-Tuning** | QLoRA pipeline with dual-objective training (attack + defense, 2,057 examples) |
| **Experiment Matrix** | 333-cell grid across 6 RQs: context, fine-tuning, attack mode, defenses, cross-model, frontier |
| **Analysis Pipeline** | Paper-ready tables with Wilson CIs, PLC event capture analysis |

---

## Research Questions & Results

| RQ | Question | Cells | Key Finding |
|----|----------|-------|-------------|
| **RQ1** | How does operational context affect LLM attack capability? | 27 | Self-deterrence under full context (3B models only) |
| **RQ2** | How does fine-tuning change attack AND defense capability? | 36 | QLoRA improves ASR 0% → 37% on Level Control |
| **RQ3** | Is closed-loop feedback essential for LLM attacks? | 27 | Static LLM: 0% valid proposals; Online MITM: up to 54% ASR |
| **RQ4** | Which defenses remain effective against LLM attackers? | 126 | LLM defender blocks 100% of attacks (but 98.7% FPR) |
| **RQ5** | Are findings robust across models? | 72 | ASR scales with size; cross-family capability comparable at 3B |
| **RQ6** | Does a frontier model behave differently? | 45 | GPT-4o-mini: 100% ASR on Sort.Weight; self-deterrence vanishes |

**Total: 333 completed runs on a real Siemens S7-1200 PLC.**

### Models

| Model | Parameters | Role |
|-------|-----------|------|
| Qwen2.5-3B-Instruct | ~3B (4-bit NF4) | Primary model (base + QLoRA finetuned) |
| Qwen3-1.7B | ~1.7B (4-bit NF4) | Within-family scaling (RQ5) |
| SmolLM3-3B | ~3B (4-bit NF4) | Cross-family robustness (RQ5) |
| GPT-4o-mini | Frontier (API) | Frontier model scaling (RQ6) |

### Evaluation Scenes

| Scene | DB | Tags | R/W | Process Type |
|-------|-----|------|-----|-------------|
| Level Control | DB14 | 15 | 4 | Continuous (PID) |
| Sorting by Height | DB21 | 30 | 8 | Discrete (state-machine) |
| Sorting by Weight | DB22 | 35 | 11 | Discrete (classification) |

---

## Quick Start

```bash
# Clone and install
git clone <repo-url> && cd CPSForge
pip install -e ".[dev]"

# Download models (requires HuggingFace access)
python download_models.py

# Verify PLC connection + scene
python verify_plc_scene.py --scene level_control

# Run a single experiment cell (dry-run, no PLC writes)
python run_experiments.py --scene level_control --context minimal --attacker online_mitm --defense none --dry-run

# Run the full experiment matrix (requires PLC + Factory I/O)
# See START_EXPERIMENTS.ps1 for the complete 333-run grid
```

> **Important:** Run from **PowerShell**, not Git Bash (bitsandbytes segfaults in Git Bash). Kill Python between experiment cells to free GPU memory.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Factory I/O (plant simulation)                         │
└───────────────────────┬─────────────────────────────────┘
                        │ physical I/O
┌───────────────────────▼─────────────────────────────────┐
│  Siemens S7-1200 PLC (TIA Portal v17)   192.168.0.1    │
└───────────────────────┬─────────────────────────────────┘
                        │ python-snap7 (S7 protocol)
┌───────────────────────▼─────────────────────────────────┐
│  CPSForge Middleware                                     │
│                                                          │
│  Observation Layer                                       │
│    Tag Poller (500ms) → Snapshot → Phase Inference       │
│                                                          │
│  Context Builder (3 tiers)                               │
│    minimal | partial | full  →  LLM Prompt               │
│                                                          │
│  Red Team LLM                    Blue Team LLM           │
│    Online MITM Attacker    ←→    LLM Defender            │
│    (same model + context)        (same model + context)  │
│                                                          │
│  Defense Chain                                           │
│    Shield → PhaseAware → IntentCheck → LLM Defender      │
│                                                          │
│  PLC Writer (approved writes only)                       │
│                                                          │
│  Event Logger (JSONL capture of all PLC events)          │
└──────────────────────────────────────────────────────────┘
```

### Layers

1. **Physical Execution** — PLC runs control logic; Factory I/O renders the plant.
2. **Observation & Phase Inference** — Cyclic tag polling, timestamped snapshots, rule-based phase detection.
3. **Context Builder** — 3-tier prompt assembly (minimal / partial / full) for controlled RQ1 ablation.
4. **LLM Attacker** — Online MITM (observe → decide → act loop), static LLM (one-shot), random baseline.
5. **Safety Shield** — Validates every write against configurable rules (range, duration, cooldown, interlock, invariant).
6. **Defense Chain** — Sequential: Safety Shield → PhaseAwareShield → IntentConsistencyChecker → LLM Defender.
7. **Event Capture** — Structured JSONL logging of all PLC reads, writes, blocks, and session events.

---

## Project Structure

```
CPSForge/
├── pyproject.toml              # Package metadata, dependencies, entry point
├── requirements.txt            # Pip-installable dependency list
├── run_experiments.py          # Main experiment runner
├── START_EXPERIMENTS.ps1       # PowerShell script for full 333-run matrix
├── download_models.py          # Download HuggingFace models
├── verify_plc_scene.py         # PLC + scene validation
├── configs/
│   ├── system/                 # PLC connection, logging
│   ├── scenes/                 # Factory I/O scene profiles (YAML)
│   ├── llm/                    # LLM provider configs
│   │   ├── huggingface.yaml            # Qwen2.5-3B base
│   │   ├── huggingface_finetuned.yaml  # Qwen2.5-3B + QLoRA adapter
│   │   ├── huggingface_qwen3_17b.yaml  # Qwen3-1.7B
│   │   ├── huggingface_smollm3_3b.yaml # SmolLM3-3B
│   │   └── prompts/                    # Online MITM + context-tier templates
│   ├── attacks/                # Attacker configurations
│   ├── defenders/              # Defense configurations
│   └── experiments/            # Experiment presets
├── cpsforge/                   # Main Python package
│   ├── observation/            # Live state collection + phase inference
│   ├── context_builder/        # 3-tier prompt context assembly (C2)
│   ├── attacker/               # Online MITM + static attackers (C1)
│   ├── defenses/               # PhaseAwareShield, IntentChecker, LLM Defender (C4)
│   ├── runner/                 # Online runner, experiment matrix
│   ├── finetune/               # QLoRA fine-tuning pipeline (C3)
│   ├── plc/                    # PLC client + event logger
│   ├── analysis/               # Paper table generation + capture analysis
│   ├── llm/                    # HuggingFace provider (4-bit NF4, LoRA)
│   ├── shield/                 # Safety shield engine
│   ├── scenes/                 # Factory I/O scene abstraction
│   ├── core/                   # Configuration + data models
│   └── logging/                # Unified per-step logging (33+ fields)
├── finetune/
│   └── adapters/               # QLoRA adapters (v2: 2,057 examples)
├── data/
│   ├── raw/                    # Per-run artifacts (traces, attacks, events)
│   ├── processed/              # Fine-tuning data, aggregate summaries
│   ├── captures/               # PLC event captures (JSONL)
│   └── replays/                # Replay data
├── models/                     # Local model weights (not committed)
│   ├── qwen2.5-3b-instruct/   # Primary model (~6 GB)
│   ├── qwen3-1.7b/            # Scaling comparator (~4 GB)
│   └── smollm3-3b/            # Cross-family (~6 GB)
├── overleaf/                   # LaTeX paper source (IEEE TII format)
├── overleaf-ccs/               # LaTeX paper source (ACM CCS format)
├── factoryio_scenes/           # TIA Portal SCL source for all scenes
├── cpsforge_tiaportal/         # TIA Portal v17 project files
├── docs/                       # Guides and documentation
└── scripts/                    # Standalone analysis scripts
```

---

## Run Artifacts

Each run produces a folder under `data/raw/<experiment>/<run_id>/`:

| File | Contents |
|------|----------|
| `trace.parquet` | Timestamped plant snapshots (33+ fields per step) |
| `attacks.json` | All proposed attack actions with shield decisions |
| `metadata.json` | Run configuration, PLC IP, scene, timing |

PLC event captures go to `data/captures/<run_id>_plc_events.jsonl`:

| Event Type | Description |
|------------|-------------|
| `poll_read` | Every 500 ms tag poll with all tag values |
| `attack_write` | Approved write executed on PLC |
| `blocked_write` | Write blocked by defense chain (stage, reason, score) |
| `connect/disconnect` | PLC TCP session events |

**Regenerate paper tables:** `py -3 -m cpsforge.analysis.generate_tables`

---

## Online MITM Attack Loop

```
Every k=3 polling steps (1.5s):
  1. Observe current PLC state (sensors, actuators, setpoints, alarms)
  2. Inspect sliding-window history
  3. Infer operational phase
  4. Build context-tier-specific prompt (minimal | partial | full)
  5. LLM decides: attack | wait
  6. If attack: emit structured JSON (target_tag, action_value, duration, reasoning)
  7. Pass through defense chain (shield → phase → intent → LLM defender)
  8. Execute approved writes on PLC (or log blocked)
  9. Observe result → continue iteratively
```

- Attack budget: max 10 per run
- LLM timeout: 120s per call (full context takes ~30s on 3B model)
- On timeout or parse failure: default to "wait" (safe fallback)

---

## Defense Chain

All proposed PLC writes pass through this chain in order:

```
Safety Shield → PhaseAwareShield → IntentConsistencyChecker → LLM Defender → PLC Write
```

Each stage can independently block a write. A write must pass ALL active stages.

| Variant | Description |
|---------|-------------|
| `none` | No defense (measures raw attacker capability) |
| `baseline` | Threshold + invariant detectors |
| `phase_aware` | PhaseAwareShield: blocks phase-inconsistent writes |
| `intent` | IntentConsistencyChecker: blocks controller-trend-opposing writes |
| `combined` | phase_aware + intent together |
| `llm_defender` | LLM-based anomaly defender (same model as attacker) |
| `llm_combined` | phase_aware + intent + LLM defender |

---

## Fine-Tuning (QLoRA)

Training data: `data/processed/finetune_v2/finetune_examples.jsonl` (2,057 examples)

| Category | Examples | Purpose |
|----------|----------|---------|
| Attack | 83 | Post-hoc verified physically successful attacks |
| Defense (block) | 608 | Known attack proposals → gold `{decision: "block"}` |
| Defense (allow) | 1,366 | Normal operation → gold `{decision: "allow"}` |

QLoRA config: rank=16, alpha=32, dropout=0.05, 3 epochs, lr=2e-4. Trainable: 29.9M params (0.96% of 3.1B).

Output: `finetune/adapters/qwen25_3b_cps_v2/final_adapter/`

---

## Hardware Setup

| Component | Details |
|-----------|---------|
| **PLC** | Siemens S7-1200, IP 192.168.0.1, TIA Portal v17 |
| **Plant** | Factory I/O (software process emulator) |
| **Bridge** | Dell Precision 5820, RTX A4000 16 GB VRAM |
| **Protocol** | python-snap7, S7 protocol, 500 ms polling |
| **OS** | Windows 11 Enterprise |
| **Safety** | `live_writes_enabled: false` by default |

---

## Configuration

All behavior is config-driven via YAML files under `configs/`. See:

- [Quick Start Guide](docs/quickstart.md)
- [Scene Config Guide](docs/scene_config.md) — Tag definitions, safety rules, attack surface
- [Hardware Deployment Guide](docs/hardware_deployment.md) — PLC + Factory I/O setup
- [Safety Notes](docs/safety_notes.md) — Shield rules, dry-run mode, live-write controls
- [Evaluation Workflow](docs/evaluation_workflow.md) — Full experiment matrix execution
- [Metrics Guide](docs/metrics_guide.md) — ASR, VAR, prevention rate definitions

## Extending CPSForge

- [Adding a New Attacker](docs/adding_attacker.md)
- [Adding a New Detector](docs/adding_detector.md)
- [Adding a New Scene](docs/adding_scene.md)

---

## Safety

CPSForge is a **CPS security research framework**, not malware.

- **Dry-run by default** — no PLC writes unless explicitly enabled
- **Mandatory safety shield** — every write validated against scene-specific safety rules
- **Structured actions only** — no raw PLC writes from LLM; all outputs parsed into JSON schema
- **Auditable** — every action, decision, and detection is logged as structured JSONL
- **Attack budget** — maximum 10 attacks per 60-step run

See [Safety Notes](docs/safety_notes.md) for full details.

---

## License

MIT
