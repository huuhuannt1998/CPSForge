# CPSForge

**CPSForge: Measuring the Realized Effects of LLM-Generated PLC Writes**
Huan Bui and Chenglong Fu, University of North Carolina at Charlotte
*IEEE IPCCC 2026* (short paper), Austin, TX, USA

CPSForge is a PLC-in-the-loop measurement framework. It couples a **physical Siemens S7-1200 PLC** with **Factory I/O** simulated plants and places a bounded, online LLM agent on a configured semantic action surface. A **mandatory safety shield** validates every proposed write before it reaches the PLC, and the same model serves as a defender with a different prompt. The framework records, separately for each proposed action:

1. whether the model produced a schema-valid proposal,
2. whether the proposal passed enforcement and was executed as an S7 write,
3. whether the target value subsequently moved toward the requested value, and
4. whether the run produced a process-level deviation.

It is a measurement instrument, not a deployment architecture. All results come from **333 runs** on a real S7-1200.

> **Safety default:** all commands run in dry-run mode (no PLC writes) unless live writes are explicitly enabled.

---

## Main Findings

All rates are conditional on the configured action surface, the mandatory shield, the prompts, and a supervisory-timescale agent (one decision per 13–33 s). See the paper for the full caveats.

| | Finding |
|---|---|
| **F1** | **Writeability is an incomplete proxy for realized effect.** In the tested programs, writes to parameters the program does not cyclically refresh show a higher target-movement rate (TMR) than writes to scan-refreshed variables: 33.7% vs. 10.8% for base Qwen2.5-3B (per-write, descriptive). A single-write intervention is consistent with cyclic overwrite erasing injected values. |
| **F1b** | **Target movement and process deviation are distinct.** Substantial process deviations occur in a minority of attack-active runs (32.5% exceed a two-unit tank excursion vs. 2.9% of quiet runs). |
| **F2** | **More context is not monotonically better.** No context tier dominates across scenes, and full context often suppresses proposals altogether. |
| **F3** | **Feedback appears to help.** In a small repaired single-action comparison, the online agent reaches 77.5% TMR vs. 57.1% for a static one-shot LLM (only 7 static writes, so directional). |
| **F4** | **Results vary across models.** Both tested 3B models produce nonzero TMR on Level Control and Qwen3-1.7B does not; model-family differences prevent attributing this to parameter count. |
| **F5** | **The same-scale LLM defender does not discriminate.** It blocks every adversarial proposal on Sorting by Height but also rejects 226 of 229 known-benign probes (FPR 98.7%). This is block-all behavior, not deployable detection. |

### Models

| Model | Parameters | Role |
|-------|-----------|------|
| Qwen2.5-3B-Instruct | ~3B (4-bit NF4) | Primary model (base; exploratory QLoRA pilot) |
| Qwen3-1.7B | ~1.7B (4-bit NF4) | Cross-model comparison |
| SmolLM3-3B | ~3B (4-bit NF4) | Cross-model comparison |
| GPT-4o-mini | API | API-model comparison |

### Evaluation Scenes

| Scene | DB | Tags | R/W | Process Type |
|-------|-----|------|-----|-------------|
| Level Control | DB14 | 15 | 4 | Continuous (PID) |
| Sorting by Height | DB21 | 30 | 8 | Discrete (state machine) |
| Sorting by Weight | DB22 | 35 | 11 | Discrete (classification) |

---

## Quick Start

```bash
# Clone and install (Python >= 3.11)
git clone https://github.com/huuhuannt1998/CPSForge.git && cd CPSForge
pip install -e ".[dev,torch]"

# Model weights are not committed. Download them into models/ and point
# configs/llm/*.yaml at them (see the comments in configs/llm/huggingface.yaml).

# Inspect and validate a scene profile
cpsforge scene info --scene level_control
cpsforge scene validate --scene level_control

# Check the PLC connection (requires the S7-1200 and Factory I/O)
cpsforge plc probe

# Run the online agent on one scene (dry-run by default: no PLC writes)
cpsforge run agent --scene level_control --experiment agent_level_control

# Summarize an experiment's runs
cpsforge report summarize --experiment agent_level_control
```

> **Windows note:** run from **PowerShell**, not Git Bash (bitsandbytes segfaults in Git Bash). Restart Python between experiment cells to free GPU memory.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Factory I/O (simulated plant)                          │
└───────────────────────┬─────────────────────────────────┘
                        │ physical I/O
┌───────────────────────▼─────────────────────────────────┐
│  Siemens S7-1200 PLC (TIA Portal v17)                   │
└───────────────────────┬─────────────────────────────────┘
                        │ python-snap7 (S7 protocol)
┌───────────────────────▼─────────────────────────────────┐
│  CPSForge Middleware                                     │
│                                                          │
│  Observation Layer                                       │
│    Tag poller (500 ms) → snapshot → phase inference      │
│                                                          │
│  Context Builder (3 tiers)                               │
│    minimal | partial | full  →  LLM prompt               │
│                                                          │
│  Red Team                        Blue Team               │
│    Online LLM agent              LLM defender            │
│    (same model + context)        (same model + context)  │
│                                                          │
│  Enforcement chain                                       │
│    Safety Shield (mandatory) → PhaseAware → Intent →     │
│    LLM defender (per configuration)                      │
│                                                          │
│  PLC writer (approved writes only)                       │
│  Event logger (JSONL capture of all PLC events)          │
└──────────────────────────────────────────────────────────┘
```

### Layers

1. **Physical execution:** the PLC runs the control logic; Factory I/O simulates the plant.
2. **Observation and phase inference:** cyclic tag polling, timestamped snapshots, rule-based phase inference (an inference, not ground truth).
3. **Context builder:** 3-tier prompt assembly (minimal / partial / full), served identically to attacker and defender.
4. **Attackers:** the online agent (observe, decide, act), a static one-shot LLM, and random baselines.
5. **Safety shield:** validates every write (whitelist, range, duration cap, cooldown, invariant, interlock, mode gate).
6. **Defense chain:** Safety Shield → PhaseAwareShield → IntentConsistencyChecker → LLM defender. Each stage can block independently.
7. **Event capture:** structured JSONL logging of all PLC reads, writes, blocks, and session events.

---

## Online Agent Loop

The agent runs at a **supervisory timescale**, not the PLC scan cycle. Tag acquisition runs in its own thread at 500 ms while the plant keeps evolving during inference.

```
Every 3rd agent iteration:
  1. Capture the latest PLC snapshot (sensors, actuators, setpoints, alarms)
  2. Inspect the sliding-window history
  3. Infer the operational phase
  4. Build the context-tier prompt (minimal | partial | full)
  5. LLM decides: attack | wait   (13–33 s per call for the 3B model)
  6. If attack: emit structured JSON (target tag, value, duration, reasoning)
  7. Pass through the enforcement chain (shield → phase → intent → LLM defender)
  8. Execute approved writes on the PLC (or log the block)
```

- Attack budget: at most 10 per 60-iteration run (6–10 minutes per run)
- On timeout or parse failure: default to `wait`

---

## Defense Configurations

| Variant | Description |
|---------|-------------|
| `none` | Mandatory safety shield only |
| `baseline` | Shield plus six anomaly detectors (threshold, invariant, CUSUM, Isolation Forest, One-Class SVM, LSTM autoencoder) |
| `phase_aware` | PhaseAwareShield: blocks phase-inconsistent writes |
| `intent` | IntentConsistencyChecker: blocks writes that oppose the controller trend |
| `combined` | `phase_aware` + `intent` |
| `llm_defender` | LLM defender (same model and context as the attacker) |
| `llm_combined` | `phase_aware` + `intent` + LLM defender |

---

## Project Structure

```
CPSForge/
├── pyproject.toml              # Package metadata; installs the `cpsforge` CLI
├── requirements.txt
├── configs/
│   ├── system/                 # PLC connection, logging
│   ├── scenes/                 # Factory I/O scene profiles (YAML)
│   ├── llm/                    # Model configs and prompt templates
│   ├── attacks/                # Attacker configurations
│   ├── defenders/              # Defense configurations
│   └── experiments/            # Experiment presets
├── cpsforge/                   # Main Python package
│   ├── cli/                    # `cpsforge` command-line interface
│   ├── observation/            # Live state collection + phase inference
│   ├── context_builder/        # 3-tier prompt context assembly
│   ├── attacker/               # Online agent + static attackers
│   ├── defenses/               # PhaseAwareShield, IntentChecker, LLM defender
│   ├── shield/                 # Safety shield engine
│   ├── runner/                 # Online runner, experiment matrix
│   ├── finetune/               # QLoRA fine-tuning pipeline
│   ├── plc/                    # PLC client + event logger
│   ├── analysis/               # Table generation + capture analysis
│   ├── llm/                    # HuggingFace provider (4-bit NF4, LoRA)
│   ├── scenes/                 # Scene abstraction
│   ├── core/                   # Configuration + data models
│   └── logging/                # Unified per-step logging
├── factoryio_scenes/           # TIA Portal SCL source for the scenes
├── cpsforge_tiaportal/         # TIA Portal v17 project files
├── docs/                       # Guides
└── scripts/                    # Experiment-matrix generator and analysis scripts
```

Model weights (`models/`), fine-tuning adapters, and run data (`data/raw/`, `data/processed/`, `data/captures/`) are not committed.

---

## Run Artifacts

Each run writes a folder under `data/raw/<experiment>/<run_id>/`:

| File | Contents |
|------|----------|
| `trace.parquet` | Timestamped acquisition samples and agent decisions |
| `attacks.json` | Proposed actions with shield and defense decisions |
| `metadata.json` | Run configuration, scene, timing |

PLC event captures go to `data/captures/<run_id>_plc_events.jsonl` (`poll_read`, `attack_write`, `blocked_write`, `connect`/`disconnect`).

The per-run traces and S7 event logs behind the paper will be released in this repository. Regenerate tables with `python -m cpsforge.analysis.generate_tables`.

**Metrics.** The paper reports the valid-proposal rate, the execution rate, the target-movement rate (TMR), and the proposal-blocking rate (Section IV of the paper). Some code identifiers and docs predate the paper and use older metric names.

---

## Fine-Tuning (Exploratory QLoRA Pilot)

Training data: 2,057 examples (83 attack, 608 defense-block, 1,366 defense-allow). QLoRA config: rank 16, alpha 32, dropout 0.05, 3 epochs, lr 2e-4. In the paper this is a single-split, single-seed pilot that did not transfer across scenes; treat it as exploratory.

---

## Hardware Setup

| Component | Details |
|-----------|---------|
| **PLC** | Siemens S7-1200, TIA Portal v17 (non-optimized DBs, PUT/GET enabled) |
| **Plant** | Factory I/O |
| **Bridge** | Dell Precision 5820, RTX A4000 16 GB |
| **Protocol** | python-snap7, S7, 500 ms polling |
| **OS** | Windows 11 |
| **Safety** | `live_writes_enabled: false` by default |

---

## Documentation

- [Quick Start Guide](docs/quickstart.md)
- [Scene Config Guide](docs/scene_config.md): tag definitions, safety rules, action surface
- [Hardware Deployment Guide](docs/hardware_deployment.md): PLC and Factory I/O setup
- [Safety Notes](docs/safety_notes.md): shield rules, dry-run mode, live-write controls
- [Evaluation Workflow](docs/evaluation_workflow.md)
- [Metrics Guide](docs/metrics_guide.md)
- [Adding a New Attacker](docs/adding_attacker.md) · [Adding a New Detector](docs/adding_detector.md) · [Adding a New Scene](docs/adding_scene.md)

---

## Safety and Responsible Use

CPSForge is a CPS security **measurement** framework, intended for isolated laboratory testbeds.

- **Dry-run by default:** no PLC writes unless explicitly enabled
- **Mandatory safety shield:** every write is validated against scene-specific safety rules
- **Structured actions only:** the LLM never issues raw PLC writes; outputs are parsed into a JSON schema
- **Auditable:** every action, decision, and detection is logged
- **Attack budget:** at most 10 writes per 60-iteration run

Never connect CPSForge to production control systems. See [Safety Notes](docs/safety_notes.md).

---

## Citation

```bibtex
@inproceedings{bui2026cpsforge,
  author    = {Bui, Huan and Fu, Chenglong},
  title     = {{CPSForge}: Measuring the Realized Effects of {LLM}-Generated {PLC} Writes},
  booktitle = {Proceedings of the 45th IEEE International Performance, Computing, and Communications Conference (IPCCC)},
  address   = {Austin, TX, USA},
  year      = {2026}
}
```

---

## License

MIT
