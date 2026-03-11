# CPSForge

**CPSForge** is a closed-loop LLM red-team / blue-team testbed for **cyber-physical systems (CPS)**. It is designed for **hardware-in-the-loop (HIL)** experimentation with a **real Siemens PLC**, **TIA Portal v17**, and **Factory I/O**.

The goal of CPSForge is to provide a research-grade framework for:

- generating **process-aware attacks** against CPS environments,
- enforcing a **runtime safety shield** before any live actuation,
- evaluating **classical and learned defenders**,
- storing **hard cases** from missed detections,
- and enabling **closed-loop defender adaptation** over repeated rounds.

CPSForge is built for reproducibility, safety, and extensibility.

---

## Key Features

- **Real PLC + Factory I/O integration**
  - Siemens S7 PLC support via `python-snap7`
  - Compatible with TIA Portal v17 deployments
  - Designed for a real PLC deployment at `192.168.1.10`
  - Factory I/O scene abstraction for continuous and discrete processes

- **Real PLC-first architecture**
  - Built around live hardware execution rather than a simulated PLC backend
  - Supports dry-run validation for safe testing of attack planning and shield decisions
  - Designed for bridge-machine deployment against an operational PLC + Factory I/O loop

- **Structured attack framework**
  - Scripted attacker
  - Random attacker
  - LLM attacker with strict JSON action schema
  - No arbitrary raw PLC writes from the LLM

- **Mandatory runtime safety shield**
  - All writes go through the shield
  - Writable-tag whitelist
  - Range checks
  - Duration limits
  - Cooldown windows
  - Scene-specific invariants
  - Rollback / deadman timer support

- **Defender framework**
  - Threshold-based detector
  - Invariant-based detector
  - Sequence-model detector scaffold
  - Optional LLM-based explanation module

- **Closed-loop adaptation**
  - Hard-case extraction from missed or late detections
  - Replay bank for failed cases
  - Retraining hooks for defender improvement over rounds

- **Experiment management**
  - Structured trace logging
  - Metrics collected directly from eval runs on the real PLC + Factory I/O loop
  - Replay-ready run folders
  - Config-driven experiments
  - CLI for attack runs, closed-loop runs, replay, and reporting

---

## Research Motivation

Large language models are increasingly being explored for cyber-physical and industrial control systems, but most current work remains limited to static datasets, isolated attack generation, or offline anomaly explanation.

CPSForge focuses on a stronger systems question:

> How can we safely evaluate and improve LLM-driven CPS attack and defense capabilities in a real hardware-in-the-loop environment?

The framework is designed to support research on:

- **process-grounded LLM attack generation**
- **runtime-safe LLM experimentation**
- **adaptive CPS defense**
- **invariant-based monitoring**
- **prompt injection and unsafe actuation risks in CPS**
- **closed-loop red-team / blue-team co-evolution**

---

## High-Level Architecture

CPSForge is organized into six layers:

### 1. Physical Execution Layer
- **PLC** runs the control logic deployed from TIA Portal
- **Factory I/O** simulates the physical process
- CPSForge communicates with the PLC through a Python middleware bridge
- The initial deployment targets a real Siemens PLC at `192.168.1.10`

### 2. Observation and Logging Layer
- polls PLC tags at a configurable interval
- creates structured plant snapshots
- logs attacks, detector outputs, shield decisions, alarms, experiment metadata, and eval metrics

### 3. Attack Layer
- supports scripted, random, and LLM-based attackers
- attackers generate **structured actions**, not direct raw writes
- actions are compiled into concrete PLC writes only after validation

### 4. Safety Shield Layer
- validates every action
- enforces scene-specific and generic safety rules
- supports rejection, normalization, expiration, and rollback planning

### 5. Defender Layer
- runs rule-based or learned detectors
- tracks detection confidence, severity, affected tags, and latency

### 6. Adaptation Layer
- stores missed or weakly detected attacks as hard cases
- supports replay, retraining, and iterative defender improvement

---

## Evaluation and Metrics Collection

All primary metrics in CPSForge are collected during explicitly labeled **eval runs** on the real PLC + Factory I/O setup. These runs generate the experiment artifacts used for analysis, comparison, reporting, and paper tables.

Metrics collected during eval runs include:

- attack action validity
- execution success
- attack success rate
- physical impact / process deviation
- shield approval and rejection behavior
- unsafe action block rate
- detector precision, recall, and F1
- false positives and false negatives
- detection latency
- hard-case frequency
- defender improvement across adaptation rounds

Each eval run stores structured artifacts such as traces, attack records, shield decisions, detector outputs, per-run metrics, and metadata for replay and offline analysis.

---

## Project Structure

```text
cpsforge/
├── README.md
├── CLAUDE.md
├── pyproject.toml
├── requirements.txt
├── .env.example
├── configs/
│   ├── system/
│   ├── scenes/
│   ├── attacks/
│   ├── defenders/
│   └── experiments/
├── cpsforge/
│   ├── __init__.py
│   ├── main.py
│   ├── cli/
│   ├── core/
│   ├── plc/
│   ├── scenes/
│   ├── attacks/
│   ├── shield/
│   ├── defenders/
│   ├── adaptation/
│   ├── logging/
│   ├── llm/
│   ├── api/
│   ├── utils/
│   └── tests/
├── scripts/
├── data/
│   ├── raw/
│   ├── processed/
│   └── replays/
├── docs/
└── examples/