# Agent Mode — Live Adversarial Multi-Agent Framework

CPSForge supports a **live adversarial multi-agent mode** where an LLM-powered
Attacker Agent and an LLM-powered Defender Agent operate as independent
processes, each with their own PLC connection, observe–reason–act loops, and
LLM reasoning cycles.

This mode complements the existing batch experiment modes (scripted, random, LLM
single-shot). It is designed for studying autonomous, continuous adversarial
dynamics on a real Siemens S7 PLC + Factory I/O plant.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                 Coordinator (Main Process)                    │
│  - ShieldEngine (serializes ALL writes from both agents)     │
│  - PLC Writer (sole write connection via snap7)              │
│  - Ground-truth Poller (fixed interval, agent-independent)   │
│  - EventBus aggregator (receives + logs events)              │
│  - TraceRecorder + AgentRunArtifactWriter                    │
│  - Experiment lifecycle (start / stop / timeout / metrics)   │
│                                                              │
│  IPC Channels:                                               │
│    write_request_queue ← agents submit WriteRequest          │
│    write_result_queues → per-agent WriteResult               │
│    event_queue ← agents publish AgentEvent                   │
└──────────────────────────────────────────────────────────────┘
        ↕ multiprocessing.Queue             ↕ multiprocessing.Queue
┌──────────────────────────┐      ┌──────────────────────────┐
│   Attacker Agent Process  │      │   Defender Agent Process  │
│   - Own PlcClient (read)  │      │   - Own PlcClient (read)  │
│   - LLM Provider instance │      │   - LLM Provider instance │
│   - Attack history buffer │      │   - Detection history      │
│   - Agent PromptBuilder   │      │   - Rule-based detectors   │
│                           │      │   - Agent PromptBuilder    │
│   Loop:                   │      │   Loop:                    │
│   1. Read PLC tags        │      │   1. Read PLC tags         │
│   2. Build context        │      │   2. Run fast detectors    │
│   3. LLM.complete()       │      │   3. LLM.complete()        │
│      → AttackAction       │      │      → Assessment + Action │
│   4. Submit WriteRequest  │      │   4. If anomaly detected:  │
│   5. Receive WriteResult  │      │      - Explain root cause  │
│   6. Update history       │      │      - Submit corrective   │
│   7. Repeat immediately   │      │   5. Publish DetectionEvent│
│                           │      │   6. Repeat immediately    │
└──────────────────────────┘      └──────────────────────────┘
```

### Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| State sharing | Each agent reads PLC directly | True real-time independence — no stale data |
| PLC writes | Coordinator only | Single point of safety enforcement |
| Concurrency | `multiprocessing.Process` | Full memory isolation, crash containment |
| IPC | `multiprocessing.Queue` | Simple, reliable, pickle-compatible |
| Agent pacing | Continuous (as fast as LLM responds) | Natural adversarial dynamics |
| Defender role | Detect + Explain + Respond | Active corrective writes, not just alerting |

---

## Components

### Messages (`cpsforge/agents/messages.py`)

IPC message contracts that cross process boundaries:

- **`WriteRequest`** — Agent submits a proposed PLC write; includes `kind` field
  (`ATTACK` or `CORRECTIVE`) so the Coordinator routes it correctly.
- **`WriteResult`** — Coordinator replies with approval/rejection and the
  `ShieldDecision`.
- **`AgentEvent`** — Timestamped event published to the shared event queue
  (13 event types: `AGENT_STARTED`, `ATTACK_PROPOSED`, `DETECTION_EMITTED`, etc.).
- **`RequestKind`** — Enum distinguishing attack writes from defender corrective
  writes.

### Event Bus (`cpsforge/agents/event_bus.py`)

Queue-backed event aggregator. The Coordinator calls `bus.collect()` each cycle
to drain agent events for logging and analysis.

### Base Agent (`cpsforge/agents/base.py`)

Abstract base for live agents. Provides the observe → reason → act skeleton:

```
while not stop_event.is_set():
    state = observe()       # Read PLC
    decision = reason(state) # LLM call
    act(decision)            # Submit write via queue
```

Also provides `submit_write_request()` and `publish_event()` helpers, bounded
history management via `max_history`, and graceful shutdown on `stop_event`.

### Attacker Agent (`cpsforge/agents/attacker_agent.py`)

LLM-powered live attacker. Each cycle:

1. Reads all scene tags from the PLC.
2. Builds a rich prompt via `PromptBuilder.build_attacker_agent_user_prompt()`.
3. Calls the LLM for a structured `AttackAction` JSON.
4. Validates and compiles the action via `ActionCompiler`.
5. Submits a `WriteRequest(kind=ATTACK)` to the Coordinator.
6. Waits for the `WriteResult`.
7. Updates attack history and publishes events.

### Defender Agent (`cpsforge/agents/defender_agent.py`)

LLM-powered defender with fast pre-screening. Each cycle:

1. Reads all scene tags from the PLC.
2. Runs threshold and invariant detectors on the snapshot locally.
3. If alerts fire, builds a prompt via `PromptBuilder.build_defender_agent_user_prompt()`.
4. LLM returns a JSON assessment with optional `corrective_action`.
5. If corrective action proposed, validates the target against the attack surface,
   wraps it in a `WriteRequest(kind=CORRECTIVE)`, and submits to the Coordinator.
6. Publishes `DetectionEvent`s to the event queue.

Corrective target validation ensures the LLM cannot write to arbitrary tags.

### Coordinator (`cpsforge/agents/coordinator.py`)

Main-process mediator that:

- Drains `write_request_queue` each tick.
- Routes `ATTACK` requests through `shield.evaluate()`.
- Routes `CORRECTIVE` requests through `shield.evaluate_corrective()` (skips
  cooldown rules for rapid recovery but enforces all other safety checks).
- Executes approved writes on the PLC via the sole write connection.
- Sends `WriteResult` back to the requesting agent.
- Records all decisions for tracing.

### Runtime (`cpsforge/agents/runtime.py`)

Lifecycle manager that:

1. Creates multiprocessing queues and stop events.
2. Spawns `AttackerAgent` and `DefenderAgent` as `Process` instances.
3. Runs the coordinator loop until `max_steps` reached or timeout.
4. Signals agents to stop and joins processes.
5. Writes run artifacts: `trace.parquet`, `agent_events.json`,
   `agent_metrics.json`, `metadata.json`.
6. Returns `AgentRuntimeResult` with metrics and artifact directory.

---

## Configuration

### Agent Configs

**Attacker:** `configs/agents/attacker_agent.yaml`

```yaml
name: attacker_agent
role: attacker
llm_config_path: configs/llm/local.yaml
max_history: 50
cycle_delay_s: 1.0
```

**Defender:** `configs/agents/defender_agent.yaml`

```yaml
name: defender_agent
role: defender
llm_config_path: configs/llm/local.yaml
max_history: 100
cycle_delay_s: 0.5
detector_configs:
  - configs/defenders/threshold_tank_control.yaml
  - configs/defenders/invariant_tank_control.yaml
```

### Experiment Config

`configs/experiments/agent_level_control.yaml`

```yaml
experiment_name: agent_level_control
scene: level_control
mode: agent              # ← selects agent runtime
dry_run: true
max_steps: 100
eval_run: false

attacker_config: configs/agents/attacker_agent.yaml
defender_config: configs/agents/defender_agent.yaml
```

Set `mode: agent` to use the multi-agent runtime. Other modes (`baseline`,
`attack`, `closed-loop`, `detect-replay`) continue to use the existing
orchestrator.

### Prompt Templates

Agent prompts live under `configs/llm/prompts/v1/`:

| File | Purpose |
|------|---------|
| `attacker_agent_system.md` | System prompt: CPS context, JSON schema, strategy guidelines |
| `attacker_agent_user.md` | Per-cycle prompt: current state, history, objective |
| `defender_agent_system.md` | System prompt: detect/explain/respond role, corrective surface |
| `defender_agent_user.md` | Per-cycle prompt: current state, alerts, detection history |

Templates use `{{placeholder}}` syntax and are rendered by `PromptBuilder`.

---

## CLI Usage

```bash
# Dry-run agent experiment (no PLC writes)
cpsforge run agent --scene level_control --dry-run --max-steps 20

# Live agent run (requires PLC + CPSFORGE_LIVE_WRITES=true)
cpsforge run agent --scene level_control --no-dry-run --max-steps 100

# With explicit config
cpsforge run agent --config configs/experiments/agent_level_control.yaml
```

---

## Run Artifacts

Agent runs produce artifacts under `data/raw/<experiment>/<run_id>/`:

| File | Contents |
|------|---------|
| `trace.parquet` | Timestamped plant snapshots |
| `agent_events.json` | All agent events (attacks, detections, errors, lifecycle) |
| `agent_metrics.json` | `AgentEvalMetrics` (attack/defense pipeline stats) |
| `metadata.json` | Config snapshot, timing, mode |

### Agent Metrics (`AgentEvalMetrics`)

| Field | Description |
|-------|-------------|
| `total_steps` | Coordinator cycles completed |
| `attacker_cycles` | Attacker observe–reason–act iterations |
| `defender_cycles` | Defender observe–reason–act iterations |
| `attacks_submitted` | Total attack write requests |
| `attacks_approved` | Approved by shield |
| `attacks_rejected` | Rejected by shield |
| `attacks_executed` | Successfully written to PLC |
| `attack_approval_rate` | `approved / submitted` |
| `detections_emitted` | Detection events published |
| `correctives_submitted` | Corrective write requests |
| `correctives_approved` | Corrective writes approved |
| `correctives_rejected` | Corrective writes rejected |
| `correctives_executed` | Corrective writes applied |
| `corrective_success_rate` | `approved / submitted` |
| `attacker_errors` | LLM / parsing / timeout errors in attacker |
| `defender_errors` | LLM / parsing / timeout errors in defender |

---

## Shield Behavior for Corrective Writes

The shield's `evaluate_corrective()` method handles defender corrective writes:

- **Cooldown bypass** — Corrective writes skip the cooldown window between
  repeated writes to the same tag (permits rapid recovery actions).
- **All other rules enforced** — Range, duration, whitelist, interlock, and
  invariant checks still apply to corrective writes.
- **Target validation** — The Defender Agent validates corrective write targets
  against the scene's `attack_surface` before submission.

This prevents the defender from being exploited as a backdoor for unsafe writes
while still allowing timely corrective responses.

---

## Safety

All safety guarantees from batch mode carry over:

1. **Dry-run by default** — `dry_run: true` prevents PLC writes.
2. **No raw PLC writes from agents** — All writes go through the Coordinator →
   Shield pipeline.
3. **Process isolation** — Agent crashes do not affect the Coordinator or PLC.
4. **Write serialization** — The Coordinator processes one write request at a
   time; no race conditions.
5. **Read-only agent connections** — Agent PLC clients are configured for read
   access only; writes are physically routed through the Coordinator.

---

## Extending Agent Mode

### Custom Attacker Agent

1. Subclass `BaseAgent` from `cpsforge/agents/base.py`.
2. Override `observe()`, `reason()`, and `act()`.
3. Register via a new agent config YAML.

### Custom Defender Agent

1. Subclass `BaseAgent`.
2. Wire in custom detectors during `observe()`.
3. Emit corrective writes via `submit_write_request(kind=CORRECTIVE)`.

### Custom Prompt Templates

Create new template files under `configs/llm/prompts/v2/` and reference the
version in your LLM config. Templates support all `{{placeholder}}` variables
documented in the template files.

---

## Relationship to Batch Mode

Agent mode and batch mode coexist:

| Aspect | Batch Mode | Agent Mode |
|--------|------------|------------|
| Entry point | `cpsforge run attack` | `cpsforge run agent` |
| Attacker | Single-shot per step | Continuous autonomous loop |
| Defender | Passive detector stack | Active detect + respond |
| LLM calls | One per attack step | Continuous per-cycle |
| PLC writes | Orchestrator writes | Coordinator mediates |
| Shield | `evaluate()` for all writes | `evaluate()` for attacks, `evaluate_corrective()` for correctives |
| Artifacts | `metrics.json`, `trace.parquet` | `agent_metrics.json`, `agent_events.json`, `trace.parquet` |

Both modes share the same PLC client, shield engine, scene profiles, and config
infrastructure.
