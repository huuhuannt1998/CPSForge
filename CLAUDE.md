You are my principal systems engineer and research code architect.

I want you to build a full research-grade prototype called CPSForge.

Project title:
CPSForge: A Closed-Loop LLM Red-Team/Blue-Team Testbed for Cyber-Physical Systems

Mission:
Build a modular, hardware-in-the-loop CPS security framework that connects to my real Siemens PLC and Factory I/O scene, enables structured LLM-driven attack planning, enforces a runtime safety shield, evaluates classical and learned defenders, and supports closed-loop defender adaptation from failed detections.

Core vision:
- A real PLC running logic engineered in TIA Portal v17 controls a Factory I/O plant.
- The PLC IP is 192.168.0.1.
- A Python middleware layer reads and writes PLC tags.
- An LLM attacker proposes structured CPS-aware attacks.
- A safety shield validates and constrains all write operations before they reach the PLC.
- A defender stack monitors the execution and detects anomalies.
- Misdetected attacks are stored as hard cases for iterative defender improvement.
- All paper metrics must be collected from evaluation runs on the real PLC + Factory I/O setup.
- The system must be reproducible, modular, safe, and publication-quality.

You must produce production-quality code, not a toy demo.

==================================================
1. HIGH-LEVEL GOALS
==================================================

Build a complete Python project with the following capabilities:

1. Connect to the real Siemens PLC through python-snap7.
2. Use the PLC IP 192.168.0.1 as the default connection target in configuration examples.
3. Read plant/controller tags cyclically.
4. Log all execution traces in a structured dataset format.
5. Represent each Factory I/O scene as a configurable environment profile.
6. Support structured attack actions, not arbitrary raw tag writes.
7. Support baseline scripted and random attacks.
8. Support an LLM attacker that outputs valid structured attack actions.
9. Enforce a runtime safety shield before any write is sent to the PLC.
10. Run baseline defenders and plug-in learned defenders.
11. Store hard cases from missed or late detections.
12. Support closed-loop replay and retraining of defenders.
13. Expose a CLI and a minimal web dashboard or terminal dashboard for monitoring runs.
14. Be easy to extend to additional scenes, detectors, and attack policies.
15. Collect all reported metrics from eval runs and save them as structured experiment artifacts.

This system is designed specifically for a real PLC + Factory I/O deployment. Do not design around a mock backend as a primary mode of operation.

==================================================
2. PRIMARY USE CASE
==================================================

The first target deployment is:

- Real Siemens S7 PLC
- PLC IP address: 192.168.0.1
- TIA Portal v17 project already deployed to hardware
- Factory I/O scene running as the plant
- A Python service on a bridge machine
- One initial scene, preferably level control or tank control
- LLM used first as an attack planner
- Defender used initially as threshold-based + one sequence model
- Shield used to constrain all experiments safely
- Metrics collected during eval runs on the live PLC-process loop

==================================================
3. SYSTEM ARCHITECTURE
==================================================

Design the codebase around these layers:

A. Physical Execution Layer
- real PLC interface
- Factory I/O environment abstraction
- scene profiles
- real hardware execution path

B. Observation and Logging Layer
- cyclic polling of tags
- consistent timestamping
- trace recording
- attack and defense labeling
- safety event logging
- metric collection during eval runs

C. Attack Layer
- baseline scripted attacker
- random attacker
- LLM attacker
- structured action schema
- action compiler

D. Safety Shield Layer
- tag whitelist
- range checks
- duration limits
- forbidden combinations
- scene-specific invariants
- rollback and deadman timer

E. Defender Layer
- threshold/rule-based detector
- sequence-based detector interface
- invariant-based detector
- optional LLM explanation module
- detection event stream

F. Adaptation Layer
- hard case extraction
- replay bank
- incremental retraining hooks
- prompt/policy refinement hooks
- evaluation across rounds

==================================================
4. NON-NEGOTIABLE ENGINEERING REQUIREMENTS
==================================================

1. Modular project structure.
2. Strong typing where practical.
3. Clean dataclasses or Pydantic models for schemas.
4. Extensive inline documentation.
5. Configuration-driven design using YAML or TOML.
6. Safe default behavior: no live writes unless explicitly enabled.
7. Support dry-run mode for safe validation of attack planning and shield decisions without applying writes.
8. All PLC writes must go through the shield.
9. Include unit tests and integration-test scaffolding.
10. Design and test against the real PLC backend rather than a mock PLC backend.
11. Include detailed README and setup instructions.
12. Include example configs for at least one scene.
13. Include reproducible experiment runner.
14. Use structured logging.
15. Avoid hardcoding scene-specific details in core logic.
16. Make metric extraction from eval runs explicit and reproducible.
17. Ensure every eval run writes all required artifacts for later analysis.

==================================================
5. SUGGESTED TECH STACK
==================================================

Use Python as the main language.

Preferred libraries:
- python 3.11+
- python-snap7
- pydantic or dataclasses
- typer or click for CLI
- fastapi + uvicorn for optional API/dashboard backend
- pandas
- numpy
- scikit-learn
- pytorch for learned detector scaffolding
- pyyaml or tomllib
- rich for terminal dashboards/logging
- sqlite and/or parquet for trace storage
- matplotlib for offline plotting utilities

Do not over-engineer the frontend. A clean CLI + optional FastAPI status endpoint is enough.

==================================================
6. PROJECT DIRECTORY STRUCTURE
==================================================

Create a clean repository structure like this:

cpsforge/
  README.md
  CLAUDE.md
  pyproject.toml
  requirements.txt
  .env.example
  configs/
    system/
    scenes/
    attacks/
    defenders/
    experiments/
  cpsforge/
    __init__.py
    main.py
    cli/
    core/
    plc/
    scenes/
    attacks/
    shield/
    defenders/
    adaptation/
    logging/
    llm/
    api/
    utils/
    tests/
  scripts/
  data/
    raw/
    processed/
    replays/
  docs/
  examples/

Refine this structure if needed, but keep it clean and scalable.

==================================================
7. CORE DATA MODELS
==================================================

Define explicit schemas/models for the following:

1. TagDefinition
Fields:
- name
- address
- data_type
- access (read/write)
- unit
- min_value
- max_value
- description
- category (sensor, actuator, mode_bit, alarm, setpoint, internal)
- scene_name

2. PlantSnapshot
Fields:
- timestamp
- scene_name
- run_id
- step_id
- sensors
- actuators
- controller_state
- alarms
- setpoints
- derived_features
- attack_context
- defense_context
- safety_context

3. AttackAction
Fields:
- action_id
- attack_type
- target
- mode
- value
- duration_ms
- start_condition
- rationale
- expected_effect
- confidence
- source (scripted, random, llm)
- approved_by_shield
- execution_status

4. ShieldDecision
Fields:
- action_id
- approved
- reasons
- normalized_value
- expiration_time
- rollback_plan
- violated_rules

5. DetectionEvent
Fields:
- timestamp
- run_id
- detector_name
- severity
- label
- confidence
- explanation
- affected_tags

6. HardCaseRecord
Fields:
- run_id
- attack_id
- detector_outcome
- failure_mode
- trace_path
- summary
- recommended_followup

7. EvalMetrics
Fields:
- run_id
- scene_name
- attacker_name
- detector_names
- action_validity_rate
- execution_success_rate
- attack_success_rate
- process_impact_score
- shield_approval_rate
- shield_rejection_rate
- unsafe_block_rate
- detector_precision
- detector_recall
- detector_f1
- detection_latency_ms
- hard_case_flag
- adaptation_round

8. SceneProfile
Fields:
- scene_name
- description
- tags
- writable_tags
- safety_rules
- reset_procedure
- sampling_interval_ms
- attack_surface

==================================================
8. SCENE ABSTRACTION
==================================================

Implement a scene abstraction that supports multiple Factory I/O scenes.

Each scene must define:
- all relevant PLC tags
- tag metadata
- writable attack surface
- safety invariants
- reset behavior
- feature extraction hooks

Create one fully implemented reference scene:
- level control or tank control

Also create placeholders/templates for:
- sorting by height
- elevator
- pick-and-place

Do not assume all scenes are continuous processes; support both continuous and discrete-control scenes.

==================================================
9. PLC INTERFACE
==================================================

Implement a PLC client wrapper with:
- connect/disconnect
- read_tag
- write_tag
- read_many
- write_many
- health check
- reconnect logic
- explicit support for Siemens S7 communication via python-snap7

The default PLC configuration example must use:
- IP: 192.168.0.1

Important:
- all direct writes must be internal-only
- external modules must call a shielded write path
- support DB, I, Q, M style addressing where practical
- design with Siemens S7 use in mind
- treat the real PLC as the primary backend

Also create:
- PLC polling loop
- configurable poll rate
- jitter/error handling
- graceful shutdown

==================================================
10. ATTACK FRAMEWORK
==================================================

Implement three attacker types:

A. ScriptedAttacker
- predefined attack templates
- deterministic replayable runs

B. RandomAttacker
- random target selection within configured capabilities
- bounded values and durations

C. LLMAttacker
- builds an LLM prompt from:
  - scene profile
  - current plant snapshot
  - attacker objective
  - constraints
  - prior actions if in multi-step mode
- receives structured JSON only
- validates JSON
- retries with schema correction if malformed
- must not be allowed to issue raw PLC addresses directly

Attack types to support initially:
- sensor_spoof
- actuator_override
- setpoint_shift
- timing_delay
- sequence_perturbation

Each attack type should have a compiler that maps the abstract action into one or more concrete tag writes.

==================================================
11. LLM INTEGRATION
==================================================

Abstract the LLM provider so the codebase can support:
- Anthropic
- OpenAI
- local model endpoint

Create:
- provider interface
- prompt builder
- JSON schema validator
- retry mechanism
- safe parsing
- run logging for prompts/responses

Important:
- prompts must be templated and versioned
- raw prompts/responses should be optionally logged with redaction controls
- the LLM should return actions in a strict schema

Provide one default system prompt for the attacker that instructs it to:
- reason about CPS process context
- choose legal targets only
- prefer stealth and plausible physical impact
- output only valid JSON

==================================================
12. SAFETY SHIELD
==================================================

This is a core contribution. Build it carefully.

The shield must enforce:
1. writable tag whitelist
2. min/max range checks
3. duration caps
4. cooldown windows
5. forbidden simultaneous actions
6. scene-specific invariants
7. deadman timer
8. rollback plan generation
9. emergency abort path

The shield must:
- inspect every proposed action
- return a structured ShieldDecision
- normalize values if needed
- reject dangerous actions with explicit reasons

Create a rule engine for safety rules.
Rules should be configurable per scene.

Example rule categories:
- mutual exclusion
- actuator interlock
- high-high / low-low boundary protection
- mode-gated write permissions
- maximum override duration
- cooldown between repeated perturbations

==================================================
13. DEFENDER FRAMEWORK
==================================================

Implement a detector interface with methods like:
- initialize
- observe(snapshot)
- score(snapshot or sequence)
- detect(snapshot or sequence)
- reset
- export_state

Implement these detectors first:

1. ThresholdDetector
- simple configurable thresholds
- high utility baseline

2. InvariantDetector
- configurable rule-based checks
- easy to align with shield rules

3. SequenceModelDetector
- scaffold for an ML-based detector
- first implementation can be simple:
  - rolling window features
  - sklearn model or small PyTorch model
- must support offline train/eval and online inference

4. Optional LLMExplainer
- not the primary detector
- given a DetectionEvent and trace context, produce a textual explanation

==================================================
14. ADAPTATION LOOP
==================================================

Implement the closed-loop improvement mechanism.

For each run:
- determine whether the attack succeeded
- determine whether the defender detected it
- measure detection latency
- measure false positive behavior
- classify the outcome

Store failed or weakly detected runs as hard cases:
- miss
- late detection
- false negative
- unstable detector response

Create:
- HardCaseBank
- replay loader
- round-based evaluation framework
- retraining hooks for the sequence detector

The first implementation of adaptation can be modest:
- retrain or fine-tune a basic detector on accumulated hard cases
- compare performance over rounds

Do not fake this layer. Build it so it can actually run experiments.

==================================================
15. TRACE LOGGING, EVAL RUNS, AND DATASET FORMAT
==================================================

Design a robust trace format.

At every step, log:
- timestamp
- run_id
- step_id
- all observed tags
- attack action applied
- shield decision
- detector outputs
- alarm state
- scene metadata
- experiment metadata

All primary metrics reported by the project must be collected during eval runs on the real PLC + Factory I/O setup. Eval runs must generate the structured artifacts used for later analysis, replay, tables, and figures.

Metrics collected during eval runs must include:
- attack action validity
- execution success
- attack success
- process impact / physical deviation
- shield approvals and rejections
- unsafe action block rate
- detector precision, recall, and F1
- false positives and false negatives
- detection latency
- hard-case frequency
- defender improvement across adaptation rounds

Support:
- parquet or csv output for timeseries
- json/yaml metadata sidecar
- replay-ready run folders
- summary metrics artifacts per run and per experiment

Recommended run folder example:
data/raw/<experiment_name>/<run_id>/
  trace.parquet
  metadata.json
  attacks.json
  detections.json
  shield_events.json
  metrics.json

Recommended experiment summary example:
data/processed/<experiment_name>/
  run_index.csv
  aggregate_metrics.csv
  summary.json

==================================================
16. CLI COMMANDS
==================================================

Build a CLI with commands like:

- cpsforge scene validate --config ...
- cpsforge plc probe --config ...
- cpsforge run baseline --scene ...
- cpsforge run attack --scene ... --attacker scripted
- cpsforge run attack --scene ... --attacker llm
- cpsforge run closed-loop --scene ...
- cpsforge detect replay --run-id ...
- cpsforge adapt train --scene ...
- cpsforge report summarize --experiment ...
- cpsforge report metrics --experiment ...

The CLI should be polished and usable.

==================================================
17. API OR DASHBOARD
==================================================

Implement a minimal status interface.

This can be:
- FastAPI backend with endpoints for:
  - current plant snapshot
  - recent attacks
  - shield decisions
  - detector status
  - experiment history
  - latest eval metrics

or a terminal dashboard using rich.

A simple, reliable implementation is preferable to a flashy one.

==================================================
18. CONFIGURATION
==================================================

Use config files heavily.

Need configs for:
- PLC connection
- scene profiles
- attack policies
- shield rules
- detector parameters
- experiment setup
- LLM provider settings

Provide sane default examples.

The default PLC system config example should include:
- host: 192.168.0.1

The experiment config should explicitly distinguish:
- dry-run validation
- live attack run
- eval run with metrics collection enabled

==================================================
19. TESTING
==================================================

Add tests for:
- schema validation
- attack compilation
- shield logic
- detector interfaces
- hard-case extraction
- metrics aggregation
- CLI smoke tests

Where possible, keep tests focused on validation, parsing, policy logic, replay behavior, and metric summarization rather than assuming a mock PLC backend.

==================================================
20. DOCUMENTATION
==================================================

Write:
1. top-level README
2. quickstart guide
3. architecture overview
4. scene config guide
5. hardware deployment guide
6. safety notes
7. adding a new attacker
8. adding a new detector
9. adding a new scene
10. evaluation workflow guide
11. metrics collection and reporting guide

Make the documentation good enough for a research lab repo.

==================================================
21. IMPLEMENTATION STRATEGY
==================================================

Implement in phases and commit a coherent codebase at each phase.

Phase 1:
- repo scaffolding
- configs
- data models
- real PLC configuration and client interface
- scene abstraction
- trace logger
- CLI skeleton

Phase 2:
- real PLC wrapper
- polling loop
- reference scene config
- scripted/random attackers
- shield engine

Phase 3:
- threshold and invariant detectors
- run orchestration
- replay support
- experiment folders
- metrics extraction for eval runs

Phase 4:
- LLM attacker
- provider abstraction
- prompt templates
- JSON validation and retries

Phase 5:
- hard-case bank
- adaptation loop
- sequence detector scaffold
- reporting utilities
- aggregate experiment metrics

Phase 6:
- docs
- tests
- cleanup
- example experiments

Do not skip early infrastructure to jump straight to LLM calls.

==================================================
22. CODING STYLE
==================================================

Please follow these coding principles:
- clear module boundaries
- small focused classes
- typed function signatures
- meaningful logs
- avoid giant monolithic files
- avoid hidden global state
- prefer explicit configuration
- fail safely
- always preserve reproducibility

==================================================
23. IMPORTANT RESEARCH CONSTRAINTS
==================================================

This is a CPS security research framework, not malware.

Therefore:
- build safety controls by default
- include dry-run mode
- require explicit enablement for live writes
- never bypass the shield in normal workflows
- support reproducible offline replay
- make every action auditable
- treat the real PLC as the actual deployment target
- ensure all reported results come from explicitly labeled eval runs

==================================================
24. CONCRETE FIRST DELIVERABLE
==================================================

The first fully working milestone must support:

- one reference scene: level control or tank control
- real PLC mode
- PLC tag polling and trace logging
- scripted attacks and random attacks
- shield approval/rejection pipeline
- threshold detector and invariant detector
- CLI to run a complete experiment
- saved experiment artifacts
- eval run artifacts with metrics collection

After that, add the LLM attacker.

==================================================
25. WHAT I WANT FROM YOU NOW
==================================================

Start coding the full repository.

Do the following in order:
1. Create the full repo structure.
2. Create pyproject.toml and dependency files.
3. Implement the core schemas/models.
4. Implement the config loader.
5. Implement the real PLC client interface and default PLC config for 192.168.0.1.
6. Implement the scene abstraction and one reference scene.
7. Implement logging and run artifact storage.
8. Implement CLI skeleton.
9. Implement shield engine.
10. Implement scripted/random attackers.
11. Implement threshold and invariant detectors.
12. Implement run orchestration.
13. Implement eval-run metric collection and summary artifacts.
14. Then implement LLM provider abstraction and LLMAttacker.
15. Then implement adaptation and replay.

At each major stage:
- explain what files you created
- explain how to run the current milestone
- keep the code runnable
- do not leave broken imports or placeholders that crash the repo

When uncertain, choose the most maintainable and safest architecture.

Begin now by generating the repository layout and all initial files for Phase 1.