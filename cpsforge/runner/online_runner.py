"""
online_runner.py — Online MITM experiment orchestrator (v2).

OnlineExperimentRunner replaces the batch loop in ExperimentOrchestrator for
online MITM runs.  Key differences from the v1 orchestrator:

  v1 (batch):  pre-generate all attacks → schedule them → replay at fixed steps
  v2 (online): observe step → decide (LLM) → act if budget allows → record

The runner integrates:
  - PlcObserver  (live state collection + history buffer)
  - PhaseInferenceEngine  (phase detection)
  - ContextBuilder  (3-tier context assembly)
  - OnlineMITMAttacker  (observe→decide→act loop)
  - ShieldEngine  (existing)
  - PhaseAwareShield  (new, C4 — optional)
  - IntentConsistencyChecker  (new, C4 — optional)
  - Defenders  (from existing defenders/ stack)
  - UnifiedStepLog  (full per-step logging)
  - RunArtifactWriter  (existing artifact persistence)

Usage
-----
    runner = OnlineExperimentRunner(config, loader)
    run_id = runner.run()

The config requires a few extra v2 fields beyond ExperimentConfig:
  context_level:   "minimal" | "partial" | "full"
  model_variant:   "base" | "finetuned" | "qwen3_17b" | "llama32_3b"
  finetune_status: "base" | "finetuned"  (derived — don't set manually)
  defense_variant: "none" | "phase_aware" | "intent" | "combined" | "baseline"
  attack_budget:   int (max attacks per run, default 10)
  decision_interval_steps: int (LLM called every N steps, default 3)
"""

from __future__ import annotations

import json
import logging
import time

# ---------------------------------------------------------------------------
# Module-level mapping: model_variant → HuggingFace LLM config name
# ---------------------------------------------------------------------------
_MODEL_CFG_MAP: dict = {
    "base":        "huggingface",           # Qwen3.5-4B base
    "finetuned":   "huggingface_finetuned", # Qwen3.5-4B + QLoRA adapter
    "qwen3_17b":   "huggingface_qwen3_17b", # Qwen3-1.7B (within-family scaling)
    "qwen25_3b":   "huggingface_qwen25_3b", # Qwen2.5-3B-Instruct (different gen)
    "phi4_mini":   "huggingface_phi4_mini",  # Phi-4-mini-instruct (Microsoft)
    "smollm3_3b":  "huggingface_smollm3_3b",# SmolLM3-3B (HuggingFace)
    "llama32_3b":  "huggingface_llama32_3b",# Llama-3.2-3B-Instruct (cross-family)
    "gpt4o_mini":  "openai_gpt4o_mini",     # GPT-4o-mini via OpenAI API (frontier)
}
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cpsforge.core.config import ConfigLoader, ExperimentConfig
from cpsforge.core.models import (
    AttackAction,
    DetectionEvent,
    EvalMetrics,
    PlantSnapshot,
    ShieldDecision,
)
from cpsforge.logging.artifacts import (
    RunArtifactWriter,
    TraceRecorder,
    get_run_dir,
    make_run_id,
)
from cpsforge.logging.unified_schema import UnifiedStepLog
from cpsforge.observation.history_buffer import HistoryBuffer
from cpsforge.observation.observer import PlcObserver
from cpsforge.observation.phase_inference import PhaseInferenceEngine
from cpsforge.context_builder.builder import ContextBuilder
from cpsforge.context_builder.schema import ContextLevel
from cpsforge.attacker.online_mitm import OnlineMITMAttacker
from cpsforge.attacker.schema import AttackDecisionType

logger = logging.getLogger(__name__)


class OnlineExperimentRunner:
    """Drives a single online MITM experiment run end-to-end.

    Parameters
    ----------
    config : ExperimentConfig
    loader : ConfigLoader
    output_base : Path, optional
    extra : dict, optional
        v2-specific overrides (context_level, model_variant, etc.).
        These supplement / override fields not currently in ExperimentConfig.
    """

    def __init__(
        self,
        config: ExperimentConfig,
        loader: ConfigLoader,
        output_base: Optional[Path] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._config = config
        self._loader = loader
        self._run_id = make_run_id()
        self._extra = extra or {}

        base = output_base or Path("data/raw")
        self._run_dir = get_run_dir(base, config.name, self._run_id)

        # v2 experiment controls
        self._context_level = ContextLevel(self._extra.get("context_level", "full"))
        self._model_variant = self._extra.get("model_variant", "unknown")
        self._finetune_status = self._extra.get("finetune_status", "base")
        self._defense_variant = self._extra.get("defense_variant", "none")
        self._attack_budget = int(self._extra.get("attack_budget", 10))
        self._decision_interval = int(self._extra.get("decision_interval_steps", 3))
        self._attacker_type = self._extra.get("attacker_type", "online_mitm")

        # Collected records
        self._step_logs: List[UnifiedStepLog] = []
        self._actions: List[AttackAction] = []
        self._detections: List[DetectionEvent] = []
        self._shield_decisions: List[ShieldDecision] = []
        self._snapshots: List[PlantSnapshot] = []

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self) -> str:
        """Execute the run and return run_id."""
        logger.info(
            "OnlineExperimentRunner start: run_id=%s scene=%s ctx=%s model=%s ft=%s def=%s",
            self._run_id,
            self._config.name,
            self._context_level.value,
            self._model_variant,
            self._finetune_status,
            self._defense_variant,
        )

        scene = self._load_scene()
        plc_cfg = self._loader.load_plc()
        if self._config.live_writes_enabled:
            plc_cfg.live_writes_enabled = True

        shield = self._build_shield(scene)
        defenders = self._build_defenders(scene)

        # Observation layer
        history = HistoryBuffer(max_size=200)
        phase_engine = PhaseInferenceEngine(scene.profile.scene_name)

        # v2 defenses share the same history/phase_engine as the main loop
        phase_shield, intent_checker, llm_defender, state_checker = self._build_v2_defenses(
            scene, history=history, phase_engine=phase_engine,
        )
        ctx_builder = ContextBuilder(
            scene=scene,
            phase_engine=phase_engine,
            history=history,
        )

        # LLM provider — pre-load model weights before the PLC loop starts
        # so that the first inference call doesn't hit the timeout.
        llm_provider = self._build_llm_provider()
        if llm_provider is not None and hasattr(llm_provider, '_ensure_loaded'):
            logger.info("Pre-loading model weights (this may take 60-120 s on first run)…")
            try:
                llm_provider._ensure_loaded()
                logger.info("Model pre-load complete.")
            except Exception as exc:
                logger.warning("Model pre-load failed: %s — attacker will use WAIT fallback.", exc)

        # Attacker (online MITM, deep state MITM, or static LLM)
        if self._attacker_type == "static_llm":
            from cpsforge.attacker.static_llm import StaticLLMAttacker
            attacker = StaticLLMAttacker(
                scene=scene,
                llm_provider=llm_provider,
                context_level=self._context_level,
                history=history,
                phase_engine=phase_engine,
                attack_budget=self._attack_budget,
                decision_interval=self._decision_interval,
                llm_timeout_s=120.0,
            )
        elif self._attacker_type == "deep_state_mitm":
            from cpsforge.attacker.deep_state_mitm import DeepStateMITMAttacker
            attacker = DeepStateMITMAttacker(
                scene=scene,
                llm_provider=llm_provider,
                context_level=self._context_level,
                history=history,
                phase_engine=phase_engine,
                attack_budget=self._attack_budget,
                decision_interval=self._decision_interval,
            )
        elif self._attacker_type == "fpr_probe":
            from cpsforge.attacker.fpr_probe import FPRProbeAttacker
            attacker = FPRProbeAttacker(
                scene=scene,
                history=history,
                phase_engine=phase_engine,
                probe_interval=self._decision_interval,
            )
        else:
            attacker = OnlineMITMAttacker(
                scene=scene,
                llm_provider=llm_provider,
                context_level=self._context_level,
                history=history,
                phase_engine=phase_engine,
                attack_budget=self._attack_budget,
                decision_interval=self._decision_interval,
            )

        # PLC client + event logger
        from cpsforge.plc.event_logger import PlcEventLogger
        from cpsforge.plc.factory import create_plc_backend
        event_logger = PlcEventLogger(run_id=self._run_id, output_dir="data/captures")
        event_logger.open()

        # Select backend: check scene config for 'backend' field
        scene_name = Path(self._config.scene_config).stem
        scene_raw = self._loader.load_scene_raw(scene_name)
        backend_type = scene_raw.get("backend", "snap7")

        if backend_type == "modbus":
            modbus_data = self._loader.load_modbus()
            if self._config.live_writes_enabled:
                modbus_data["live_writes_enabled"] = True
            plc_client = create_plc_backend(
                backend_type="modbus",
                modbus_config_dict=modbus_data,
                event_logger=event_logger,
            )
        else:
            plc_client = create_plc_backend(
                backend_type="snap7",
                plc_config=plc_cfg,
                event_logger=event_logger,
            )

        if not self._config.dry_run:
            plc_client.connect()
            logger.info("PLC connected (%s backend).", backend_type)
            if backend_type == "snap7" and scene.profile.scene_id is not None:
                plc_client.switch_active_scene(scene.profile.scene_id)
                time.sleep(max(0.5, scene.profile.sampling_interval_ms / 1000.0))

        # Process simulator for OpenPLC scenes (replaces Factory I/O)
        simulator = None
        use_sim = self._extra.get("use_simulator", True)
        if backend_type == "modbus" and not self._config.dry_run and use_sim:
            sim_type = scene_raw.get("process_simulator")
            if sim_type:
                simulator = self._start_simulator(sim_type, modbus_data)
        elif not use_sim:
            logger.info("Process simulator disabled (use_simulator=False); "
                        "expecting external plant (e.g. Factory I/O).")

        interrupted = False
        try:
            self._main_loop(
                plc_client=plc_client,
                scene=scene,
                shield=shield,
                phase_shield=phase_shield,
                intent_checker=intent_checker,
                llm_defender=llm_defender,
                state_checker=state_checker,
                defenders=defenders,
                attacker=attacker,
                history=history,
                phase_engine=phase_engine,
            )
        except KeyboardInterrupt:
            interrupted = True
            logger.warning("Run interrupted. Saving partial artifacts.")
        except Exception as exc:
            interrupted = True
            logger.error("Run failed: %s", exc, exc_info=True)
        finally:
            if simulator is not None:
                simulator.stop()
            if not self._config.dry_run:
                plc_client.disconnect()
            event_logger.close()

        try:
            self._write_artifacts(scene)
        except Exception as exc:
            logger.error("Artifact write failed: %s", exc)

        logger.info(
            "Run %s: run_id=%s steps=%d attacks=%d",
            "interrupted" if interrupted else "complete",
            self._run_id,
            len(self._snapshots),
            len(self._actions),
        )
        return self._run_id

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def _main_loop(
        self,
        plc_client: Any,
        scene: Any,
        shield: Any,
        phase_shield: Any,
        intent_checker: Any,
        llm_defender: Any,
        state_checker: Any,
        defenders: List[Any],
        attacker: OnlineMITMAttacker,
        history: HistoryBuffer,
        phase_engine: PhaseInferenceEngine,
    ) -> None:
        step = 0
        max_steps = self._config.max_steps
        run_start = time.monotonic()
        poll_interval_s = scene.profile.sampling_interval_ms / 1000.0
        event_logger = plc_client._event_logger

        # Track current active attack for ground-truth labelling
        active_action: Optional[AttackAction] = None
        active_until_step: int = -1
        attack_start_step: int = -1
        attack_start_snapshot: Optional[PlantSnapshot] = None

        # Detection latency tracking
        attack_active_unreported = False
        first_detection_step: Optional[int] = None

        while step < max_steps:
            step_start = time.monotonic()

            if self._config.run_duration_s and (
                time.monotonic() - run_start > self._config.run_duration_s
            ):
                logger.info("Wall-clock limit reached.")
                break

            # ----------------------------------------------------------
            # 1. Poll PLC → snapshot
            # ----------------------------------------------------------
            plc_client._current_step = step
            snapshot = self._poll_snapshot(plc_client, scene, step)
            if snapshot is None:
                step += 1
                time.sleep(poll_interval_s)
                continue

            scene.extract_derived_features(snapshot)
            history.append(snapshot)
            self._snapshots.append(snapshot)

            # ----------------------------------------------------------
            # 2. Phase inference
            # ----------------------------------------------------------
            phase_result = phase_engine.infer(snapshot, history.window(20))

            # ----------------------------------------------------------
            # 3. Create unified log entry for this step
            # ----------------------------------------------------------
            log = UnifiedStepLog.empty(
                run_id=self._run_id,
                step_id=step,
                scene=scene.profile.scene_name,
                attacker_type=self._attacker_type,
                context_level=self._context_level.value,
                model_variant=self._model_variant,
                finetune_status=self._finetune_status,
                defense_variant=self._defense_variant,
            )
            log.inferred_phase = phase_result.phase.value
            log.phase_confidence = phase_result.confidence
            log.observation_dict = _snapshot_to_obs_dict(snapshot)
            log.derived_features = dict(snapshot.derived_features or {})

            # ----------------------------------------------------------
            # 4. Mark active attack ground-truth
            # ----------------------------------------------------------
            if active_action and step <= active_until_step:
                snapshot.attack_context.active = True
                snapshot.attack_context.action_id = active_action.action_id
                snapshot.attack_context.attack_type = active_action.attack_type
                snapshot.attack_context.target_tag = active_action.target
                log.attack_active = True
                attack_active_unreported = True
            elif active_action and step > active_until_step:
                # Attack window closed — evaluate success
                success = scene.evaluate_attack_success(
                    active_action,
                    attack_start_snapshot if attack_start_snapshot is not None else snapshot,
                    snapshot,
                )
                log.attack_success = success
                attacker.record_outcome(
                    step_id=step,
                    shield_approved=True,
                    write_executed=True,
                    attack_success=success,
                )
                active_action = None
                attack_start_snapshot = None
                attack_active_unreported = False

            # ----------------------------------------------------------
            # 5. Run defenders
            # ----------------------------------------------------------
            for defender in defenders:
                events = defender.detect(snapshot)
                for event in events:
                    event.run_id = self._run_id
                    self._detections.append(event)
                    log.detector_alerts.append(defender.__class__.__name__)
                    if attack_active_unreported and first_detection_step is None:
                        first_detection_step = step
                        log.detection_latency_steps = step - attack_start_step

            # ----------------------------------------------------------
            # 6. Online MITM decision
            # ----------------------------------------------------------
            if attacker.should_call_llm():
                decision = attacker.decide(snapshot)
                log.llm_raw_output = decision.raw_output
                log.parsed_decision = decision.decision.value if decision.parse_success else None
                log.parse_success = decision.parse_success
                log.llm_latency_ms = decision.llm_latency_ms

                if decision.parse_success:
                    # Hash the prompts for reproducibility tracking
                    try:
                        last_prompts = getattr(attacker, "_last_prompts", ("", ""))
                        log.context_payload_hash = UnifiedStepLog.hash_prompts(*last_prompts)
                    except Exception:
                        pass

                if (
                    decision.parse_success
                    and decision.decision == AttackDecisionType.ATTACK
                ):
                    log.validation_success = True
                    action = attacker.to_attack_action(decision)
                    if action:
                        log.action_target_tag = action.target
                        log.action_type = action.attack_type
                        log.action_value = float(action.value) if action.value is not None else None
                        log.action_duration_ms = action.duration_ms

                        # --- Shield evaluation chain ---
                        sd = shield.evaluate(action)
                        self._shield_decisions.append(sd)
                        log.shield_decision = "approved" if sd.approved else "blocked"
                        if not sd.approved and event_logger:
                            event_logger.log_blocked(
                                step_id=step, tag_name=action.target,
                                written_value=action.value,
                                block_stage="safety_shield",
                                block_reason=(", ".join(sd.reasons) if sd.reasons else "rule_violation"),
                                address_str=getattr(action, "address", None),
                            )

                        # Phase-aware shield (if enabled)
                        if sd.approved and phase_shield is not None:
                            ps_decision = phase_shield.evaluate(action, snapshot)
                            if not ps_decision.approved:
                                sd = ps_decision
                                log.phase_shield_blocked = True
                                log.shield_decision = "blocked"
                                if event_logger:
                                    event_logger.log_blocked(
                                        step_id=step, tag_name=action.target,
                                        written_value=action.value,
                                        block_stage="phase_shield",
                                        block_reason=(", ".join(ps_decision.reasons) if ps_decision.reasons else "phase_inconsistent"),
                                    )

                        # Intent consistency checker (if enabled)
                        if sd.approved and intent_checker is not None:
                            ic_decision = intent_checker.evaluate(action, snapshot)
                            if not ic_decision.approved:
                                sd = ic_decision
                                log.intent_check_blocked = True
                                log.shield_decision = "blocked"
                                if event_logger:
                                    event_logger.log_blocked(
                                        step_id=step, tag_name=action.target,
                                        written_value=action.value,
                                        block_stage="intent_checker",
                                        block_reason=(", ".join(ic_decision.reasons) if ic_decision.reasons else "trend_opposing"),
                                    )

                        # State consistency checker (if enabled)
                        if sd.approved and state_checker is not None:
                            sc_decision = state_checker.evaluate(action, snapshot)
                            if not sc_decision.approved:
                                sd = sc_decision
                                log.shield_decision = "blocked"
                                if event_logger:
                                    event_logger.log_blocked(
                                        step_id=step, tag_name=action.target,
                                        written_value=action.value,
                                        block_stage="state_consistency",
                                        block_reason=(", ".join(sc_decision.reasons) if sc_decision.reasons else "state_inconsistent"),
                                    )

                        # LLM defender (if enabled)
                        if sd.approved and llm_defender is not None:
                            ld_decision = llm_defender.evaluate(action, snapshot)
                            if not ld_decision.approved:
                                sd = ld_decision
                                log.llm_defender_blocked = True
                                log.shield_decision = "blocked"
                                if event_logger:
                                    event_logger.log_blocked(
                                        step_id=step, tag_name=action.target,
                                        written_value=action.value,
                                        block_stage="llm_defender",
                                        block_reason="llm_suspicion",
                                        suspicion_score=getattr(ld_decision, "suspicion_score", None),
                                    )

                        # Execute if approved
                        if sd.approved and self._config.live_writes_enabled:
                            executed = self._execute_action(action, plc_client, scene)
                            log.write_executed = executed
                            if executed:
                                # Annotate the write event with attack context
                                if event_logger:
                                    event_logger.log_write(
                                        step_id=step,
                                        tag_name=action.target,
                                        address_str=getattr(action, "address", ""),
                                        written_value=action.value,
                                        action_type=str(action.attack_type) if action.attack_type else None,
                                        expected_effect=getattr(decision, "expected_effect", None),
                                    )
                                self._actions.append(action)
                                duration_steps = max(
                                    1,
                                    (action.duration_ms or 1000) // int(
                                        scene.profile.sampling_interval_ms or 1000
                                    ),
                                )
                                active_action = action
                                active_until_step = step + duration_steps
                                attack_start_step = step
                                attack_start_snapshot = snapshot
                                first_detection_step = None
                                attack_active_unreported = False
                        elif not self._config.live_writes_enabled:
                            log.write_executed = False
                            logger.debug(
                                "Dry-run: shield approved, but live writes disabled."
                            )

            # ----------------------------------------------------------
            # 7. Finalise step log
            # ----------------------------------------------------------
            step_elapsed_ms = (time.monotonic() - step_start) * 1000.0
            log.step_latency_ms = step_elapsed_ms
            self._step_logs.append(log)

            # ----------------------------------------------------------
            # 8. Sleep to next poll interval
            # ----------------------------------------------------------
            elapsed = time.monotonic() - step_start
            sleep_s = max(0.0, poll_interval_s - elapsed)
            if sleep_s > 0:
                time.sleep(sleep_s)
            step += 1

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _poll_snapshot(
        self, plc_client: Any, scene: Any, step: int
    ) -> Optional[PlantSnapshot]:
        from datetime import datetime, timezone
        from cpsforge.core.models import AttackContext, DefenseContext, SafetyContext, TagCategory

        if self._config.dry_run:
            # Produce zero-valued structural snapshot so all code paths exercise.
            return PlantSnapshot(
                timestamp=datetime.now(timezone.utc),
                scene_name=scene.name,
                run_id=self._run_id,
                step_id=step,
                sensors={t.name: None for t in scene.profile.tags if t.category.value == "sensor"},
                actuators={t.name: None for t in scene.profile.tags if t.category.value == "actuator"},
                controller_state={
                    t.name: None for t in scene.profile.tags
                    if t.category.value in ("mode_bit", "internal")
                },
                alarms={t.name: None for t in scene.profile.tags if t.category.value == "alarm"},
                setpoints={t.name: None for t in scene.profile.tags if t.category.value == "setpoint"},
                attack_context=AttackContext(),
                defense_context=DefenseContext(),
                safety_context=SafetyContext(live_writes_enabled=False),
            )

        try:
            raw = plc_client.read_many(scene.profile.tags)
        except Exception as exc:
            logger.warning("PLC read failed at step %d: %s", step, exc)
            return None

        sensors, actuators, controller_state, alarms, setpoints = {}, {}, {}, {}, {}
        from cpsforge.core.models import TagCategory
        for tag in scene.profile.tags:
            val = raw.get(tag.name)
            {
                TagCategory.SENSOR: sensors,
                TagCategory.ACTUATOR: actuators,
                TagCategory.MODE_BIT: controller_state,
                TagCategory.INTERNAL: controller_state,
                TagCategory.ALARM: alarms,
                TagCategory.SETPOINT: setpoints,
            }.get(tag.category, controller_state)[tag.name] = val

        return PlantSnapshot(
            timestamp=datetime.now(timezone.utc),
            scene_name=scene.name,
            run_id=self._run_id,
            step_id=step,
            sensors=sensors,
            actuators=actuators,
            controller_state=controller_state,
            alarms=alarms,
            setpoints=setpoints,
            attack_context=AttackContext(),
            defense_context=DefenseContext(),
            safety_context=SafetyContext(
                live_writes_enabled=plc_client._config.live_writes_enabled
            ),
        )

    def _execute_action(self, action: AttackAction, plc_client: Any, scene: Any = None) -> bool:
        try:
            from cpsforge.attacks.compiler import compile_action
            writes = compile_action(action, scene)
            for tag_name, value in writes.items():
                tag = scene.get_tag(tag_name) if scene else None
                if tag:
                    plc_client.write_tag(tag, value)
            return True
        except Exception as exc:
            logger.error("Execute action failed: %s", exc)
            return False

    def _start_simulator(self, sim_type: str, modbus_data: dict):
        """Create and start a process simulator for OpenPLC scenes."""
        from cpsforge.plc.modbus_client import ModbusClient, ModbusConfig
        from cpsforge.simulation import (
            TankSimulator, WeightSorterSimulator, HeightSorterSimulator,
        )

        _SIM_MAP = {
            "tank": TankSimulator,
            "weight_sorter": WeightSorterSimulator,
            "height_sorter": HeightSorterSimulator,
        }
        sim_cls = _SIM_MAP.get(sim_type)
        if sim_cls is None:
            logger.warning("Unknown process_simulator type: %s — skipping.", sim_type)
            return None

        # Own Modbus connection for the simulator (separate from runner's)
        sim_config = ModbusConfig.from_dict(modbus_data)
        sim_config.live_writes_enabled = True  # simulator must write sensor feedback
        sim_client = ModbusClient(sim_config)
        sim_client.connect()

        simulator = sim_cls(sim_client, tick_interval_s=0.1)
        simulator.reset()
        simulator.start()
        logger.info("Process simulator '%s' started.", sim_type)
        return simulator

    def _load_scene(self) -> Any:
        from cpsforge.scenes.factory import load_scene
        scene_name = Path(self._config.scene_config).stem
        return load_scene(scene_name, self._loader)

    def _build_shield(self, scene: Any) -> Any:
        from cpsforge.shield.engine import ShieldEngine
        return ShieldEngine(scene.profile)

    def _build_v2_defenses(
        self, scene: Any, history: HistoryBuffer, phase_engine: PhaseInferenceEngine,
    ):
        """Instantiate v2 defenses based on defense_variant.

        The *history* and *phase_engine* arguments MUST be the same
        instances used by the main loop so that the defenses operate on
        live data rather than empty buffers.
        """
        phase_shield = None
        intent_checker_obj = None
        llm_defender_obj = None
        variant = self._defense_variant

        if variant in ("phase_aware", "combined"):
            from cpsforge.defenses.phase_aware_shield import PhaseAwareShield
            phase_shield = PhaseAwareShield(
                scene_name=scene.profile.scene_name,
                phase_engine=phase_engine,
                history=history,
            )

        if variant in ("intent", "combined"):
            from cpsforge.defenses.intent_checker import IntentConsistencyChecker
            # Build tag ranges from scene profile
            tag_ranges = {}
            for tag_def in scene.profile.tags:
                if tag_def.min_value is not None and tag_def.max_value is not None:
                    tag_ranges[tag_def.name] = (tag_def.min_value, tag_def.max_value)
            intent_checker_obj = IntentConsistencyChecker(
                history=history,
                tag_ranges=tag_ranges,
            )

        if variant in ("llm_defender", "llm_combined"):
            from cpsforge.defenses.llm_defender import LLMDefender
            # Build a separate LLM provider for the defender
            defender_provider = self._build_llm_provider()
            if defender_provider is not None:
                llm_defender_obj = LLMDefender(
                    scene=scene,
                    llm_provider=defender_provider,
                    phase_engine=phase_engine,
                    history=history,
                )
                logger.info("LLM Defender enabled (variant=%s)", variant)

        if variant == "llm_combined":
            # llm_combined = phase_aware + intent + llm_defender
            from cpsforge.defenses.phase_aware_shield import PhaseAwareShield
            from cpsforge.defenses.intent_checker import IntentConsistencyChecker
            if phase_shield is None:
                phase_shield = PhaseAwareShield(
                    scene_name=scene.profile.scene_name,
                    phase_engine=phase_engine,
                    history=history,
                )
            if intent_checker_obj is None:
                tag_ranges = {}
                for tag_def in scene.profile.tags:
                    if tag_def.min_value is not None and tag_def.max_value is not None:
                        tag_ranges[tag_def.name] = (tag_def.min_value, tag_def.max_value)
                intent_checker_obj = IntentConsistencyChecker(
                    history=history,
                    tag_ranges=tag_ranges,
                )

        # State consistency checker (Tier 2 defense)
        state_checker_obj = None
        if variant in ("state_consistency", "state_combined"):
            from cpsforge.defenses.state_consistency import StateConsistencyChecker
            state_checker_obj = StateConsistencyChecker(
                scene_name=scene.profile.scene_name,
                phase_engine=phase_engine,
                history=history,
            )

        if variant == "state_combined":
            # state_combined = phase_aware + intent + state_consistency
            from cpsforge.defenses.phase_aware_shield import PhaseAwareShield
            from cpsforge.defenses.intent_checker import IntentConsistencyChecker
            if phase_shield is None:
                phase_shield = PhaseAwareShield(
                    scene_name=scene.profile.scene_name,
                    phase_engine=phase_engine,
                    history=history,
                )
            if intent_checker_obj is None:
                tag_ranges = {}
                for tag_def in scene.profile.tags:
                    if tag_def.min_value is not None and tag_def.max_value is not None:
                        tag_ranges[tag_def.name] = (tag_def.min_value, tag_def.max_value)
                intent_checker_obj = IntentConsistencyChecker(
                    history=history,
                    tag_ranges=tag_ranges,
                )

        return phase_shield, intent_checker_obj, llm_defender_obj, state_checker_obj

    def _build_defenders(self, scene: Any) -> List[Any]:
        from cpsforge.defenders.factory import build_defender
        if self._defense_variant == "none":
            return []
        defenders = []
        for def_name in (self._config.defenders or []):
            try:
                cfg = self._loader.load_defender(def_name)
                defenders.append(build_defender(cfg))
            except Exception as exc:
                logger.warning("Could not load defender %s: %s", def_name, exc)
        return defenders

    def _build_llm_provider(self) -> Any:
        from cpsforge.llm.factory import build_provider

        # Map model_variant → HuggingFace config file.
        # base        → huggingface           (Qwen3.5-4B, no adapter)
        # finetuned   → huggingface_finetuned  (Qwen3.5-4B + QLoRA)
        # qwen3_17b   → huggingface_qwen3_17b  (Qwen3-1.7B, within-family)
        # llama32_3b  → huggingface_llama32_3b (Llama-3.2-3B, cross-family)
        cfg_name = _MODEL_CFG_MAP.get(self._model_variant, "huggingface")
        try:
            llm_cfg = self._loader.load_llm(cfg_name)
            provider = build_provider(llm_cfg)
            logger.info("LLM provider: huggingface (config=%s, model_variant=%s)", cfg_name, self._model_variant)
            return provider
        except Exception as exc:
            logger.warning("LLM provider load failed (%s): %s — attacker will use WAIT fallback.", cfg_name, exc)
            return None

    def _write_artifacts(self, scene: Any) -> None:
        """Write all run artifacts including unified step logs."""
        import pandas as pd

        self._run_dir.mkdir(parents=True, exist_ok=True)

        # Unified step log → parquet
        if self._step_logs:
            rows = [log.as_dict() for log in self._step_logs]
            df = pd.DataFrame(rows)
            df.to_parquet(self._run_dir / "unified_steps.parquet", index=False)
            logger.info("Wrote unified_steps.parquet (%d rows)", len(rows))

        # Standard artifacts
        writer = RunArtifactWriter(run_dir=self._run_dir)
        metadata = {
            "run_id": self._run_id,
            "scene_name": scene.profile.scene_name,
            "attacker_name": self._attacker_type,
            "context_level": self._context_level.value,
            "model_variant": self._model_variant,
            "finetune_status": self._finetune_status,
            "defense_variant": self._defense_variant,
            "attack_budget": self._attack_budget,
            "decision_interval": self._decision_interval,
            "total_steps": len(self._snapshots),
            "total_attacks": len(self._actions),
        }
        writer.write_metadata(metadata)
        writer.write_attacks(self._actions)
        writer.write_detections(self._detections)
        writer.write_shield_events(self._shield_decisions)


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _snapshot_to_obs_dict(snapshot: PlantSnapshot) -> Dict[str, Any]:
    """Flatten all tag values from a snapshot into a single dict."""
    obs: Dict[str, Any] = {}
    for k, v in (snapshot.sensors or {}).items():
        obs[k] = v
    for k, v in (snapshot.actuators or {}).items():
        obs[k] = v
    for k, v in (snapshot.controller_state or {}).items():
        obs[k] = v
    for k, v in (snapshot.setpoints or {}).items():
        obs[k] = v
    return obs
