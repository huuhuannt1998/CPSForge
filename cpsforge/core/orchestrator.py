"""
CPSForge Experiment Orchestrator
==================================
The orchestrator is the central controller for a CPSForge experiment run.
It wires together:
  - PLC client + polling loop
  - scene abstraction
  - attacker(s)
  - safety shield
  - defender(s)
  - trace recorder + artifact writer

A single orchestrator instance manages one run_id. Multiple orchestrator
instances (for multi-round closed-loop experiments) are coordinated by the CLI.

Execution model:
  1. Load configs (scene, PLC, attackers, defenders).
  2. Connect to PLC (or skip for dry-run).
  3. Start polling loop.
  4. For each configured attacker:
       a. Generate an attack action.
       b. Pass through safety shield.
       c. If approved and live_writes_enabled: execute write(s).
       d. Continue polling; collect defender detections.
       e. After action expires: collect post-action snapshot for impact scoring.
  5. Compute EvalMetrics from run data.
  6. Write all artifacts.
  7. Disconnect gracefully.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cpsforge.core.config import ConfigLoader, ExperimentConfig
from cpsforge.core.models import (
    AttackAction,
    DetectionEvent,
    EvalMetrics,
    ExecutionStatus,
    PlantSnapshot,
    ShieldDecision,
)
from cpsforge.logging.artifacts import (
    RunArtifactWriter,
    TraceRecorder,
    get_run_dir,
    make_run_id,
)

logger = logging.getLogger(__name__)


class ExperimentOrchestrator:
    """
    Drives a single CPSForge experiment run from start to finish.

    Parameters
    ----------
    config:
        Loaded :class:`ExperimentConfig`.
    loader:
        :class:`ConfigLoader` for loading scene / attacker / defender configs.
    output_base:
        Override for the data/raw/ base directory.
    """

    def __init__(
        self,
        config: ExperimentConfig,
        loader: ConfigLoader,
        output_base: Optional[Path] = None,
    ) -> None:
        self._config = config
        self._loader = loader
        self._run_id = make_run_id()

        # Determine output directory
        base = output_base or Path("data/raw")
        self._run_dir = get_run_dir(base, config.name, self._run_id)

        # Runtime state
        self._snapshots: List[PlantSnapshot] = []
        self._actions: List[AttackAction] = []
        self._decisions: List[ShieldDecision] = []
        self._detections: List[DetectionEvent] = []
        self._ground_truth_attack_steps: set[int] = set()  # step_ids with active attacks
        # Phase 2+3: per-action tracking for impact, success, and latency scoring.
        self._pre_attack_snaps: Dict[str, PlantSnapshot] = {}
        self._attack_impact_map: Dict[str, float] = {}
        self._attack_success_map: Dict[str, bool] = {}
        self._attack_start_steps: Dict[str, int] = {}  # action_id → step when attack launched
        self._defender_names: List[str] = []           # populated by _build_defenders for metrics
        self._llm_metadata: Dict[str, Any] = {}       # populated by LLM attackers for artifacts

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run(self) -> str:
        """
        Execute the full experiment and return the run_id.

        Returns
        -------
        str
            The run ID for this execution.
        """
        logger.info(
            "Starting run '%s' (run_id=%s, dry_run=%s, eval_run=%s)",
            self._config.name,
            self._run_id,
            self._config.dry_run,
            self._config.eval_run,
        )

        # --- Load scene ---
        scene = self._load_scene()

        # --- Load components ---
        plc_cfg = self._loader.load_plc()
        # Propagate the experiment-level live_writes flag to the PLC client.
        # plc.yaml defaults to live_writes_enabled=false for safety; the
        # experiment config (or CLI --no-dry-run) is the authoritative source.
        if self._config.live_writes_enabled:
            plc_cfg.live_writes_enabled = True
        shield = self._build_shield(scene)
        defenders = self._build_defenders(scene)
        attackers = self._build_attackers(scene)

        # --- Connect to PLC (skipped in dry-run) ---
        from cpsforge.plc.client import PlcClient
        plc_client = PlcClient(plc_cfg)

        if not self._config.dry_run:
            plc_client.connect()
            logger.info("PLC connected.")
            # --- Switch PLC to the correct scene via DB_Config.ActiveScene ---
            # OB_Main uses a CASE statement on DB1.ActiveScene to select which FB
            # runs each scan cycle. If this is not set, the PLC runs whatever scene
            # was last compiled into DB_Config (default: scene 19, Sorting Height Basic).
            if scene.profile.scene_id is not None:
                ok = plc_client.switch_active_scene(scene.profile.scene_id)
                if ok:
                    # Allow 1 full PLC scan cycle for the new FB to initialise before polling.
                    time.sleep(max(0.5, scene.profile.sampling_interval_ms / 1000.0))
                else:
                    logger.warning(
                        "ActiveScene write failed for scene_id=%d (%s). "
                        "Proceeding anyway — data quality may be poor if the wrong scene FB is active.",
                        scene.profile.scene_id,
                        scene.profile.scene_name,
                    )
            else:
                logger.warning(
                    "Scene '%s' has no scene_id configured. "
                    "DB_Config.ActiveScene will NOT be updated. "
                    "Add 'scene_id: N' to configs/scenes/%s.yaml to fix this.",
                    scene.profile.scene_name,
                    scene.profile.scene_name,
                )
        else:
            logger.info("Dry-run mode: PLC connection skipped.")

        # --- Run main loop ---
        interrupted = False
        try:
            self._main_loop(
                plc_client=plc_client,
                scene=scene,
                shield=shield,
                defenders=defenders,
                attackers=attackers,
            )
            # --- Optional scene reset after a live run ---
            if self._config.reset_after_run and not self._config.dry_run:
                from cpsforge.plc.reset import SceneResetter
                SceneResetter().reset(plc_client, scene, shield, dry_run=False)
                logger.info("Scene reset after run complete.")
        except KeyboardInterrupt:
            interrupted = True
            logger.warning("Run interrupted by user (SIGINT). Saving partial artifacts.")
        except Exception as exc:
            interrupted = True
            logger.error("Run failed with exception: %s", exc)
        finally:
            if not self._config.dry_run:
                plc_client.disconnect()

        # --- Write artifacts (always, even on interrupt/error) ---
        try:
            self._write_artifacts(scene)
            logger.info(
                "Run %s: %s (steps=%d)",
                "interrupted" if interrupted else "complete",
                self._run_id,
                len(self._snapshots),
            )
        except Exception as exc:
            logger.error("Failed to write artifacts: %s", exc)

        return self._run_id

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def _main_loop(
        self,
        plc_client: Any,
        scene: Any,
        shield: Any,
        defenders: List[Any],
        attackers: List[Any],
    ) -> None:
        """Step-by-step experiment execution."""
        step = 0
        max_steps = self._config.max_steps
        run_start = time.monotonic()
        poll_interval_s = scene.profile.sampling_interval_ms / 1000.0
        attack_queue: List[AttackAction] = []

        # Pre-generate attacks from all attackers
        for attacker in attackers:
            actions = attacker.generate_actions(scene)
            attack_queue.extend(actions)
            self._actions.extend(actions)
            logger.info(
                "Attacker '%s' generated %d actions.", attacker.name, len(actions)
            )
            # Collect LLM metadata from LLM attackers
            get_meta = getattr(attacker, "get_run_metadata", None)
            if callable(get_meta):
                self._llm_metadata.update(get_meta())

        # Sort attack queue by step (interleave attacks across the run)
        # Simple strategy: spread attacks evenly across the run window
        attack_spacing = max(1, max_steps // max(len(attack_queue), 1))
        attack_schedule: Dict[int, AttackAction] = {}
        for i, action in enumerate(attack_queue):
            scheduled_step = min(i * attack_spacing + 5, max_steps - 1)
            attack_schedule[scheduled_step] = action

        active_action: Optional[AttackAction] = None
        active_until_step: int = 0

        while step < max_steps:
            # Check wall-clock limit
            if self._config.run_duration_s and (
                time.monotonic() - run_start > self._config.run_duration_s
            ):
                logger.info("Wall-clock limit reached. Stopping.")
                break

            # Poll PLC (or generate synthetic snapshot in dry-run)
            snapshot = self._poll_snapshot(plc_client, scene, step)
            if snapshot is None:
                step += 1
                time.sleep(poll_interval_s)
                continue

            # Mark active attack in snapshot; detect expiry to score impact.
            if active_action:
                if step <= active_until_step:
                    self._ground_truth_attack_steps.add(step)
                    snapshot.attack_context.active = True
                    snapshot.attack_context.action_id = active_action.action_id
                    snapshot.attack_context.attack_type = active_action.attack_type
                    snapshot.attack_context.target_tag = active_action.target
                    snapshot.attack_context.source = active_action.source
                else:
                    # Attack window just closed -- compute process impact against pre-attack state.
                    pre = self._pre_attack_snaps.get(active_action.action_id)
                    if pre is not None:
                        impact = scene.compute_process_impact(pre, snapshot)
                        success = scene.evaluate_attack_success(active_action, pre, snapshot)
                        self._attack_impact_map[active_action.action_id] = impact
                        self._attack_success_map[active_action.action_id] = success
                        logger.info(
                            "Attack %s expired at step %d: success=%s, impact=%.3f",
                            active_action.action_id[:8], step, success, impact,
                        )
                    active_action = None

            # Extract derived features
            scene.extract_derived_features(snapshot)

            # Run defenders
            for defender in defenders:
                events = defender.detect(snapshot)
                for event in events:
                    event.run_id = self._run_id
                    self._detections.append(event)
                    snapshot.defense_context.latest_detection = event.label
                    snapshot.defense_context.anomaly_score = event.confidence

            self._snapshots.append(snapshot)

            # Execute scheduled attack
            if step in attack_schedule:
                action = attack_schedule[step]
                decision = shield.evaluate(action, snapshot)
                self._decisions.append(decision)

                if decision.approved:
                    duration_steps = int(
                        action.duration_ms / scene.profile.sampling_interval_ms
                    )
                    active_until_step = step + duration_steps
                    active_action = action
                    # Capture pre-attack snapshot for process impact scoring.
                    self._pre_attack_snaps[action.action_id] = snapshot
                    # Record launch step for detection latency and hard case extraction.
                    self._attack_start_steps[action.action_id] = step

                    if not self._config.dry_run:
                        success = self._execute_action(action, scene, plc_client, snapshot=snapshot)
                        action.execution_status = ExecutionStatus.EXECUTED if success else ExecutionStatus.REJECTED
                    else:
                        action.execution_status = ExecutionStatus.DRY_RUN
                        logger.debug(
                            "DRY-RUN: would write %s=%s to PLC.", action.target, action.value
                        )

                    action.approved_by_shield = True
                    logger.info(
                        "Attack scheduled at step %d: %s -> %s=%s (duration=%dms)",
                        step,
                        action.attack_type.value,
                        action.target,
                        action.value,
                        action.duration_ms,
                    )
                else:
                    action.approved_by_shield = False
                    action.execution_status = ExecutionStatus.REJECTED
                    logger.info(
                        "Shield REJECTED attack at step %d: %s. Reasons: %s",
                        step,
                        action.attack_type.value,
                        decision.reasons,
                    )

            step += 1
            time.sleep(poll_interval_s)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _poll_snapshot(
        self, plc_client: Any, scene: Any, step: int
    ) -> Optional[PlantSnapshot]:
        """Read a snapshot from PLC or generate a zero-valued one in dry-run."""
        # Ensure models are imported without scoping conflicts
        from cpsforge.core.models import (  # noqa: PLC0415
            AttackContext, DefenseContext, SafetyContext, TagCategory,
        )

        if self._config.dry_run:
            # In dry-run we still produce structural snapshots so the framework
            # exercises all code paths. Values default to None (no PLC).
            return PlantSnapshot(
                timestamp=datetime.now(timezone.utc),
                scene_name=scene.name,
                run_id=self._run_id,
                step_id=step,
                sensors={t.name: None for t in scene.profile.tags if t.category.value == "sensor"},
                actuators={t.name: None for t in scene.profile.tags if t.category.value == "actuator"},
                controller_state={
                    t.name: None
                    for t in scene.profile.tags
                    if t.category.value in ("mode_bit", "internal")
                },
                alarms={t.name: None for t in scene.profile.tags if t.category.value == "alarm"},
                setpoints={t.name: None for t in scene.profile.tags if t.category.value == "setpoint"},
                attack_context=AttackContext(),
                defense_context=DefenseContext(),
                safety_context=SafetyContext(live_writes_enabled=False),
            )
        else:
            # For synchronous polling in the main loop
            try:
                raw = plc_client.read_many(scene.profile.tags)
            except Exception as exc:
                logger.error("PLC read_many failed at step %d: %s", step, exc)
                return None

            sensors, actuators, controller_state, alarms, setpoints = {}, {}, {}, {}, {}
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

    def _execute_action(self, action: AttackAction, scene: Any, plc_client: Any, snapshot: Any = None) -> bool:
        """Translate an approved AttackAction into PLC writes via the action compiler.

        Returns True on success, False if writes failed.
        """
        from cpsforge.attacks.compiler import compile_action
        try:
            writes = compile_action(action, scene, current_snapshot=snapshot)
            for tag_name, value in writes.items():
                tag = scene.get_tag(tag_name)
                if tag:
                    plc_client.write_tag(tag, value)
            return True
        except Exception as exc:
            logger.error("Action execution failed for %s: %s", action.action_id[:8], exc)
            return False

    def _load_scene(self) -> Any:
        from cpsforge.scenes.factory import load_scene
        # Extract scene name from config path like "scenes/tank_control.yaml"
        scene_name = Path(self._config.scene_config).stem
        return load_scene(scene_name, self._loader)

    def _build_shield(self, scene: Any) -> Any:
        from cpsforge.shield.engine import ShieldEngine
        return ShieldEngine(scene.profile)

    def _build_defenders(self, scene: Any) -> List[Any]:
        from cpsforge.defenders.factory import build_defender
        defenders = []
        self._defender_names = []
        for def_name in self._config.defenders:
            try:
                cfg = self._loader.load_defender(def_name)
                det = build_defender(cfg)
                defenders.append(det)
                self._defender_names.append(det.name)
            except FileNotFoundError:
                logger.warning("Defender config not found: %s -- skipping.", def_name)
        return defenders

    def _build_attackers(self, scene: Any) -> List[Any]:
        from cpsforge.attacks.factory import build_attacker
        attackers = []
        for atk_name in self._config.attackers:
            try:
                cfg = self._loader.load_attack_policy(atk_name)
                attackers.append(build_attacker(cfg, scene))
            except FileNotFoundError:
                logger.warning("Attacker config not found: %s -- skipping.", atk_name)
        return attackers

    # ------------------------------------------------------------------
    # Metrics computation
    # ------------------------------------------------------------------

    def _compute_metrics(self, scene: Any) -> EvalMetrics:
        scene_name = scene.name
        total = len(self._actions)
        approved = sum(1 for a in self._actions if a.approved_by_shield)
        rejected = sum(1 for a in self._actions if a.approved_by_shield is False)
        executed = sum(
            1 for a in self._actions
            if a.execution_status.value in ("executed", "dry_run")
        )

        # action_validity_rate: fraction of generated actions whose target is in the scene's
        # attack surface.  This is a pre-shield measure of attacker output quality; it is
        # critical for evaluating the LLM attacker (which may hallucinate tag names).
        attack_surface_set = set(scene.profile.attack_surface)
        valid_count = sum(1 for a in self._actions if a.target in attack_surface_set)
        action_validity_rate = round(valid_count / total, 4) if total > 0 else 0.0

        # unsafe_block_rate: fraction blocked by safety-critical rules only.
        # Distinct from shield_rejection_rate, which includes all operational constraints.
        # Safety-critical rule types: 'range', 'invariant', 'interlock'.
        # Operational-only types (counted in rejection_rate but NOT here): 'cooldown', 'duration', 'mode_gate'.
        _SAFETY_RULE_TYPES = frozenset({"range", "invariant", "interlock"})
        rule_type_map = {r.rule_id: r.rule_type for r in scene.profile.safety_rules}
        unsafe_blocked = 0
        for decision in self._decisions:
            if not decision.approved:
                for rule_id in decision.violated_rules:
                    if rule_type_map.get(rule_id, "") in _SAFETY_RULE_TYPES:
                        unsafe_blocked += 1
                        break
        unsafe_block_rate = round(unsafe_blocked / total, 4) if total > 0 else 0.0

        # Detection metrics against ground truth
        attack_steps = self._ground_truth_attack_steps
        detected_steps: set[int] = set()
        for event in self._detections:
            if event.step_id is not None:
                detected_steps.add(event.step_id)

        # TP: attack steps where a detection occurred (within same step window)
        tp = len(attack_steps & detected_steps)
        fp = len(detected_steps - attack_steps)
        fn = len(attack_steps - detected_steps)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        # Detection latency: for each executed attack, measure the step gap from
        # attack launch to the first detection event at or after that launch step.
        latencies = []
        for action in self._actions:
            if action.execution_status.value not in ("executed", "dry_run"):
                continue
            start_step = self._attack_start_steps.get(action.action_id)
            if start_step is None:
                continue
            first_det: Optional[int] = None
            for ev in self._detections:
                if ev.step_id is not None and ev.step_id >= start_step:
                    if first_det is None or ev.step_id < first_det:
                        first_det = ev.step_id
            if first_det is not None:
                lat_ms = (first_det - start_step) * scene.profile.sampling_interval_ms
                latencies.append(max(0.0, lat_ms))
        mean_latency = sum(latencies) / len(latencies) if latencies else 0.0

        attacker_names = list({a.source.value for a in self._actions}) if self._actions else ["none"]
        # Prefer the list of loaded defender names so detector_names is non-empty even when
        # no detection events fired (e.g. all-miss run).  Fall back to event-derived names.
        detector_names = self._defender_names if self._defender_names else list(
            set(e.detector_name for e in self._detections)
        )

        # Attack success rate and process impact.
        # Include still-active attacks (run ended while attack window was open) with defaults
        # (success=False, impact=0.0) so the denominator stays consistent with executed count.
        _executed_ids = {
            a.action_id for a in self._actions
            if a.execution_status.value in ("executed", "dry_run")
        }
        attack_success_full = {aid: self._attack_success_map.get(aid, False) for aid in _executed_ids}
        attack_impact_full  = {aid: self._attack_impact_map.get(aid, 0.0)  for aid in _executed_ids}
        attack_success_rate = (
            round(sum(1 for v in attack_success_full.values() if v) / len(attack_success_full), 4)
            if attack_success_full else 0.0
        )
        process_impact_score = (
            round(sum(attack_impact_full.values()) / len(attack_impact_full), 4)
            if attack_impact_full else 0.0
        )

        # Stealth score: fraction of attack steps that were NOT detected.
        # A stealth score of 1.0 means no attack step was detected.
        undetected_attack_steps = attack_steps - detected_steps
        stealth_score = (
            round(len(undetected_attack_steps) / len(attack_steps), 4)
            if attack_steps else 0.0
        )

        # Mean deviation: average process impact across all executed attacks.
        mean_deviation = process_impact_score  # alias for now; same computation

        # Campaign phases: check if any attacker is a CampaignAttacker
        campaign_phases = 0
        for attacker in self._actions:
            if attacker.rationale and any(
                attacker.rationale.startswith(f"[{p.upper()}]")
                for p in ("reconnaissance", "preparation", "exploitation", "persistence")
            ):
                campaign_phases = 4
                break

        return EvalMetrics(
            run_id=self._run_id,
            scene_name=scene_name,
            attacker_name=", ".join(attacker_names),
            detector_names=detector_names,
            action_validity_rate=action_validity_rate,
            # execution_success_rate: of shield-approved actions, fraction that actually ran.
            execution_success_rate=round(executed / approved, 4) if approved > 0 else 0.0,
            attack_success_rate=attack_success_rate,
            process_impact_score=process_impact_score,
            shield_approval_rate=round(approved / total, 4) if total > 0 else 0.0,
            shield_rejection_rate=round(rejected / total, 4) if total > 0 else 0.0,
            unsafe_block_rate=unsafe_block_rate,
            detector_precision=round(precision, 4),
            detector_recall=round(recall, 4),
            detector_f1=round(f1, 4),
            detection_latency_ms=round(mean_latency, 2),
            false_positives=fp,
            false_negatives=fn,
            hard_case_flag=(fn > 0),
            adaptation_round=self._config.adaptation_round,
            stealth_score=stealth_score,
            mean_deviation=mean_deviation,
            campaign_phases=campaign_phases,
            total_steps=len(self._snapshots),
            total_attacks=total,
            eval_run=self._config.eval_run,
        )

    def _write_artifacts(self, scene: Any) -> None:
        """Persist all run artifacts to disk."""
        self._run_dir.mkdir(parents=True, exist_ok=True)
        recorder = TraceRecorder(self._run_dir)
        for snap in self._snapshots:
            recorder.record(snap)

        writer = RunArtifactWriter(self._run_dir)

        if self._config.save_trace and self._snapshots:
            recorder.flush()

        writer.write_attacks(self._actions)
        writer.write_detections(self._detections)
        writer.write_shield_events(self._decisions)

        if self._config.save_metrics:
            metrics = self._compute_metrics(scene)
            writer.write_metrics(metrics)

        # Phase 3: extract and archive hard cases (missed / late detections).
        try:
            from cpsforge.adaptation.hard_cases import extract_and_write_hard_cases
            extract_and_write_hard_cases(
                actions=self._actions,
                detections=self._detections,
                attack_start_steps=self._attack_start_steps,
                attack_success_map=self._attack_success_map,
                ground_truth_steps=self._ground_truth_attack_steps,
                sampling_interval_ms=scene.profile.sampling_interval_ms,
                run_id=self._run_id,
                run_dir=self._run_dir,
                dry_run=self._config.dry_run,
            )
        except Exception as exc:
            logger.warning("Hard case extraction failed (non-fatal): %s", exc)

        writer.write_metadata({
            "run_id": self._run_id,
            "experiment_name": self._config.name,
            "scene": scene.name,
            "dry_run": self._config.dry_run,
            "eval_run": self._config.eval_run,
            "adaptation_round": self._config.adaptation_round,
            "total_steps": len(self._snapshots),
            "total_attacks": len(self._actions),
            "created_at": datetime.now(timezone.utc).isoformat(),
            **self._llm_metadata,
        })
        logger.info("Run artifacts written to: %s", self._run_dir)



