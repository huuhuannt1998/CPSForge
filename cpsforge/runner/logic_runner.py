"""
logic_runner.py — Experiment runner for logic-level attacks via TIA Openness.

Orchestrates the full pipeline:
  1. Attach to TIA Portal
  2. Back up original block
  3. Read original SCL and current PLC state
  4. LLM generates adversarial modification
  5. Validate and apply modification to SCL
  6. Deploy modified SCL via TIA Openness (import → compile)
  7. User downloads to PLC (manual step — Openness download API unreliable)
  8. Observe physical effect via snap7 polling
  9. Restore original code
  10. Save artifacts

This runner is DIFFERENT from OnlineExperimentRunner:
  - It modifies the PLC PROGRAM, not I/O values
  - It makes ONE modification, not a polling loop of decisions
  - The observation phase is passive (no more LLM calls)
  - Restoration is mandatory after each experiment

Usage:
    runner = LogicExperimentRunner(config, loader)
    run_id = runner.run()
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from cpsforge.attacker.logic_mitm import (
    LogicMITMAttacker,
    LogicAttackResult,
    _BLOCK_NAMES,
    _SCL_NAMES,
)
from cpsforge.context_builder.schema import ContextLevel
from cpsforge.core.config import ConfigLoader
from cpsforge.core.models import PlantSnapshot
from cpsforge.llm.base_provider import BaseLLMProvider
from cpsforge.observation.history_buffer import HistoryBuffer
from cpsforge.observation.phase_inference import PhaseInferenceEngine
from cpsforge.plc.tia_openness import TiaOpennessClient
from cpsforge.scenes.base import BaseScene

logger = logging.getLogger(__name__)


class LogicExperimentRunner:
    """Run a logic-level attack experiment.

    Parameters
    ----------
    config : dict or ExperimentConfig
        Experiment configuration.
    loader : ConfigLoader
        Configuration loader for scene/PLC/LLM settings.
    output_base : Path, optional
        Base directory for artifacts.
    extra : dict
        Extra parameters:
          - context_level: "minimal" | "partial" | "full"
          - model_variant: "base" | "finetuned"
          - observation_steps: int (how many steps to observe after deployment)
          - poll_interval_ms: int (observation polling interval)
          - auto_download: bool (if True, prompt user; if False, skip PLC download)
    """

    def __init__(
        self,
        config: Any,
        loader: ConfigLoader,
        output_base: Optional[Path] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._config = config
        self._loader = loader
        self._output_base = output_base or Path("data/raw")
        self._extra = extra or {}
        self._run_id = f"logic_{uuid.uuid4().hex[:8]}"

        # Parse extra params
        ctx_str = self._extra.get("context_level", "full")
        self._context_level = ContextLevel(ctx_str)
        self._observation_steps = int(self._extra.get("observation_steps", 60))
        self._poll_interval_ms = int(self._extra.get("poll_interval_ms", 500))
        self._auto_download = self._extra.get("auto_download", True)

    def run(self) -> str:
        """Execute the full logic attack pipeline. Returns run_id."""
        scene_name = Path(self._config.scene_config).stem
        logger.info(
            "=== Logic Attack Experiment: %s (context=%s, run=%s) ===",
            scene_name, self._context_level.value, self._run_id,
        )

        events: List[Dict[str, Any]] = []
        artifacts: Dict[str, Any] = {
            "run_id": self._run_id,
            "scene": scene_name,
            "context_level": self._context_level.value,
            "model_variant": self._extra.get("model_variant", "base"),
            "started_at": datetime.now().isoformat(),
        }

        def log_event(event_type: str, details: Optional[Dict] = None):
            entry = {"timestamp": datetime.now().isoformat(), "event": event_type}
            if details:
                entry.update(details)
            events.append(entry)
            logger.info("[%s] %s", event_type, details or "")

        try:
            # ── Step 1: Load scene ──
            from cpsforge.scenes.factory import load_scene
            scene = load_scene(scene_name, self._loader)
            log_event("scene_loaded", {"scene": scene_name})

            # ── Step 2: Build LLM provider ──
            llm_provider = self._build_llm_provider()
            if llm_provider and hasattr(llm_provider, "_ensure_loaded"):
                log_event("model_loading")
                llm_provider._ensure_loaded()
                log_event("model_loaded")

            # ── Step 3: Build components ──
            history = HistoryBuffer(max_size=50)
            phase_engine = PhaseInferenceEngine(scene_name)
            attacker = LogicMITMAttacker(
                scene=scene,
                llm_provider=llm_provider,
                context_level=self._context_level,
                history=history,
                phase_engine=phase_engine,
            )

            # ── Step 4: Read current PLC state (for FULL context) ──
            snapshot = None
            if self._context_level == ContextLevel.FULL:
                snapshot = self._read_snapshot(scene, history)
                if snapshot:
                    log_event("snapshot_read", {
                        "tags": len(snapshot.sensors) + len(snapshot.actuators),
                    })

            # ── Step 5: Attach to TIA Portal ──
            tia = TiaOpennessClient()
            if not tia.attach():
                log_event("tia_attach_failed")
                raise RuntimeError("Cannot attach to TIA Portal")
            log_event("tia_attached")

            # ── Step 6: Backup original block ──
            block_name = _BLOCK_NAMES.get(scene_name, f"FB_{scene_name}")
            backup_path = tia.backup_block(block_name)
            if backup_path:
                log_event("backup_created", {
                    "block": block_name,
                    "path": str(backup_path),
                    "size": backup_path.stat().st_size,
                })

            # ── Step 7: LLM generates modification ──
            log_event("llm_generating")
            t0 = time.monotonic()
            attack_result = attacker.generate_attack(snapshot=snapshot)
            gen_time = (time.monotonic() - t0) * 1000.0

            artifacts["attack_result"] = attack_result.as_dict()
            log_event("llm_generated", {
                "parse_success": attack_result.parse_success,
                "original_matched": attack_result.original_code_matched,
                "modification_type": (
                    attack_result.modification.modification_type
                    if attack_result.modification else None
                ),
                "latency_ms": round(gen_time, 1),
            })

            if not attack_result.success or not attack_result.modification:
                log_event("attack_failed", {"error": attack_result.error})
                artifacts["outcome"] = "generation_failed"
                self._save_artifacts(scene_name, artifacts, events)
                return self._run_id

            # ── Step 8: Apply modification to SCL ──
            original_scl = attacker.get_scl_source(scene_name)
            modified_scl = attacker.apply_modification(
                original_scl, attack_result.modification,
            )

            if modified_scl is None:
                log_event("apply_failed", {"error": "Could not apply modification to SCL"})
                artifacts["outcome"] = "apply_failed"
                self._save_artifacts(scene_name, artifacts, events)
                return self._run_id

            log_event("modification_applied", {
                "original_len": len(original_scl),
                "modified_len": len(modified_scl),
                "diff_chars": abs(len(modified_scl) - len(original_scl)),
            })

            # ── Step 9: Deploy via TIA Openness ──
            source_name = _SCL_NAMES.get(scene_name, f"FB_{scene_name}.scl")
            success, message = tia.deploy_scl(modified_scl, source_name)

            artifacts["compilation_ok"] = success
            artifacts["compilation_message"] = message
            log_event("deployed", {"success": success, "message": message})

            if not success:
                log_event("compilation_failed", {"message": message})
                # Restore original
                log_event("restoring_original")
                tia.restore_block(block_name, Path("factoryio_scenes") / source_name)
                log_event("original_restored")
                artifacts["outcome"] = "compilation_failed"
                self._save_artifacts(scene_name, artifacts, events)
                return self._run_id

            # ── Step 10: Download to PLC ──
            if self._auto_download:
                log_event("awaiting_download", {
                    "instruction": "Download to PLC from TIA Portal: Online → Download to device → Load → Start all",
                })
                print("\n" + "=" * 60)
                print("MODIFIED CODE COMPILED SUCCESSFULLY")
                print("Please download to PLC from TIA Portal:")
                print("  Online → Download to device → Load → Start all modules")
                print("Press ENTER when download is complete...")
                print("=" * 60)
                input()
                log_event("download_confirmed")

            # ── Step 11: Observe physical effect ──
            log_event("observation_start", {"steps": self._observation_steps})
            observations = self._observe_effect(
                scene, history,
                n_steps=self._observation_steps,
                poll_ms=self._poll_interval_ms,
            )
            log_event("observation_complete", {"steps_collected": len(observations)})
            artifacts["observations"] = observations

            # ── Step 12: Restore original ──
            log_event("restoring_original")
            restore_ok, restore_msg = tia.restore_block(
                block_name, Path("factoryio_scenes") / source_name,
            )
            log_event("original_restored", {"success": restore_ok, "message": restore_msg})

            if restore_ok and self._auto_download:
                print("\n" + "=" * 60)
                print("ORIGINAL CODE RESTORED AND COMPILED")
                print("Please download to PLC from TIA Portal:")
                print("  Online → Download to device → Load → Start all modules")
                print("Press ENTER when download is complete...")
                print("=" * 60)
                input()
                log_event("restore_download_confirmed")

            artifacts["outcome"] = "success"

        except Exception as exc:
            logger.error("Logic experiment failed: %s", exc, exc_info=True)
            log_event("error", {"message": str(exc)})
            artifacts["outcome"] = "error"
            artifacts["error"] = str(exc)

        artifacts["finished_at"] = datetime.now().isoformat()
        self._save_artifacts(scene_name, artifacts, events)
        return self._run_id

    # ------------------------------------------------------------------
    # PLC observation
    # ------------------------------------------------------------------

    def _read_snapshot(
        self,
        scene: BaseScene,
        history: HistoryBuffer,
    ) -> Optional[PlantSnapshot]:
        """Read one snapshot from the PLC for context building."""
        try:
            import snap7
            plc_cfg = self._loader.load_plc()
            client = snap7.client.Client()
            client.connect(plc_cfg.host, plc_cfg.rack, plc_cfg.slot)

            profile = scene.profile
            sensors = {}
            actuators = {}
            setpoints = {}

            for tag in profile.tags:
                try:
                    val = self._read_tag_value(client, tag)
                    if tag.category.value == "sensor":
                        sensors[tag.name] = val
                    elif tag.category.value == "actuator":
                        actuators[tag.name] = val
                    elif tag.category.value == "setpoint":
                        setpoints[tag.name] = val
                    else:
                        sensors[tag.name] = val
                except Exception:
                    pass

            client.disconnect()

            snapshot = PlantSnapshot(
                timestamp=datetime.now().isoformat(),
                scene_name=scene.profile.scene_name,
                run_id=self._run_id,
                step_id=0,
                sensors=sensors,
                actuators=actuators,
                setpoints=setpoints,
            )
            history.append(snapshot)
            return snapshot

        except Exception as exc:
            logger.warning("Failed to read PLC snapshot: %s", exc)
            return None

    def _observe_effect(
        self,
        scene: BaseScene,
        history: HistoryBuffer,
        n_steps: int = 60,
        poll_ms: int = 500,
    ) -> List[Dict[str, Any]]:
        """Poll PLC repeatedly and record observations."""
        observations = []
        try:
            import snap7
            plc_cfg = self._loader.load_plc()
            client = snap7.client.Client()
            client.connect(plc_cfg.host, plc_cfg.rack, plc_cfg.slot)

            profile = scene.profile
            for step in range(n_steps):
                t0 = time.monotonic()
                obs = {"step": step, "timestamp": datetime.now().isoformat()}

                for tag in profile.tags:
                    try:
                        obs[tag.name] = self._read_tag_value(client, tag)
                    except Exception:
                        obs[tag.name] = None

                observations.append(obs)

                if step % 10 == 0:
                    logger.info("Observation step %d/%d", step, n_steps)

                elapsed = (time.monotonic() - t0) * 1000.0
                sleep_ms = max(0, poll_ms - elapsed)
                if sleep_ms > 0:
                    time.sleep(sleep_ms / 1000.0)

            client.disconnect()

        except Exception as exc:
            logger.error("Observation failed: %s", exc)

        return observations

    def _read_tag_value(self, client, tag) -> Any:
        """Read a single tag value from the PLC via snap7."""
        import struct

        address = tag.address
        # Parse "DB14,REAL12" format
        parts = address.split(",")
        db_num = int(parts[0].replace("DB", ""))

        type_offset = parts[1]
        if type_offset.startswith("REAL"):
            offset = int(type_offset[4:])
            data = client.db_read(db_num, offset, 4)
            return round(struct.unpack(">f", data)[0], 4)
        elif type_offset.startswith("DINT"):
            offset = int(type_offset[4:])
            data = client.db_read(db_num, offset, 4)
            return struct.unpack(">i", data)[0]
        elif type_offset.startswith("BOOL"):
            offset = int(type_offset[4:])
            data = client.db_read(db_num, offset, 1)
            return bool(data[0])
        elif type_offset.startswith("X"):
            # Bit address: DB14,X0.0
            byte_bit = type_offset[1:].split(".")
            offset = int(byte_bit[0])
            bit = int(byte_bit[1])
            data = client.db_read(db_num, offset, 1)
            return bool(data[0] & (1 << bit))
        else:
            offset = int("".join(c for c in type_offset if c.isdigit()))
            data = client.db_read(db_num, offset, 4)
            return data.hex()

    # ------------------------------------------------------------------
    # LLM provider
    # ------------------------------------------------------------------

    def _build_llm_provider(self) -> Optional[BaseLLMProvider]:
        """Build the LLM provider from config."""
        model_variant = self._extra.get("model_variant", "base")
        if model_variant == "finetuned":
            llm_config = self._loader.load_llm("huggingface_finetuned")
        else:
            llm_config = self._loader.load_llm("huggingface")

        from cpsforge.llm.huggingface_provider import HuggingFaceProvider
        return HuggingFaceProvider(llm_config)

    # ------------------------------------------------------------------
    # Artifacts
    # ------------------------------------------------------------------

    def _save_artifacts(
        self,
        scene_name: str,
        artifacts: Dict[str, Any],
        events: List[Dict[str, Any]],
    ):
        """Save experiment artifacts to disk."""
        out_dir = self._output_base / scene_name / self._run_id
        out_dir.mkdir(parents=True, exist_ok=True)

        # Main artifacts
        with open(out_dir / "logic_attack.json", "w") as f:
            json.dump(artifacts, f, indent=2, default=str)

        # Event log
        with open(out_dir / "events.jsonl", "w") as f:
            for evt in events:
                f.write(json.dumps(evt, default=str) + "\n")

        # Observations as separate file if present
        obs = artifacts.get("observations")
        if obs:
            with open(out_dir / "observations.jsonl", "w") as f:
                for o in obs:
                    f.write(json.dumps(o, default=str) + "\n")

        logger.info("Artifacts saved to %s", out_dir)
