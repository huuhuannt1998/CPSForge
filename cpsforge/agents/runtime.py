"""Live multi-agent runtime (attacker + defender + coordinator)."""

from __future__ import annotations

import logging
import multiprocessing as mp
import time
from dataclasses import dataclass, field
from multiprocessing import Process, Queue
from pathlib import Path
from typing import Dict, List, Optional

from cpsforge.agents.attacker_agent import AttackerAgent
from cpsforge.agents.coordinator import AgentCoordinator
from cpsforge.agents.defender_agent import DefenderAgent
from cpsforge.agents.event_bus import EventBus
from cpsforge.agents.messages import AgentEvent
from cpsforge.core.config import AgentConfig, ConfigLoader, ExperimentConfig
from cpsforge.core.models import AgentEvalMetrics, PlantSnapshot
from cpsforge.defenders.factory import build_defender
from cpsforge.logging.artifacts import AgentRunArtifactWriter, compute_agent_metrics
from cpsforge.scenes.factory import load_scene
from cpsforge.shield.engine import ShieldEngine

logger = logging.getLogger(__name__)


@dataclass
class AgentRuntimeResult:
    """High-level output of one agent runtime execution."""

    run_id: str
    snapshots: List[PlantSnapshot]
    events: List[AgentEvent]
    processed_requests: int
    metrics: Optional[AgentEvalMetrics] = None
    artifact_dir: Optional[Path] = None


def _run_attacker_process(
    stop_event: mp.Event,
    run_id: str,
    scene_profile,
    plc_config,
    llm_config,
    write_request_queue: Queue,
    write_result_queue: Queue,
    event_queue: Queue,
    max_history: int,
) -> None:
    agent = AttackerAgent(
        agent_name="attacker-agent",
        run_id=run_id,
        scene_profile=scene_profile,
        plc_config=plc_config,
        llm_config=llm_config,
        write_request_queue=write_request_queue,
        write_result_queue=write_result_queue,
        event_queue=event_queue,
        max_history=max_history,
    )
    agent.run(stop_event)


def _run_defender_process(
    stop_event: mp.Event,
    run_id: str,
    scene_profile,
    plc_config,
    llm_config,
    write_request_queue: Queue,
    write_result_queue: Queue,
    event_queue: Queue,
    max_history: int,
    defender_names: List[str],
    configs_dir: str,
) -> None:
    loader = ConfigLoader(configs_dir=Path(configs_dir))
    detectors = []
    for defender_name in defender_names:
        try:
            defender_cfg = loader.load_defender(defender_name)
            detectors.append(build_defender(defender_cfg))
        except FileNotFoundError:
            continue

    agent = DefenderAgent(
        agent_name="defender-agent",
        run_id=run_id,
        scene_profile=scene_profile,
        plc_config=plc_config,
        llm_config=llm_config,
        write_request_queue=write_request_queue,
        write_result_queue=write_result_queue,
        event_queue=event_queue,
        max_history=max_history,
        detectors=detectors,
    )
    agent.run(stop_event)


class AgentRuntime:
    """Runs attacker and defender as independent processes in real time."""

    def __init__(
        self,
        *,
        run_id: str,
        loader: ConfigLoader,
        exp_config: ExperimentConfig,
        attacker_cfg: AgentConfig,
        defender_cfg: AgentConfig,
    ) -> None:
        self._run_id = run_id
        self._loader = loader
        self._exp = exp_config
        self._attacker_cfg = attacker_cfg
        self._defender_cfg = defender_cfg

    def run(self) -> AgentRuntimeResult:
        scene_name = self._attacker_cfg.scene_name
        scene = load_scene(scene_name, self._loader)
        shield = ShieldEngine(scene.profile)

        plc_cfg = self._loader.load_plc()
        # Propagate the experiment-level live_writes flag to the PLC client.
        if self._exp.live_writes_enabled:
            plc_cfg.live_writes_enabled = True
        llm_attacker = self._loader.load_llm(self._attacker_cfg.llm_provider)
        llm_defender = self._loader.load_llm(self._defender_cfg.llm_provider)
        if self._attacker_cfg.llm_model:
            llm_attacker.model = self._attacker_cfg.llm_model
        if self._defender_cfg.llm_model:
            llm_defender.model = self._defender_cfg.llm_model

        # Agent prompts are compact single-JSON responses; cap max_tokens
        # to avoid exceeding local model context windows.
        _AGENT_MAX_TOKENS = 256
        if llm_attacker.max_tokens > _AGENT_MAX_TOKENS:
            llm_attacker.max_tokens = _AGENT_MAX_TOKENS
        if llm_defender.max_tokens > _AGENT_MAX_TOKENS:
            llm_defender.max_tokens = _AGENT_MAX_TOKENS

        write_request_queue: Queue = mp.Queue()
        event_queue: Queue = mp.Queue()
        attacker_result_queue: Queue = mp.Queue()
        defender_result_queue: Queue = mp.Queue()

        coordinator = AgentCoordinator(
            plc_config=plc_cfg,
            scene=scene,
            shield=shield,
            write_request_queue=write_request_queue,
            write_result_queues={
                "attacker-agent": attacker_result_queue,
                "defender-agent": defender_result_queue,
            },
            dry_run=self._exp.dry_run,
        )

        stop_event = mp.Event()
        attacker_proc = Process(
            target=_run_attacker_process,
            args=(
                stop_event,
                self._run_id,
                scene.profile,
                plc_cfg,
                llm_attacker,
                write_request_queue,
                attacker_result_queue,
                event_queue,
                self._attacker_cfg.max_history,
            ),
            name="attacker-agent",
            daemon=True,
        )
        defender_proc = Process(
            target=_run_defender_process,
            args=(
                stop_event,
                self._run_id,
                scene.profile,
                plc_cfg,
                llm_defender,
                write_request_queue,
                defender_result_queue,
                event_queue,
                self._defender_cfg.max_history,
                self._exp.defenders,
                str(self._loader.configs_dir),
            ),
            name="defender-agent",
            daemon=True,
        )

        snapshots: List[PlantSnapshot] = []
        events: List[AgentEvent] = []
        processed_requests = 0
        bus = EventBus(event_queue)

        coordinator.start()
        attacker_proc.start()
        defender_proc.start()
        t_start = time.monotonic()

        try:
            for step_id in range(self._exp.max_steps):
                snapshot = coordinator.poll_snapshot(self._run_id, step_id)
                if snapshot is not None:
                    snapshots.append(snapshot)
                processed_requests += coordinator.process_write_requests(snapshot)
                events.extend(bus.collect())
                time.sleep(scene.profile.sampling_interval_ms / 1000.0)
        finally:
            stop_event.set()
            attacker_proc.join(timeout=5.0)
            defender_proc.join(timeout=5.0)
            # Collect any remaining events after agents stop
            events.extend(bus.collect())
            coordinator.stop()

        duration_s = time.monotonic() - t_start

        # --- Write artifacts ---
        output_base = Path(self._exp.output_dir) if self._exp.output_dir else Path("data/raw")
        run_dir = output_base / self._exp.name / self._run_id
        writer = AgentRunArtifactWriter(run_dir)

        if snapshots and self._exp.save_trace:
            writer.write_trace(snapshots)

        writer.write_events(events)
        writer.write_metadata({
            "run_id": self._run_id,
            "mode": "agent",
            "scene_name": scene_name,
            "experiment": self._exp.name,
            "dry_run": self._exp.dry_run,
            "eval_run": self._exp.eval_run,
            "max_steps": self._exp.max_steps,
            "total_steps": len(snapshots),
            "duration_s": round(duration_s, 2),
            "attacker_agent": self._attacker_cfg.name,
            "defender_agent": self._defender_cfg.name,
            "attacker_llm_model": llm_attacker.model,
            "defender_llm_model": llm_defender.model,
        })

        metrics = compute_agent_metrics(
            run_id=self._run_id,
            scene_name=scene_name,
            events=events,
            total_steps=len(snapshots),
            duration_s=duration_s,
            eval_run=self._exp.eval_run,
            dry_run=self._exp.dry_run,
        )
        if self._exp.save_metrics:
            writer.write_agent_metrics(metrics)

        logger.info(
            "Agent run %s complete: %d steps, %d events, %d writes in %.1fs",
            self._run_id, len(snapshots), len(events), processed_requests, duration_s,
        )

        return AgentRuntimeResult(
            run_id=self._run_id,
            snapshots=snapshots,
            events=events,
            processed_requests=processed_requests,
            metrics=metrics,
            artifact_dir=run_dir,
        )
