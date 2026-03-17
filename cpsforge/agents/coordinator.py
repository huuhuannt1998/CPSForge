"""Coordinator for live multi-agent write mediation."""

from __future__ import annotations

import logging
from multiprocessing import Queue
from queue import Empty
from typing import Dict, Optional

from cpsforge.agents.messages import RequestKind, WriteRequest, WriteResult
from cpsforge.attacks.compiler import compile_action
from cpsforge.core.config import PLCConfig
from cpsforge.core.models import PlantSnapshot
from cpsforge.plc.client import PlcClient
from cpsforge.scenes.base import BaseScene
from cpsforge.shield.engine import ShieldEngine

logger = logging.getLogger(__name__)


class AgentCoordinator:
    """Mediates all agent writes through shield and single PLC writer."""

    def __init__(
        self,
        *,
        plc_config: PLCConfig,
        scene: BaseScene,
        shield: ShieldEngine,
        write_request_queue: Queue,
        write_result_queues: Dict[str, Queue],
        dry_run: bool,
    ) -> None:
        self._scene = scene
        self._shield = shield
        self._write_request_queue = write_request_queue
        self._write_result_queues = write_result_queues
        self._dry_run = dry_run
        self._plc = PlcClient(plc_config)

    def start(self) -> None:
        if not self._dry_run:
            self._plc.connect()

    def stop(self) -> None:
        self._plc.disconnect()

    def poll_snapshot(self, run_id: str, step_id: int) -> Optional[PlantSnapshot]:
        """Read a ground-truth snapshot for coordinator-side logging/metrics."""
        values = self._plc.read_many(self._scene.profile.tags) if not self._dry_run else {}
        if values is None:
            return None

        from cpsforge.core.models import AttackContext, DefenseContext, SafetyContext

        sensors = {}
        actuators = {}
        controller = {}
        alarms = {}
        setpoints = {}

        for tag in self._scene.profile.tags:
            value = values.get(tag.name)
            category = tag.category.value
            if category == "sensor":
                sensors[tag.name] = value
            elif category == "actuator":
                actuators[tag.name] = value
            elif category == "alarm":
                alarms[tag.name] = value
            elif category == "setpoint":
                setpoints[tag.name] = value
            else:
                controller[tag.name] = value

        return PlantSnapshot(
            scene_name=self._scene.name,
            run_id=run_id,
            step_id=step_id,
            sensors=sensors,
            actuators=actuators,
            controller_state=controller,
            alarms=alarms,
            setpoints=setpoints,
            attack_context=AttackContext(),
            defense_context=DefenseContext(),
            safety_context=SafetyContext(live_writes_enabled=not self._dry_run),
        )

    def process_write_requests(self, snapshot: Optional[PlantSnapshot], max_items: int = 100) -> int:
        """Drain write requests, evaluate shield, execute approved writes, return count processed."""
        processed = 0
        while processed < max_items:
            try:
                request = self._write_request_queue.get_nowait()
            except Empty:
                break
            if not isinstance(request, WriteRequest):
                continue

            # Use corrective evaluation (relaxed cooldown) for defender writes
            if request.kind == RequestKind.CORRECTIVE:
                decision = self._shield.evaluate_corrective(request.action, snapshot)
            else:
                decision = self._shield.evaluate(request.action, snapshot)
            approved = decision.approved
            executed = False
            status = "rejected"
            reason = "; ".join(decision.reasons)

            if approved:
                status = "approved"
                if not self._dry_run:
                    writes = compile_action(request.action, self._scene, snapshot)
                    try:
                        for tag_name, value in writes.items():
                            tag = self._scene.get_tag(tag_name)
                            if tag is None:
                                continue
                            self._plc.write_tag(tag, value)
                        executed = True
                        status = "executed"
                        reason = ""
                    except Exception as exc:  # pragma: no cover - hardware path
                        status = "failed"
                        reason = str(exc)

            result = WriteResult(
                request_id=request.request_id,
                approved=approved,
                executed=executed,
                status=status,
                reason=reason,
                shield_decision=decision,
                metadata={"kind": request.kind.value, "agent": request.agent_name},
            )

            queue = self._write_result_queues.get(request.agent_name)
            if queue is not None:
                queue.put(result)
            processed += 1

        return processed
