"""
CPSForge Base Agent
===================
Abstract process-safe base class for live attacker/defender agents.

Subclasses implement reason() and act(). The base class provides:
- safe PLC observation loop
- event publishing
- bounded in-memory history
- coordinator write-request helper
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from multiprocessing import Event, Queue
from queue import Empty
from typing import Any, Dict, List, Optional

from cpsforge.agents.messages import AgentEvent, AgentEventType, RequestKind, WriteRequest, WriteResult
from cpsforge.core.config import LLMConfig, PLCConfig
from cpsforge.core.models import (
    AttackAction,
    AttackContext,
    DefenseContext,
    PlantSnapshot,
    SafetyContext,
    SceneProfile,
    TagCategory,
)
from cpsforge.llm.base_provider import BaseLLMProvider
from cpsforge.llm.factory import build_provider
from cpsforge.plc.client import PlcClient

logger = logging.getLogger(__name__)


_utcnow = lambda: datetime.now(timezone.utc)  # noqa: E731


class BaseAgent(ABC):
    """Base class for long-running runtime agents in multiprocess mode."""

    def __init__(
        self,
        *,
        agent_name: str,
        run_id: str,
        scene_profile: SceneProfile,
        plc_config: PLCConfig,
        llm_config: LLMConfig,
        write_request_queue: Queue,
        write_result_queue: Queue,
        event_queue: Queue,
        max_history: int = 100,
    ) -> None:
        self._agent_name = agent_name
        self._run_id = run_id
        self._scene = scene_profile
        self._plc = PlcClient(plc_config)
        self._llm: BaseLLMProvider = build_provider(llm_config)
        self._write_request_queue = write_request_queue
        self._write_result_queue = write_result_queue
        self._event_queue = event_queue
        self._max_history = max(1, max_history)
        self._history: List[Dict[str, Any]] = []
        self._step_id: int = 0

    @property
    def name(self) -> str:
        return self._agent_name

    @property
    def step_id(self) -> int:
        return self._step_id

    @property
    def history(self) -> List[Dict[str, Any]]:
        return self._history

    def setup(self) -> None:
        """Initialize external resources before the main loop starts."""
        self._plc.connect()
        self.publish_event(AgentEventType.AGENT_STARTED, {"agent": self._agent_name})

    def teardown(self) -> None:
        """Release resources when the main loop exits."""
        try:
            self._plc.disconnect()
        finally:
            self.publish_event(AgentEventType.AGENT_STOPPED, {"agent": self._agent_name})

    def run(self, stop_event: Event) -> None:
        """Run observe -> reason -> act continuously until stop_event is set."""
        self.setup()
        try:
            while not stop_event.is_set():
                snapshot = self.observe()
                if snapshot is None:
                    continue
                decision = self.reason(snapshot)
                self.act(snapshot, decision)
                self._step_id += 1
        except Exception as exc:  # pragma: no cover - safety guard for runtime loops
            logger.exception("Agent %s crashed: %s", self._agent_name, exc)
            self.publish_event(
                AgentEventType.AGENT_ERROR,
                {"error": str(exc), "agent": self._agent_name},
            )
        finally:
            self.teardown()

    def observe(self) -> Optional[PlantSnapshot]:
        """Read all scene tags from the PLC and build a categorized snapshot."""
        if not self._plc.is_connected():
            self._plc.connect()

        values = self._plc.read_many(self._scene.tags)
        if not values:
            return None

        sensors: Dict[str, Any] = {}
        actuators: Dict[str, Any] = {}
        controller_state: Dict[str, Any] = {}
        alarms: Dict[str, Any] = {}
        setpoints: Dict[str, Any] = {}

        for tag in self._scene.tags:
            value = values.get(tag.name)
            if tag.category == TagCategory.SENSOR:
                sensors[tag.name] = value
            elif tag.category == TagCategory.ACTUATOR:
                actuators[tag.name] = value
            elif tag.category == TagCategory.ALARM:
                alarms[tag.name] = value
            elif tag.category == TagCategory.SETPOINT:
                setpoints[tag.name] = value
            else:
                controller_state[tag.name] = value

        return PlantSnapshot(
            timestamp=_utcnow(),
            scene_name=self._scene.scene_name,
            run_id=self._run_id,
            step_id=self._step_id,
            sensors=sensors,
            actuators=actuators,
            controller_state=controller_state,
            alarms=alarms,
            setpoints=setpoints,
            derived_features={},
            attack_context=AttackContext(),
            defense_context=DefenseContext(),
            safety_context=SafetyContext(),
        )

    @abstractmethod
    def reason(self, snapshot: PlantSnapshot) -> Any:
        """Produce an agent decision from the current snapshot."""

    @abstractmethod
    def act(self, snapshot: PlantSnapshot, decision: Any) -> None:
        """Apply a decision by emitting events and/or write requests."""

    def submit_write_request(
        self,
        *,
        action: AttackAction,
        kind: RequestKind,
        timeout_s: float = 10.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[WriteResult]:
        """Send write intent to coordinator and await result for this action."""
        request = WriteRequest(
            agent_name=self._agent_name,
            kind=kind,
            action=action,
            metadata=metadata or {},
        )
        self._write_request_queue.put(request)

        deadline = _utcnow().timestamp() + timeout_s
        while _utcnow().timestamp() < deadline:
            try:
                result = self._write_result_queue.get(timeout=0.2)
            except Empty:
                continue
            if isinstance(result, WriteResult) and result.request_id == request.request_id:
                return result
        return None

    def add_history(self, entry: Dict[str, Any]) -> None:
        """Append to bounded history buffer used by prompt construction."""
        self._history.append(entry)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history :]

    def publish_event(self, event_type: AgentEventType, payload: Dict[str, Any]) -> None:
        """Emit a structured runtime event to the coordinator."""
        event = AgentEvent(
            event_type=event_type,
            agent_name=self._agent_name,
            run_id=self._run_id,
            step_id=self._step_id,
            payload=payload,
        )
        self._event_queue.put_nowait(event)
