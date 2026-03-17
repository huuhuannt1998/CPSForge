"""
CPSForge Agent Event Bus
========================
Simple multiprocessing event bus for agent-to-coordinator telemetry.
"""

from __future__ import annotations

from multiprocessing import Queue
from queue import Empty
from typing import List

from cpsforge.agents.messages import AgentEvent


class EventBus:
    """Queue-backed event collector used by live agent runtime."""

    def __init__(self, queue: Queue):
        self._queue = queue

    def publish(self, event: AgentEvent) -> None:
        """Publish a single event without blocking the caller."""
        self._queue.put_nowait(event)

    def collect(self, max_items: int = 1000) -> List[AgentEvent]:
        """Drain up to max_items events and return them in arrival order."""
        events: List[AgentEvent] = []
        while len(events) < max_items:
            try:
                msg = self._queue.get_nowait()
            except Empty:
                break
            if isinstance(msg, AgentEvent):
                events.append(msg)
        return events
