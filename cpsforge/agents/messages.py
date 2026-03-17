"""
CPSForge Agent IPC Messages
===========================
Typed message contracts exchanged between agent processes and coordinator.

These models must remain lightweight and pickle-safe because they travel
through multiprocessing queues.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from cpsforge.core.models import AttackAction, ShieldDecision


_utcnow = lambda: datetime.now(timezone.utc)  # noqa: E731


class RequestKind(str, Enum):
    """Kinds of write requests an agent can submit."""

    ATTACK = "attack"
    CORRECTIVE = "corrective"


class AgentEventType(str, Enum):
    """Common event categories emitted by runtime agents."""

    AGENT_STARTED = "agent_started"
    AGENT_STOPPED = "agent_stopped"
    AGENT_ERROR = "agent_error"
    ATTACK_SUBMITTED = "attack_submitted"
    ATTACK_APPROVED = "attack_approved"
    ATTACK_REJECTED = "attack_rejected"
    ATTACK_EXECUTED = "attack_executed"
    DETECTION_EMITTED = "detection_emitted"
    CORRECTIVE_SUBMITTED = "corrective_submitted"
    CORRECTIVE_APPROVED = "corrective_approved"
    CORRECTIVE_REJECTED = "corrective_rejected"
    CORRECTIVE_EXECUTED = "corrective_executed"


class WriteRequest(BaseModel):
    """A write intent submitted by an attacker or defender agent."""

    request_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=_utcnow)
    agent_name: str
    kind: RequestKind
    action: AttackAction
    metadata: Dict[str, Any] = Field(default_factory=dict)


class WriteResult(BaseModel):
    """Shield and execution outcome returned by the coordinator."""

    request_id: str
    timestamp: datetime = Field(default_factory=_utcnow)
    approved: bool
    executed: bool
    status: str = "pending"
    reason: str = ""
    shield_decision: Optional[ShieldDecision] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AgentEvent(BaseModel):
    """An auditable event emitted by an agent process."""

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=_utcnow)
    event_type: AgentEventType
    agent_name: str
    run_id: str
    step_id: Optional[int] = None
    payload: Dict[str, Any] = Field(default_factory=dict)
