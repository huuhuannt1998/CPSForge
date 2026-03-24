"""
CPSForge Core Data Models
=========================
All primary domain schemas are defined here using Pydantic v2.
These models are the shared vocabulary across every CPSForge layer:
plc, attacks, shield, defenders, adaptation, and logging.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4

_utcnow = lambda: datetime.now(timezone.utc)  # noqa: E731

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class DataType(str, Enum):
    """Supported PLC tag data types."""
    BOOL = "bool"
    INT = "int"
    DINT = "dint"
    REAL = "real"
    WORD = "word"
    DWORD = "dword"
    BYTE = "byte"


class TagAccess(str, Enum):
    """Whether a tag is readable, writable, or both."""
    READ = "read"
    WRITE = "write"
    READ_WRITE = "read_write"


class TagCategory(str, Enum):
    """Semantic category of a PLC tag."""
    SENSOR = "sensor"
    ACTUATOR = "actuator"
    MODE_BIT = "mode_bit"
    ALARM = "alarm"
    SETPOINT = "setpoint"
    INTERNAL = "internal"


class AttackType(str, Enum):
    """Available attack types in CPSForge."""
    SENSOR_SPOOF = "sensor_spoof"
    ACTUATOR_OVERRIDE = "actuator_override"
    SETPOINT_SHIFT = "setpoint_shift"
    TIMING_DELAY = "timing_delay"
    SEQUENCE_PERTURBATION = "sequence_perturbation"


class AttackSource(str, Enum):
    """Origin of an attack action."""
    SCRIPTED = "scripted"
    RANDOM = "random"
    LLM = "llm"
    REPLAY = "replay"


class ExecutionStatus(str, Enum):
    """Outcome of an attack action execution attempt."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    DRY_RUN = "dry_run"


class DetectionSeverity(str, Enum):
    """Alarm severity levels for detection events."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HardCaseFailureMode(str, Enum):
    """How a detector failed on a hard case."""
    MISS = "miss"
    LATE_DETECTION = "late_detection"
    FALSE_NEGATIVE = "false_negative"
    UNSTABLE_RESPONSE = "unstable_response"


# ---------------------------------------------------------------------------
# Tag Definition
# ---------------------------------------------------------------------------


class TagDefinition(BaseModel):
    """
    Complete description of a single PLC tag.

    A tag is the atomic unit of PLC I/O. Each tag maps a named variable
    to a physical or logical address in the PLC memory space.
    """

    name: str = Field(..., description="Human-readable tag name, e.g. 'tank_level'")
    address: str = Field(
        ...,
        description=(
            "PLC memory address in canonical S7 notation. "
            "Examples: 'DB1,REAL4' (data block), 'MW10' (memory word), "
            "'QW0' (output word), 'IW2' (input word)."
        ),
    )
    data_type: DataType = Field(..., description="PLC data type of this tag")
    access: TagAccess = Field(TagAccess.READ, description="Read/write access mode")
    unit: Optional[str] = Field(None, description="Engineering unit, e.g. '%', 'bar', 'rpm'")
    min_value: Optional[float] = Field(None, description="Minimum valid physical value")
    max_value: Optional[float] = Field(None, description="Maximum valid physical value")
    description: str = Field("", description="Human-readable description of this tag")
    category: TagCategory = Field(..., description="Semantic category of the tag")
    scene_name: str = Field(..., description="Name of the Factory I/O scene this tag belongs to")


# ---------------------------------------------------------------------------
# Plant Snapshot
# ---------------------------------------------------------------------------


class AttackContext(BaseModel):
    """Attack-related metadata embedded in a plant snapshot."""

    active: bool = False
    action_id: Optional[str] = None
    attack_type: Optional[AttackType] = None
    target_tag: Optional[str] = None
    injected_value: Optional[float] = None
    source: Optional[AttackSource] = None


class DefenseContext(BaseModel):
    """Defense-related metadata embedded in a plant snapshot."""

    detectors_active: List[str] = Field(default_factory=list)
    latest_detection: Optional[str] = None
    anomaly_score: Optional[float] = None


class SafetyContext(BaseModel):
    """Shield / safety metadata embedded in a plant snapshot."""

    shield_active: bool = True
    live_writes_enabled: bool = False
    last_rejected_action: Optional[str] = None
    deadman_triggered: bool = False


class PlantSnapshot(BaseModel):
    """
    A complete, time-stamped observation of the plant state.

    One snapshot is recorded per polling cycle and forms the primary unit
    of the trace dataset. All downstream analysis is performed on sequences
    of PlantSnapshot objects.
    """

    timestamp: datetime = Field(default_factory=_utcnow)
    scene_name: str
    run_id: str
    step_id: int = Field(0, ge=0)
    # Tag value maps: tag_name -> raw value
    sensors: Dict[str, Any] = Field(default_factory=dict)
    actuators: Dict[str, Any] = Field(default_factory=dict)
    controller_state: Dict[str, Any] = Field(default_factory=dict)
    alarms: Dict[str, Any] = Field(default_factory=dict)
    setpoints: Dict[str, Any] = Field(default_factory=dict)
    # Computed features (e.g. rate-of-change, deviations)
    derived_features: Dict[str, float] = Field(default_factory=dict)
    # Context overlays
    attack_context: AttackContext = Field(default_factory=AttackContext)
    defense_context: DefenseContext = Field(default_factory=DefenseContext)
    safety_context: SafetyContext = Field(default_factory=SafetyContext)


# ---------------------------------------------------------------------------
# Attack Action
# ---------------------------------------------------------------------------


class AttackAction(BaseModel):
    """
    A structured, validated attack request.

    Attack actions are abstract descriptions of what should happen to the
    plant. They are never raw PLC writes. An action compiler maps them into
    concrete tag-level operations, which then pass through the safety shield
    before any write reaches the PLC.
    """

    action_id: str = Field(default_factory=lambda: str(uuid4()))
    attack_type: AttackType
    target: str = Field(
        ...,
        description="Target tag name from the scene's writable attack surface",
    )
    mode: str = Field(
        "override",
        description="Attack mode: 'override', 'offset', 'replay', 'freeze', etc.",
    )
    value: Optional[float] = Field(
        None,
        description="The injected value (absolute or relative depending on mode)",
    )
    duration_ms: int = Field(
        5000,
        ge=0,
        description="How long the attack should remain active, in milliseconds",
    )
    start_condition: Optional[str] = Field(
        None,
        description="Optional logical condition that must be true before execution",
    )
    rationale: str = Field("", description="Attacker's reasoning for this action")
    expected_effect: str = Field("", description="Expected physical or control-loop impact")
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    source: AttackSource = AttackSource.SCRIPTED
    # Set by the shield and executor
    approved_by_shield: Optional[bool] = None
    execution_status: ExecutionStatus = ExecutionStatus.PENDING


# ---------------------------------------------------------------------------
# Shield Decision
# ---------------------------------------------------------------------------


class ShieldDecision(BaseModel):
    """
    The safety shield's verdict on a proposed attack action.

    Every AttackAction must obtain a ShieldDecision before execution.
    Rejected actions are logged but never sent to the PLC.
    """

    action_id: str
    approved: bool
    reasons: List[str] = Field(default_factory=list)
    violated_rules: List[str] = Field(default_factory=list)
    normalized_value: Optional[float] = Field(
        None,
        description="Value after range normalization (if applicable)",
    )
    expiration_time: Optional[datetime] = Field(
        None,
        description="When this approval expires (deadman timer)",
    )
    rollback_plan: Optional[Dict[str, Any]] = Field(
        None,
        description="Tag-value map to restore pre-attack state on rollback",
    )


# ---------------------------------------------------------------------------
# Detection Event
# ---------------------------------------------------------------------------


class DetectionEvent(BaseModel):
    """
    An anomaly detection event raised by a defender.

    Multiple detectors can emit events for the same plant state.
    Events are timestamped and labelled for metric computation.
    """

    timestamp: datetime = Field(default_factory=_utcnow)
    run_id: str
    detector_name: str
    severity: DetectionSeverity = DetectionSeverity.LOW
    label: str = Field("anomaly", description="Short classifier label")
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    explanation: str = Field("", description="Human-readable explanation of the detection")
    affected_tags: List[str] = Field(default_factory=list)
    step_id: Optional[int] = None


# ---------------------------------------------------------------------------
# Hard Case Record
# ---------------------------------------------------------------------------


class HardCaseRecord(BaseModel):
    """
    A record of an attack that was missed or weakly detected.

    Hard cases are stored in the HardCaseBank and used to drive
    closed-loop adaptation of defenders.
    """

    record_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    attack_id: str
    detector_outcome: str = Field(
        ...,
        description="What the detector(s) reported for this attack",
    )
    failure_mode: HardCaseFailureMode
    trace_path: str = Field(..., description="Relative path to the run trace folder")
    summary: str = Field("", description="Short narrative of why this is a hard case")
    recommended_followup: str = Field(
        "",
        description="Suggested next step for adaptation",
    )
    created_at: datetime = Field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Eval Metrics
# ---------------------------------------------------------------------------


class EvalMetrics(BaseModel):
    """
    All primary evaluation metrics for a single CPSForge run.

    These metrics are collected only during explicitly labelled eval runs
    on the real PLC + Factory I/O setup. They must not be fabricated or
    estimated from simulation.
    """

    run_id: str
    scene_name: str
    attacker_name: str
    detector_names: List[str] = Field(default_factory=list)
    # Attack-level rates
    action_validity_rate: float = Field(0.0, ge=0.0, le=1.0)
    execution_success_rate: float = Field(0.0, ge=0.0, le=1.0)
    attack_success_rate: float = Field(0.0, ge=0.0, le=1.0)
    process_impact_score: float = Field(0.0, ge=0.0)
    # Shield performance
    shield_approval_rate: float = Field(0.0, ge=0.0, le=1.0)
    shield_rejection_rate: float = Field(0.0, ge=0.0, le=1.0)
    unsafe_block_rate: float = Field(0.0, ge=0.0, le=1.0)
    # Detector performance
    detector_precision: float = Field(0.0, ge=0.0, le=1.0)
    detector_recall: float = Field(0.0, ge=0.0, le=1.0)
    detector_f1: float = Field(0.0, ge=0.0, le=1.0)
    detection_latency_ms: float = Field(0.0, ge=0.0)
    false_positives: int = Field(0, ge=0)
    false_negatives: int = Field(0, ge=0)
    # Adaptation
    hard_case_flag: bool = False
    adaptation_round: int = Field(0, ge=0)
    # Stealth and campaign metrics (Option A)
    stealth_score: float = Field(
        0.0, ge=0.0, le=1.0,
        description="Fraction of attack steps that were not detected (1.0 = fully stealthy)",
    )
    mean_deviation: float = Field(
        0.0, ge=0.0,
        description="Mean absolute process deviation during attack steps",
    )
    campaign_phases: int = Field(
        0, ge=0, description="Number of campaign phases executed (0 = non-campaign run)"
    )
    # Run metadata
    total_steps: int = Field(0, ge=0)
    total_attacks: int = Field(0, ge=0)
    eval_run: bool = Field(
        True,
        description="Must be True for metrics to be considered official paper results",
    )
    created_at: datetime = Field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Shield Safety Rule
# ---------------------------------------------------------------------------


class SafetyRule(BaseModel):
    """
    A single configurable safety rule enforced by the shield.

    Rules are loaded from scene configs and evaluated against every
    proposed attack action.
    """

    rule_id: str
    description: str
    rule_type: str = Field(
        ...,
        description=(
            "Rule type: 'range', 'duration', 'cooldown', 'mutual_exclusion', "
            "'mode_gate', 'invariant', 'interlock'"
        ),
    )
    tags: List[str] = Field(default_factory=list, description="Tags this rule applies to")
    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Rule-specific parameters (min, max, period_ms, forbidden_pairs, etc.)",
    )
    enabled: bool = True
    priority: int = Field(0, description="Higher = evaluated first")


# ---------------------------------------------------------------------------
# Scene Profile
# ---------------------------------------------------------------------------


class SceneProfile(BaseModel):
    """
    Complete description of a Factory I/O scene for CPSForge.

    A scene profile is loaded from a YAML config file and drives the
    tag map, safety rules, and attack surface for an entire experiment.
    """

    scene_name: str
    description: str = ""
    scene_id: Optional[int] = Field(
        None,
        description=(
            "OB_Main CASE selector value (1-21). "
            "CPSForge writes this to DB_Config.ActiveScene (DB1,INT0) before each run "
            "so the correct Factory I/O FB executes on the real PLC."
        ),
    )
    tags: List[TagDefinition] = Field(default_factory=list)
    writable_tags: List[str] = Field(
        default_factory=list,
        description="Tag names that attackers are permitted to write",
    )
    safety_rules: List[SafetyRule] = Field(default_factory=list)
    reset_procedure: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Ordered list of tag writes to reset the scene to safe state",
    )
    sampling_interval_ms: int = Field(500, ge=10, description="Polling interval in ms")
    attack_surface: List[str] = Field(
        default_factory=list,
        description="Tag names exposed as valid attack targets (subset of writable_tags)",
    )

    def get_tag(self, name: str) -> Optional[TagDefinition]:
        """Return the TagDefinition for a given tag name, or None."""
        for tag in self.tags:
            if tag.name == name:
                return tag
        return None

    def get_writable_tag_definitions(self) -> List[TagDefinition]:
        """Return only TagDefinitions whose names are in the writable_tags list."""
        ws = set(self.writable_tags)
        return [t for t in self.tags if t.name in ws]


# ---------------------------------------------------------------------------
# Agent Eval Metrics
# ---------------------------------------------------------------------------


class AgentEvalMetrics(BaseModel):
    """
    Evaluation metrics for an agent-mode experiment run.

    Extends the standard EvalMetrics with agent-specific telemetry:
    attacker/defender cycle counts, LLM call latencies, corrective
    action statistics, and adversarial adaptation scores.
    """

    run_id: str
    scene_name: str
    mode: str = Field("agent", description="Always 'agent' for agent-mode runs")
    # Agent cycle counts
    total_steps: int = Field(0, ge=0, description="Coordinator polling steps")
    attacker_cycles: int = Field(0, ge=0, description="Attacker observe-reason-act cycles completed")
    defender_cycles: int = Field(0, ge=0, description="Defender observe-reason-act cycles completed")
    # Attack pipeline
    attacks_submitted: int = Field(0, ge=0)
    attacks_approved: int = Field(0, ge=0)
    attacks_rejected: int = Field(0, ge=0)
    attacks_executed: int = Field(0, ge=0)
    attack_approval_rate: float = Field(0.0, ge=0.0, le=1.0)
    # Defender pipeline
    detections_emitted: int = Field(0, ge=0)
    correctives_submitted: int = Field(0, ge=0)
    correctives_approved: int = Field(0, ge=0)
    correctives_rejected: int = Field(0, ge=0)
    correctives_executed: int = Field(0, ge=0)
    corrective_success_rate: float = Field(0.0, ge=0.0, le=1.0)
    # Error counts
    attacker_errors: int = Field(0, ge=0)
    defender_errors: int = Field(0, ge=0)
    # Timing
    total_duration_s: float = Field(0.0, ge=0.0)
    # Flags
    eval_run: bool = False
    dry_run: bool = True
    created_at: datetime = Field(default_factory=_utcnow)
