"""
CPSForge Configuration System
==============================
Loads, validates, and provides typed access to all CPSForge YAML configs.

Config hierarchy:
  configs/system/plc.yaml        -> PLCConfig
  configs/system/logging.yaml    -> LoggingConfig
  configs/scenes/<name>.yaml     -> SceneProfile (core/models.py)
  configs/attacks/<name>.yaml    -> AttackPolicyConfig
  configs/defenders/<name>.yaml  -> DefenderConfig
  configs/experiments/<name>.yaml -> ExperimentConfig
  configs/llm/<provider>.yaml    -> LLMConfig

All live-write and eval-run flags must be explicitly set to True in config;
the default is always safe (dry-run, no live writes).
"""

from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from pydantic import BaseModel, Field, field_validator
from dotenv import load_dotenv

# Load .env on first import of this module
load_dotenv()

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).parent.parent.parent  # cpsforge/ -> CPSForge/
_CONFIGS_DIR = _REPO_ROOT / "configs"


def _config_path(subdir: str, filename: str) -> Path:
    return _CONFIGS_DIR / subdir / filename


def _load_yaml(path: Path) -> Dict[str, Any]:
    """Load a YAML file and return its contents as a dict."""
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return data or {}


# ---------------------------------------------------------------------------
# PLC Config
# ---------------------------------------------------------------------------


class PLCConfig(BaseModel):
    """Connection parameters for the real Siemens S7 PLC."""

    host: str = Field(
        "192.168.0.1",
        description="IP address of the Siemens PLC. Must be reachable from this host.",
    )
    rack: int = Field(0, description="PLC rack number (default 0 for most S7-300/400/1200/1500)")
    slot: int = Field(1, description="PLC slot number (1 for S7-300/400, 0 for S7-1200/1500)")
    port: int = Field(102, description="ISO-on-TCP port (default 102)")
    connect_timeout_s: float = Field(5.0, description="Seconds before connection attempt times out")
    poll_interval_ms: int = Field(
        500, ge=10, description="Default tag polling interval in milliseconds"
    )
    reconnect_attempts: int = Field(3, ge=0, description="Number of reconnect attempts before giving up")
    reconnect_delay_s: float = Field(2.0, description="Delay between reconnect attempts")
    live_writes_enabled: bool = Field(
        False,
        description=(
            "SAFETY FLAG: must be explicitly True to issue real PLC writes. "
            "Overridden by CPSFORGE_LIVE_WRITES env var."
        ),
    )

    @field_validator("live_writes_enabled", mode="before")
    @classmethod
    def apply_env_override(cls, v: bool) -> bool:
        """Environment variable CPSFORGE_LIVE_WRITES overrides config file value."""
        env = os.environ.get("CPSFORGE_LIVE_WRITES", "").strip().lower()
        if env in ("1", "true", "yes"):
            return True
        if env in ("0", "false", "no"):
            return False
        return v


# ---------------------------------------------------------------------------
# Logging Config
# ---------------------------------------------------------------------------


class LoggingConfig(BaseModel):
    """Parameters for CPSForge structured logging and trace storage."""

    log_level: str = Field("INFO", description="Python logging level: DEBUG/INFO/WARNING/ERROR")
    log_dir: Path = Field(Path("data/raw"), description="Root directory for run artifacts")
    console_rich: bool = Field(True, description="Use Rich for coloured console output")
    log_prompts: bool = Field(
        False,
        description="Log raw LLM prompt/response pairs (may contain sensitive info)",
    )
    redact_keys: List[str] = Field(
        default_factory=lambda: ["api_key", "password", "token"],
        description="Keys to redact from logged JSON structures",
    )

    @field_validator("log_dir", mode="before")
    @classmethod
    def apply_env_log_dir(cls, v: Any) -> Path:
        env = os.environ.get("CPSFORGE_LOG_DIR")
        return Path(env) if env else Path(v)


# ---------------------------------------------------------------------------
# Attack Policy Config
# ---------------------------------------------------------------------------


class AttackPolicyConfig(BaseModel):
    """Configuration for a single attacker instance."""

    name: str
    attacker_type: str = Field(
        ...,
        description="One of: 'scripted', 'random', 'llm'",
    )
    scene_name: str
    max_actions: int = Field(10, ge=1, description="Maximum attacks per run")
    inter_attack_delay_ms: int = Field(
        2000, ge=0, description="Minimum gap between consecutive attacks"
    )
    attack_types: List[str] = Field(
        default_factory=lambda: ["actuator_override", "sensor_spoof", "setpoint_shift"],
        description="Whitelisted attack types for this policy",
    )
    # Scripted attacker specific
    script_file: Optional[str] = Field(None, description="Path to scripted attack JSON")
    # Random attacker specific
    random_seed: Optional[int] = Field(None, description="Seed for reproducible random runs")
    value_noise_std: float = Field(0.05, description="Std dev for random value perturbation")
    # LLM attacker specific
    llm_provider: str = Field("local_openai_compatible", description="LLM provider name")
    llm_model: Optional[str] = None
    llm_max_retries: int = Field(3, ge=1)
    multi_step: bool = Field(False, description="Enable multi-step attack chain reasoning")
    # Extra freeform parameters (e.g. attacker_objective, prompt_notes for LLM attacker)
    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Freeform key-value parameters passed to the attacker. "
            "LLM attacker uses 'attacker_objective' and 'prompt_notes'."
        ),
    )


# ---------------------------------------------------------------------------
# Defender Config
# ---------------------------------------------------------------------------


class DefenderConfig(BaseModel):
    """Configuration for a single detector instance."""

    name: str
    detector_type: str = Field(
        ...,
        description="One of: 'threshold', 'invariant', 'sequence_model', 'llm_explainer'",
    )
    scene_name: str
    enabled: bool = True
    # Threshold detector -- list of threshold rule dicts (tag, operator, value, severity...)
    thresholds: List[Dict[str, Any]] = Field(default_factory=list)
    # Invariant detector
    invariant_rules: List[Dict[str, Any]] = Field(default_factory=list)
    # Sequence model detector / ML detectors
    model_path: Optional[str] = None
    window_size: int = Field(20, ge=1)
    anomaly_threshold: float = Field(0.5, ge=0.0, le=1.0)
    # LLM explainer
    llm_provider: Optional[str] = None
    # Freeform parameters for extensible detectors (CUSUM, OCSVM, IForest, LSTM-AD, etc.)
    parameters: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Experiment Config
# ---------------------------------------------------------------------------


class ExperimentConfig(BaseModel):
    """
    Top-level configuration for a CPSForge experiment run.

    The 'eval_run' flag must be True for metrics to count as official
    paper results. 'live_writes_enabled' must be True for actual PLC
    writes; otherwise everything runs in dry-run mode.
    """

    name: str
    description: str = ""
    mode: str = Field("batch", description="Execution mode: 'batch' or 'agent'")
    scene_config: str = Field(..., description="Relative path to scene YAML under configs/scenes/")
    plc_config: str = Field("system/plc.yaml", description="Relative path to PLC config YAML")
    attackers: List[str] = Field(
        default_factory=list,
        description="List of attack policy config filenames under configs/attacks/",
    )
    defenders: List[str] = Field(
        default_factory=list,
        description="List of defender config filenames under configs/defenders/",
    )
    attacker_agent: Optional[str] = Field(
        None,
        description="Agent config filename under configs/agents/ for attacker role.",
    )
    defender_agent: Optional[str] = Field(
        None,
        description="Agent config filename under configs/agents/ for defender role.",
    )
    # Safety flags
    eval_run: bool = Field(
        False,
        description=(
            "Set to True to label this as an official eval run. "
            "Metrics from non-eval runs are not reported as paper results."
        ),
    )
    live_writes_enabled: bool = Field(
        False,
        description="Must be True for live PLC writes; False = dry-run mode",
    )
    dry_run: bool = Field(
        True,
        description="Explicit dry-run flag (overridden to False only when live_writes_enabled=True)",
    )
    # Run control
    max_steps: int = Field(1000, ge=1, description="Maximum polling steps per run")
    run_duration_s: Optional[float] = Field(None, description="Wall-clock run limit in seconds")
    adaptation_round: int = Field(0, ge=0, description="Which defender adaptation round this is")
    # Output
    output_dir: Optional[str] = None
    save_trace: bool = Field(True, description="Persist trace.parquet after run")
    save_metrics: bool = Field(True, description="Persist metrics.json after run")
    # Phase 2: write reset_procedure tags back to PLC after a live run
    reset_after_run: bool = Field(
        False,
        description=(
            "If True and live_writes_enabled=True, reset all writable tags to "
            "their reset_procedure values when the run finishes."
        ),
    )

    @field_validator("dry_run", mode="before")
    @classmethod
    def derive_dry_run(cls, v: bool, info: Any) -> bool:
        # If live_writes_enabled is explicitly False, dry_run must be True
        data = info.data if hasattr(info, "data") else {}
        if not data.get("live_writes_enabled", False):
            return True
        return v


# ---------------------------------------------------------------------------
# LLM Provider Config
# ---------------------------------------------------------------------------


class LLMConfig(BaseModel):
    """Configuration for a single LLM provider."""

    provider: str = Field(
        "local_openai_compatible",
        description="Provider name: 'local_openai_compatible'",
    )
    model: str = Field("qwen2-7b-instruct", description="Model identifier")
    api_key_env: str = Field(
        "",
        description="Name of env var holding the API key (blank for local models)",
    )
    base_url: Optional[str] = Field(
        "http://127.0.0.1:1234/v1",
        description="Base URL of the OpenAI-compatible server (LM Studio default)",
    )
    max_tokens: int = Field(1024, ge=64)
    temperature: float = Field(0.2, ge=0.0, le=2.0)
    timeout_s: float = Field(30.0, description="HTTP timeout for API calls")
    log_prompts: bool = Field(
        False,
        description=(
            "Write full prompt/response text to llm_log.jsonl. "
            "Safe default is False -- prompts may contain plant state or objectives."
        ),
    )
    redact_prompts: bool = Field(
        False,
        description=(
            "When True AND log_prompts=True, replace prompt/response text "
            "with [REDACTED] in the log."
        ),
    )
    prompt_template_version: str = Field(
        "v1",
        description=(
            "Sub-folder under configs/llm/prompts/ to load prompt templates from. "
            "Increment to 'v2', 'v3' etc. when iterating on prompt design."
        ),
    )
    log_llm_responses: bool = Field(
        True,
        description="Log LLM call metadata (model, tokens, latency) even when log_prompts=False.",
    )

    @property
    def api_key(self) -> Optional[str]:
        """Retrieve API key from environment at runtime."""
        return os.environ.get(self.api_key_env)


# ---------------------------------------------------------------------------
# Agent Runtime Config
# ---------------------------------------------------------------------------


class AgentRole(str, Enum):
    """Supported live-agent roles in adversarial runtime mode."""

    ATTACKER = "attacker"
    DEFENDER = "defender"


class AgentConfig(BaseModel):
    """Configuration for a live runtime agent process."""

    name: str
    role: AgentRole
    scene_name: str
    llm_provider: str = Field("local", description="LLM provider config filename (without .yaml)")
    llm_model: Optional[str] = None
    max_history: int = Field(100, ge=1, description="Max history items retained in memory")
    write_timeout_s: float = Field(10.0, gt=0.0, description="Timeout waiting for coordinator write result")
    enabled: bool = True
    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Freeform role-specific options for prompting and runtime logic.",
    )


# ---------------------------------------------------------------------------
# Config Loader
# ---------------------------------------------------------------------------


class ConfigLoader:
    """
    Central loader for all CPSForge YAML configuration files.

    Usage::

        loader = ConfigLoader()
        plc_cfg = loader.load_plc()
        scene = loader.load_scene("tank_control")
        exp = loader.load_experiment("eval_run_01")
    """

    def __init__(self, configs_dir: Optional[Path] = None) -> None:
        self.configs_dir = configs_dir or _CONFIGS_DIR

    def _load(self, subdir: str, filename: str) -> Dict[str, Any]:
        path = self.configs_dir / subdir / filename
        # Allow .yaml or .yml
        if not path.exists() and path.suffix == ".yaml":
            alt = path.with_suffix(".yml")
            if alt.exists():
                path = alt
        return _load_yaml(path)

    def load_plc(self, filename: str = "plc.yaml") -> PLCConfig:
        """Load and validate the PLC connection config."""
        data = self._load("system", filename)
        return PLCConfig(**data)

    def load_logging(self, filename: str = "logging.yaml") -> LoggingConfig:
        """Load and validate the logging config."""
        data = self._load("system", filename)
        return LoggingConfig(**data)

    def load_scene_raw(self, scene_name: str) -> Dict[str, Any]:
        """Return raw dict for a scene config (used by scene factory)."""
        return self._load("scenes", f"{scene_name}.yaml")

    def load_attack_policy(self, name: str) -> AttackPolicyConfig:
        data = self._load("attacks", f"{name}.yaml")
        return AttackPolicyConfig(**data)

    def load_defender(self, name: str) -> DefenderConfig:
        data = self._load("defenders", f"{name}.yaml")
        return DefenderConfig(**data)

    def load_experiment(self, name: str) -> ExperimentConfig:
        data = self._load("experiments", f"{name}.yaml")
        return ExperimentConfig(**data)

    def load_llm(self, provider: str = "local") -> LLMConfig:
        data = self._load("llm", f"{provider}.yaml")
        return LLMConfig(**data)

    def load_agent(self, name: str) -> AgentConfig:
        """Load and validate a runtime agent config from configs/agents/."""
        data = self._load("agents", f"{name}.yaml")
        return AgentConfig(**data)


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------


def get_config_loader() -> ConfigLoader:
    """Return a ConfigLoader pointing at the default configs/ directory."""
    return ConfigLoader()
