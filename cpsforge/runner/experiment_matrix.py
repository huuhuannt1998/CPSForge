"""
experiment_matrix.py — RQ1-RQ5 experiment grid generator and executor.

This module generates and executes the full CPSForge v2 experiment matrix.

Matrix summary
--------------
RQ1 (Context Ablation):
  3 context_levels × 5 scenes × 3 repeats = 45 runs
  attacker=online_mitm, model=base (Qwen2.5-3B-Instruct), defense=none

RQ2 (Fine-Tuning):
  2 model_variants × 3 scenes × 2 contexts × 3 repeats = 36 runs
  Models: base (Qwen2.5-3B-Instruct), finetuned (Qwen2.5-3B+QLoRA)
  attacker=online_mitm, defense=none

RQ3 (Attacker Comparison):
  3 attacker_types × 5 scenes × 3 repeats = 45 runs
  model=base (Qwen2.5-3B-Instruct), context=full, defense=none

RQ4 (Defenses):
  5 defense_variants × 5 scenes × 3 repeats = 75 runs
  attacker=online_mitm, context=full, model=finetuned, defense=each

RQ5 (Cross-Model Robustness):
  3 models × 2 scenes × 2 contexts × 2 attackers × 2 defenses × 3 repeats = 72 runs
  Working models on Windows: Qwen2.5-3B, Qwen3-1.7B, SmolLM3-3B
  (Qwen3.5-4B and Phi-4-mini require Linux/WSL2 due to SSM/driver issues)

Total: ~273 runs

Usage
-----
  # Generate only (no PLC):
  python -m cpsforge.runner.experiment_matrix --dry-run --generate-only

  # Run full matrix:
  python -m cpsforge.runner.experiment_matrix --config configs/experiments/v2_matrix.yaml
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Experiment cell definition
# ---------------------------------------------------------------------------

@dataclass
class ExperimentCell:
    """One cell in the v2 experiment matrix.

    Each cell corresponds to one CPSForge run with fixed controls.
    """
    rq: str                        # "RQ1" | "RQ2" | "RQ3" | "RQ4" | "RQ5"
    cell_id: str                   # unique deterministic identifier

    # Experimental controls (independent variables)
    scene: str
    context_level: str             # "minimal" | "partial" | "full"
    attacker_type: str             # "online_mitm" | "static_llm" | "random"
    model_variant: str             # "base" | "finetuned" | "qwen3_17b" | "llama32_3b"
    defense_variant: str           # "none" | "phase_aware" | "intent" | "combined" | "baseline"
    repeat: int                    # 1-indexed repeat number

    # Fixed parameters (same across all runs)
    attack_budget: int = 10
    decision_interval_steps: int = 3
    max_steps: int = 180           # 3 minutes @ 1s/step
    run_duration_s: int = 200      # hard wall-clock cap

    # Filled at runtime
    run_id: Optional[str] = None
    status: str = "pending"        # "pending" | "running" | "done" | "failed"
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    error: Optional[str] = None

    # Derived (not in __init__, set by __post_init__)
    finetune_status: str = field(init=False)

    def __post_init__(self) -> None:
        # "finetuned" model_variant is the only QLoRA-adapted variant;
        # all others run as base (no adapter).
        self.finetune_status = "finetuned" if self.model_variant == "finetuned" else "base"

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Matrix builder
# ---------------------------------------------------------------------------

_SCENES = ["level_control", "filling_tank", "sorting_weight", "sorting_height_basic", "from_a_to_b"]
_REPEATS = 3

_RQ1_CONTEXTS   = ["minimal", "partial", "full"]
_RQ2_MODELS     = ["base", "finetuned"]
_RQ2_CONTEXTS   = ["minimal", "full"]
_RQ2_SCENES     = ["level_control", "sorting_weight", "sorting_height_basic"]
_RQ3_ATTACKERS  = ["random", "static_llm", "online_mitm"]
_RQ4_DEFENSES   = ["none", "baseline", "phase_aware", "intent", "combined", "llm_defender", "llm_combined"]
_RQ5_MODELS     = ["qwen25_3b", "qwen3_17b", "smollm3_3b"]  # Windows-compatible models only
_RQ5_SCENES     = ["level_control", "sorting_weight"]
_RQ5_CONTEXTS   = ["minimal", "full"]
_RQ5_ATTACKERS  = ["static_llm", "online_mitm"]
_RQ5_DEFENSES   = ["none"]  # defense comparison is RQ4's job; RQ5 tests model robustness only


def build_matrix(
    scenes: List[str] = _SCENES,
    repeats: int = _REPEATS,
    include_rqs: Optional[List[str]] = None,
) -> List[ExperimentCell]:
    """Generate the full experiment matrix.

    Parameters
    ----------
    scenes : list of str
        Which scenes to include.
    repeats : int
        Number of repeats per cell.
    include_rqs : list of str or None
        Filter to specific RQs (e.g. ["RQ1", "RQ3"]).  None = all.
    """
    cells: List[ExperimentCell] = []
    include = set(include_rqs) if include_rqs else {"RQ1", "RQ2", "RQ3", "RQ4", "RQ5"}

    if "RQ1" in include:
        for ctx in _RQ1_CONTEXTS:
            for scene in scenes:
                for r in range(1, repeats + 1):
                    cid = f"RQ1_{ctx}_{scene}_r{r}"
                    cells.append(ExperimentCell(
                        rq="RQ1",
                        cell_id=cid,
                        scene=scene,
                        context_level=ctx,
                        attacker_type="online_mitm",
                        model_variant="base",
                        defense_variant="none",
                        repeat=r,
                    ))

    if "RQ2" in include:
        rq2_scenes = [s for s in _RQ2_SCENES if s in scenes]
        for mv in _RQ2_MODELS:
            for ctx in _RQ2_CONTEXTS:
                for scene in rq2_scenes:
                    for r in range(1, repeats + 1):
                        cid = f"RQ2_{mv}_{ctx}_{scene}_r{r}"
                        cells.append(ExperimentCell(
                            rq="RQ2",
                            cell_id=cid,
                            scene=scene,
                            context_level=ctx,
                            attacker_type="online_mitm",
                            model_variant=mv,
                            defense_variant="none",
                            repeat=r,
                        ))

    if "RQ3" in include:
        for at in _RQ3_ATTACKERS:
            for scene in scenes:
                for r in range(1, repeats + 1):
                    cid = f"RQ3_{at}_{scene}_r{r}"
                    cells.append(ExperimentCell(
                        rq="RQ3",
                        cell_id=cid,
                        scene=scene,
                        context_level="full",
                        attacker_type=at,
                        model_variant="base",
                        defense_variant="none",
                        repeat=r,
                    ))

    if "RQ4" in include:
        # RQ4 tests both base and finetuned models against all defense
        # variants.  The model_variant controls BOTH attacker and defender
        # LLM (symmetric setup), enabling comparison of:
        #   - base attacker vs. base LLM defender
        #   - finetuned attacker vs. finetuned LLM defender
        _RQ4_MODELS = ["base", "finetuned"]
        for mv in _RQ4_MODELS:
            for dv in _RQ4_DEFENSES:
                for scene in scenes:
                    for r in range(1, repeats + 1):
                        cid = f"RQ4_{mv}_{dv}_{scene}_r{r}"
                        cells.append(ExperimentCell(
                            rq="RQ4",
                            cell_id=cid,
                            scene=scene,
                            context_level="full",
                            attacker_type="online_mitm",
                            model_variant=mv,
                            defense_variant=dv,
                            repeat=r,
                        ))

    if "RQ5" in include:
        rq5_scenes = [s for s in _RQ5_SCENES if s in scenes]
        for mv in _RQ5_MODELS:
            for ctx in _RQ5_CONTEXTS:
                for at in _RQ5_ATTACKERS:
                    for dv in _RQ5_DEFENSES:
                        for scene in rq5_scenes:
                            for r in range(1, repeats + 1):
                                cid = f"RQ5_{mv}_{ctx}_{at}_{dv}_{scene}_r{r}"
                                cells.append(ExperimentCell(
                                    rq="RQ5",
                                    cell_id=cid,
                                    scene=scene,
                                    context_level=ctx,
                                    attacker_type=at,
                                    model_variant=mv,
                                    defense_variant=dv,
                                    repeat=r,
                                ))

    # ------------------------------------------------------------------
    # FPR (False Positive Rate) — measures defense false-block rate
    # on known-legitimate writes.  Uses fpr_probe attacker that generates
    # controller-consistent writes, routed through the defense chain.
    # 2 models × 2 defenses × 3 scenes × 3 repeats = 36 cells.
    # ------------------------------------------------------------------
    _FPR_SCENES = ["level_control", "sorting_weight", "sorting_height_basic"]
    _FPR_MODELS = ["base", "finetuned"]
    _FPR_DEFENSES = ["llm_defender", "llm_combined"]

    if "FPR" in include:
        fpr_scenes = [s for s in _FPR_SCENES if s in scenes]
        for mv in _FPR_MODELS:
            for dv in _FPR_DEFENSES:
                for scene in fpr_scenes:
                    for r in range(1, repeats + 1):
                        cid = f"FPR_{mv}_{dv}_{scene}_r{r}"
                        cells.append(ExperimentCell(
                            rq="FPR",
                            cell_id=cid,
                            scene=scene,
                            context_level="full",
                            attacker_type="fpr_probe",
                            model_variant=mv,
                            defense_variant=dv,
                            repeat=r,
                            attack_budget=999,  # Unlimited probes
                        ))

    # ------------------------------------------------------------------
    # TIER2 — Deep State MitM experiments (Tier 2 threat model).
    # Tests DeepStateMITMAttacker targeting internal PLC state variables
    # (setpoints, thresholds, enable flags) that the PLC logic never
    # overwrites — a single write persists indefinitely.
    # 2 models × 5 defenses × 3 scenes × 3 repeats = 90 cells.
    # ------------------------------------------------------------------
    _T2_SCENES = ["level_control", "sorting_weight", "sorting_height_basic"]
    _T2_MODELS = ["base", "finetuned"]
    _T2_DEFENSES = ["none", "state_consistency", "state_combined", "llm_defender", "llm_combined"]
    _T2_CONTEXTS = ["partial", "full"]

    if "TIER2" in include:
        t2_scenes = [s for s in _T2_SCENES if s in scenes]
        for mv in _T2_MODELS:
            for ctx in _T2_CONTEXTS:
                for dv in _T2_DEFENSES:
                    for scene in t2_scenes:
                        for r in range(1, repeats + 1):
                            cid = f"TIER2_{mv}_{ctx}_{dv}_{scene}_r{r}"
                            cells.append(ExperimentCell(
                                rq="TIER2",
                                cell_id=cid,
                                scene=scene,
                                context_level=ctx,
                                attacker_type="deep_state_mitm",
                                model_variant=mv,
                                defense_variant=dv,
                                repeat=r,
                            ))

    # ------------------------------------------------------------------
    # FRONTIER — GPT-4o-mini (frontier model) experiments.
    # CCS Phase 1: prove findings aren't 3B-model artifacts.
    #
    # RQ1-equivalent: 3 contexts × 3 scenes × 3 repeats = 27 runs
    # RQ3-equivalent: online_mitm × 3 scenes × 3 repeats = 9 runs
    # RQ4-equivalent: 3 key defenses × 3 scenes × 3 repeats = 27 runs
    # Total: 63 runs
    # ------------------------------------------------------------------
    _FRONTIER_SCENES = ["level_control", "sorting_weight", "sorting_height_basic"]
    _FRONTIER_CONTEXTS = ["minimal", "partial", "full"]
    _FRONTIER_DEFENSES = ["none", "llm_defender", "llm_combined"]

    if "FRONTIER" in include:
        fr_scenes = [s for s in _FRONTIER_SCENES if s in scenes]

        # RQ1-equivalent: context ablation with frontier model
        for ctx in _FRONTIER_CONTEXTS:
            for scene in fr_scenes:
                for r in range(1, repeats + 1):
                    cid = f"FRONTIER_ctx_{ctx}_{scene}_r{r}"
                    cells.append(ExperimentCell(
                        rq="FRONTIER",
                        cell_id=cid,
                        scene=scene,
                        context_level=ctx,
                        attacker_type="online_mitm",
                        model_variant="gpt4o_mini",
                        defense_variant="none",
                        repeat=r,
                    ))

        # RQ4-equivalent: defense evaluation with frontier model
        for dv in _FRONTIER_DEFENSES:
            for scene in fr_scenes:
                for r in range(1, repeats + 1):
                    cid = f"FRONTIER_def_{dv}_{scene}_r{r}"
                    # Skip "none" defense — already covered by context ablation full context
                    if dv == "none":
                        continue
                    cells.append(ExperimentCell(
                        rq="FRONTIER",
                        cell_id=cid,
                        scene=scene,
                        context_level="full",
                        attacker_type="online_mitm",
                        model_variant="gpt4o_mini",
                        defense_variant=dv,
                        repeat=r,
                    ))

    logger.info("Built experiment matrix: %d cells", len(cells))
    return cells


# ---------------------------------------------------------------------------
# Matrix executor
# ---------------------------------------------------------------------------

class MatrixExecutor:
    """Execute the v2 experiment matrix cell by cell.

    Parameters
    ----------
    cells : list of ExperimentCell
    config_loader : ConfigLoader
    base_experiment_config_path : str or Path
        A baseline ExperimentConfig YAML that is overridden per-cell.
    output_base : Path
        Root for run artifacts.
    dry_run : bool
        If True, no PLC writes are executed.
    resume : bool
        If True, skip cells that already have status=="done" in checkpoint.
    checkpoint_path : str or Path
        JSON file to persist per-cell status for resume support.
    inter_run_sleep_s : float
        Seconds to wait between runs (allow PLC to settle).
    """

    def __init__(
        self,
        cells: List[ExperimentCell],
        config_loader: Any,
        base_experiment_config_path: str = "configs/experiments/v2_online.yaml",
        output_base: Path = Path("data/raw"),
        dry_run: bool = False,
        resume: bool = True,
        checkpoint_path: str = "data/processed/v2_matrix_checkpoint.json",
        inter_run_sleep_s: float = 5.0,
    ) -> None:
        self._cells = cells
        self._loader = config_loader
        self._base_cfg_path = base_experiment_config_path
        self._output_base = Path(output_base)
        self._dry_run = dry_run
        self._resume = resume
        self._ckpt_path = Path(checkpoint_path)
        self._sleep = inter_run_sleep_s

        if resume:
            self._load_checkpoint()

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run_all(self) -> List[ExperimentCell]:
        """Execute all pending cells. Returns completed cell list."""
        pending = [c for c in self._cells if c.status == "pending"]
        logger.info(
            "Matrix executor: %d cells total, %d pending",
            len(self._cells),
            len(pending),
        )
        for i, cell in enumerate(pending):
            logger.info(
                "[%d/%d] Running cell: %s", i + 1, len(pending), cell.cell_id
            )
            self._run_cell(cell)
            self._save_checkpoint()
            if i < len(pending) - 1:
                time.sleep(self._sleep)

        done = sum(1 for c in self._cells if c.status == "done")
        failed = sum(1 for c in self._cells if c.status == "failed")
        logger.info("Matrix complete: %d done, %d failed", done, failed)
        return self._cells

    # ------------------------------------------------------------------
    # Per-cell execution
    # ------------------------------------------------------------------

    def _run_cell(self, cell: ExperimentCell) -> None:
        from datetime import datetime, timezone
        cell.status = "running"
        cell.start_time = datetime.now(timezone.utc).isoformat()

        try:
            run_id = self._dispatch(cell)
            cell.run_id = run_id
            cell.status = "done"
        except Exception as exc:
            logger.error("Cell %s failed: %s", cell.cell_id, exc, exc_info=True)
            cell.status = "failed"
            cell.error = str(exc)
        finally:
            from datetime import datetime, timezone
            cell.end_time = datetime.now(timezone.utc).isoformat()

    def _dispatch(self, cell: ExperimentCell) -> str:
        """Route cell to the appropriate runner based on attacker_type."""
        experiment_name = f"v2_{cell.rq}_{cell.scene}"

        if cell.attacker_type in ("online_mitm", "static_llm", "deep_state_mitm", "fpr_probe"):
            # All LLM-based attackers (including FPR probe) go through the v2 runner
            # so they produce identical UnifiedStepLog output for fair comparison.
            return self._run_online_mitm(cell, experiment_name)
        elif cell.attacker_type in ("random", "scripted"):
            return self._run_batch(cell, experiment_name)
        else:
            raise ValueError(f"Unknown attacker_type: {cell.attacker_type!r}")

    def _run_online_mitm(self, cell: ExperimentCell, experiment_name: str) -> str:
        from cpsforge.runner.online_runner import OnlineExperimentRunner
        from cpsforge.core.config import ConfigLoader

        config = self._load_base_config(cell, experiment_name)
        extra = {
            "context_level": cell.context_level,
            "model_variant": cell.model_variant,
            "finetune_status": cell.finetune_status,
            "defense_variant": cell.defense_variant,
            "attack_budget": cell.attack_budget,
            "decision_interval_steps": cell.decision_interval_steps,
            "attacker_type": cell.attacker_type,
        }
        runner = OnlineExperimentRunner(
            config=config,
            loader=self._loader,
            output_base=self._output_base / experiment_name,
            extra=extra,
        )
        return runner.run()

    def _run_batch(self, cell: ExperimentCell, experiment_name: str) -> str:
        from cpsforge.core.orchestrator import ExperimentOrchestrator
        config = self._load_base_config(cell, experiment_name)
        orch = ExperimentOrchestrator(
            config=config,
            loader=self._loader,
            output_base=self._output_base / experiment_name,
        )
        return orch.run()

    def _load_base_config(self, cell: ExperimentCell, experiment_name: str) -> Any:
        from cpsforge.core.config import ExperimentConfig
        import copy

        # load_experiment expects just the stem name (strips path prefix + ext)
        cfg_name = Path(self._base_cfg_path).stem
        config = self._loader.load_experiment(cfg_name)

        # Override with cell parameters
        config.name = experiment_name
        config.dry_run = self._dry_run
        config.max_steps = cell.max_steps
        config.run_duration_s = cell.run_duration_s

        # Override attacker if not online_mitm (let batch orchestrator handle)
        if hasattr(config, "attacker_configs") and config.attacker_configs:
            for ac in config.attacker_configs:
                if hasattr(ac, "attacker_type"):
                    ac.attacker_type = cell.attacker_type

        # Set scene from cell
        if hasattr(config, "scene_config"):
            config.scene_config = f"configs/scenes/{cell.scene}.yaml"

        return config

    # ------------------------------------------------------------------
    # Checkpoint
    # ------------------------------------------------------------------

    def _save_checkpoint(self) -> None:
        self._ckpt_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._ckpt_path, "w") as f:
            json.dump([c.as_dict() for c in self._cells], f, indent=2)

    def _load_checkpoint(self) -> None:
        if not self._ckpt_path.exists():
            return
        try:
            with open(self._ckpt_path) as f:
                saved = json.load(f)
            by_id = {c["cell_id"]: c for c in saved}
            for cell in self._cells:
                if cell.cell_id in by_id:
                    s = by_id[cell.cell_id]
                    cell.status = s.get("status", "pending")
                    cell.run_id = s.get("run_id")
                    cell.start_time = s.get("start_time")
                    cell.end_time = s.get("end_time")
                    cell.error = s.get("error")
            logger.info("Loaded checkpoint from %s", self._ckpt_path)
        except Exception as exc:
            logger.warning("Could not load checkpoint: %s", exc)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(description="Run CPSForge v2 experiment matrix")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Disable live PLC writes (safe for testing)"
    )
    parser.add_argument(
        "--generate-only", action="store_true",
        help="Print matrix and exit without running"
    )
    parser.add_argument(
        "--rqs", nargs="+", choices=["RQ1", "RQ2", "RQ3", "RQ4", "RQ5"],
        help="Run only these research questions"
    )
    parser.add_argument(
        "--scenes", nargs="+", default=_SCENES,
        help="Scenes to include"
    )
    parser.add_argument(
        "--repeats", type=int, default=_REPEATS,
        help="Repeats per cell"
    )
    parser.add_argument(
        "--base-config",
        default="configs/experiments/v2_online.yaml",
        help="Base experiment config YAML"
    )
    parser.add_argument(
        "--output-base", default="data/raw",
        help="Root for run artifacts"
    )
    parser.add_argument(
        "--no-resume", action="store_true",
        help="Ignore checkpoint and re-run all cells"
    )
    args = parser.parse_args()

    cells = build_matrix(
        scenes=args.scenes,
        repeats=args.repeats,
        include_rqs=args.rqs,
    )

    if args.generate_only:
        for c in cells:
            print(json.dumps(c.as_dict()))
        print(f"\nTotal: {len(cells)} cells", file=sys.stderr)
        sys.exit(0)

    from cpsforge.core.config import ConfigLoader
    loader = ConfigLoader()

    executor = MatrixExecutor(
        cells=cells,
        config_loader=loader,
        base_experiment_config_path=args.base_config,
        output_base=Path(args.output_base),
        dry_run=args.dry_run,
        resume=not args.no_resume,
    )
    executor.run_all()
