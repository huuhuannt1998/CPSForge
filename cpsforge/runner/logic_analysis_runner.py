"""
logic_analysis_runner.py — Offline LLM logic analysis experiment runner.

This runner orchestrates Sub-testbed B: LLM-based PLC logic vulnerability
analysis and adversarial code generation. It does NOT interact with the PLC.

Workflow per run:
  1. Load SCL source for a scene
  2. LogicAnalyzer finds vulnerabilities
  3. LogicAnalyzer generates adversarial modifications (7 categories)
  4. CodeReviewDefender reviews each modification
  5. Save all artifacts (VulnerabilityReport, ReviewResults)

Usage
-----
    runner = LogicAnalysisRunner(loader)
    run_id = runner.run(scene_name="level_control")
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from cpsforge.attacker.logic_analyzer import LogicAnalyzer, VulnerabilityReport
from cpsforge.core.config import ConfigLoader
from cpsforge.defenses.code_reviewer import CodeReviewDefender, ReviewResult
from cpsforge.logging.artifacts import make_run_id

logger = logging.getLogger(__name__)

# Scene descriptions for attack context
_SCENE_DESCRIPTIONS: Dict[str, str] = {
    "level_control": (
        "PID-controlled tank level system. A fill valve and drain valve regulate "
        "liquid level to match a setpoint. The PLC runs a proportional-integral "
        "controller with anti-windup. Safety: tank overflow and underflow."
    ),
    "sorting_weight": (
        "3-way weight classification sorting line. Items arrive on a conveyor, "
        "pass over a scale, and are routed to left (light), forward (medium), "
        "or right (heavy) exits based on weight thresholds. State machine with "
        "8 states controls the flow."
    ),
    "sorting_height_basic": (
        "2-way height classification sorting line. Items arrive on a conveyor, "
        "pass under a height sensor, and are routed to left (tall) or right (short) "
        "exits. 5-state machine (Feed→Load→Transfer→Clear→Finish) with a dwell "
        "timer for confirmation."
    ),
}


class LogicAnalysisRunner:
    """Orchestrates offline LLM logic analysis experiments.

    Parameters
    ----------
    loader : ConfigLoader
        For loading LLM configs.
    output_base : Path, optional
        Base output directory (default: data/raw).
    scl_dir : Path, optional
        Directory containing SCL files (default: factoryio_scenes/).
    model_variant : str
        Model config to use (default: "base").
    """

    def __init__(
        self,
        loader: ConfigLoader,
        output_base: Optional[Path] = None,
        scl_dir: Optional[Path] = None,
        model_variant: str = "base",
    ) -> None:
        self._loader = loader
        self._output_base = output_base or Path("data/raw")
        self._scl_dir = scl_dir or Path("factoryio_scenes")
        self._model_variant = model_variant

    def run(
        self,
        scene_name: str,
        attack_categories: Optional[List[str]] = None,
        run_defense: bool = True,
    ) -> str:
        """Execute a logic analysis run and return run_id.

        Parameters
        ----------
        scene_name : str
            Scene to analyze.
        attack_categories : list, optional
            Which attack categories to generate (default: all 7).
        run_defense : bool
            Whether to also run the code review defender on each modification.
        """
        run_id = make_run_id()
        run_dir = self._output_base / f"logic_analysis_{scene_name}" / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        logger.info(
            "LogicAnalysisRunner start: run_id=%s scene=%s model=%s",
            run_id, scene_name, self._model_variant,
        )

        # Build LLM provider
        llm_provider = self._build_llm_provider()
        if llm_provider is None:
            logger.error("No LLM provider — cannot run logic analysis.")
            return run_id

        # Pre-load model
        if hasattr(llm_provider, '_ensure_loaded'):
            logger.info("Pre-loading model weights...")
            try:
                llm_provider._ensure_loaded()
            except Exception as exc:
                logger.warning("Model pre-load failed: %s", exc)

        t0 = time.monotonic()

        # Step 1: Vulnerability analysis + modification generation
        analyzer = LogicAnalyzer(
            llm_provider=llm_provider,
            scl_dir=self._scl_dir,
        )
        scene_desc = _SCENE_DESCRIPTIONS.get(scene_name, f"{scene_name} process")
        report = analyzer.analyze_scene(
            scene_name=scene_name,
            scene_description=scene_desc,
            attack_categories=attack_categories,
        )

        # Save vulnerability report
        report_path = run_dir / "vulnerability_report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report.as_dict(), f, indent=2, default=str)
        logger.info("Saved vulnerability report: %d vulns, %d modifications",
                     len(report.vulnerabilities), len(report.modifications))

        # Step 2: Code review defense (if enabled)
        review_results: List[Dict[str, Any]] = []
        if run_defense and report.modifications:
            reviewer = CodeReviewDefender(
                llm_provider=llm_provider,
                rejection_threshold=0.5,
            )

            # Load original SCL for diff comparison
            scl_file = analyzer._find_scl_file(scene_name)
            original_scl = scl_file.read_text(encoding="utf-8") if scl_file else ""

            for mod in report.modifications:
                if not mod.parse_success or not mod.modified_code:
                    review_results.append({
                        "modification_type": mod.modification_type,
                        "review_skipped": True,
                        "reason": "modification generation failed",
                    })
                    continue

                result = reviewer.review(
                    original_scl=original_scl,
                    modified_scl=mod.modified_code,
                    scene_name=scene_name,
                    scene_description=scene_desc,
                    change_description=f"{mod.modification_type}: {mod.vulnerability_description}",
                )
                review_results.append({
                    "modification_type": mod.modification_type,
                    **result.as_dict(),
                })
                logger.info(
                    "Code review: type=%s decision=%s suspicion=%.2f latency=%.0f ms",
                    mod.modification_type, result.decision,
                    result.suspicion_score, result.llm_latency_ms,
                )

            # Save review results
            review_path = run_dir / "code_review_results.json"
            with open(review_path, "w", encoding="utf-8") as f:
                json.dump(review_results, f, indent=2, default=str)

        total_time = (time.monotonic() - t0) * 1000.0

        # Save run metadata
        metadata = {
            "run_id": run_id,
            "scene_name": scene_name,
            "model_variant": self._model_variant,
            "total_vulnerabilities": len(report.vulnerabilities),
            "total_modifications": len(report.modifications),
            "successful_modifications": sum(1 for m in report.modifications if m.parse_success),
            "total_reviews": len(review_results),
            "reviews_rejected": sum(1 for r in review_results if r.get("decision") == "reject"),
            "reviews_approved": sum(1 for r in review_results if r.get("decision") == "approve"),
            "total_time_ms": total_time,
        }
        meta_path = run_dir / "metadata.json"
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        logger.info(
            "LogicAnalysisRunner complete: run_id=%s vulns=%d mods=%d "
            "reviews=%d (rejected=%d) time=%.1f s",
            run_id,
            metadata["total_vulnerabilities"],
            metadata["total_modifications"],
            metadata["total_reviews"],
            metadata["reviews_rejected"],
            total_time / 1000.0,
        )
        return run_id

    def _build_llm_provider(self) -> Any:
        from cpsforge.llm.factory import build_provider
        from cpsforge.runner.online_runner import _MODEL_CFG_MAP

        cfg_name = _MODEL_CFG_MAP.get(self._model_variant, "huggingface")
        try:
            llm_cfg = self._loader.load_llm(cfg_name)
            return build_provider(llm_cfg)
        except Exception as exc:
            logger.error("LLM provider load failed (%s): %s", cfg_name, exc)
            return None
