"""
CPSForge Round Metrics
=======================
Data models and utilities for tracking defender performance across multiple
adaptation rounds in the closed-loop experiment.

Each *round* is one full attack-run with a particular detector state.
Between rounds the detector may be retrained on accumulated hard cases.

:class:`RoundSummary` captures the key metrics for a single round.
:func:`write_round_metrics` persists the per-round series as structured
artifacts so they can be used for paper tables and figures without
re-running experiments.
"""

from __future__ import annotations

import csv
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class RoundSummary(BaseModel):
    """
    Compact performance record for one adaptation round.

    Populated by :class:`~cpsforge.adaptation.adaptation_loop.AdaptationLoop`
    after each round's orchestrator run completes.
    """

    round_idx: int = Field(..., description="0-based round index.")
    run_id: str = Field(..., description="Run ID produced by the orchestrator.")
    experiment_name: str = Field("", description="Parent experiment name.")
    attacker_name: str = Field("", description="Comma-joined attacker config names.")
    retrained: bool = Field(
        False,
        description="Whether the sequence detector was retrained before this round.",
    )
    model_path: Optional[str] = Field(
        None,
        description="Path to the model used in this round (None = untrained).",
    )

    # -- Detector metrics --------------------------------------------------
    detector_f1: float = Field(0.0, ge=0.0, le=1.0)
    detector_precision: float = Field(0.0, ge=0.0, le=1.0)
    detector_recall: float = Field(0.0, ge=0.0, le=1.0)
    detection_latency_ms: float = Field(0.0, ge=0.0)
    false_positives: int = Field(0, ge=0)
    false_negatives: int = Field(0, ge=0)

    # -- Attack / shield metrics ------------------------------------------
    attack_success_rate: float = Field(0.0, ge=0.0, le=1.0)
    shield_rejection_rate: float = Field(0.0, ge=0.0, le=1.0)
    hard_case_count: int = Field(0, ge=0)
    hard_case_cumulative: int = Field(
        0, ge=0, description="Total hard cases in the bank after this round."
    )

    # -- Run control -------------------------------------------------------
    total_steps: int = Field(0, ge=0)
    total_attacks: int = Field(0, ge=0)
    eval_run: bool = Field(False)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # ------------------------------------------------------------------
    # Factories
    # ------------------------------------------------------------------

    @classmethod
    def from_eval_metrics(
        cls,
        round_idx: int,
        run_id: str,
        metrics: Any,  # EvalMetrics
        hard_case_count: int,
        hard_case_cumulative: int,
        retrained: bool = False,
        model_path: Optional[str] = None,
        experiment_name: str = "",
    ) -> "RoundSummary":
        """
        Construct a :class:`RoundSummary` from an
        :class:`~cpsforge.core.models.EvalMetrics` instance.
        """
        att = ", ".join(metrics.detector_names) if hasattr(metrics, "detector_names") else ""
        return cls(
            round_idx=round_idx,
            run_id=run_id,
            experiment_name=experiment_name or (metrics.scene_name if metrics else ""),
            attacker_name=metrics.attacker_name if metrics else "",
            retrained=retrained,
            model_path=model_path,
            detector_f1=metrics.detector_f1 if metrics else 0.0,
            detector_precision=metrics.detector_precision if metrics else 0.0,
            detector_recall=metrics.detector_recall if metrics else 0.0,
            detection_latency_ms=metrics.detection_latency_ms if metrics else 0.0,
            false_positives=metrics.false_positives if (metrics and metrics.false_positives is not None) else 0,
            false_negatives=metrics.false_negatives if (metrics and metrics.false_negatives is not None) else 0,
            attack_success_rate=metrics.attack_success_rate if metrics else 0.0,
            shield_rejection_rate=metrics.shield_rejection_rate if metrics else 0.0,
            hard_case_count=hard_case_count,
            hard_case_cumulative=hard_case_cumulative,
            total_steps=metrics.total_steps if metrics else 0,
            total_attacks=metrics.total_attacks if metrics else 0,
            eval_run=metrics.eval_run if metrics else False,
        )


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------


_CSV_COLUMNS = [
    "round_idx",
    "run_id",
    "retrained",
    "eval_run",
    "detector_f1",
    "detector_precision",
    "detector_recall",
    "detection_latency_ms",
    "false_positives",
    "false_negatives",
    "attack_success_rate",
    "shield_rejection_rate",
    "hard_case_count",
    "hard_case_cumulative",
    "total_steps",
    "total_attacks",
    "model_path",
    "attacker_name",
]


def write_round_metrics(
    summaries: List[RoundSummary],
    output_dir: Path,
    experiment_name: str = "",
) -> None:
    """
    Write per-round metrics to ``<output_dir>/round_metrics.csv`` and
    ``<output_dir>/round_summary.json``.

    Parameters
    ----------
    summaries:
        Ordered list of :class:`RoundSummary` objects, one per round.
    output_dir:
        Directory to write into (created if absent).
    experiment_name:
        Written into the summary JSON header.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # -- CSV: one row per round, easy to load in pandas / Excel ------------
    csv_path = output_dir / "round_metrics.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for s in summaries:
            writer.writerow(s.model_dump(mode="json"))
    logger.info("Round metrics written to %s", csv_path)

    # -- JSON summary: aggregates + per-round list -------------------------
    json_path = output_dir / "round_summary.json"

    # Compute improvement from round 0 → last round
    f1_values = [s.detector_f1 for s in summaries]
    asr_values = [s.attack_success_rate for s in summaries]
    hc_values = [s.hard_case_count for s in summaries]

    def _delta(values: List[float]) -> Optional[float]:
        if len(values) >= 2:
            return round(values[-1] - values[0], 4)
        return None

    summary: Dict[str, Any] = {
        "experiment": experiment_name,
        "n_rounds": len(summaries),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "f1_improvement": _delta(f1_values),
        "asr_change": _delta(asr_values),
        "total_hard_cases_final": summaries[-1].hard_case_cumulative if summaries else 0,
        "rounds_with_retraining": sum(1 for s in summaries if s.retrained),
        "rounds": [s.model_dump(mode="json") for s in summaries],
    }

    with json_path.open("w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, default=str)
    logger.info("Round summary written to %s", json_path)


def print_round_table(summaries: List[RoundSummary]) -> None:
    """
    Print a Rich comparison table of per-round metrics to stdout.

    Requires ``rich``.  Falls back to plain text if Rich is unavailable.
    """
    try:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        table = Table(title="Adaptation Round Comparison", show_lines=True)

        table.add_column("Round", justify="right", style="cyan")
        table.add_column("Run ID", style="dim", max_width=22)
        table.add_column("Retrained", justify="center")
        table.add_column("F1", justify="right", style="green")
        table.add_column("Prec", justify="right")
        table.add_column("Recall", justify="right")
        table.add_column("Lat (ms)", justify="right")
        table.add_column("ASR", justify="right")
        table.add_column("HC this run", justify="right", style="yellow")
        table.add_column("HC total", justify="right", style="yellow")

        for s in summaries:
            table.add_row(
                str(s.round_idx),
                s.run_id[:22],
                "✓" if s.retrained else "–",
                f"{s.detector_f1:.3f}",
                f"{s.detector_precision:.3f}",
                f"{s.detector_recall:.3f}",
                f"{s.detection_latency_ms:.0f}",
                f"{s.attack_success_rate:.3f}",
                str(s.hard_case_count),
                str(s.hard_case_cumulative),
            )

        console.print(table)

        if len(summaries) >= 2:
            delta = summaries[-1].detector_f1 - summaries[0].detector_f1
            sign = "+" if delta >= 0 else ""
            console.print(
                f"\n[bold]F1 change across {len(summaries)} round(s): "
                f"[{'green' if delta >= 0 else 'red'}]{sign}{delta:.3f}[/][/bold]"
            )

    except ImportError:
        # Plain-text fallback
        print(f"{'Round':>5}  {'F1':>6}  {'Prec':>6}  {'Recall':>6}  "
              f"{'Lat(ms)':>8}  {'HC':>4}  {'Retrained'}")
        for s in summaries:
            print(
                f"{s.round_idx:>5}  {s.detector_f1:>6.3f}  "
                f"{s.detector_precision:>6.3f}  {s.detector_recall:>6.3f}  "
                f"{s.detection_latency_ms:>8.0f}  {s.hard_case_count:>4}  "
                f"{'yes' if s.retrained else 'no'}"
            )
