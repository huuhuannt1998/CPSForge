"""
CPSForge Hard Case Bank
========================
Aggregates :class:`~cpsforge.core.models.HardCaseRecord` objects from multiple
experiment runs and provides labeled feature windows for sequence-model
defender retraining.

A *hard case* is an attack run that was either:
  - **miss**            -- completely evaded all defenders
  - **late_detection**  -- detected after the grace window (too slow to be useful)

The bank is the single source of truth for the adaptation layer. It knows
which run directories have been scanned, which records have been loaded, and
how to extract aligned time-series windows from ``trace.parquet`` files that
can be fed directly to :class:`~cpsforge.adaptation.trainer.SequenceDetectorTrainer`.

Typical usage::

    bank = HardCaseBank(experiment_dir=Path("data/raw/my_experiment"))
    n = bank.load_from_experiment()
    print(bank.summary())

    hard_windows = bank.get_attack_windows()
    normal_windows = bank.get_normal_windows(baseline_run_dirs)
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from cpsforge.core.models import HardCaseFailureMode, HardCaseRecord

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Feature column helpers
# ---------------------------------------------------------------------------


def get_feature_columns(df: pd.DataFrame) -> List[str]:
    """
    Return all sensor / actuator / setpoint / derived-feature columns from a
    trace DataFrame (the columns written by :class:`TraceRecorder`).

    Prefixes matched: ``sensor__``, ``actuator__``, ``setpoint__``,
    ``feat__``, ``ctrl__``.
    """
    prefixes = ("sensor__", "actuator__", "setpoint__", "feat__", "ctrl__")
    return [c for c in df.columns if any(c.startswith(p) for p in prefixes)]


def find_attack_start_step(df: pd.DataFrame, attack_id: str) -> Optional[int]:
    """
    Find the first ``step_id`` where a given attack action was active in the
    trace, using the ``attack_action_id`` and ``attack_active`` columns.

    Returns ``None`` when the information is unavailable.
    """
    if "attack_action_id" not in df.columns or "step_id" not in df.columns:
        return None
    mask = df["attack_action_id"].astype(str) == str(attack_id)
    matching = df[mask]
    if matching.empty:
        return None
    return int(matching["step_id"].min())


# ---------------------------------------------------------------------------
# HardCaseBank
# ---------------------------------------------------------------------------


class HardCaseBank:
    """
    Persistent, in-memory aggregation of hard cases from one or more runs.

    Parameters
    ----------
    experiment_dir:
        Root run-folder directory, e.g. ``data/raw/<experiment_name>/``.
        Each child directory is assumed to be a run folder containing
        ``hard_cases.json`` (and optionally ``trace.parquet``).
    window_size:
        Default number of time steps to include in extracted feature windows.
        Overridable per-call in :meth:`get_attack_windows` and
        :meth:`get_normal_windows`.
    """

    def __init__(
        self,
        experiment_dir: Path,
        window_size: int = 20,
    ) -> None:
        self._experiment_dir = Path(experiment_dir)
        self._window_size = window_size
        self._records: List[HardCaseRecord] = []
        self._loaded_runs: List[str] = []

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def count(self) -> int:
        """Total number of hard case records loaded."""
        return len(self._records)

    @property
    def records(self) -> List[HardCaseRecord]:
        """All loaded :class:`HardCaseRecord` objects (read-only copy)."""
        return list(self._records)

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_from_experiment(
        self,
        failure_modes: Optional[List[str]] = None,
    ) -> int:
        """
        Scan every run directory under :attr:`experiment_dir` and collect hard
        cases from ``hard_cases.json``.

        Previously scanned run IDs are skipped for efficiency — calling this
        method multiple times is safe and additive.

        Parameters
        ----------
        failure_modes:
            If set, only load records whose ``failure_mode.value`` is in this
            list.  Pass ``["miss", "late_detection"]`` to limit to true failures.

        Returns
        -------
        int
            Number of *new* records loaded in this call.
        """
        if not self._experiment_dir.exists():
            logger.warning(
                "HardCaseBank: experiment directory not found: %s",
                self._experiment_dir,
            )
            return 0

        from cpsforge.adaptation.hard_cases import load_hard_cases

        run_dirs = sorted(d for d in self._experiment_dir.iterdir() if d.is_dir())
        new_count = 0

        for run_dir in run_dirs:
            run_id = run_dir.name
            if run_id in self._loaded_runs:
                continue

            records = load_hard_cases(run_dir)
            for rec in records:
                if failure_modes is not None:
                    mode_val = rec.failure_mode.value if rec.failure_mode else ""
                    if mode_val not in failure_modes:
                        continue
                self._records.append(rec)
                new_count += 1

            # Mark as scanned even if 0 hard cases (to avoid re-scanning)
            self._loaded_runs.append(run_id)

        logger.info(
            "HardCaseBank: loaded %d new record(s) from %d scan(s) "
            "(bank total: %d).",
            new_count,
            len(run_dirs),
            self.count,
        )
        return new_count

    def load_from_run(self, run_dir: Path) -> int:
        """
        Load hard cases from a single run directory.

        Idempotent — skips if the run was already loaded.  Returns the number
        of records added.
        """
        from cpsforge.adaptation.hard_cases import load_hard_cases

        run_id = run_dir.name
        if run_id in self._loaded_runs:
            return 0

        records = load_hard_cases(run_dir)
        self._records.extend(records)
        self._loaded_runs.append(run_id)
        logger.info(
            "HardCaseBank: loaded %d record(s) from run %s.", len(records), run_id
        )
        return len(records)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def filter_by_failure_mode(
        self, modes: List[HardCaseFailureMode]
    ) -> List[HardCaseRecord]:
        """Return records whose ``failure_mode`` is in *modes*."""
        return [r for r in self._records if r.failure_mode in modes]

    # ------------------------------------------------------------------
    # Feature window extraction
    # ------------------------------------------------------------------

    def get_attack_windows(
        self,
        window_before: int = 5,
        window_after: Optional[int] = None,
    ) -> List[Tuple[np.ndarray, str, str]]:
        """
        Extract feature windows around each hard-case attack from
        ``trace.parquet``.

        For each record the corresponding run's trace is loaded and a
        sub-sequence of shape ``(window_before + window_after, n_features)``
        is extracted around the attack's start step.

        Parameters
        ----------
        window_before:
            Steps to include before the attack start step (context).
        window_after:
            Steps to include after the attack start step.
            Defaults to ``self.window_size``.

        Returns
        -------
        List of ``(feature_array, failure_mode_str, run_id)`` tuples.
        Arrays have shape ``(window_before + window_after, n_features)``.
        Windows that cannot be extracted (trace absent, step unknown) are
        silently skipped.
        """
        wa = window_after if window_after is not None else self._window_size
        windows: List[Tuple[np.ndarray, str, str]] = []

        for rec in self._records:
            trace_path = Path(rec.trace_path) / "trace.parquet"
            if not trace_path.exists():
                logger.debug(
                    "trace.parquet not found for hard case %s in %s",
                    rec.attack_id,
                    rec.trace_path,
                )
                continue

            try:
                df = pd.read_parquet(trace_path)
                feature_cols = get_feature_columns(df)
                if not feature_cols:
                    continue

                start_step = find_attack_start_step(df, rec.attack_id)
                if start_step is None:
                    # Fall back to a window near the middle of the trace
                    start_step = len(df) // 2
                    logger.debug(
                        "attack_id %s not found in trace; using step %d.",
                        rec.attack_id,
                        start_step,
                    )

                lo = max(0, start_step - window_before)
                hi = min(len(df), start_step + wa)
                window_df = df.iloc[lo:hi][feature_cols].fillna(0.0)

                if len(window_df) < 2:
                    continue

                arr = window_df.values.astype(np.float32)
                mode_str = rec.failure_mode.value if rec.failure_mode else "unknown"
                windows.append((arr, mode_str, rec.run_id))

            except Exception as exc:
                logger.warning(
                    "Could not extract window for hard case %s: %s",
                    rec.attack_id,
                    exc,
                )

        logger.info(
            "HardCaseBank: extracted %d attack window(s) from %d record(s).",
            len(windows),
            len(self._records),
        )
        return windows

    def get_normal_windows(
        self,
        baseline_run_dirs: List[Path],
        num_windows: int = 200,
        window_size: Optional[int] = None,
    ) -> List[np.ndarray]:
        """
        Extract normal operation (no-attack) feature windows from baseline
        run traces.

        Parameters
        ----------
        baseline_run_dirs:
            List of run directories containing baseline (attack-free) traces.
        num_windows:
            Maximum number of windows to extract across all baseline runs.
        window_size:
            Window length in steps.  Defaults to ``self.window_size``.

        Returns
        -------
        List of feature arrays of shape ``(window_size, n_features)``.
        """
        ws = window_size if window_size is not None else self._window_size
        normal_windows: List[np.ndarray] = []

        for run_dir in baseline_run_dirs:
            trace_path = run_dir / "trace.parquet"
            if not trace_path.exists():
                continue

            try:
                df = pd.read_parquet(trace_path)
                feature_cols = get_feature_columns(df)
                if not feature_cols:
                    continue

                # Exclude steps where any attack was active
                if "attack_active" in df.columns:
                    df = df[~df["attack_active"].fillna(False).astype(bool)]

                features = df[feature_cols].fillna(0.0).values.astype(np.float32)

                # Sliding window with 50% stride
                stride = max(1, ws // 2)
                for start in range(0, len(features) - ws, stride):
                    if len(normal_windows) >= num_windows:
                        break
                    window = features[start : start + ws]
                    if window.shape[0] == ws:
                        normal_windows.append(window)

            except Exception as exc:
                logger.warning(
                    "Could not extract normal windows from %s: %s", run_dir, exc
                )

        logger.info(
            "HardCaseBank: extracted %d normal window(s) from %d baseline run(s).",
            len(normal_windows),
            len(baseline_run_dirs),
        )
        return normal_windows

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def export_manifest(self, output_path: Path) -> None:
        """
        Write a JSON manifest of all loaded records to *output_path*.

        The manifest is a lightweight index (no trace data) useful for
        auditing and cross-experiment analysis.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        manifest: Dict[str, Any] = {
            "summary": self.summary(),
            "records": [r.model_dump(mode="json") for r in self._records],
        }
        with output_path.open("w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, default=str)
        logger.info("HardCaseBank manifest written to %s", output_path)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def summary(self) -> Dict[str, Any]:
        """Return a human-readable summary dict of the bank contents."""
        mode_counts: Counter = Counter(
            r.failure_mode.value if r.failure_mode else "unknown"
            for r in self._records
        )
        return {
            "total_hard_cases": self.count,
            "loaded_runs": len(self._loaded_runs),
            "failure_mode_counts": dict(mode_counts),
            "experiment_dir": str(self._experiment_dir),
        }
