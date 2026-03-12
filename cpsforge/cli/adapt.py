"""
CPSForge CLI -- Adaptation Commands
======================================
``cpsforge adapt list-hard-cases``  -- display hard cases from an experiment
``cpsforge adapt train``            -- retrain sequence detector on hard cases
``cpsforge adapt run-rounds``       -- run the full multi-round adaptation loop
``cpsforge adapt round-summary``    -- display per-round metrics for an experiment

These commands implement the closed-loop improvement loop:

1. Run attack experiments to collect traces::

    cpsforge run attack --scene tank_control --attacker scripted
    cpsforge run attack --scene tank_control --attacker random

2. Review what the defenders missed::

    cpsforge adapt list-hard-cases --experiment phase5_adaptation

3. Retrain the sequence detector on accumulated hard cases::

    cpsforge adapt train --experiment phase5_adaptation

4. Or run the full multi-round loop (attack → detect → retrain → repeat)::

    cpsforge adapt run-rounds --experiment phase5_adaptation --rounds 5

5. Compare defender performance across rounds::

    cpsforge adapt round-summary --experiment phase5_adaptation
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import click
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    help="Defender adaptation and hard case management commands.",
    no_args_is_help=True,
)
console = Console()


# ---------------------------------------------------------------------------
# list-hard-cases
# ---------------------------------------------------------------------------


@app.command("list-hard-cases")
def list_hard_cases(
    experiment: str = typer.Option(..., "--experiment", "-e", help="Experiment name"),
    data_dir: Path = typer.Option(Path("data"), "--data-dir", help="Base data directory"),
    min_count: int = typer.Option(
        0, "--min-count", help="Only show runs with at least N hard cases"
    ),
) -> None:
    """
    Display hard cases extracted from every run in an experiment.

    Reads ``hard_cases.json`` from each run directory under
    ``<data_dir>/raw/<experiment>/`` and presents a summary table.
    Use this to identify which attack patterns consistently evade detection.
    """
    from cpsforge.adaptation.hard_cases import load_hard_cases

    raw_dir = data_dir / "raw" / experiment
    if not raw_dir.exists():
        console.print(f"[red]Experiment directory not found:[/red] {raw_dir}")
        raise typer.Exit(code=1)

    run_dirs = sorted(d for d in raw_dir.iterdir() if d.is_dir())
    if not run_dirs:
        console.print(f"[yellow]No runs found under {raw_dir}[/yellow]")
        raise typer.Exit(code=0)

    table = Table(title=f"Hard Cases — {experiment}", show_lines=True)
    table.add_column("run_id", style="cyan", max_width=26)
    table.add_column("#", style="red", justify="right")
    table.add_column("failure_mode", style="yellow")
    table.add_column("outcome", style="")
    table.add_column("summary", style="dim", max_width=60)

    total_hard = 0
    reported_runs = 0

    for run_dir in run_dirs:
        records = load_hard_cases(run_dir)
        if len(records) < min_count:
            continue

        total_hard += len(records)
        reported_runs += 1

        if not records:
            table.add_row(run_dir.name[:26], "0", "-", "-", "-")
        else:
            for i, rec in enumerate(records):
                table.add_row(
                    run_dir.name[:26] if i == 0 else "",
                    str(len(records)) if i == 0 else "",
                    rec.failure_mode.value if rec.failure_mode else "-",
                    rec.detector_outcome,
                    rec.summary[:60] if rec.summary else "-",
                )

    console.print(table)
    console.print(
        f"\n[bold]Total hard cases:[/bold] {total_hard} "
        f"across {reported_runs}/{len(run_dirs)} run(s)"
    )
    if total_hard == 0:
        console.print(
            "[green]No hard cases found — detectors are performing well "
            "or no attacks were executed yet.[/green]"
        )
    else:
        console.print(
            f"\n[dim]Inspect individual runs in:[/dim] {raw_dir}\n"
            "[dim]Use 'cpsforge adapt train' to retrain once enough data is "
            "collected.[/dim]"
        )


# ---------------------------------------------------------------------------
# train
# ---------------------------------------------------------------------------


@app.command("train")
def adapt_train(
    experiment: str = typer.Option(..., "--experiment", "-e", help="Experiment name"),
    scene: str = typer.Option("tank_control", "--scene", "-s", help="Scene name"),
    data_dir: Path = typer.Option(Path("data"), "--data-dir", help="Base data directory"),
    round_idx: int = typer.Option(0, "--round", help="Round number label for the saved model"),
    baseline_experiment: Optional[str] = typer.Option(
        None,
        "--baseline",
        help="Name of a baseline (no-attack) experiment to use as normal-data source",
    ),
    window_size: int = typer.Option(20, "--window-size", help="Feature window size in steps"),
    min_hard_cases: int = typer.Option(
        5, "--min-hard-cases", help="Minimum hard cases required before training"
    ),
    anomaly_threshold: float = typer.Option(
        0.60, "--threshold", help="Anomaly score threshold to write into the defender config"
    ),
    dry_run_train: bool = typer.Option(
        False, "--dry-run/--no-dry-run", help="Report readiness without actually training"
    ),
) -> None:
    """
    Retrain the sequence-model defender on accumulated hard cases.

    Loads hard cases from every run in ``<data_dir>/raw/<experiment>/``,
    extracts feature windows from the trace files, and trains an
    IsolationForest.  The trained model is saved under::

        <data_dir>/models/<experiment>/round_<N>/sequence_model.pkl

    The defender config is updated to point to the new model path so the
    next experiment run automatically uses the retrained detector.

    Workflow::

        # Collect data
        cpsforge run attack --scene tank_control --attacker scripted
        cpsforge run attack --scene tank_control --attacker random

        # Review hard cases
        cpsforge adapt list-hard-cases -e phase5_adaptation

        # Retrain
        cpsforge adapt train -e phase5_adaptation --round 1
    """
    from cpsforge.adaptation.bank import HardCaseBank
    from cpsforge.adaptation.trainer import SequenceDetectorTrainer

    raw_dir = data_dir / "raw" / experiment
    if not raw_dir.exists():
        console.print(f"[red]Experiment directory not found:[/red] {raw_dir}")
        raise typer.Exit(code=1)

    # -- Load hard cases --------------------------------------------------
    bank = HardCaseBank(experiment_dir=raw_dir, window_size=window_size)
    n_loaded = bank.load_from_experiment(failure_modes=["miss", "late_detection"])
    summary = bank.summary()

    console.print(f"\n[bold]Adaptation readiness — experiment:[/bold] {experiment}")
    console.print(f"  Scene              : {scene}")
    console.print(f"  Hard cases loaded  : [bold red]{n_loaded}[/bold red]")
    console.print(f"  Failure mode split : {summary['failure_mode_counts']}")
    console.print(f"  Loaded runs        : {summary['loaded_runs']}")

    if n_loaded < min_hard_cases:
        console.print(
            f"\n[yellow]Only {n_loaded} hard case(s) "
            f"(minimum {min_hard_cases} recommended).[/yellow]"
        )
        try:
            if not typer.confirm("Train anyway?", default=False):
                raise typer.Exit(code=0)
        except (click.exceptions.Abort, EOFError, KeyboardInterrupt):
            console.print("[dim]Non-interactive — skipping training.[/dim]")
            raise typer.Exit(code=0)

    if dry_run_train:
        console.print("\n[dim]--dry-run set — skipping actual training.[/dim]")
        raise typer.Exit(code=0)

    # -- Extract windows --------------------------------------------------
    console.print("\nExtracting attack windows from traces…")
    hard_tuples = bank.get_attack_windows(
        window_before=window_size // 4,
        window_after=window_size,
    )
    hard_windows = [t[0] for t in hard_tuples]
    console.print(f"  Extracted [cyan]{len(hard_windows)}[/cyan] hard-case window(s).")

    console.print("Extracting normal windows…")
    baseline_run_dirs = []
    if baseline_experiment:
        bl_dir = data_dir / "raw" / baseline_experiment
        if bl_dir.exists():
            baseline_run_dirs = sorted(d for d in bl_dir.iterdir() if d.is_dir())
    if not baseline_run_dirs:
        # Use non-attack steps from current experiment
        baseline_run_dirs = sorted(d for d in raw_dir.iterdir() if d.is_dir())

    normal_windows = bank.get_normal_windows(
        baseline_run_dirs=baseline_run_dirs,
        num_windows=500,
        window_size=window_size,
    )
    console.print(f"  Extracted [cyan]{len(normal_windows)}[/cyan] normal window(s).")

    if len(normal_windows) < 2:
        console.print(
            "[red]Not enough normal windows to train (need ≥ 2). "
            "Run a baseline experiment first:[/red]\n"
            f"  cpsforge run baseline --scene {scene}"
        )
        raise typer.Exit(code=1)

    # -- Train ------------------------------------------------------------
    console.print("\nTraining IsolationForest…")
    trainer = SequenceDetectorTrainer(random_state=42)
    meta = trainer.fit(normal_windows, hard_windows)

    console.print(
        f"  contamination = [cyan]{meta['contamination']:.4f}[/cyan]  |  "
        f"n_estimators = {meta['n_estimators']}  |  "
        f"features = {meta['feature_dim']}"
    )

    # -- Evaluate on a held-out split -------------------------------------
    if len(normal_windows) >= 4 and len(hard_windows) >= 2:
        mid_n = len(normal_windows) // 2
        mid_h = max(1, len(hard_windows) // 2)
        eval_result = trainer.evaluate(
            normal_windows[mid_n:],
            hard_windows[mid_h:],
            threshold=anomaly_threshold,
        )
        console.print(
            f"  Eval (held-out) — precision={eval_result['precision']:.3f}  "
            f"recall={eval_result['recall']:.3f}  f1={eval_result['f1']:.3f}  "
            f"(n={eval_result['n_evaluated']})"
        )

    # -- Save model -------------------------------------------------------
    model_path = (
        data_dir / "models" / experiment / f"round_{round_idx}" / "sequence_model.pkl"
    )
    trainer.save(model_path)
    console.print(f"\n[bold green]Model saved to:[/bold green] {model_path}")

    # -- Patch defender config --------------------------------------------
    _patch_sequence_defender_config(scene, str(model_path), anomaly_threshold)

    console.print(
        "\n[bold green]Training complete.[/bold green] "
        "Run the next experiment to evaluate the retrained detector:\n"
        f"  cpsforge run attack --scene {scene} "
        f"--experiment {experiment} --eval-run"
    )


# ---------------------------------------------------------------------------
# run-rounds
# ---------------------------------------------------------------------------


@app.command("run-rounds")
def run_rounds(
    experiment: str = typer.Option(..., "--experiment", "-e", help="Experiment name"),
    rounds: int = typer.Option(3, "--rounds", "-r", help="Total number of rounds"),
    data_dir: Path = typer.Option(Path("data"), "--data-dir", help="Base data directory"),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run"),
    min_hard_cases: int = typer.Option(
        10, "--min-hard-cases", help="Hard cases required to trigger retraining"
    ),
    window_size: int = typer.Option(20, "--window-size", help="Feature window size"),
    baseline_experiment: Optional[str] = typer.Option(
        None, "--baseline", help="Baseline experiment for normal windows"
    ),
) -> None:
    """
    Run the full multi-round adaptation loop.

    Each round: attack → detect → extract hard cases → (retrain if ready) → next round.

    After all rounds, round_metrics.csv and round_summary.json are written to::

        <data_dir>/processed/<experiment>/

    Example::

        cpsforge adapt run-rounds --experiment phase5_adaptation --rounds 5
        cpsforge adapt round-summary --experiment phase5_adaptation
    """
    from cpsforge.adaptation.adaptation_loop import AdaptationLoop
    from cpsforge.adaptation.round_metrics import print_round_table
    from cpsforge.core.config import ConfigLoader, ExperimentConfig
    from cpsforge.logging.logger import setup_logging

    setup_logging()
    loader = ConfigLoader()

    # Load experiment config
    try:
        base_cfg = loader.load_experiment(experiment)
    except FileNotFoundError:
        console.print(
            f"[yellow]Experiment config '{experiment}' not found — "
            "using phase5_adaptation as template.[/yellow]"
        )
        try:
            base_cfg = loader.load_experiment("phase5_adaptation")
            base_cfg.name = experiment
        except FileNotFoundError:
            base_cfg = ExperimentConfig(
                name=experiment,
                scene_config="scenes/tank_control.yaml",
                attackers=["scripted_tank_control", "random_tank_control"],
                defenders=[
                    "threshold_tank_control",
                    "invariant_tank_control",
                    "sequence_model_tank_control",
                ],
                dry_run=dry_run,
                live_writes_enabled=not dry_run,
                max_steps=400,
            )

    base_cfg.dry_run = dry_run
    base_cfg.live_writes_enabled = not dry_run

    if not dry_run:
        confirm = typer.confirm(
            "[!] dry_run=False — live PLC writes will be issued. Continue?"
        )
        if not confirm:
            raise typer.Abort()

    console.print(
        f"\n[bold]Starting adaptation loop:[/bold] {rounds} round(s) "
        f"— experiment: {experiment}\n"
    )

    loop = AdaptationLoop(
        base_config=base_cfg,
        loader=loader,
        n_rounds=rounds,
        experiment_name=experiment,
        data_dir=data_dir,
        min_hard_cases_to_retrain=min_hard_cases,
        window_size=window_size,
        baseline_experiment=baseline_experiment,
    )
    results = loop.run()

    # Print comparison table
    from cpsforge.adaptation.round_metrics import RoundSummary

    summaries = [
        RoundSummary.from_eval_metrics(
            round_idx=r.round_idx,
            run_id=r.run_id,
            metrics=r.metrics,
            hard_case_count=r.hard_case_count,
            hard_case_cumulative=r.hard_case_cumulative,
            retrained=r.retrained,
            model_path=str(r.model_path) if r.model_path else None,
            experiment_name=experiment,
        )
        for r in results
    ]
    print_round_table(summaries)

    processed_dir = data_dir / "processed" / experiment
    console.print(
        f"\n[bold green]Adaptation loop complete.[/bold green]\n"
        f"  round_metrics.csv  → {processed_dir / 'round_metrics.csv'}\n"
        f"  round_summary.json → {processed_dir / 'round_summary.json'}\n"
        f"  hard_case_bank.json → {processed_dir / 'hard_case_bank.json'}"
    )


# ---------------------------------------------------------------------------
# round-summary
# ---------------------------------------------------------------------------


@app.command("round-summary")
def round_summary(
    experiment: str = typer.Option(..., "--experiment", "-e", help="Experiment name"),
    data_dir: Path = typer.Option(Path("data"), "--data-dir", help="Base data directory"),
) -> None:
    """
    Display round-by-round adaptation metrics from a previous run-rounds call.

    Reads ``round_metrics.csv`` from::

        <data_dir>/processed/<experiment>/round_metrics.csv
    """
    processed_dir = data_dir / "processed" / experiment
    csv_path = processed_dir / "round_metrics.csv"
    json_path = processed_dir / "round_summary.json"

    if not csv_path.exists():
        console.print(
            f"[red]round_metrics.csv not found:[/red] {csv_path}\n"
            "Run the adaptation loop first:\n"
            f"  cpsforge adapt run-rounds --experiment {experiment}"
        )
        raise typer.Exit(code=1)

    import csv
    import json

    # Print per-round table
    with csv_path.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    table = Table(title=f"Round Metrics — {experiment}", show_lines=True)
    for col in ["round_idx", "retrained", "detector_f1", "detector_precision",
                "detector_recall", "detection_latency_ms", "attack_success_rate",
                "hard_case_count", "hard_case_cumulative"]:
        table.add_column(col, style="cyan" if col == "round_idx" else "")

    for row in rows:
        retrained_display = "[green]✓[/green]" if row.get("retrained", "").lower() in ("true", "1", "yes") else "–"
        table.add_row(
            row.get("round_idx", "?"),
            retrained_display,
            row.get("detector_f1", "?"),
            row.get("detector_precision", "?"),
            row.get("detector_recall", "?"),
            row.get("detection_latency_ms", "?"),
            row.get("attack_success_rate", "?"),
            row.get("hard_case_count", "?"),
            row.get("hard_case_cumulative", "?"),
        )
    console.print(table)

    # Print summary stats
    if json_path.exists():
        with json_path.open() as fh:
            summary = json.load(fh)
        console.print(f"\n[bold]F1 improvement:[/bold] {summary.get('f1_improvement', 'n/a')}")
        console.print(f"[bold]ASR change:[/bold]     {summary.get('asr_change', 'n/a')}")
        console.print(f"[bold]Rounds retrained:[/bold] {summary.get('rounds_with_retraining', 0)}")
        console.print(
            f"[bold]Final hard case bank:[/bold] "
            f"{summary.get('total_hard_cases_final', 0)} records"
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _patch_sequence_defender_config(
    scene: str, model_path: str, anomaly_threshold: float
) -> None:
    """Update the sequence_model defender YAML with the new model path."""
    import yaml
    from cpsforge.core.config import _CONFIGS_DIR

    yaml_path = _CONFIGS_DIR / "defenders" / f"sequence_model_{scene}.yaml"
    if not yaml_path.exists():
        console.print(
            f"[yellow]Defender config not found at {yaml_path} — "
            "skipping auto-patch.[/yellow]"
        )
        return

    with yaml_path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    data["model_path"] = model_path
    data["anomaly_threshold"] = anomaly_threshold

    with yaml_path.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh, default_flow_style=False)

    console.print(f"[dim]Defender config updated: {yaml_path}[/dim]")
