"""
CPSForge CLI -- Report Commands
================================
``cpsforge report summarize``   -- aggregate metrics across an experiment
``cpsforge report metrics``     -- display metrics for one or all runs
``cpsforge report cross-attacker``  -- Table 1: attacker comparison
``cpsforge report cross-detector``  -- Table 3: detector comparison
``cpsforge report shield-analysis`` -- Table 2: shield effectiveness
``cpsforge report adaptation``      -- Table 4: round-over-round
``cpsforge report attack-types``    -- breakdown by attack type
``cpsforge report cross-model``     -- compare LLM models side-by-side
``cpsforge report export-all``      -- generate all paper-ready artifacts
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Experiment metrics, paper-ready tables, and reporting.\n\nGenerate publication-quality CSV/JSON artifacts from eval runs.")
console = Console()


@app.command("summarize")
def summarize_experiment(
    experiment: str = typer.Option(..., "--experiment", "-e", help="Experiment name"),
    data_dir: Path = typer.Option(Path("data"), "--data-dir"),
) -> None:
    """
    Aggregate metrics across all runs in an experiment and write summary files.

    Reads ``data/raw/<experiment>/<run_id>/metrics.json`` for each run,
    computes aggregates, and writes to ``data/processed/<experiment>/``.
    """
    import pandas as pd
    from cpsforge.core.models import EvalMetrics
    from cpsforge.logging.artifacts import write_experiment_summary

    raw_dir = data_dir / "raw" / experiment
    if not raw_dir.exists():
        console.print(f"[red]Experiment directory not found:[/red] {raw_dir}")
        raise typer.Exit(code=1)

    run_ids = [d.name for d in raw_dir.iterdir() if d.is_dir()]
    if not run_ids:
        console.print(f"[yellow]No runs found under {raw_dir}[/yellow]")
        raise typer.Exit(code=0)

    all_metrics: list[EvalMetrics] = []
    for run_id in run_ids:
        mpath = raw_dir / run_id / "metrics.json"
        if mpath.exists():
            with mpath.open() as fh:
                data = json.load(fh)
            all_metrics.append(EvalMetrics(**data))

    write_experiment_summary(
        experiment_name=experiment,
        run_ids=run_ids,
        all_metrics=all_metrics,
        base_dir=data_dir / "raw",
    )
    console.print(
        f"[bold green]Summary written for '{experiment}' "
        f"({len(run_ids)} runs, {len(all_metrics)} with metrics).[/bold green]"
    )


@app.command("metrics")
def show_metrics(
    experiment: str = typer.Option(..., "--experiment", "-e"),
    run_id: Optional[str] = typer.Option(None, "--run-id", "-r"),
    data_dir: Path = typer.Option(Path("data"), "--data-dir"),
) -> None:
    """
    Display metrics for a specific run or all runs in an experiment.
    """
    from cpsforge.core.models import EvalMetrics

    raw_dir = data_dir / "raw" / experiment
    if not raw_dir.exists():
        console.print(f"[red]Not found:[/red] {raw_dir}")
        raise typer.Exit(code=1)

    if run_id:
        run_dirs = [raw_dir / run_id]
    else:
        run_dirs = sorted(d for d in raw_dir.iterdir() if d.is_dir())

    table = Table(title=f"Metrics -- {experiment}", show_lines=True)
    cols = [
        ("run_id", "cyan"),
        ("eval_run", "yellow"),
        ("attacker_name", ""),
        ("attack_success_rate", ""),
        ("detector_f1", ""),
        ("detector_precision", ""),
        ("detector_recall", ""),
        ("detection_latency_ms", ""),
        ("shield_rejection_rate", ""),
        ("hard_case_flag", ""),
    ]
    for col, style in cols:
        table.add_column(col, style=style)

    for rd in run_dirs:
        mpath = rd / "metrics.json"
        if not mpath.exists():
            continue
        with mpath.open() as fh:
            data = json.load(fh)
        m = EvalMetrics(**data)
        table.add_row(
            m.run_id[:20],
            str(m.eval_run),
            m.attacker_name,
            f"{m.attack_success_rate:.3f}",
            f"{m.detector_f1:.3f}",
            f"{m.detector_precision:.3f}",
            f"{m.detector_recall:.3f}",
            f"{m.detection_latency_ms:.1f}",
            f"{m.shield_rejection_rate:.3f}",
            str(m.hard_case_flag),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Paper-ready analysis commands
# ---------------------------------------------------------------------------


@app.command("cross-attacker")
def cross_attacker(
    experiment: str = typer.Option(..., "--experiment", "-e"),
    data_dir: Path = typer.Option(Path("data"), "--data-dir"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="CSV output path"),
    eval_only: bool = typer.Option(True, "--eval-only/--all-runs"),
) -> None:
    """Table 1: Compare attack metrics across attacker types."""
    from cpsforge.analysis.tables import cross_attacker_table

    df = cross_attacker_table(data_dir, experiment, eval_only=eval_only)
    if df.empty:
        console.print("[yellow]No data for cross-attacker table.[/yellow]")
        raise typer.Exit(code=0)

    if output:
        df.to_csv(output)
        console.print(f"[green]Written to {output}[/green]")
    else:
        _print_df(df, title=f"Table 1: Attacker Comparison -- {experiment}")


@app.command("cross-detector")
def cross_detector(
    experiment: str = typer.Option(..., "--experiment", "-e"),
    data_dir: Path = typer.Option(Path("data"), "--data-dir"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    eval_only: bool = typer.Option(True, "--eval-only/--all-runs"),
) -> None:
    """Table 3: Compare detector metrics per detector."""
    from cpsforge.analysis.tables import cross_detector_table

    df = cross_detector_table(data_dir, experiment, eval_only=eval_only)
    if df.empty:
        console.print("[yellow]No data for cross-detector table.[/yellow]")
        raise typer.Exit(code=0)

    if output:
        df.to_csv(output)
        console.print(f"[green]Written to {output}[/green]")
    else:
        _print_df(df, title=f"Table 3: Detector Comparison -- {experiment}")


@app.command("shield-analysis")
def shield_analysis(
    experiment: str = typer.Option(..., "--experiment", "-e"),
    data_dir: Path = typer.Option(Path("data"), "--data-dir"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    eval_only: bool = typer.Option(True, "--eval-only/--all-runs"),
) -> None:
    """Table 2: Shield effectiveness analysis."""
    from cpsforge.analysis.tables import shield_analysis_table

    df = shield_analysis_table(data_dir, experiment, eval_only=eval_only)
    if df.empty:
        console.print("[yellow]No data for shield analysis.[/yellow]")
        raise typer.Exit(code=0)

    # Also show rule breakdown if available
    rule_counts = df.attrs.get("rule_rejection_counts", {})

    if output:
        df.to_csv(output)
        if rule_counts:
            import json as _json
            rc_path = output.parent / f"{output.stem}_by_rule{output.suffix}"
            with rc_path.open("w") as fh:
                _json.dump(rule_counts, fh, indent=2)
            console.print(f"[green]Written to {output} + {rc_path}[/green]")
        else:
            console.print(f"[green]Written to {output}[/green]")
    else:
        _print_df(df, title=f"Table 2: Shield Analysis -- {experiment}")
        if rule_counts:
            console.print("\n[bold]Rule rejection breakdown:[/bold]")
            for rule, cnt in sorted(rule_counts.items(), key=lambda x: -x[1]):
                console.print(f"  {rule}: {cnt}")


@app.command("adaptation")
def adaptation(
    experiment: str = typer.Option(..., "--experiment", "-e"),
    data_dir: Path = typer.Option(Path("data"), "--data-dir"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    """Table 4: Adaptation round-over-round performance."""
    from cpsforge.analysis.tables import adaptation_round_table

    df = adaptation_round_table(data_dir, experiment)
    if df.empty:
        console.print("[yellow]No adaptation data found.[/yellow]")
        raise typer.Exit(code=0)

    if output:
        df.to_csv(output)
        console.print(f"[green]Written to {output}[/green]")
    else:
        _print_df(df, title=f"Table 4: Adaptation Rounds -- {experiment}")


@app.command("attack-types")
def attack_types(
    experiment: str = typer.Option(..., "--experiment", "-e"),
    data_dir: Path = typer.Option(Path("data"), "--data-dir"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    eval_only: bool = typer.Option(True, "--eval-only/--all-runs"),
) -> None:
    """Supplemental: Attack success by attack type."""
    from cpsforge.analysis.tables import attack_type_breakdown

    df = attack_type_breakdown(data_dir, experiment, eval_only=eval_only)
    if df.empty:
        console.print("[yellow]No attack type data found.[/yellow]")
        raise typer.Exit(code=0)

    if output:
        df.to_csv(output)
        console.print(f"[green]Written to {output}[/green]")
    else:
        _print_df(df, title=f"Attack Type Breakdown -- {experiment}")


@app.command("cross-model")
def cross_model(
    experiment: str = typer.Option(..., "--experiment", "-e"),
    data_dir: Path = typer.Option(Path("data"), "--data-dir"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="CSV output path"),
    eval_only: bool = typer.Option(True, "--eval-only/--all-runs"),
) -> None:
    """Compare LLM attack performance across different models.

    Groups runs by llm_model from metadata.json and shows per-model
    attack success, validity, impact, detector F1, and LLM latency.
    """
    from cpsforge.analysis.tables import cross_model_table

    df = cross_model_table(data_dir, experiment, eval_only=eval_only)
    if df.empty:
        console.print("[yellow]No model comparison data found. Runs must use LLM attacker with model metadata.[/yellow]")
        raise typer.Exit(code=0)

    if output:
        df.to_csv(output)
        console.print(f"[green]Written to {output}[/green]")
    else:
        _print_df(df, title=f"Cross-Model Comparison -- {experiment}")


@app.command("export-all")
def export_all(
    experiment: str = typer.Option(..., "--experiment", "-e"),
    data_dir: Path = typer.Option(Path("data"), "--data-dir"),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir"),
    eval_only: bool = typer.Option(True, "--eval-only/--all-runs"),
) -> None:
    """Generate all paper-ready artifacts in one shot."""
    from cpsforge.analysis.tables import full_paper_export

    out = full_paper_export(data_dir, experiment, output_dir=output_dir, eval_only=eval_only)
    console.print(f"[bold green]All paper artifacts exported to {out}[/bold green]")


@app.command("compare-detectors")
def compare_detectors(
    run_dir: Path = typer.Option(..., "--run-dir", "-r", help="Path to run directory with trace.parquet"),
    detectors: str = typer.Option(
        ..., "--detectors", "-d",
        help="Comma-separated detector config names (e.g. threshold_level_control,cusum_level_control)"
    ),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output CSV path"),
) -> None:
    """
    Compare multiple detectors on the same saved trace.

    Replays a saved experiment run through each detector and produces a
    side-by-side comparison of precision, recall, F1, and latency.
    """
    import pandas as pd
    from cpsforge.analysis.detector_comparison import DetectorComparison

    detector_names = [d.strip() for d in detectors.split(",") if d.strip()]
    if not detector_names:
        console.print("[red]No detectors specified.[/red]")
        raise typer.Exit(code=1)

    if not run_dir.exists():
        console.print(f"[red]Run directory not found:[/red] {run_dir}")
        raise typer.Exit(code=1)

    comp = DetectorComparison(run_dir, detector_names)
    results = comp.run()

    if not results:
        console.print("[yellow]No results produced.[/yellow]")
        raise typer.Exit(code=0)

    df = comp.to_dataframe()

    # Display as Rich table
    table = Table(title="Detector Comparison", show_lines=True)
    for col in df.columns:
        table.add_column(str(col))
    for _, row in df.iterrows():
        vals = []
        for v in row.values:
            if isinstance(v, float):
                vals.append(f"{v:.4f}")
            else:
                vals.append(str(v))
        table.add_row(*vals)
    console.print(table)

    if output:
        comp.save_results(output)
        console.print(f"[bold green]Results saved to {output}[/bold green]")


@app.command("compare-detectors-experiment")
def compare_detectors_experiment(
    experiment: str = typer.Option(..., "--experiment", "-e"),
    detectors: str = typer.Option(
        ..., "--detectors", "-d",
        help="Comma-separated detector config names"
    ),
    data_dir: Path = typer.Option(Path("data"), "--data-dir"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    """
    Compare detectors across all runs in an experiment.

    Produces per-detector aggregated metrics (mean +/- std) across runs.
    """
    from cpsforge.analysis.detector_comparison import (
        aggregate_comparison,
        compare_detectors_across_runs,
    )

    detector_names = [d.strip() for d in detectors.split(",") if d.strip()]
    exp_dir = data_dir / "raw" / experiment

    if not exp_dir.exists():
        console.print(f"[red]Experiment directory not found:[/red] {exp_dir}")
        raise typer.Exit(code=1)

    df = compare_detectors_across_runs(exp_dir, detector_names)
    if df.empty:
        console.print("[yellow]No results produced.[/yellow]")
        raise typer.Exit(code=0)

    agg = aggregate_comparison(df)

    # Display
    table = Table(title=f"Detector Comparison — {experiment} (aggregated)", show_lines=True)
    for col in agg.columns:
        table.add_column(str(col))
    for _, row in agg.iterrows():
        vals = []
        for v in row.values:
            if isinstance(v, float):
                vals.append(f"{v:.4f}")
            else:
                vals.append(str(v))
        table.add_row(*vals)
    console.print(table)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        agg.to_csv(output, index=False)
        console.print(f"[bold green]Aggregated results saved to {output}[/bold green]")


# ---------------------------------------------------------------------------
# Helper: render dataframe as Rich table
# ---------------------------------------------------------------------------


def _print_df(df, title: str = "") -> None:
    """Render a pandas DataFrame as a Rich table."""
    table = Table(title=title, show_lines=True)
    table.add_column(df.index.name or "index", style="cyan")
    for col in df.columns:
        table.add_column(str(col))

    for idx, row in df.iterrows():
        vals = [str(idx)]
        for v in row.values:
            if isinstance(v, float):
                vals.append(f"{v:.4f}")
            else:
                vals.append(str(v))
        table.add_row(*vals)

    console.print(table)
