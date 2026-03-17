"""
CPSForge CLI -- Run Commands
==============================
``cpsforge run baseline``     -- run polling without attacks (establish baseline)
``cpsforge run attack``       -- run attack experiment (scripted or random)
``cpsforge run agent``        -- run live attacker/defender independent agents
``cpsforge run closed-loop``  -- run full red-team/blue-team loop
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

app = typer.Typer(help="Execute CPSForge experiments against the real PLC.\n\nAll commands default to --dry-run (no live PLC writes).")
console = Console()
logger = logging.getLogger(__name__)


_utcnow = lambda: datetime.now(timezone.utc)  # noqa: E731


def _resolve_experiment(
    experiment: Optional[str],
    scene: Optional[str],
) -> str:
    """Return experiment config name, falling back to a default for the scene."""
    if experiment:
        return experiment
    if scene:
        return f"{scene}_baseline"
    return "phase1_baseline"


@app.command("baseline")
def run_baseline(
    scene: str = typer.Option("tank_control", "--scene", "-s"),
    experiment: Optional[str] = typer.Option(None, "--experiment", "-e"),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run"),
    max_steps: int = typer.Option(100, "--max-steps"),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir"),
) -> None:
    """
    Run a polling-only baseline (no attacks) to collect a normal-operation trace.

    Use this to establish baseline data before adversarial experiments.
    """
    from cpsforge.core.config import ConfigLoader
    from cpsforge.core.orchestrator import ExperimentOrchestrator
    from cpsforge.logging.logger import setup_logging

    setup_logging()
    loader = ConfigLoader()

    exp_cfg_name = _resolve_experiment(experiment, scene)
    try:
        exp_cfg = loader.load_experiment(exp_cfg_name)
    except FileNotFoundError:
        # Build a minimal in-memory config
        from cpsforge.core.config import ExperimentConfig
        exp_cfg = ExperimentConfig(
            name=f"{scene}_baseline",
            scene_config=f"scenes/{scene}.yaml",
            attackers=[],
            defenders=[],
            dry_run=dry_run,
            live_writes_enabled=False,
            max_steps=max_steps,
        )

    exp_cfg.dry_run = dry_run
    if not dry_run:
        console.print("[bold yellow]WARNING: dry_run=False -- live writes may be issued.[/bold yellow]")

    orchestrator = ExperimentOrchestrator(exp_cfg, loader, output_base=output_dir)
    run_id = orchestrator.run()
    console.print(f"\n[bold green]Baseline run complete. Run ID: {run_id}[/bold green]")


@app.command("attack")
def run_attack(
    scene: str = typer.Option("tank_control", "--scene", "-s"),
    attacker: str = typer.Option(
        "scripted", "--attacker", "-a",
        help="Attacker type: scripted | random | llm"
    ),
    experiment: Optional[str] = typer.Option(None, "--experiment", "-e"),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run"),
    max_steps: int = typer.Option(200, "--max-steps"),
    eval_run: bool = typer.Option(False, "--eval-run/--no-eval-run"),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip live-write confirmation prompt"),
) -> None:
    """
    Run an adversarial attack experiment.

    Attackers: scripted (deterministic), random, or llm.
    Use --eval-run to label this as an official paper-result run.
    """
    from cpsforge.core.config import ConfigLoader, ExperimentConfig
    from cpsforge.core.orchestrator import ExperimentOrchestrator
    from cpsforge.logging.logger import setup_logging

    setup_logging()
    loader = ConfigLoader()

    exp_cfg_name = experiment or f"{attacker}_{scene}"
    try:
        exp_cfg = loader.load_experiment(exp_cfg_name)
    except FileNotFoundError:
        attacker_cfg_name = f"{attacker}_{scene}"
        exp_cfg = ExperimentConfig(
            name=f"{attacker}_{scene}_attack",
            scene_config=f"scenes/{scene}.yaml",
            attackers=[attacker_cfg_name],
            defenders=[f"threshold_{scene}", f"invariant_{scene}"],
            dry_run=dry_run,
            live_writes_enabled=not dry_run,
            eval_run=eval_run,
            max_steps=max_steps,
        )

    exp_cfg.dry_run = dry_run
    exp_cfg.eval_run = eval_run

    if not dry_run and not yes:
        confirm = typer.confirm(
            "[!] live_writes_enabled=True. This will issue REAL PLC writes. Continue?"
        )
        if not confirm:
            raise typer.Abort()

    orchestrator = ExperimentOrchestrator(exp_cfg, loader, output_base=output_dir)
    run_id = orchestrator.run()
    console.print(f"\n[bold green]Attack run complete. Run ID: {run_id}[/bold green]")
    if eval_run:
        console.print("[bold cyan]Eval run metrics saved.[/bold cyan]")


@app.command("agent")
def run_agent(
    scene: str = typer.Option("level_control", "--scene", "-s"),
    experiment: Optional[str] = typer.Option(None, "--experiment", "-e"),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run"),
    max_steps: int = typer.Option(200, "--max-steps"),
    eval_run: bool = typer.Option(False, "--eval-run/--no-eval-run"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip live-write confirmation prompt"),
) -> None:
    """Run live independent attacker/defender agents with coordinator mediation."""
    from cpsforge.agents.runtime import AgentRuntime
    from cpsforge.core.config import ConfigLoader, ExperimentConfig
    from cpsforge.logging.logger import setup_logging

    setup_logging()
    loader = ConfigLoader()

    exp_cfg_name = experiment or f"agent_{scene}"
    try:
        exp_cfg = loader.load_experiment(exp_cfg_name)
    except FileNotFoundError:
        exp_cfg = ExperimentConfig(
            name=exp_cfg_name,
            mode="agent",
            scene_config=f"scenes/{scene}.yaml",
            defenders=[f"threshold_{scene}", f"invariant_{scene}"],
            attacker_agent="attacker_agent",
            defender_agent="defender_agent",
            dry_run=dry_run,
            live_writes_enabled=not dry_run,
            eval_run=eval_run,
            max_steps=max_steps,
        )

    exp_cfg.mode = "agent"
    exp_cfg.dry_run = dry_run
    exp_cfg.live_writes_enabled = not dry_run
    exp_cfg.eval_run = eval_run
    exp_cfg.max_steps = max_steps

    if not dry_run and not yes:
        confirm = typer.confirm("[!] live agent mode will issue REAL PLC writes. Continue?")
        if not confirm:
            raise typer.Abort()

    attacker_cfg_name = exp_cfg.attacker_agent or "attacker_agent"
    defender_cfg_name = exp_cfg.defender_agent or "defender_agent"
    attacker_cfg = loader.load_agent(attacker_cfg_name)
    defender_cfg = loader.load_agent(defender_cfg_name)
    attacker_cfg.scene_name = scene
    defender_cfg.scene_name = scene

    run_id = f"agent-{scene}-{_utcnow().strftime('%Y%m%d-%H%M%S')}"
    runtime = AgentRuntime(
        run_id=run_id,
        loader=loader,
        exp_config=exp_cfg,
        attacker_cfg=attacker_cfg,
        defender_cfg=defender_cfg,
    )
    result = runtime.run()

    console.print(
        f"\n[bold green]Agent run complete. Run ID: {result.run_id}[/bold green]\n"
        f"Snapshots: {len(result.snapshots)}\n"
        f"Events: {len(result.events)}\n"
        f"Write requests processed: {result.processed_requests}"
    )


@app.command("closed-loop")
def run_closed_loop(
    scene: str = typer.Option("tank_control", "--scene", "-s"),
    rounds: int = typer.Option(3, "--rounds", "-r", help="Number of adaptation rounds"),
    experiment: Optional[str] = typer.Option(None, "--experiment", "-e"),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run"),
    max_steps: int = typer.Option(400, "--max-steps", help="Max steps per round"),
    min_hard_cases: int = typer.Option(
        10, "--min-hard-cases",
        help="Hard cases required before retraining the sequence detector"
    ),
    window_size: int = typer.Option(20, "--window-size", help="Feature window size in steps"),
    baseline_experiment: Optional[str] = typer.Option(
        None, "--baseline",
        help="Name of a baseline (no-attack) experiment for normal training windows"
    ),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir"),
) -> None:
    """
    Run the full closed-loop red-team / blue-team experiment across multiple rounds.

    Each round:
      1. Run a full attack experiment with the current defender state.
      2. Extract hard cases from the run.
      3. Add them to the HardCaseBank.
      4. If enough hard cases (--min-hard-cases) have accumulated, retrain
         the sequence-model detector.
      5. Proceed to the next round.

    After all rounds, writes::

        data/processed/<experiment>/round_metrics.csv
        data/processed/<experiment>/round_summary.json
        data/processed/<experiment>/hard_case_bank.json

    Compare performance across rounds::

        cpsforge adapt round-summary --experiment <experiment>
    """
    from cpsforge.adaptation.adaptation_loop import AdaptationLoop
    from cpsforge.adaptation.round_metrics import RoundSummary, print_round_table
    from cpsforge.core.config import ConfigLoader, ExperimentConfig
    from cpsforge.logging.logger import setup_logging

    setup_logging()
    loader = ConfigLoader()
    data_dir = output_dir or Path("data")

    exp_name = experiment or f"closed_loop_{scene}"

    # Load or build experiment config
    try:
        base_cfg = loader.load_experiment(exp_name)
    except FileNotFoundError:
        try:
            base_cfg = loader.load_experiment("phase5_adaptation")
            base_cfg.name = exp_name
        except FileNotFoundError:
            base_cfg = ExperimentConfig(
                name=exp_name,
                scene_config=f"scenes/{scene}.yaml",
                attackers=[f"scripted_{scene}", f"random_{scene}"],
                defenders=[
                    f"threshold_{scene}",
                    f"invariant_{scene}",
                    f"sequence_model_{scene}",
                ],
                dry_run=dry_run,
                live_writes_enabled=not dry_run,
                max_steps=max_steps,
            )

    base_cfg.dry_run = dry_run
    base_cfg.live_writes_enabled = not dry_run
    base_cfg.max_steps = max_steps

    if not dry_run:
        confirm = typer.confirm(
            "[!] dry_run=False — live PLC writes will be issued. Continue?"
        )
        if not confirm:
            raise typer.Abort()

    console.print(
        f"\n[bold]Starting closed-loop experiment:[/bold] {rounds} round(s) "
        f"— scene: {scene}, experiment: {exp_name}\n"
    )

    loop = AdaptationLoop(
        base_config=base_cfg,
        loader=loader,
        n_rounds=rounds,
        experiment_name=exp_name,
        data_dir=data_dir,
        min_hard_cases_to_retrain=min_hard_cases,
        window_size=window_size,
        baseline_experiment=baseline_experiment,
    )
    results = loop.run()

    # Round comparison table
    summaries = [
        RoundSummary.from_eval_metrics(
            round_idx=r.round_idx,
            run_id=r.run_id,
            metrics=r.metrics,
            hard_case_count=r.hard_case_count,
            hard_case_cumulative=r.hard_case_cumulative,
            retrained=r.retrained,
            model_path=str(r.model_path) if r.model_path else None,
            experiment_name=exp_name,
        )
        for r in results
    ]
    print_round_table(summaries)

    processed_dir = data_dir / "processed" / exp_name
    console.print(
        f"\n[bold green]Closed-loop experiment complete.[/bold green]\n"
        f"  Artifacts: {processed_dir}\n"
        f"  Review:    cpsforge adapt round-summary --experiment {exp_name}"
    )


@app.command("detect-replay")
def detect_replay(
    run_id: str = typer.Option(..., "--run-id", "-r", help="Run ID folder to replay"),
    experiment: str = typer.Option(..., "--experiment", "-e", help="Experiment name"),
    scene: str = typer.Option(
        "tank_control", "--scene", "-s",
        help="Scene name (used to select defender configs when experiment config is absent)",
    ),
    data_dir: Path = typer.Option(Path("data"), "--data-dir"),
) -> None:
    """
    Replay a saved trace through the defender stack without re-running the PLC.

    Loads ``trace.parquet`` from a completed run, reconstructs all
    :class:`PlantSnapshot` objects, runs each configured defender in sequence,
    and writes ``replay_detections.json`` back into the same run folder.

    Use this command to:
      - Evaluate a new or retrained detector against a historical attack trace.
      - Check whether a detector that missed an attack would catch it after retraining.
      - Iterate on defender configurations without touching the PLC.
    """
    from cpsforge.core.config import ConfigLoader
    from cpsforge.core.models import DetectionEvent
    from cpsforge.defenders.factory import build_defender
    from cpsforge.logging.artifacts import RunArtifactWriter, load_trace_snapshots
    from cpsforge.logging.logger import setup_logging

    setup_logging()
    loader = ConfigLoader()

    run_dir = data_dir / "raw" / experiment / run_id
    trace_path = run_dir / "trace.parquet"
    if not trace_path.exists():
        console.print(f"[red]Trace file not found:[/red] {trace_path}")
        raise typer.Exit(code=1)

    console.print(f"\n[bold]Replaying trace:[/bold] {trace_path}")
    snapshots = load_trace_snapshots(trace_path, run_id=run_id)
    console.print(f"  Loaded [cyan]{len(snapshots)}[/cyan] snapshots.")

    # ------------ Resolve defender names -----------------------------------
    try:
        exp_cfg = loader.load_experiment(experiment)
        defender_names = exp_cfg.defenders
    except FileNotFoundError:
        defender_names = [f"threshold_{scene}", f"invariant_{scene}"]

    defenders = []
    for name in defender_names:
        try:
            cfg = loader.load_defender(name)
            defenders.append(build_defender(cfg))
            console.print(f"  Loaded defender: [green]{name}[/green]")
        except FileNotFoundError:
            console.print(f"  [yellow]Defender config not found: {name} -- skipped.[/yellow]")

    if not defenders:
        console.print("[red]No defenders loaded. Cannot replay.[/red]")
        raise typer.Exit(code=1)

    # ------------ Run replay -----------------------------------------------
    all_detections: list[DetectionEvent] = []
    for snap in snapshots:
        for defender in defenders:
            events = defender.detect(snap)
            for ev in events:
                ev.run_id = run_id
                all_detections.append(ev)

    # ------------ Write results --------------------------------------------
    writer = RunArtifactWriter(run_dir)
    writer._write_json(
        "replay_detections.json",
        [e.model_dump(mode="json") for e in all_detections],
    )
    console.print(
        f"\n[bold green]Replay complete:[/bold green] "
        f"{len(all_detections)} detection(s) -- "
        f"saved to {run_dir / 'replay_detections.json'}"
    )

