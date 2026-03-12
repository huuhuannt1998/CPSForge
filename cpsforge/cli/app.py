"""
CPSForge CLI -- Main Typer Application
======================================
All CLI sub-commands are registered here.

Commands are grouped into five command groups:
  scene   -- scene validation and inspection
  plc     -- PLC connectivity checks
  run     -- experiment execution (baseline, attack, closed-loop, replay)
  report  -- metrics summarisation, paper-ready tables, and reporting
  adapt   -- defender adaptation and hard-case management

Run ``cpsforge --help`` to see all available commands.
"""

from __future__ import annotations

import typer

from cpsforge.cli import scene as scene_cmds
from cpsforge.cli import plc as plc_cmds
from cpsforge.cli import run as run_cmds
from cpsforge.cli import report as report_cmds
from cpsforge.cli import adapt as adapt_cmds

app = typer.Typer(
    name="cpsforge",
    help=(
        "CPSForge: Closed-Loop LLM Red-Team/Blue-Team Testbed for Cyber-Physical Systems.\n\n"
        "Default PLC target: 192.168.0.1  |  Safe by default (dry-run mode)\n"
        "Set CPSFORGE_LIVE_WRITES=true in .env to enable real PLC writes."
    ),
    no_args_is_help=True,
    add_completion=False,
)

app.add_typer(scene_cmds.app, name="scene")
app.add_typer(plc_cmds.app, name="plc")
app.add_typer(run_cmds.app, name="run")
app.add_typer(report_cmds.app, name="report")
app.add_typer(adapt_cmds.app, name="adapt")


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """CPSForge root entry-point."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
