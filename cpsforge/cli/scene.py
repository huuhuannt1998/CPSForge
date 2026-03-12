"""
CPSForge CLI -- Scene Commands
================================
``cpsforge scene validate``  -- load and validate a scene config
``cpsforge scene info``      -- pretty-print scene tag table
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Inspect and validate Factory I/O scene configurations.\n\nScenes define the PLC tag map, safety rules, and attack surface for an experiment.")
console = Console()


@app.command("validate")
def validate_scene(
    scene: str = typer.Option(..., "--scene", "-s", help="Scene name (e.g. tank_control)"),
    configs_dir: Optional[Path] = typer.Option(
        None, "--configs-dir", help="Override configs/ directory path"
    ),
) -> None:
    """
    Validate a scene YAML config and print a summary.

    Loads the scene config, validates all tag definitions and safety rules,
    and reports any errors. Does NOT connect to the PLC.
    """
    from cpsforge.core.config import ConfigLoader
    from cpsforge.scenes.factory import load_scene

    loader = ConfigLoader(configs_dir) if configs_dir else ConfigLoader()
    try:
        scene_obj = load_scene(scene, loader)
    except FileNotFoundError as exc:
        console.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1)
    except Exception as exc:
        console.print(f"[red]Validation failed:[/red] {exc}")
        raise typer.Exit(code=1)

    p = scene_obj.profile
    console.print(f"\n[bold green]OK Scene '{p.scene_name}' is valid.[/bold green]")
    console.print(f"  Tags        : {len(p.tags)}")
    console.print(f"  Writable    : {len(p.writable_tags)}")
    console.print(f"  Attack surface: {len(p.attack_surface)}")
    console.print(f"  Safety rules: {len(p.safety_rules)}")
    console.print(f"  Poll interval: {p.sampling_interval_ms} ms\n")


@app.command("info")
def scene_info(
    scene: str = typer.Option(..., "--scene", "-s", help="Scene name"),
    configs_dir: Optional[Path] = typer.Option(None, "--configs-dir"),
) -> None:
    """Print a detailed tag table for a scene."""
    from cpsforge.core.config import ConfigLoader
    from cpsforge.scenes.factory import load_scene

    loader = ConfigLoader(configs_dir) if configs_dir else ConfigLoader()
    try:
        scene_obj = load_scene(scene, loader)
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)

    p = scene_obj.profile
    table = Table(title=f"Scene: {p.scene_name}", show_lines=True)
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Category", style="yellow")
    table.add_column("Address")
    table.add_column("Type")
    table.add_column("Access")
    table.add_column("Range")
    table.add_column("Unit")
    table.add_column("Description")

    for tag in p.tags:
        rng = ""
        if tag.min_value is not None and tag.max_value is not None:
            rng = f"{tag.min_value} - {tag.max_value}"
        table.add_row(
            tag.name,
            tag.category.value,
            tag.address,
            tag.data_type.value,
            tag.access.value,
            rng,
            tag.unit or "",
            tag.description,
        )

    console.print(table)
