"""
CPSForge CLI -- PLC Commands
==============================
``cpsforge plc probe``   -- test connectivity to the real PLC
``cpsforge plc read``    -- read one or more tags from the PLC
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="PLC connectivity and tag inspection commands.\n\nDefault target: 192.168.0.1 (configured in configs/system/plc.yaml).")
console = Console()


@app.command("probe")
def plc_probe(
    config: Optional[Path] = typer.Option(
        None, "--config", "-c",
        help="Path to PLC config YAML (default: configs/system/plc.yaml)"
    ),
) -> None:
    """
    Test the connection to the real Siemens PLC.

    Attempts to connect using the configured IP (default 192.168.0.1),
    runs a health check, then disconnects. Prints the result.
    """
    from cpsforge.core.config import ConfigLoader
    from cpsforge.plc.client import PlcClient, PLCConnectionError

    loader = ConfigLoader()
    if config:
        import yaml
        with config.open() as fh:
            raw = yaml.safe_load(fh)
        from cpsforge.core.config import PLCConfig
        plc_cfg = PLCConfig(**raw)
    else:
        plc_cfg = loader.load_plc()

    console.print(
        f"\n[bold]Probing PLC at [cyan]{plc_cfg.host}[/cyan] "
        f"(rack={plc_cfg.rack}, slot={plc_cfg.slot})[/bold]"
    )
    client = PlcClient(plc_cfg)
    try:
        client.connect()
        healthy = client.health_check()
        if healthy:
            console.print("[bold green]OK PLC is reachable and responding.[/bold green]\n")
        else:
            console.print("[yellow][!] Connected but health check returned no data.[/yellow]\n")
    except PLCConnectionError as exc:
        console.print(f"[red][X] Connection failed:[/red] {exc}\n")
        raise typer.Exit(code=1)
    finally:
        client.disconnect()


@app.command("read")
def plc_read(
    scene: str = typer.Option(..., "--scene", "-s", help="Scene name to read tags from"),
    tags: Optional[List[str]] = typer.Option(
        None, "--tag", "-t", help="Tag name(s) to read (repeat for multiple)"
    ),
    config: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """
    Read one or more tags from the real PLC and display their current values.

    If no --tag options are given, all scene tags are read.
    """
    from cpsforge.core.config import ConfigLoader
    from cpsforge.plc.client import PlcClient, PLCConnectionError
    from cpsforge.scenes.factory import load_scene

    loader = ConfigLoader()
    plc_cfg = loader.load_plc()
    scene_obj = load_scene(scene, loader)
    all_tags = scene_obj.get_all_tags()

    if tags:
        tag_set = set(tags)
        selected = [t for t in all_tags if t.name in tag_set]
        missing = tag_set - {t.name for t in selected}
        if missing:
            console.print(f"[yellow]Unknown tags: {missing}[/yellow]")
    else:
        selected = all_tags

    client = PlcClient(plc_cfg)
    try:
        client.connect()
        results = client.read_many(selected)
    except PLCConnectionError as exc:
        console.print(f"[red]Connection failed:[/red] {exc}")
        raise typer.Exit(code=1)
    finally:
        client.disconnect()

    table = Table(title=f"PLC Tag Read -- {scene}", show_lines=True)
    table.add_column("Tag", style="cyan")
    table.add_column("Value")
    table.add_column("Unit")
    table.add_column("Category")

    for tag in selected:
        val = results.get(tag.name)
        val_str = str(round(val, 4)) if isinstance(val, float) else str(val)
        table.add_row(tag.name, val_str, tag.unit or "", tag.category.value)

    console.print(table)
