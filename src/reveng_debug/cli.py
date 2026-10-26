"""reveng-debug CLI (SPEC-RD-003+, CL4)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

from reveng_debug import __version__, service

app = typer.Typer(
    name="reveng-debug",
    help="Evidence-first debugging studio. Does not execute targets by default.",
    no_args_is_help=True,
    add_completion=False,
)
session_app = typer.Typer(help="Session workspace commands.")
app.add_typer(session_app, name="session")


def _emit(payload: Any) -> None:
    typer.echo(json.dumps(payload, indent=2, default=str))


@app.callback()
def _root() -> None:
    """reveng-debug."""


@app.command()
def version() -> None:
    """Print package version."""
    _emit({"version": __version__})


@app.command()
def doctor() -> None:
    """Report tool presence without claiming missing tools as absent."""
    _emit(service.doctor())


@app.command()
def identify(
    path: Path = typer.Argument(..., exists=True, readable=True),
) -> None:
    """Classify a target from magic bytes and extension."""
    _emit(service.identify(path))


@app.command()
def inventory(
    path: Path = typer.Argument(..., exists=True, readable=True),
    session_id: str | None = typer.Option(None, "--session-id"),
) -> None:
    """Copy the target into a session workspace and emit evidence-backed inventory."""
    result = service.inventory(path, session_id=session_id)
    _emit(result.model_dump())


@app.command()
def slice(
    path: Path = typer.Argument(..., exists=True, readable=True),
    needle: str = typer.Argument(...),
    session_id: str | None = typer.Option(None, "--session-id"),
) -> None:
    """Bounded text slice around a needle (static; does not execute)."""
    _emit(service.slice_file(path, needle, session_id=session_id))


@session_app.command("show")
def session_show(session_id: str = typer.Argument(...)) -> None:
    """Show session metadata and evidence."""
    _emit(service.session_show(session_id))


@app.command("mcp")
def mcp_stdio() -> None:
    """Serve the six-tool MCP stdio catalog."""
    from reveng_debug.mcp import main as mcp_main

    mcp_main()


def main() -> None:
    app()
