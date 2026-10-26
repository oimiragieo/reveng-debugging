"""reveng-debug CLI (SPEC-RD-003+, Wave 2)."""

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


@app.command("clone-website")
def clone_website(
    target: str = typer.Argument(..., help="Local HTML/capture JSON path, or http(s) URL"),
    session_id: str | None = typer.Option(None, "--session-id"),
) -> None:
    """Clone a website snapshot (static HTML or gotcontext-chrome capture JSON)."""
    result = service.clone_website(target, session_id=session_id)
    _emit(result.model_dump())


@app.command()
def slice(
    path: Path = typer.Argument(..., exists=True, readable=True),
    needle: str = typer.Argument(...),
    session_id: str | None = typer.Option(None, "--session-id"),
) -> None:
    """Bounded text slice around a needle (static; does not execute)."""
    _emit(service.slice_file(path, needle, session_id=session_id))


@app.command()
def ghidra(
    path: Path = typer.Argument(..., exists=True, readable=True),
    session_id: str | None = typer.Option(None, "--session-id"),
) -> None:
    """Opt-in BYO Ghidra headless on a session copy. Does not execute the target."""
    result = service.ghidra_headless(path, session_id=session_id)
    _emit(result.model_dump())


@app.command("app-re")
def app_re(
    path: Path = typer.Argument(..., exists=True, readable=True),
    session_id: str | None = typer.Option(None, "--session-id"),
) -> None:
    """Opt-in BYO reverse-engineer-app on a session copy. Does not execute the target."""
    result = service.app_re(path, session_id=session_id)
    _emit(result.model_dump())


@app.command()
def tui() -> None:
    """Interactive TUI. Attach omega-vision at http://127.0.0.1:8092/attach."""
    from reveng_debug.tui import run_tui

    run_tui()


@session_app.command("show")
def session_show(session_id: str = typer.Argument(...)) -> None:
    """Show session metadata and evidence."""
    try:
        payload = service.session_show(session_id)
    except (FileNotFoundError, ValueError) as exc:
        # A mistyped or malformed id is a caller error, not a crash: emit the same
        # JSON shape the rest of the CLI emits instead of a Python traceback.
        _emit({"error": str(exc), "session_id": session_id})
        raise typer.Exit(code=2) from None
    _emit(payload)


@app.command("mcp")
def mcp_stdio() -> None:
    """Serve the thin MCP stdio catalog including Wave 2 opt-in tools."""
    from reveng_debug.mcp import main as mcp_main

    mcp_main()


def main() -> None:
    app()
