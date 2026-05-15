"""
Lacuna CLI.

Usage:
    lacuna scan --manifest <path> [--workspace <path>]
                 [--mode sast|sast+dast|diff]
                 [--fail-on none|critical|high|medium]
                 [--diff-base <ref>] [--diff-head <ref>]
                 [--diff-max-depth <n>]
    lacuna status
    lacuna report --reports-dir <path>
    lacuna version
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click

from . import __version__


@click.group()
def cli() -> None:
    """Lacuna — agentic application-level security scanner."""


@cli.command()
@click.option("--manifest", "manifest_path", required=True,
                type=click.Path(exists=True, path_type=Path))
@click.option("--workspace", "workspace_path", default=Path("/workspace"),
                type=click.Path(path_type=Path))
@click.option("--mode", "mode", default="sast",
                type=click.Choice(["sast", "sast+dast", "diff"]))
@click.option("--fail-on", "fail_on", default="critical",
                type=click.Choice(["none", "critical", "high", "medium"]))
@click.option("--wall-clock-hours", "wall_clock", type=float, default=None)
@click.option("--max-parallel", "max_parallel", type=int, default=None)
@click.option("--diff-base", "diff_base", default=None,
                envvar="LACUNA_DIFF_BASE",
                help="Git ref for diff base (required when --mode=diff)")
@click.option("--diff-head", "diff_head", default=None,
                envvar="LACUNA_DIFF_HEAD",
                help="Git ref for diff head (default: HEAD)")
@click.option("--diff-max-depth", "diff_max_depth", type=int, default=3,
                envvar="LACUNA_DIFF_MAX_IMPORT_DEPTH",
                help="Max transitive import hops for diff scope (default: 3)")
def scan(
    manifest_path: Path, workspace_path: Path, mode: str, fail_on: str,
    wall_clock: float | None, max_parallel: int | None,
    diff_base: str | None, diff_head: str | None, diff_max_depth: int,
) -> None:
    """Run a full scan."""
    from .harness import run_scan

    if mode == "diff" and not diff_base:
        raise click.UsageError(
            "--mode=diff requires --diff-base (or LACUNA_DIFF_BASE env var)"
        )

    wall_clock = wall_clock if wall_clock is not None else float(
        os.environ.get("LACUNA_WALL_CLOCK_HOURS", "4")
    )
    max_parallel = max_parallel if max_parallel is not None else int(
        os.environ.get("LACUNA_MAX_PARALLEL_SUBAGENTS", "8")
    )
    rc = run_scan(
        manifest_path=manifest_path,
        workspace=workspace_path,
        mode=mode,
        fail_on=fail_on,
        wall_clock_hours=wall_clock,
        max_parallel=max_parallel,
        diff_base=diff_base,
        diff_head=diff_head or "HEAD",
        diff_max_depth=diff_max_depth,
    )
    sys.exit(rc)


@cli.command()
def status() -> None:
    """Print current KG status as JSON."""
    from .kg import open_kg
    kg = open_kg()
    click.echo(json.dumps(kg.status_summary(), indent=2, default=str))
    kg.close()


@cli.command()
@click.option("--reports-dir", "reports_dir", default=Path("/reports"),
                type=click.Path(path_type=Path))
def report(reports_dir: Path) -> None:
    """Regenerate reports from the current KG."""
    from .reports import write_reports
    write_reports(reports_dir)
    click.echo(f"reports written to {reports_dir}")


@cli.command()
def version() -> None:
    """Print Lacuna version."""
    click.echo(f"Lacuna {__version__}")


if __name__ == "__main__":
    cli()
