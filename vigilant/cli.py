"""
vigilant/cli.py
────────────────
Typer CLI entry point for Vigilant-X.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from vigilant.orchestrator import run_review

app = typer.Typer(
    name="vigilant-x",
    help="🔍 Vigilant-X — Agentic C++ security review with formal verification.",
    add_completion=False,
    invoke_without_command=True,   # show help when called with no subcommand
    no_args_is_help=True,
)
console = Console()


@app.command()
def version() -> None:
    """Print Vigilant-X version and exit."""
    from vigilant import __version__
    console.print(f"vigilant-x v{__version__}")


@app.command()
def review(
    repo: Path = typer.Option(
        Path("."),
        "--repo", "-r",
        help="Path to the repository root.",
        exists=True, file_okay=False, dir_okay=True,
    ),
    pr_number: int = typer.Option(
        0, "--pr-number", "-n",
        help="Pull Request number (0 for local analysis).",
    ),
    base_sha: str = typer.Option(
        "", "--base-sha",
        help="Base commit SHA (PR base).",
    ),
    head_sha: str = typer.Option(
        "", "--head-sha",
        help="Head commit SHA (PR head).",
    ),
    github_repo: str = typer.Option(
        "",
        "--github-repo", "-g",
        help="GitHub repo in 'owner/repo' format.",
        envvar="GITHUB_REPO",
    ),
    changed_files: Optional[str] = typer.Option(
        None,
        "--changed-files",
        help="Comma-separated list of changed files. Auto-detected from git diff if omitted.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print report to stdout instead of posting to GitHub.",
    ),
    output_json: Optional[Path] = typer.Option(
        None,
        "--output-json",
        help="Save the final AgentState as JSON to this path.",
    ),
) -> None:
    """Run a full Vigilant-X security review on a repo or PR."""

    console.print(Panel(
        Text("Vigilant-X", style="bold blue") +
        Text(" — Agentic C++ Security Review", style="dim"),
        subtitle=f"repo={repo} | PR=#{pr_number} | dry_run={dry_run}",
    ))

    # ── Resolve changed files ────────────────────────────────────────────────
    files: list[str] = []
    if changed_files:
        files = [f.strip() for f in changed_files.split(",") if f.strip()]
    elif base_sha and head_sha:
        files = _git_changed_files(repo, base_sha, head_sha)
    else:
        # Fall back: all C/C++ files in repo
        files = [
            str(p.relative_to(repo))
            for ext in ("*.cpp", "*.cc", "*.c", "*.h", "*.hpp")
            for p in repo.rglob(ext)
        ]
        console.print(f"[yellow]⚠ No SHA range provided — analysing all {len(files)} C/C++ files[/]")

    console.print(f"[blue]Files to analyse:[/] {len(files)}")

    # ── Run pipeline ─────────────────────────────────────────────────────────
    import shutil
    if shutil.which("joern") is None and shutil.which("joern-cli") is None:
        if shutil.which("clang-tidy"):
            console.print("[yellow]⚠ Joern not found — using clang-tidy fallback. "
                          "Coverage reduced (~50% of Joern). Templates and macro sinks may be missed.[/]")
        else:
            console.print("[red]⚠ Neither Joern nor clang-tidy found — regex stub active. "
                          "Coverage severely limited. Install Joern for production use.[/]")

    final_state = run_review(
        repo_path=str(repo.resolve()),
        pr_number=pr_number,
        base_sha=base_sha or "HEAD~1",
        head_sha=head_sha or "HEAD",
        changed_files=files,
        github_repo=github_repo or os.environ.get("GITHUB_REPO", ""),
        dry_run=dry_run,
    )

    # ── Errors summary ───────────────────────────────────────────────────────
    if final_state.errors:
        console.print(f"\n[red]⚠ {len(final_state.errors)} error(s) during analysis:[/]")
        for err in final_state.errors:
            console.print(f"  • {err}", style="red")

    # ── Save JSON ────────────────────────────────────────────────────────────
    if output_json:
        output_json.write_text(final_state.model_dump_json(indent=2))
        console.print(f"\n[green]JSON output saved to {output_json}[/]")

    # ── Exit code ────────────────────────────────────────────────────────────
    from vigilant.models import VulnerabilityStatus
    has_verified = any(
        v.status in {
            VulnerabilityStatus.PROVEN,
            VulnerabilityStatus.FUZZ_VERIFIED,
            VulnerabilityStatus.SANDBOX_VERIFIED,
        }
        for v in final_state.vulnerabilities
    )
    raise typer.Exit(code=1 if has_verified else 0)


def _git_changed_files(repo: Path, base: str, head: str) -> list[str]:
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", base, head],
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return [f for f in result.stdout.splitlines() if f.strip()]
    except Exception as e:
        console.print(f"[yellow]Could not run git diff: {e}[/]")
        return []


if __name__ == "__main__":
    app()
