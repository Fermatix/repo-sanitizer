from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

import typer

app = typer.Typer(name="repo-sanitizer", help="Anonymize Git repositories before sharing.")


def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@app.command()
def sanitize(
    source: str = typer.Argument(..., help="Local path or Git URL of the repository"),
    rulepack: Path = typer.Option(..., "--rulepack", help="Path to rulepack directory"),
    out: Path = typer.Option(..., "--out", help="Output directory"),
    rev: str = typer.Option("HEAD", "--rev", help="Git revision to checkout"),
    salt_env: str = typer.Option(
        "REPO_SANITIZER_SALT", "--salt-env", help="Env variable name containing the salt"
    ),
    max_file_mb: int = typer.Option(20, "--max-file-mb", help="Max file size in MB"),
    history_since: Optional[str] = typer.Option(None, "--history-since", help="Lower bound for history"),
    history_until: Optional[str] = typer.Option(None, "--history-until", help="Upper bound for history"),
) -> None:
    """Sanitize a Git repository: scan, redact, rewrite history, and package."""
    _setup_logging()
    from repo_sanitizer.pipeline import run_sanitize

    try:
        exit_code = run_sanitize(
            source=source,
            out_dir=out,
            rulepack_path=rulepack,
            salt_env=salt_env,
            rev=rev,
            max_file_mb=max_file_mb,
            history_since=history_since,
            history_until=history_until,
        )
    except Exception as e:
        logging.getLogger(__name__).error("Fatal error: %s", e)
        raise typer.Exit(code=1)
    raise typer.Exit(code=exit_code)


@app.command()
def scan(
    source: str = typer.Argument(..., help="Local path or Git URL of the repository"),
    rulepack: Path = typer.Option(..., "--rulepack", help="Path to rulepack directory"),
    out: Path = typer.Option(..., "--out", help="Output directory"),
    rev: str = typer.Option("HEAD", "--rev", help="Git revision to checkout"),
    salt_env: str = typer.Option(
        "REPO_SANITIZER_SALT", "--salt-env", help="Env variable name containing the salt"
    ),
    max_file_mb: int = typer.Option(20, "--max-file-mb", help="Max file size in MB"),
    history_since: Optional[str] = typer.Option(None, "--history-since", help="Lower bound for history"),
    history_until: Optional[str] = typer.Option(None, "--history-until", help="Upper bound for history"),
) -> None:
    """Scan a Git repository for PII, secrets, and sensitive data (read-only)."""
    _setup_logging()
    from repo_sanitizer.pipeline import run_scan_only

    try:
        exit_code = run_scan_only(
            source=source,
            out_dir=out,
            rulepack_path=rulepack,
            salt_env=salt_env,
            rev=rev,
            max_file_mb=max_file_mb,
            history_since=history_since,
            history_until=history_until,
        )
    except Exception as e:
        logging.getLogger(__name__).error("Fatal error: %s", e)
        raise typer.Exit(code=1)
    raise typer.Exit(code=exit_code)


@app.command("install-grammars")
def install_grammars(
    rulepack: Path = typer.Option(..., "--rulepack", help="Path to rulepack directory"),
) -> None:
    """Install tree-sitter grammar packages listed in the rulepack's extractors.yaml."""
    _setup_logging()
    import subprocess
    from repo_sanitizer.rulepack import load_rulepack
    from repo_sanitizer.extractors.treesitter import check_grammar_packages

    try:
        rp = load_rulepack(rulepack)
    except Exception as e:
        logging.getLogger(__name__).error("Cannot load rulepack: %s", e)
        raise typer.Exit(code=1)

    statuses = check_grammar_packages(rp.extractor)
    if not statuses:
        typer.echo("No grammar packages configured in extractors.yaml.")
        return

    typer.echo("Grammar packages:")
    to_install = []
    for s in statuses:
        if s.installed and not s.missing_attribute:
            typer.echo(f"  ✓ {s.grammar_package} ({s.language_id})")
        else:
            typer.echo(f"  ✗ {s.grammar_package} ({s.language_id}) — not installed")
            to_install.append(s.grammar_package)

    if not to_install:
        typer.echo("All grammar packages are already installed.")
        return

    typer.echo(f"\nInstalling {len(to_install)} package(s)...")
    cmd = [sys.executable, "-m", "pip", "install"] + to_install
    result = subprocess.run(cmd)
    if result.returncode != 0:
        logging.getLogger(__name__).error("pip install failed (exit %d)", result.returncode)
        raise typer.Exit(code=result.returncode)

    typer.echo("\nDone. Re-run to verify:")
    typer.echo(f"  repo-sanitizer install-grammars --rulepack {rulepack}")


def app_main() -> None:
    app()


if __name__ == "__main__":
    app_main()
