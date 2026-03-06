from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

import typer

app = typer.Typer(name="repo-sanitizer", help="Anonymize Git repositories before sharing.")

batch_app = typer.Typer(name="batch", help="Batch-process multiple GitLab repositories.")
app.add_typer(batch_app, name="batch")


def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-5s %(message)s",
        datefmt="%H:%M:%S",
    )


def _exit_for_missing_dependency(error: ModuleNotFoundError, feature: str) -> None:
    module = error.name or "unknown-module"
    package = "python-gitlab" if module == "gitlab" else module
    logging.getLogger(__name__).error(
        "Missing dependency '%s' required for %s. Install dependencies with `uv sync` "
        "or `pip install %s`.",
        package,
        feature,
        package,
    )
    raise typer.Exit(code=1) from error


def _load_batch_cfg(config: Path) -> "BatchConfig":
    from repo_sanitizer.batch.config import load_batch_config
    try:
        return load_batch_config(config)
    except Exception as e:
        logging.getLogger(__name__).error("Cannot load batch config: %s", e)
        raise typer.Exit(code=1)


def _summarize_batch_error(error: Exception) -> str:
    message = str(error).strip().replace("\n", " ")
    if "Just a moment..." in message and "cloudflare" in message.lower():
        return (
            "GitLab returned a Cloudflare challenge (HTTP 403). "
            "Check `gitlab.url` in your batch config: it should be the host "
            "URL (for example, `https://gitlab.com`), not a group/project URL."
        )
    if len(message) > 500:
        return f"{message[:500]}... [truncated]"
    return message


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
    ner_device: Optional[str] = typer.Option(
        None, "--ner-device",
        help="Device for NER model: cpu | cuda | cuda:0 | cuda:1 | auto (overrides policies.yaml)"
    ),
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
            ner_device=ner_device,
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
    ner_device: Optional[str] = typer.Option(
        None, "--ner-device",
        help="Device for NER model: cpu | cuda | cuda:0 | cuda:1 | auto (overrides policies.yaml)"
    ),
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
            ner_device=ner_device,
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


@batch_app.command("run")
def batch_run(
    config: Path = typer.Option(..., "--config", help="Path to batch YAML config file"),
    partner: list[str] = typer.Option(
        [], "--partner", help="Process only these partners (repeatable)"
    ),
    repo: list[str] = typer.Option(
        [], "--repo", help="Process only these repos as partner/name (repeatable)"
    ),
    retry_failed: bool = typer.Option(
        False, "--retry-failed", help="Re-process repos that failed in a previous run"
    ),
) -> None:
    """Sanitize all matching GitLab repositories and push bundles to the delivery group."""
    _setup_logging()
    try:
        from repo_sanitizer.batch.orchestrator import run_batch
    except ModuleNotFoundError as e:
        _exit_for_missing_dependency(e, "batch mode")

    cfg = _load_batch_cfg(config)
    try:
        exit_code = run_batch(
            config=cfg,
            override_partners=list(partner) or None,
            override_repos=list(repo) or None,
            retry_failed=retry_failed,
        )
    except Exception as e:
        logging.getLogger(__name__).error("Batch failed: %s", _summarize_batch_error(e))
        raise typer.Exit(code=1)

    raise typer.Exit(code=exit_code)


@batch_app.command("list")
def batch_list(
    config: Path = typer.Option(..., "--config", help="Path to batch YAML config file"),
) -> None:
    """List all repositories that would be processed according to the config scope."""
    _setup_logging()
    try:
        from repo_sanitizer.batch.orchestrator import list_repos
    except ModuleNotFoundError as e:
        _exit_for_missing_dependency(e, "batch mode")

    cfg = _load_batch_cfg(config)
    try:
        tasks = list_repos(cfg)
    except Exception as e:
        logging.getLogger(__name__).error(
            "Failed to list repos: %s", _summarize_batch_error(e)
        )
        raise typer.Exit(code=1)

    typer.echo(f"Found {len(tasks)} repositories:\n")
    for task in tasks:
        typer.echo(f"  {task.partner}/{task.name}")


def app_main() -> None:
    app()


if __name__ == "__main__":
    app_main()
