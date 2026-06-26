from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

import typer

app = typer.Typer(name="repo-sanitizer", help="Anonymize Git repositories before sharing.")

batch_app = typer.Typer(name="batch", help="Batch-process multiple GitLab repositories.")
app.add_typer(batch_app, name="batch")


# ANSI color codes per level — only used when stderr is a TTY
_LEVEL_COLOR = {
    logging.DEBUG:    "\033[2m",     # dim
    logging.WARNING:  "\033[33m",    # yellow
    logging.ERROR:    "\033[31m",    # red
    logging.CRITICAL: "\033[1;31m",  # bold red
}
_RESET = "\033[0m"

# Third-party loggers that are too noisy at INFO/WARNING
_QUIET_LOGGERS = ("urllib3", "transformers", "httpx", "filelock", "huggingface_hub")


class _ColorFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        color = _LEVEL_COLOR.get(record.levelno, "")
        return f"{color}{msg}{_RESET}" if color else msg


def _setup_logging() -> None:
    fmt = "%(asctime)s %(levelname)-5s %(message)s"
    datefmt = "%H:%M:%S"
    handler = logging.StreamHandler(sys.stderr)
    if sys.stderr.isatty():
        handler.setFormatter(_ColorFormatter(fmt=fmt, datefmt=datefmt))
    else:
        handler.setFormatter(logging.Formatter(fmt=fmt, datefmt=datefmt))
    logging.basicConfig(level=logging.INFO, handlers=[handler])

    for name in _QUIET_LOGGERS:
        logging.getLogger(name).setLevel(logging.ERROR)


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
    ner_service_url: Optional[str] = typer.Option(
        None, "--ner-service-url",
        help="URL of a running NER service (e.g. http://localhost:8765). "
             "Skips local model loading; multiple runs can share one service."
    ),
    ner_scope: str = typer.Option(
        "head", "--ner-scope",
        help="Where NER runs: head (working tree only — default, fast) | "
             "all (also commit metadata + every history blob — slow; NER-only "
             "names found in history are reported as a gate worklist, not "
             "auto-rewritten, like brands) | off (never load NER — fastest)."
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
            ner_service_url=ner_service_url,
            ner_scope=ner_scope,
        )
    except Exception as e:
        logging.getLogger(__name__).error("Fatal error: %s", e)
        raise typer.Exit(code=1)
    raise typer.Exit(code=exit_code)


@app.command("sanitize-batch")
def sanitize_batch(
    list_file: Path = typer.Argument(
        ...,
        help="Text file with one repo per line (local path, .bundle, or Git URL). "
             "Blank lines and # comments are ignored.",
    ),
    rulepack: Path = typer.Option(..., "--rulepack", help="Path to rulepack directory"),
    out: Path = typer.Option(..., "--out", help="Output root; each repo goes to <out>/<key>/"),
    workers: int = typer.Option(
        0, "--workers", help="Parallel worker processes (default: min(8, cpu-2))"
    ),
    retry_failed: bool = typer.Option(
        False, "--retry-failed", help="Re-process repos that failed in a previous run"
    ),
    salt_env: str = typer.Option(
        "REPO_SANITIZER_SALT", "--salt-env", help="Env variable name containing the salt"
    ),
    max_file_mb: int = typer.Option(20, "--max-file-mb", help="Max file size in MB"),
    ner_device: Optional[str] = typer.Option(
        None, "--ner-device",
        help="Device for the shared NER model: cpu | cuda | cuda:0 | auto (overrides policies.yaml)",
    ),
    ner_service_url: Optional[str] = typer.Option(
        None, "--ner-service-url",
        help="URL of an already-running NER service. If set, no service is started for the batch.",
    ),
    ner_scope: str = typer.Option(
        "head", "--ner-scope",
        help="Where NER runs per repo: head (working tree only — default) | all (also history) | "
             "off (never load NER — no service started).",
    ),
    ner_service_port: int = typer.Option(
        8765, "--ner-service-port", help="Port for the shared NER service started for this batch"
    ),
    preflight: bool = typer.Option(
        True, "--preflight/--no-preflight",
        help="Before starting, check access to each remote URL: try existing HTTPS "
             "credentials, then SSH keys, then prompt for a token. Aborts if any repo "
             "is unreachable, instead of failing workers mid-run.",
    ),
) -> None:
    """Sanitize every repo listed in a file into <out>/<key>/ — local sources, local output.

    Reuses the per-repo pipeline and a single shared NER service across all
    workers. No GitLab discovery and no push (unlike `batch run`).
    """
    _setup_logging()
    try:
        from repo_sanitizer.batch.local import run_local_batch
    except ModuleNotFoundError as e:
        _exit_for_missing_dependency(e, "batch mode")

    try:
        exit_code = run_local_batch(
            list_file=list_file,
            rulepack=rulepack,
            out=out,
            workers=workers or None,
            retry_failed=retry_failed,
            salt_env=salt_env,
            max_file_mb=max_file_mb,
            ner_device=ner_device,
            ner_service_url=ner_service_url,
            ner_scope=ner_scope,
            ner_service_port=ner_service_port,
            preflight=preflight,
        )
    except Exception as e:
        logging.getLogger(__name__).error("Batch failed: %s", _summarize_batch_error(e))
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
    ner_service_url: Optional[str] = typer.Option(
        None, "--ner-service-url",
        help="URL of a running NER service (e.g. http://localhost:8765). "
             "Skips local model loading; multiple runs can share one service."
    ),
    ner_scope: str = typer.Option(
        "head", "--ner-scope",
        help="Where NER runs: head (working tree only — default, fast) | "
             "all (also commit metadata + every history blob — slow) | "
             "off (never load NER at all — fastest)."
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
            ner_service_url=ner_service_url,
            ner_scope=ner_scope,
        )
    except Exception as e:
        logging.getLogger(__name__).error("Fatal error: %s", e)
        raise typer.Exit(code=1)
    raise typer.Exit(code=exit_code)


@app.command("apply-map")
def apply_map(
    source: str = typer.Argument(
        ..., help="Pass-1 output to finalize: its work/ dir or sanitized.bundle (or a Git URL)"
    ),
    brand_map: Path = typer.Option(
        ..., "--brand-map",
        help="Pass-2 tiered brand map (JSON or CSV): rows of "
             "{pattern, replacement, is_regex, preserve_case}."
    ),
    out: Path = typer.Option(..., "--out", help="Output directory"),
    rev: str = typer.Option("HEAD", "--rev", help="Git revision to checkout"),
    salt_env: str = typer.Option(
        "REPO_SANITIZER_SALT", "--salt-env",
        help="Env variable with the salt (required by the framework; UNUSED by "
             "apply-map — brand replacements come from the map, not salted hashes)"
    ),
) -> None:
    """Pass-3: apply the Pass-2 brand map across ALL git history, then re-bundle.

    One git-filter-repo pass substitutes the mapped brands in every blob, commit
    message, and path segment (paths renamed coherently with content). Run this
    AFTER Pass-1 sanitize + the Pass-2 brand-map generation; the mandatory
    codex/agent audit still follows.
    """
    _setup_logging()
    from repo_sanitizer.pipeline import run_apply_map

    if not brand_map.exists():
        logging.getLogger(__name__).error("Brand map not found: %s", brand_map)
        raise typer.Exit(code=1)

    try:
        exit_code = run_apply_map(
            source=source,
            out_dir=out,
            brand_map_path=brand_map,
            salt_env=salt_env,
            rev=rev,
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

    # Step 1: install tree-sitter-language-pack first — it bundles many grammars
    # that have no standalone PyPI package (Vue, Svelte, etc.).
    typer.echo("\nInstalling tree-sitter-language-pack...")
    lp_result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "tree-sitter-language-pack"],
        capture_output=True,
    )
    if lp_result.returncode == 0:
        typer.echo("  ✓ installed tree-sitter-language-pack")
    else:
        typer.echo("  ✗ tree-sitter-language-pack install failed (continuing anyway)")

    # Step 2: re-check which packages are still missing now that language-pack may cover some.
    statuses = check_grammar_packages(rp.extractor)
    still_missing = [
        s.grammar_package
        for s in statuses
        if not (s.installed and not s.missing_attribute)
    ]

    # Step 3: install remaining individual packages one by one.
    if still_missing:
        typer.echo(f"\nInstalling {len(still_missing)} remaining package(s)...")
        failed = []
        for pkg in still_missing:
            cmd = [sys.executable, "-m", "pip", "install", pkg]
            result = subprocess.run(cmd, capture_output=True)
            if result.returncode == 0:
                typer.echo(f"  ✓ installed {pkg}")
            else:
                typer.echo(f"  ✗ skipped {pkg} (not found on PyPI)")
                failed.append(pkg)

        if failed:
            logging.getLogger(__name__).warning(
                "Could not install %d package(s): %s. "
                "These languages will fall back to the regex extractor.",
                len(failed),
                ", ".join(failed),
            )

    typer.echo("\nDone. Re-run to verify:")
    typer.echo(f"  repo-sanitizer install-grammars --rulepack {rulepack}")


@app.command("expand-variants")
def expand_variants(
    input_file: Path = typer.Argument(
        ..., help="Text file with one brand term per line (# comments allowed)"
    ),
    output_file: Optional[Path] = typer.Argument(
        None, help="Write expanded terms here (default: stdout)"
    ),
) -> None:
    """Expand brand terms to all separator / Cyrillic / mojibake variants.

    The dictionary/brand matchers are case-insensitive, so case variants are
    redundant; this materializes the forms case-folding does not cover. Useful
    to inspect what a brand token will match, or to pre-bake a dictionary file.
    """
    _setup_logging()
    from repo_sanitizer.variants import expand_term

    if not input_file.exists():
        logging.getLogger(__name__).error("Input file not found: %s", input_file)
        raise typer.Exit(code=1)

    terms = [
        line.strip()
        for line in input_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    expanded: set[str] = set()
    for term in terms:
        expanded |= expand_term(term)

    body = "\n".join(sorted(expanded))
    if output_file is not None:
        output_file.write_text(body + "\n", encoding="utf-8")
        typer.echo(f"Wrote {len(expanded)} variants from {len(terms)} terms → {output_file}")
    else:
        typer.echo(body)


@app.command("ner-service")
def ner_service(
    port: int = typer.Option(8765, "--port", help="TCP port to listen on"),
    device: str = typer.Option("cpu", "--device", help="Device: cpu | cuda | cuda:0 | auto"),
    backend: str = typer.Option("hf", "--backend", help="Backend: hf | gliner"),
    batch_size: int = typer.Option(32, "--batch-size", help="Max chunks per GPU forward pass"),
    model: Optional[str] = typer.Option(None, "--model", help="Model name (overrides rulepack)"),
    rulepack: Optional[Path] = typer.Option(None, "--rulepack", help="Rulepack to read NER config from"),
    idle_timeout: int = typer.Option(
        60, "--idle-timeout",
        help="Seconds of inactivity before the service shuts itself down. 0 = never."
    ),
) -> None:
    """Start a shared NER inference service (foreground).

    Load the model once and serve all sanitize/scan runs via --ner-service-url.
    The service stops automatically after --idle-timeout seconds of no requests,
    or when you press Ctrl+C.
    """
    _setup_logging()
    from repo_sanitizer.batch.ner_service import _run_server

    # Apply rulepack defaults, then let explicit CLI flags override
    resolved_model = model
    resolved_device = device
    resolved_backend = backend
    if rulepack is not None:
        try:
            from repo_sanitizer.rulepack import load_rulepack
            rp = load_rulepack(rulepack)
            if resolved_model is None:
                resolved_model = rp.ner.model
            if device == "cpu":  # still at default — use rulepack value
                resolved_device = rp.ner.device
            if backend == "hf":  # still at default — use rulepack value
                resolved_backend = rp.ner.backend
        except Exception as e:
            logging.getLogger(__name__).error("Cannot load rulepack: %s", e)
            raise typer.Exit(code=1)

    if resolved_model is None:
        resolved_model = "Davlan/bert-base-multilingual-cased-ner-hrl"

    logging.getLogger(__name__).info(
        "Starting NER service on port %d (model=%s, backend=%s, device=%s, idle_timeout=%ds)",
        port, resolved_model, resolved_backend, resolved_device, idle_timeout,
    )
    _run_server(
        model_name=resolved_model,
        device=resolved_device,
        port=port,
        batch_size=batch_size,
        backend=resolved_backend,
        min_score=0.7,
        entity_types=["PER", "ORG"],
        idle_timeout=float(idle_timeout),
    )


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
