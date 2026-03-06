from __future__ import annotations

import logging
from pathlib import Path

import pytest
import typer

import repo_sanitizer.cli as cli
from repo_sanitizer.batch import gitlab_client


def _write_batch_config(path: Path) -> None:
    path.write_text(
        (
            "gitlab:\n"
            "  url: https://gitlab.example.com\n"
            "  token_env: GITLAB_TOKEN\n"
            "  source_group: source-group\n"
            "  delivery_group: delivery-group\n"
            "scope:\n"
            "  all: true\n"
        ),
        encoding="utf-8",
    )


def test_batch_list_missing_gitlab_dependency_exits_cleanly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    cfg = tmp_path / "batch.yaml"
    _write_batch_config(cfg)
    monkeypatch.setenv("GITLAB_TOKEN", "dummy-token")

    missing = ModuleNotFoundError("No module named 'gitlab'")
    missing.name = "gitlab"
    monkeypatch.setattr(gitlab_client, "gitlab", None)
    monkeypatch.setattr(gitlab_client, "_gitlab_import_error", missing)

    caplog.set_level(logging.ERROR)
    with pytest.raises(typer.Exit) as exc:
        cli.batch_list(config=cfg)

    assert exc.value.exit_code == 1
    assert any(
        "python-gitlab" in record.getMessage() and "Failed to list repos" in record.getMessage()
        for record in caplog.records
    )


def test_summarize_batch_error_cloudflare_page() -> None:
    error = RuntimeError("403: Just a moment... cloudflare challenge page")
    summary = cli._summarize_batch_error(error)
    assert "Cloudflare challenge" in summary
    assert "gitlab.url" in summary
