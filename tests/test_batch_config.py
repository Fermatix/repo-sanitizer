from __future__ import annotations

from pathlib import Path

import pytest

from repo_sanitizer.batch.config import load_batch_config


def _write_batch_config(path: Path, url: str) -> None:
    path.write_text(
        (
            "gitlab:\n"
            f"  url: {url}\n"
            "  token_env: GITLAB_TOKEN\n"
            "  source_group: source-group\n"
            "  delivery_group: delivery-group\n"
            "scope:\n"
            "  all: true\n"
        ),
        encoding="utf-8",
    )


def test_batch_config_accepts_host_url(tmp_path: Path) -> None:
    cfg_path = tmp_path / "batch.yaml"
    _write_batch_config(cfg_path, "https://gitlab.com/")

    cfg = load_batch_config(cfg_path)

    assert cfg.gitlab.url == "https://gitlab.com"


def test_batch_config_rejects_group_path_url(tmp_path: Path) -> None:
    cfg_path = tmp_path / "batch.yaml"
    _write_batch_config(cfg_path, "https://gitlab.com/acme/private-group/")

    with pytest.raises(
        ValueError,
        match="gitlab.url must point to the GitLab host",
    ):
        load_batch_config(cfg_path)
