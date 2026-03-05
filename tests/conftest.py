from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_REPO = FIXTURES_DIR / "sample_repo"
RULES_DIR = Path(__file__).parent.parent / "repo_sanitizer" / "rules"


@pytest.fixture
def salt() -> bytes:
    return b"test-salt-12345"


@pytest.fixture
def sample_repo_path() -> Path:
    return SAMPLE_REPO


@pytest.fixture
def rules_path() -> Path:
    return RULES_DIR


@pytest.fixture
def history_repo(tmp_path: Path) -> Path:
    """Create a temporary history repo using the fixture script."""
    script = FIXTURES_DIR / "create_history_repo.sh"
    dest = tmp_path / "history_repo"
    subprocess.run(
        ["bash", str(script), str(dest)],
        check=True,
        capture_output=True,
        text=True,
    )
    return dest


@pytest.fixture(autouse=True)
def set_salt_env(salt: bytes):
    """Ensure REPO_SANITIZER_SALT is set for all tests."""
    old = os.environ.get("REPO_SANITIZER_SALT")
    os.environ["REPO_SANITIZER_SALT"] = salt.decode()
    yield
    if old is None:
        os.environ.pop("REPO_SANITIZER_SALT", None)
    else:
        os.environ["REPO_SANITIZER_SALT"] = old
