"""A corrupt / unreadable git bundle must fail with git's own explanation, not a
bare ``Command '[...]' returned non-zero exit status 128``.
"""

from __future__ import annotations

import subprocess

import pytest

from repo_sanitizer.steps.fetch import _run_git, _verify_git_bundle


def _git(args, cwd, **kw):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, **kw)


def test_corrupt_bundle_raises_clear_error(tmp_path):
    bad = tmp_path / "RBCC.bundle"
    bad.write_bytes(b"this is not a git bundle\n")

    with pytest.raises(RuntimeError) as ei:
        _verify_git_bundle(bad)

    msg = str(ei.value)
    assert "RBCC.bundle" in msg
    assert "not usable" in msg
    # git's own diagnostic is attached, not just an exit code.
    assert len(msg.splitlines()) > 1


def test_run_git_surfaces_stderr_on_failure(tmp_path):
    missing = tmp_path / "nope.bundle"
    dest = tmp_path / "work"

    with pytest.raises(RuntimeError) as ei:
        _run_git(["clone", str(missing), str(dest)])

    msg = str(ei.value)
    assert "failed (exit" in msg
    # The real reason (git's stderr) is included — message is more than a header.
    assert len(msg.strip().splitlines()) > 1


def test_valid_bundle_passes_verify(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(["init"], repo)
    _git(["config", "user.email", "t@t.com"], repo)
    _git(["config", "user.name", "T"], repo)
    (repo / "f.txt").write_text("x\n")
    _git(["add", "."], repo)
    _git(["commit", "-m", "init"], repo)

    bundle = tmp_path / "ok.bundle"
    _git(["bundle", "create", str(bundle), "--all"], repo)

    # Must not raise for a complete, well-formed bundle.
    _verify_git_bundle(bundle)
