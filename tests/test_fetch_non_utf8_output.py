"""Regression: non-UTF-8 output from git must not kill the fetch step.

``_run_git`` captured with a bare ``text=True``, i.e. the strict UTF-8 decoder.
A repository authored in cp1251 makes git emit raw 0xC0-0xFF bytes — in a commit
subject, a branch name or a path it prints back — and subprocess then raises
``UnicodeDecodeError: 'utf-8' codec can't decode byte 0xcd ...`` from inside
``communicate()``. The whole run died at the very first step, before a single
blob had been looked at, and the error carried no hint of where it came from.

Everything ``_run_git`` captures ends up in an error message, never in a parsed
path, so decoding with ``errors="replace"`` is lossless for the purpose.
"""

from __future__ import annotations

import subprocess

import pytest

from repo_sanitizer.steps.fetch import _run_git


def _git(args, cwd, **kw):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, **kw)


@pytest.fixture
def cp1251_repo(tmp_path):
    """A repo whose HEAD commit subject is raw cp1251 — invalid UTF-8 on its own."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(["init"], repo)
    _git(["config", "user.email", "t@t.com"], repo)
    _git(["config", "user.name", "T"], repo)
    _git(["config", "i18n.commitEncoding", "cp1251"], repo)
    _git(["config", "i18n.logOutputEncoding", "cp1251"], repo)
    (repo / "f.txt").write_text("x\n")
    _git(["add", "."], repo)
    msg = "Начало проекта".encode("cp1251")   # 0xCD == Cyrillic Н
    assert b"\xcd" in msg          # the byte from the reported crash
    msg_file = tmp_path / "msg.txt"
    msg_file.write_bytes(msg)
    _git(["commit", "-F", str(msg_file)], repo)
    return repo


def test_non_utf8_git_output_does_not_crash(cp1251_repo):
    result = _run_git(["log", "-1", "--format=%s"], cwd=cp1251_repo)
    assert result.returncode == 0
    assert result.stdout          # undecodable bytes became U+FFFD, not an exception


def test_failing_git_still_reports_its_own_message(cp1251_repo):
    """The diagnostic path must survive the same bytes: a failure inside a cp1251
    repository has to surface git's stderr, not a decode traceback."""
    with pytest.raises(RuntimeError) as e:
        _run_git(["checkout", "no-such-ref"], cwd=cp1251_repo)
    assert "exit" in str(e.value)
