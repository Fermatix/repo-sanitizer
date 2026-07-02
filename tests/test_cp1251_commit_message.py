"""Regression: a cp1251-encoded commit message must not crash the history scan
with ``'utf-8' codec can't decode byte 0xca ... invalid continuation byte``.

The two history scanners dump every commit message via ``git log --format=%B``.
Capturing that output as strict UTF-8 (subprocess ``text=True``) aborts the whole
run on Russian (cp1251) messages; ``_git_all_commit_messages`` must decode with
detection instead.
"""

from __future__ import annotations

import subprocess

from repo_sanitizer.steps.history_rewrite import _git_all_commit_messages


def _git(args, cwd, **kw):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, **kw)


def test_cp1251_commit_message_does_not_crash(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(["init"], repo)
    _git(["config", "user.email", "t@t.com"], repo)
    _git(["config", "user.name", "T"], repo)
    # Force git to store AND emit the message in cp1251, so `git log --format=%B`
    # yields raw 0xC0-0xFF bytes — exactly the input that makes a strict UTF-8
    # (subprocess text=True) capture raise the reported crash.
    _git(["config", "i18n.commitEncoding", "cp1251"], repo)
    _git(["config", "i18n.logOutputEncoding", "cp1251"], repo)
    (repo / "f.txt").write_text("x\n")
    _git(["add", "."], repo)

    # Commit message stored as raw cp1251 bytes (0xCA == Cyrillic 'К'), an
    # invalid standalone UTF-8 sequence.
    msg = "Комментарий: пароль в коде".encode("cp1251")
    assert b"\xca" in msg
    msg_file = tmp_path / "msg.txt"
    msg_file.write_bytes(msg)
    _git(["commit", "-F", str(msg_file)], repo)

    # Must not raise UnicodeDecodeError; cp1251 fallback recovers the Cyrillic.
    text = _git_all_commit_messages(repo)
    assert text is not None
    assert "Комментарий" in text


def test_utf8_commit_message_still_reads(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(["init"], repo)
    _git(["config", "user.email", "t@t.com"], repo)
    _git(["config", "user.name", "T"], repo)
    (repo / "f.txt").write_text("x\n")
    _git(["add", "."], repo)
    _git(["commit", "-m", "Обычный UTF-8 коммит"], repo)

    text = _git_all_commit_messages(repo)
    assert text is not None
    assert "UTF-8" in text
