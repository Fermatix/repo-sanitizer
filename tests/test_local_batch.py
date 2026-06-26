from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from repo_sanitizer.batch.local import (
    _build_tasks,
    _derive_key,
    _filter_tasks,
    _https_to_ssh,
    _inject_creds,
    parse_list_file,
    preflight_auth,
    run_local_batch,
)


def _run(cmd: list[str], cwd: Path) -> None:
    subprocess.run(cmd, cwd=str(cwd), check=True, capture_output=True, text=True)


def _make_repo(path: Path, name: str) -> None:
    path.mkdir(parents=True, exist_ok=True)
    _run(["git", "init", "-q", "-b", "main"], path)
    _run(["git", "config", "user.email", "t@e.com"], path)
    _run(["git", "config", "user.name", "T"], path)
    (path / "README.md").write_text(f"# {name} admin@example.com\n", encoding="utf-8")
    (path / "app.py").write_text(f'def f():\n    return "{name}"\n', encoding="utf-8")
    _run(["git", "add", "-A"], path)
    _run(["git", "commit", "-qm", f"init {name}"], path)


# ---- pure-function units -------------------------------------------------

@pytest.mark.parametrize(
    "source,expected",
    [
        ("https://gitlab.com/group/sub/4kmonitor", "4kmonitor"),
        ("https://gitlab.com/group/repo.git", "repo"),
        ("git@gitlab.com:group/sub/myrepo.git", "myrepo"),
        ("/home/x/accepted/12869880-f4d7.bundle", "12869880-f4d7"),
        ("/home/x/matched/org/somerepo/", "somerepo"),
        ("./local", "local"),
    ],
)
def test_derive_key(source: str, expected: str):
    assert _derive_key(source) == expected


def test_build_tasks_dedupes_colliding_keys(tmp_path: Path):
    tasks = _build_tasks(["x/a", "y/a", "z/a"], tmp_path)
    assert [t.key for t in tasks] == ["a", "a-2", "a-3"]
    assert tasks[1].out_dir == str(tmp_path / "a-2")


def test_parse_list_file_skips_comments_and_blanks_and_dupes(tmp_path: Path):
    f = tmp_path / "repos.txt"
    f.write_text("# header\n\n/a\n/b\n/a\n  # indented comment\n/c\n", encoding="utf-8")
    assert parse_list_file(f) == ["/a", "/b", "/c"]


def test_parse_list_file_empty_raises(tmp_path: Path):
    f = tmp_path / "repos.txt"
    f.write_text("# only comments\n\n", encoding="utf-8")
    with pytest.raises(ValueError):
        parse_list_file(f)


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://gitlab.com/group/repo", "git@gitlab.com:group/repo.git"),
        ("https://github.com/org/repo.git", "git@github.com:org/repo.git"),
        ("https://bitbucket.org/ws/repo", "git@bitbucket.org:ws/repo.git"),
    ],
)
def test_https_to_ssh(url: str, expected: str):
    assert _https_to_ssh(url) == expected


def test_inject_creds_url_encodes_and_keeps_path():
    out = _inject_creds("https://gitlab.com/g/r.git", "oauth2", "tok/en+1")
    assert out == "https://oauth2:tok%2Fen%2B1@gitlab.com/g/r.git"


def test_preflight_skips_local_sources(tmp_path: Path):
    # local paths / bundles never need auth -> nothing unresolved, no network
    tasks = _build_tasks([str(tmp_path / "a"), str(tmp_path / "b.bundle")], tmp_path)
    assert preflight_auth(tasks) == []


def test_filter_tasks_skips_done_retries_failed(tmp_path: Path):
    tasks = _build_tasks(["x/a", "y/b", "z/c"], tmp_path)
    state = {"a": {"status": "done"}, "b": {"status": "failed"}}
    # default: skip done AND failed (failed only retried on demand)
    assert [t.key for t in _filter_tasks(tasks, state, retry_failed=False)] == ["c"]
    # retry_failed: re-run the failed one too
    assert [t.key for t in _filter_tasks(tasks, state, retry_failed=True)] == ["b", "c"]


# ---- end-to-end (NER off, local sources) ---------------------------------

def test_run_local_batch_end_to_end(tmp_path: Path, rules_path: Path):
    a = tmp_path / "repo-a"
    b = tmp_path / "repo-b"
    _make_repo(a, "alpha")
    _make_repo(b, "beta")
    list_file = tmp_path / "repos.txt"
    list_file.write_text(f"# repos\n{a}\n\n{b}\n", encoding="utf-8")
    out = tmp_path / "out"

    code = run_local_batch(
        list_file=list_file, rulepack=rules_path, out=out,
        workers=2, ner_scope="off",
    )
    assert code == 0
    # per-repo output bundle
    assert (out / "repo-a" / "output" / "sanitized.bundle").is_file()
    assert (out / "repo-b" / "output" / "sanitized.bundle").is_file()
    # summary + state
    summary = json.loads((out / "batch_summary.json").read_text())
    assert summary["total"] == 2 and summary["done"] == 2 and summary["failed"] == 0
    assert (out / ".sanitize_batch_state.json").is_file()

    # re-run skips everything (idempotent), still exit 0
    code2 = run_local_batch(
        list_file=list_file, rulepack=rules_path, out=out,
        workers=2, ner_scope="off",
    )
    assert code2 == 0
