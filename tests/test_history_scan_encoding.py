"""5268dbed (2026-09-07): one cp1251 commit message in an otherwise UTF-8 history aborted the whole Pass-1 —
`run_history_scan` decoded `git log` with a strict `text=True` ("'utf-8' codec can't decode byte 0xd3"). Each commit
record is now decoded on its own with detection, so the scan survives and still finds the PII in that message."""
from __future__ import annotations

import subprocess
from pathlib import Path

from repo_sanitizer.context import RunContext
from repo_sanitizer.detectors.regex_pii import RegexPIIDetector
from repo_sanitizer.rulepack import load_rulepack
from repo_sanitizer.steps.history_scan import run_history_scan

RULES_DIR = Path(__file__).parent.parent / "repo_sanitizer" / "rules"
ENV = {"GIT_AUTHOR_NAME": "Dev", "GIT_AUTHOR_EMAIL": "dev@example.com", "GIT_COMMITTER_NAME": "Dev",
       "GIT_COMMITTER_EMAIL": "dev@example.com", "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"}


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=ENV)


def test_history_scan_survives_a_cp1251_commit_message(tmp_path):
    repo = tmp_path / "work"; repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("one\n")
    _git(repo, "add", "-A"); _git(repo, "commit", "-q", "-m", "первый коммит (utf-8)")
    (repo / "a.txt").write_text("two\n")
    msg = tmp_path / "msg.txt"
    msg.write_bytes("Уточнил контакт: ivan.petrov@client-corp.ru, звонить Утром".encode("cp1251"))   # 0xd3 = У in cp1251
    _git(repo, "add", "-A"); _git(repo, "commit", "-q", "-F", str(msg))
    artifacts = tmp_path / "artifacts"; artifacts.mkdir()
    rp = load_rulepack(RULES_DIR)
    ctx = RunContext(salt=b"test-salt", work_dir=repo, out_dir=tmp_path / "out", artifacts_dir=artifacts,
                     rulepack_path=RULES_DIR, rulepack=rp)
    findings = run_history_scan(ctx, [RegexPIIDetector(rp.pii_patterns)], "history_scan_pre.json")   # must not raise
    values = {f.matched_value for f in findings}
    assert "ivan.petrov@client-corp.ru" in values, values                    # the e-mail inside the cp1251 message is still found
    assert (artifacts / "history_scan_pre.json").is_file()
