"""Equivalence guards for the one-shot gitleaks prescan.

The prescan (SecretsDetector.prescan_tree) MUST detect exactly what the per-file
detect() path detects — a missed secret is shipped to the client. These tests
pin the three ways the prescan could diverge:

  1. gitleaks' default path-allowlist (node_modules/, bower_components/, …) makes
     a whole-tree scan SKIP files the per-file path (basename-only) FINDS;
  2. a failed prescan must not leave a stale cache serving old findings;
  3. a populated cache must not swallow commit-metadata targets (cache-miss →
     must fall through to per-file, not be served an empty list).
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from repo_sanitizer.detectors.base import Category, ScanTarget

requires_gitleaks = pytest.mark.skipif(
    shutil.which("gitleaks") is None, reason="gitleaks not installed"
)

RULES_DIR = Path(__file__).parent.parent / "repo_sanitizer" / "rules"


def _bad_report_run(report_text):
    """Return a subprocess.run stub that writes `report_text` (or nothing, if
    None → missing report) to the --report-path and 'succeeds'."""
    def _run(cmd, *a, **k):
        if report_text is not None:
            Path(cmd[cmd.index("--report-path") + 1]).write_text(
                report_text, encoding="utf-8"
            )
        class R:
            returncode = 0
            stdout = stderr = ""
        return R()
    return _run

# The validated high-entropy generic key (matches SecretsDetector._validate).
CANARY = "api_key=Xb7Kp2Lm9Qr4Ts8Wv3Yz6Ac1Df5Gh0Jk\n"

# Paths gitleaks' useDefault allowlist filters by DIRECTORY — a whole-tree scan
# skips these, the per-file (basename) path does not. node_modules/ is the
# canonical, version-stable case and the regression originally confirmed; the
# others are belt-and-suspenders (if a gitleaks version doesn't allowlist one,
# both paths still find it and equivalence holds).
_ALLOWLISTED = [
    "node_modules/pkg/n.txt",
    "bower_components/widget/b.txt",
    "vendor/github.com/acme/v.txt",
    "env/lib/python3.11/site-packages/leak.txt",
    "dist/pkg.dist-info/d.txt",
]
_NORMAL = "src/config.txt"


def _found(findings) -> bool:
    return any(f.category == Category.SECRET for f in findings)


@requires_gitleaks
def test_prescan_matches_per_file_on_allowlisted_dirs(tmp_path):
    """The fix: a secret under a gitleaks-allowlisted DIR (node_modules/…) is
    found by the prescan exactly as by the per-file path. This FAILS on the
    unfixed branch (prescan scanned the real tree → those dirs skipped)."""
    from repo_sanitizer.detectors.secrets import SecretsDetector

    rels = _ALLOWLISTED + [_NORMAL]
    for rel in rels:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(CANARY, encoding="utf-8")

    # Reference: the strict per-file path (cache stays None) finds every one.
    per_file_det = SecretsDetector()
    per_file = {
        rel: _found(per_file_det.detect(ScanTarget(file_path=rel, content=CANARY)))
        for rel in rels
    }
    assert all(per_file.values()), f"per-file path missed: {per_file}"

    # Prescan path: build the cache, then serve from it. Must match per-file.
    pre_det = SecretsDetector()
    pre_det.prescan_tree(tmp_path, rels)
    assert pre_det._cache is not None
    # Every scanned path is a cache member (clean files map to []).
    assert set(pre_det._cache) == set(rels)
    prescan = {
        rel: _found(pre_det.detect(ScanTarget(file_path=rel, content=CANARY)))
        for rel in rels
    }
    assert prescan == per_file, (
        f"prescan diverged from per-file: prescan={prescan} per_file={per_file}"
    )
    # Specifically the confirmed leak: node_modules secret is now FOUND.
    assert prescan["node_modules/pkg/n.txt"] is True


@requires_gitleaks
def test_failed_prescan_clears_cache_no_stale_serve(tmp_path, monkeypatch):
    """A prescan that fails (no report) must leave self._cache is None so detect()
    falls back to per-file — never serve a stale cache from an earlier pass."""
    import repo_sanitizer.detectors.secrets as secrets_mod
    from repo_sanitizer.detectors.secrets import SecretsDetector

    det = SecretsDetector()  # real gitleaks for _validate()
    det._cache = {"old/path.py": []}  # stale cache from a prior pass

    (tmp_path / "f.txt").write_text(CANARY, encoding="utf-8")

    # gitleaks writes no report → prescan_tree must raise (fail closed).
    def _noop_run(*a, **k):
        class R:
            returncode = 1
            stdout = stderr = ""
        return R()

    monkeypatch.setattr(secrets_mod.subprocess, "run", _noop_run)

    with pytest.raises(RuntimeError):
        det.prescan_tree(tmp_path, ["f.txt"])
    assert det._cache is None, "failed prescan must clear the cache (per-file fallback)"


@requires_gitleaks
def test_cache_does_not_swallow_commit_metadata(tmp_path):
    """Under --ner-scope all the working-tree detector (with a populated cache)
    is reused for commit metadata. A <commit:.../field> target is never a SCAN
    relpath → must NOT be served [] from the cache; it must scan per-file."""
    from repo_sanitizer.detectors.secrets import SecretsDetector

    (tmp_path / "real.py").write_text("clean = 1\n", encoding="utf-8")
    det = SecretsDetector()
    det.prescan_tree(tmp_path, ["real.py"])
    assert det._cache == {"real.py": []}  # clean working-tree file: cache hit → []

    # A clean cached path is served from cache (membership hit).
    assert det.detect(ScanTarget(file_path="real.py", content="clean = 1\n")) == []

    # A commit-metadata target carrying a secret is a cache MISS → per-file finds it.
    meta = ScanTarget(file_path="<commit:abc12345/message>", content=CANARY)
    assert _found(det.detect(meta)), (
        "commit-metadata secret must be found per-file, not swallowed by the cache"
    )


@requires_gitleaks
def test_synthetic_path_collision_never_served_from_cache():
    """Even if a synthetic metadata path COLLIDES with a cached (clean) entry —
    a repo file literally named "<commit:.../message>" — the metadata target must
    still be scanned per-file, never served the cached []. The "<...>" bypass is
    the safety net: cache membership alone would swallow this secret."""
    from repo_sanitizer.detectors.secrets import SecretsDetector

    det = SecretsDetector()
    # Worst case: the synthetic path is PRESENT in the cache, marked clean.
    det._cache = {"<commit:abc12345/message>": [], "real.py": []}
    target = ScanTarget(file_path="<commit:abc12345/message>", content=CANARY)
    assert _found(det.detect(target)), (
        "a '<...>' target must bypass the cache and scan per-file even on a "
        "direct cache-key collision"
    )


@requires_gitleaks
def test_corrupt_report_fails_closed(tmp_path, monkeypatch):
    """A truncated/invalid gitleaks JSON report must NOT be read as 'no secrets'
    (which would seed a clean cache for the WHOLE scan set). prescan_tree must
    raise and leave self._cache None → per-file fallback."""
    import repo_sanitizer.detectors.secrets as secrets_mod
    from repo_sanitizer.detectors.secrets import SecretsDetector

    det = SecretsDetector()
    det._cache = {"stale": []}
    (tmp_path / "f.txt").write_text(CANARY, encoding="utf-8")

    # gitleaks writes a present-but-CORRUPT report (e.g. killed mid-write).
    def _corrupt_run(cmd, *a, **k):
        rp = cmd[cmd.index("--report-path") + 1]
        from pathlib import Path as _P
        _P(rp).write_text("{ this is not valid json", encoding="utf-8")
        class R:
            returncode = 0
            stdout = stderr = ""
        return R()

    monkeypatch.setattr(secrets_mod.subprocess, "run", _corrupt_run)

    with pytest.raises(RuntimeError):
        det.prescan_tree(tmp_path, ["f.txt"])
    assert det._cache is None, "corrupt report must fail closed (per-file fallback)"


@requires_gitleaks
def test_empty_report_fails_closed(tmp_path, monkeypatch):
    """A PRESENT but zero-byte/whitespace report (killed mid-write) must NOT be
    read as a clean scan (gitleaks writes "[]\\n" when clean). prescan_tree must
    raise and leave self._cache None → per-file fallback for the whole set."""
    import repo_sanitizer.detectors.secrets as secrets_mod
    from repo_sanitizer.detectors.secrets import SecretsDetector

    det = SecretsDetector()
    det._cache = {"stale": []}
    (tmp_path / "f.txt").write_text(CANARY, encoding="utf-8")

    def _empty_run(cmd, *a, **k):
        from pathlib import Path as _P
        _P(cmd[cmd.index("--report-path") + 1]).write_text("", encoding="utf-8")
        class R:
            returncode = 0
            stdout = stderr = ""
        return R()

    monkeypatch.setattr(secrets_mod.subprocess, "run", _empty_run)

    with pytest.raises(RuntimeError):
        det.prescan_tree(tmp_path, ["f.txt"])
    assert det._cache is None, "empty report must fail closed (per-file fallback)"


@requires_gitleaks
@pytest.mark.parametrize(
    "report_text", [None, "", "   \n", "{ not json"],
    ids=["missing", "empty", "whitespace", "corrupt"],
)
def test_per_file_path_fails_closed(monkeypatch, report_text):
    """The per-file detect() path (cache None) must FAIL CLOSED on a missing /
    empty / corrupt report — never return [] (= 'no secrets' for that file)."""
    import repo_sanitizer.detectors.secrets as secrets_mod
    from repo_sanitizer.detectors.secrets import SecretsDetector

    det = SecretsDetector()  # real gitleaks for _validate
    assert det._cache is None
    monkeypatch.setattr(secrets_mod.subprocess, "run", _bad_report_run(report_text))
    with pytest.raises(RuntimeError):
        det.detect(ScanTarget(file_path="f.txt", content=CANARY))


@requires_gitleaks
@pytest.mark.parametrize("name", ["report.json", "config.json", "data.toml", "x.txt"])
def test_per_file_report_path_not_clobbered(name):
    """A scanned file named "report.json" must NOT collide with the per-file
    gitleaks --report-path — its secret must still be found. Regression for the
    clobber bug: the report previously lived inside the scanned tmpdir, so a
    file named report.json was overwritten by gitleaks' own output and never
    scanned. (Now the report lives in cfgdir, outside the scanned tree.)"""
    from repo_sanitizer.detectors.secrets import SecretsDetector

    det = SecretsDetector()  # cache None → per-file path
    findings = det.detect(ScanTarget(file_path=name, content=CANARY))
    assert _found(findings), f"secret in a file named {name!r} must be found"


@requires_gitleaks
def test_gitleaks_config_named_file_is_equivalent_in_both_paths():
    """KNOWN gitleaks limitation (pre-existing, NOT a prescan regression): a file
    literally named gitleaks.toml/.gitleaks.toml is skipped by gitleaks itself
    (it treats it as a config file), so its secret is missed by BOTH the per-file
    AND the prescan path. Pin that they stay EQUIVALENT (the prescan never does
    worse than the per-file reference) rather than asserting detection."""
    from repo_sanitizer.detectors.secrets import SecretsDetector

    per_file = SecretsDetector()
    pre = SecretsDetector()
    name = "gitleaks.toml"
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / name
        p.write_text(CANARY, encoding="utf-8")
        pre.prescan_tree(Path(d), [name])
    pf = _found(per_file.detect(ScanTarget(file_path=name, content=CANARY)))
    pc = _found(pre.detect(ScanTarget(file_path=name, content=CANARY)))
    assert pf == pc, "prescan must match per-file even for gitleaks-skipped names"


@requires_gitleaks
def test_run_scan_aborts_on_secretsdetector_failure(tmp_path, monkeypatch):
    """End to end: a SecretsDetector failure (gitleaks didn't complete) must
    ABORT run_scan, not be swallowed by its broad detector try/except — else the
    file ships unscanned for secrets. Other detectors keep warn-and-continue."""
    import repo_sanitizer.detectors.secrets as secrets_mod
    from repo_sanitizer.context import (
        FileAction,
        FileCategory,
        InventoryItem,
        RunContext,
    )
    from repo_sanitizer.detectors.secrets import SecretsDetector
    from repo_sanitizer.rulepack import load_rulepack
    from repo_sanitizer.steps.scan import run_scan

    work = tmp_path / "work"
    artifacts = tmp_path / "out" / "artifacts"
    work.mkdir(parents=True)
    artifacts.mkdir(parents=True)
    body = CANARY
    (work / "f.txt").write_text(body, encoding="utf-8")
    ctx = RunContext(
        salt=b"s", work_dir=work, out_dir=tmp_path / "out",
        artifacts_dir=artifacts, rulepack_path=RULES_DIR,
        rulepack=load_rulepack(RULES_DIR),
    )
    ctx.inventory = [
        InventoryItem(path="f.txt", size=len(body), mime="text/plain",
                      category=FileCategory.DOCS, action=FileAction.SCAN)
    ]
    det = SecretsDetector()  # real gitleaks for _validate
    # Every gitleaks run now yields a corrupt report (prescan AND per-file).
    monkeypatch.setattr(secrets_mod.subprocess, "run", _bad_report_run("{ bad"))
    with pytest.raises(RuntimeError):
        run_scan(ctx, [det], "scan_report_pre.json")
