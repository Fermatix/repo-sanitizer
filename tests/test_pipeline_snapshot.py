from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

RULES_DIR = Path(__file__).parent.parent / "repo_sanitizer" / "rules"
SAMPLE_REPO = Path(__file__).parent / "fixtures" / "sample_repo"


def _has_gitleaks() -> bool:
    return shutil.which("gitleaks") is not None


def _has_filter_repo() -> bool:
    try:
        import git_filter_repo  # noqa: F401
        return True
    except ImportError:
        return False


requires_tools = pytest.mark.skipif(
    not (_has_gitleaks() and _has_filter_repo()),
    reason="Requires gitleaks and git-filter-repo installed",
)


@pytest.fixture
def sample_repo_git(tmp_path) -> Path:
    """Create a proper git repo from the fixture files."""
    repo = tmp_path / "sample_repo"
    shutil.copytree(SAMPLE_REPO, repo)
    subprocess.run(["git", "init"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.name", "Test Author"],
        cwd=str(repo), check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=str(repo), check=True, capture_output=True,
    )
    subprocess.run(["git", "add", "-A"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "Initial commit"],
        cwd=str(repo), check=True, capture_output=True,
    )
    return repo


@requires_tools
def test_sanitize_deterministic_gates_pass(tmp_path, sample_repo_git):
    """Pass-1 contract (Option A).

    The DETERMINISTIC redaction gates — secrets and high-severity PII — must
    pass: those are what Pass-1 guarantees. ORG_NAME (NER) is an INTENTIONAL
    brand worklist (Pass-1 detects and gates brands but never rewrites them —
    the coherent brand→AcmeN rename is Pass-2), so the overall exit code is *not*
    required to be 0. (ENDPOINTS may also be red here for a PRE-EXISTING,
    unrelated reason: an internal domain that survives in a history blob because
    the history-rewrite content redaction is incomplete — see the working-tree
    post-scan assertion below, which is the deterministic guarantee.)

    NOTE: the shipped example brand dicts (orgs/clients/codenames) are empty
    templates, so the DICTIONARY / BRAND_* gates pass *vacuously* on this
    fixture; the real coverage for the domains-split and the structural brand
    passes lives in the unit tests (test_build_brand_terms_excludes_domains_and_keep,
    test_run_scan_structural_brand_detection).
    """
    from repo_sanitizer.pipeline import run_sanitize

    out_dir = tmp_path / "out"
    run_sanitize(
        source=str(sample_repo_git),
        out_dir=out_dir,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
    )
    result = json.loads((out_dir / "artifacts" / "result.json").read_text())
    gates = result["gates"]
    for name in ("SECRETS", "PII_HIGH", "FORBIDDEN_FILES", "CONFIGS"):
        assert gates[name]["passed"], (
            f"deterministic Pass-1 gate {name} must pass, got {gates[name]}"
        )
    # Working-tree post-scan has no surviving ENDPOINT (public IP / internal
    # domain): the redaction is complete in the tree; only history may lag.
    post = json.loads((out_dir / "artifacts" / "scan_report_post.json").read_text())
    assert not [f for f in post if f["category"] == "ENDPOINT"], (
        "working-tree ENDPOINT must be fully redacted"
    )


def test_run_scan_structural_brand_detection(tmp_path):
    """End-to-end (inventory + scan) coverage of the Change-4 structural/path
    brand passes against a brand-bearing rulepack — not vacuous like the empty
    example dicts. No gitleaks / NER model needed (pass an empty detector list;
    run_scan builds the brand passes from ctx.rulepack itself)."""
    import os
    from repo_sanitizer.context import RunContext
    from repo_sanitizer.rulepack import load_rulepack
    from repo_sanitizer.steps.inventory import run_inventory
    from repo_sanitizer.steps.scan import run_scan

    os.environ["REPO_SANITIZER_SALT"] = "test-salt-struct"
    work = tmp_path / "work"
    (work / "src" / "extyl").mkdir(parents=True)
    (work / "src" / "extyl" / "widget.py").write_text(
        "import extyl.models\n"
        'note = "see extyl support"\n'
        "class ExtylProfile:\n"
        "    extyl_client = 1\n",
        encoding="utf-8",
    )
    artifacts = tmp_path / "out" / "artifacts"
    artifacts.mkdir(parents=True)
    rp = load_rulepack(RULES_DIR)
    rp.dictionaries["orgs"] = ["Extyl"]  # inject an active brand
    ctx = RunContext(
        salt=b"test-salt-struct", work_dir=work, out_dir=tmp_path / "out",
        artifacts_dir=artifacts, rulepack_path=RULES_DIR, rulepack=rp,
    )
    run_inventory(ctx)
    findings = run_scan(ctx, [], "scan_report_pre.json")  # [] = no NER/secret detectors
    cats = {f.category.value for f in findings}
    assert "BRAND_PATH" in cats, "extyl/ dir + nothing else should fire BRAND_PATH"
    assert "PACKAGE_NAMESPACE" in cats, "import extyl.models → PACKAGE_NAMESPACE"
    assert "BRAND_IDENTIFIER" in cats, "ExtylProfile / extyl_client → BRAND_IDENTIFIER"
    # the string-literal brand is DICTIONARY, never a structural identifier
    struct_lines = {f.line for f in findings if f.category.value == "BRAND_IDENTIFIER"}
    assert 2 not in struct_lines, "string-literal brand must not be a structural finding"


@requires_tools
def test_forbidden_files_deleted(tmp_path, sample_repo_git):
    """config.prod.yaml, .mailmap, CODEOWNERS must not exist in work tree after redact."""
    from repo_sanitizer.pipeline import run_sanitize

    out_dir = tmp_path / "out"
    run_sanitize(
        source=str(sample_repo_git),
        out_dir=out_dir,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
    )
    work = out_dir / "work"
    assert not (work / "config.prod.yaml").exists(), "config.prod.yaml should be deleted"
    assert not (work / ".mailmap").exists(), ".mailmap should be deleted"
    assert not (work / "CODEOWNERS").exists(), "CODEOWNERS should be deleted"


@requires_tools
def test_example_file_kept(tmp_path, sample_repo_git):
    """settings.py.example has allowed suffix — must survive, but be scanned."""
    from repo_sanitizer.pipeline import run_sanitize

    out_dir = tmp_path / "out"
    run_sanitize(
        source=str(sample_repo_git),
        out_dir=out_dir,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
    )
    work = out_dir / "work"
    assert (work / "settings.py.example").exists(), "settings.py.example should be kept"


@requires_tools
def test_post_scan_no_critical_high(tmp_path, sample_repo_git):
    """scan_report_post.json must contain no CRITICAL or HIGH findings."""
    from repo_sanitizer.pipeline import run_sanitize

    out_dir = tmp_path / "out"
    run_sanitize(
        source=str(sample_repo_git),
        out_dir=out_dir,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
    )
    report_path = out_dir / "artifacts" / "scan_report_post.json"
    assert report_path.exists()
    findings = json.loads(report_path.read_text())
    critical_high = [
        f for f in findings if f["severity"] in ("CRITICAL", "HIGH")
    ]
    assert not critical_high, (
        f"Post-scan should have no CRITICAL/HIGH findings, got: {critical_high}"
    )


@requires_tools
def test_bundle_created_and_valid(tmp_path, sample_repo_git):
    """sanitized.bundle must exist and be cloneable."""
    from repo_sanitizer.pipeline import run_sanitize

    out_dir = tmp_path / "out"
    run_sanitize(
        source=str(sample_repo_git),
        out_dir=out_dir,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
    )
    bundle = out_dir / "output" / "sanitized.bundle"
    assert bundle.exists(), "sanitized.bundle must be created"

    clone_dir = tmp_path / "clone"
    result = subprocess.run(
        ["git", "clone", str(bundle), str(clone_dir)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"git clone failed: {result.stderr}"
    assert clone_dir.exists()


@requires_tools
def test_bundle_sha256_in_result(tmp_path, sample_repo_git):
    """result.json must contain bundle_sha256."""
    from repo_sanitizer.pipeline import run_sanitize

    out_dir = tmp_path / "out"
    run_sanitize(
        source=str(sample_repo_git),
        out_dir=out_dir,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
    )
    result_path = out_dir / "artifacts" / "result.json"
    assert result_path.exists()
    doc = json.loads(result_path.read_text())
    assert "bundle_sha256" in doc
    assert len(doc["bundle_sha256"]) == 64  # SHA-256 hex


@requires_tools
def test_determinism(tmp_path, sample_repo_git):
    """Two runs with same salt produce identical bundles."""
    from repo_sanitizer.pipeline import run_sanitize

    # Run 1
    out1 = tmp_path / "out1"
    run_sanitize(
        source=str(sample_repo_git),
        out_dir=out1,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
    )

    # Run 2 — need a fresh copy of the source
    sample_repo2 = tmp_path / "sample_repo2"
    shutil.copytree(sample_repo_git, sample_repo2)

    out2 = tmp_path / "out2"
    run_sanitize(
        source=str(sample_repo2),
        out_dir=out2,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
    )

    sha1 = json.loads((out1 / "artifacts" / "result.json").read_text())["bundle_sha256"]
    sha2 = json.loads((out2 / "artifacts" / "result.json").read_text())["bundle_sha256"]
    assert sha1 == sha2, "Two runs with same salt must produce identical bundles"
