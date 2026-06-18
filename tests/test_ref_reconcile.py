from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from repo_sanitizer.redaction.history_ops import Scrubber
from repo_sanitizer.steps.ref_reconcile import _dedupe, _ref_conflict, make_ref_slug

RULES_DIR = Path(__file__).parent.parent / "repo_sanitizer" / "rules"
FIXTURES_DIR = Path(__file__).parent / "fixtures"
SALT = b"test-salt-12345"


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


def _ref_format_ok(slug: str) -> bool:
    return subprocess.run(
        ["git", "check-ref-format", "--branch", slug], capture_output=True
    ).returncode == 0


# ── make_ref_slug: validity, fallback, idempotence ──────────────────────────────

@pytest.mark.parametrize(
    "name",
    [
        "main",
        "develop",
        "feature/login",
        "feature/jane@corp.com",          # email → masked, then sanitized
        "release with space",
        "bad~^:?*[]\\chars",
        "trailing.dot.",
        "name.lock",
        "double..dot",
        "@{weird}",
        "Имя/Ветка",                       # cyrillic
        "..",                              # degenerate → fallback
        "@",                               # degenerate → fallback
        "///",                             # degenerate → fallback
    ],
)
def test_make_ref_slug_always_valid_and_nonempty(name: str):
    # An empty (no-pattern) scrubber isolates the ref-name sanitizer.
    scrubber = Scrubber(SALT)
    slug = make_ref_slug(name, scrubber, SALT)
    assert slug, "slug must never be empty (branch must survive)"
    assert _ref_format_ok(slug), f"{name!r} → {slug!r} is not a valid git ref"


def test_make_ref_slug_keeps_clean_names():
    scrubber = Scrubber(SALT)
    for name in ("main", "develop", "feature/login", "release-1.0"):
        assert make_ref_slug(name, scrubber, SALT) == name


def test_make_ref_slug_is_deterministic_and_idempotent():
    scrubber = Scrubber(SALT)
    a = make_ref_slug("..", scrubber, SALT)
    b = make_ref_slug("..", scrubber, SALT)
    assert a == b and a.startswith("branch-")


def test_make_ref_slug_scrubs_brand_in_name():
    # Pass-3 path: a brand map renames a brand surviving in a branch name.
    rows = [{"pattern": "acme", "replacement": "Acme1", "is_regex": False, "preserve_case": False}]
    scrubber = Scrubber(SALT, brand_map_rows=rows)
    slug = make_ref_slug("feature/acme-login", scrubber, SALT)
    assert "acme" not in slug.lower().replace("acme1", "")
    assert "Acme1" in slug and _ref_format_ok(slug)


def test_dedupe_appends_stable_suffix():
    used: set[str] = set()
    s1 = _dedupe("x", used); used.add(s1)
    s2 = _dedupe("x", used); used.add(s2)
    s3 = _dedupe("x", used)
    assert [s1, s2, s3] == ["x", "x-2", "x-3"]


def test_ref_conflict_detects_directory_file():
    # git forbids a head `foo` coexisting with `foo/bar` (D/F conflict).
    assert _ref_conflict("foo", {"foo/bar"})
    assert _ref_conflict("foo/bar", {"foo"})
    assert _ref_conflict("a/b/c", {"a/b"})
    assert not _ref_conflict("foobar", {"foo"})
    assert not _ref_conflict("foo/baz", {"foo/bar"})


def test_dedupe_resolves_directory_file_conflict():
    # Two source branches scrubbing to `foo` and `foo/x` must both survive: the
    # second is flattened so update-ref can't reject it (and drop a branch).
    used = {"foo"}
    s = _dedupe("foo/x", used)
    assert not _ref_conflict(s, used) and "/" not in s


def test_make_ref_slug_head_is_degenerate():
    # A name that scrubs to a bare "HEAD"/"@" is an ambiguous ref → fallback.
    scrubber = Scrubber(SALT)
    for name in ("HEAD", "@"):
        slug = make_ref_slug(name, scrubber, SALT)
        assert slug.startswith("branch-") and _ref_format_ok(slug)


# ── end-to-end: keep all branches, scrub names, drop tags, scrub all branches ───

@pytest.fixture
def multibranch_repo(tmp_path) -> Path:
    dest = tmp_path / "mb_repo"
    subprocess.run(
        ["bash", str(FIXTURES_DIR / "create_multibranch_repo.sh"), str(dest)],
        check=True, capture_output=True, text=True,
    )
    return dest


def _git(cmd: list[str], cwd: Path) -> str:
    return subprocess.run(["git", *cmd], cwd=str(cwd), capture_output=True, text=True).stdout


def test_remote_only_branch_with_pruned_tip_is_kept(tmp_path):
    """A branch present ONLY as refs/remotes/origin/* (local materialization
    failed) whose tip the commit-map marks pruned (zero) must still be kept via
    its surviving rewritten remote ref — never silently dropped."""
    from repo_sanitizer.context import RunContext
    from repo_sanitizer.steps.ref_reconcile import run_ref_reconcile

    work = tmp_path / "work"
    work.mkdir()

    def g(*a, check=True):
        return subprocess.run(["git", "-C", str(work), *a], capture_output=True, text=True, check=check)

    g("init", "-b", "main"); g("config", "user.email", "a@b.c"); g("config", "user.name", "a")
    (work / "f").write_text("x", encoding="utf-8"); g("add", "-A"); g("commit", "-m", "c1")
    tip = g("rev-parse", "HEAD").stdout.strip()
    # remote-only branch (NO local head), pointing at the surviving ancestor commit
    g("update-ref", "refs/remotes/origin/feature", tip)
    # simulate filter-repo's commit-map marking the intake tip as pruned (zero)
    fr = work / ".git" / "filter-repo"; fr.mkdir(parents=True)
    (fr / "commit-map").write_text(f"old{' ' * 38}new\n{tip} {'0' * 40}\n", encoding="utf-8")

    out = tmp_path / "out"; (out / "artifacts").mkdir(parents=True); (out / "output").mkdir(parents=True)
    ctx = RunContext(
        salt=SALT, work_dir=work, out_dir=out, artifacts_dir=out / "artifacts",
        rulepack_path=RULES_DIR, rulepack=None,
        intake_branch_tips={"main": tip, "feature": tip}, intake_default_branch="main",
    )
    run_ref_reconcile(ctx)

    heads = subprocess.run(
        ["git", "-C", str(work), "for-each-ref", "--format=%(refname:short)", "refs/heads"],
        capture_output=True, text=True,
    ).stdout.split()
    assert "feature" in heads, "remote-only pruned-tip branch was silently dropped"
    assert "main" in heads
    assert ctx.branch_rename_map.get("feature") == "feature"


@requires_tools
def test_keep_all_branches_drop_tags_scrub_names(tmp_path, multibranch_repo):
    from repo_sanitizer.pipeline import run_sanitize

    out_dir = tmp_path / "out"
    exit_code = run_sanitize(
        source=str(multibranch_repo),
        out_dir=out_dir,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
        ner_scope="off",
    )
    assert exit_code == 0
    bundle = out_dir / "output" / "sanitized.bundle"
    assert bundle.exists()

    heads_raw = _git(["bundle", "list-heads", str(bundle)], tmp_path)
    head_refs = [ln.split()[1] for ln in heads_raw.splitlines() if "refs/heads/" in ln]

    # All three branches survive (one renamed because its name held an email).
    assert "refs/heads/main" in head_refs
    assert "refs/heads/develop" in head_refs           # benign name survives verbatim
    assert len([r for r in head_refs]) == 3            # no branch lost

    # No tags, no remote-tracking refs ship.
    assert "refs/tags/" not in heads_raw
    assert "refs/remotes/" not in heads_raw

    # The email in the BRANCH NAME is gone from every head name.
    joined = "\n".join(head_refs)
    assert "corp.com" not in joined and "jane" not in joined

    # Clone the bundle: succeeds, checks out the (benign) default branch.
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", str(bundle), str(clone)], check=True, capture_output=True, text=True)
    assert _git(["symbolic-ref", "--short", "HEAD"], clone).strip() == "main"

    # Content + commit-message PII scrubbed across ALL branches (incl. develop's
    # unique commit, which is not reachable from main).
    all_msgs = _git(["log", "--all", "--format=%B"], clone)
    assert "corp.com" not in all_msgs
    all_emails = _git(["log", "--all", "--format=%ae"], clone)
    assert all_emails.strip(), "expected some commits"
    assert all(line.endswith("@example.invalid") for line in all_emails.splitlines() if line.strip())

    # develop's app.py email is scrubbed in content too.
    app = _git(["show", "develop:app.py"], clone)
    assert "corp.com" not in app

    # No tags in the clone.
    assert not _git(["tag"], clone).strip()
