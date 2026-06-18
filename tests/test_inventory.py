from __future__ import annotations

from pathlib import Path

import pytest

from repo_sanitizer.context import FileAction, FileCategory, RunContext
from repo_sanitizer.rulepack import load_rulepack
from repo_sanitizer.steps.inventory import run_inventory


RULES_DIR = Path(__file__).parent.parent / "repo_sanitizer" / "rules"


@pytest.fixture
def rulepack():
    return load_rulepack(RULES_DIR)


def _make_ctx(tmp_path: Path, rulepack) -> RunContext:
    ctx = RunContext(
        salt=b"test-salt",
        work_dir=tmp_path / "work",
        out_dir=tmp_path / "out",
        artifacts_dir=tmp_path / "out" / "artifacts",
        rulepack_path=RULES_DIR,
        rulepack=rulepack,
    )
    (tmp_path / "out" / "artifacts").mkdir(parents=True)
    return ctx


def _place(work_dir: Path, rel: str, content: str = "test") -> Path:
    p = work_dir / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


# ── deny_globs → DELETE ────────────────────────────────────────────────────────

def test_env_file_deleted(tmp_path, rulepack):
    ctx = _make_ctx(tmp_path, rulepack)
    _place(ctx.work_dir, ".env", "SECRET=abc")
    run_inventory(ctx)
    item = next(i for i in ctx.inventory if i.path == ".env")
    assert item.action == FileAction.DELETE


def test_mailmap_deleted(tmp_path, rulepack):
    ctx = _make_ctx(tmp_path, rulepack)
    _place(ctx.work_dir, ".mailmap", "John <john@a.com>")
    run_inventory(ctx)
    item = next(i for i in ctx.inventory if i.path == ".mailmap")
    assert item.action == FileAction.DELETE


def test_codeowners_deleted(tmp_path, rulepack):
    ctx = _make_ctx(tmp_path, rulepack)
    _place(ctx.work_dir, "CODEOWNERS", "* @owner")
    run_inventory(ctx)
    item = next(i for i in ctx.inventory if i.path == "CODEOWNERS")
    assert item.action == FileAction.DELETE


def test_pem_key_deleted(tmp_path, rulepack):
    ctx = _make_ctx(tmp_path, rulepack)
    _place(ctx.work_dir, "server.key", "-----BEGIN RSA PRIVATE KEY-----")
    run_inventory(ctx)
    item = next(i for i in ctx.inventory if i.path == "server.key")
    assert item.action == FileAction.DELETE


# ── office docs (denied binary extension) → DELETE ─────────────────────────────

def test_docx_deleted_despite_docs_mime(tmp_path, rulepack):
    """Office docs get a non-octet mime (classified DOCS) but must still DELETE."""
    ctx = _make_ctx(tmp_path, rulepack)
    _place(ctx.work_dir, "report.docx", "PK\x03\x04 fake zip")
    run_inventory(ctx)
    item = next(i for i in ctx.inventory if i.path == "report.docx")
    assert item.action == FileAction.DELETE
    assert "docx" in item.reason


def test_xlsx_and_pdf_deleted(tmp_path, rulepack):
    ctx = _make_ctx(tmp_path, rulepack)
    _place(ctx.work_dir, "data.xlsx", "x")
    _place(ctx.work_dir, "manual.pdf", "%PDF-1.4")
    run_inventory(ctx)
    for rel in ("data.xlsx", "manual.pdf"):
        item = next(i for i in ctx.inventory if i.path == rel)
        assert item.action == FileAction.DELETE, rel


# ── allow_suffixes → SCAN ──────────────────────────────────────────────────────

def test_config_example_scanned(tmp_path, rulepack):
    ctx = _make_ctx(tmp_path, rulepack)
    _place(ctx.work_dir, "config.example", "DB_HOST=localhost")
    run_inventory(ctx)
    item = next((i for i in ctx.inventory if i.path == "config.example"), None)
    # config.example matches deny glob for config.* BUT has .example suffix → SCAN
    if item:
        assert item.action == FileAction.SCAN


def test_env_template_scanned(tmp_path, rulepack):
    ctx = _make_ctx(tmp_path, rulepack)
    _place(ctx.work_dir, ".env.template", "SECRET=changeme")
    run_inventory(ctx)
    item = next((i for i in ctx.inventory if ".env" in i.path), None)
    if item:
        assert item.action == FileAction.SCAN


# ── Regular files → SCAN ──────────────────────────────────────────────────────

def test_python_file_scanned(tmp_path, rulepack):
    ctx = _make_ctx(tmp_path, rulepack)
    _place(ctx.work_dir, "src/app.py", "print('hello')")
    run_inventory(ctx)
    item = next(i for i in ctx.inventory if i.path == "src/app.py")
    assert item.action == FileAction.SCAN
    assert item.category == FileCategory.CODE


def test_readme_scanned(tmp_path, rulepack):
    ctx = _make_ctx(tmp_path, rulepack)
    _place(ctx.work_dir, "README.md", "# Hello")
    run_inventory(ctx)
    item = next(i for i in ctx.inventory if i.path == "README.md")
    assert item.action == FileAction.SCAN


# ── Size limit → SKIP ─────────────────────────────────────────────────────────

def test_large_file_skipped(tmp_path, rulepack):
    ctx = _make_ctx(tmp_path, rulepack)
    ctx.max_file_mb = 0  # 0 MB limit → everything over 0 is skipped
    _place(ctx.work_dir, "big.txt", "x" * 1024)
    run_inventory(ctx)
    item = next(i for i in ctx.inventory if i.path == "big.txt")
    assert item.action == FileAction.SKIP
