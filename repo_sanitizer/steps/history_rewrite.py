from __future__ import annotations

import ipaddress
import json
import logging
import os
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

import repo_sanitizer
from repo_sanitizer.context import RunContext
from repo_sanitizer.detectors.secrets import (
    _read_gitleaks_report,
    build_gitleaks_config,
)
from repo_sanitizer.encoding import decode_bytes_detect
from repo_sanitizer.rulepack import Rulepack

logger = logging.getLogger(__name__)


def _git_all_commit_messages(work) -> str | None:
    """All commit-message text (``git log --all --format=%B``), decoded with
    encoding detection.

    Commit messages carry arbitrary bytes: Russian repos routinely use cp1251,
    whose 0xC0-0xFF bytes are not valid standalone UTF-8. Letting subprocess
    decode the output as text (strict UTF-8) therefore aborts the whole run with
    e.g. ``'utf-8' codec can't decode byte 0xca ... invalid continuation byte``.
    Capture bytes instead and run them through ``decode_bytes_detect``
    (UTF-8 -> cp1251 -> replace), so a legacy-encoded message never crashes the
    history scan. Returns ``None`` when git itself fails.
    """
    r = subprocess.run(
        ["git", "log", "--all", "--format=%B%x00"],
        cwd=str(work),
        capture_output=True,
    )
    if r.returncode != 0:
        return None
    text, _enc = decode_bytes_detect(r.stdout)
    return text


@dataclass
class FilterPlan:
    """What a single git-filter-repo pass should rewrite.

    One plan drives both the Pass-1 ``sanitize`` rewrite (authors + all PII +
    secret literals, NO brands) and the Pass-3 ``apply-map`` rewrite (brand map
    only). Empty lists are no-ops, so the same generated script serves both.
    """

    rewrite_authors: bool = True
    pii_pattern_defs: list = field(default_factory=list)       # [(name, pattern_str)]
    secret_literals: list = field(default_factory=list)        # [str]
    person_literals: list = field(default_factory=list)        # NER PER names → ANON_PER_*
    brand_map_rows: list = field(default_factory=list)         # [{pattern, replacement, ...}]
    deny_globs: list = field(default_factory=list)
    binary_deny_extensions: list = field(default_factory=list)
    allow_suffixes: list = field(default_factory=list)         # never-delete suffixes
    keep: list = field(default_factory=list)                   # allowlisted IP/domain literals
    scrub_public_ips: bool = False                             # Pass-1 only (public-IP pass)
    scrub_urls: bool = False                                   # Pass-1 only (non-allowlisted URL-host pass)


def run_history_rewrite(ctx: RunContext) -> None:
    """Pass-1 history rewrite: authors + all PII (messages & blobs) + full-history
    secret literals + deny/binary file deletion. Brands are NOT rewritten here
    (detection-only; the coherent brand→AcmeN map is applied later by ``apply-map``)."""
    rulepack: Rulepack = ctx.rulepack
    # Same keep-set that scan.py feeds EndpointDetector — so the Scrubber's
    # public-IP pass exempts exactly the allowlisted IP/domain literals.
    from repo_sanitizer.steps.scan import build_brand_terms
    _brand_terms, keep = build_brand_terms(rulepack)
    plan = FilterPlan(
        rewrite_authors=True,
        pii_pattern_defs=[(p.name, p.pattern.pattern) for p in rulepack.pii_patterns],
        secret_literals=_collect_secret_literals(ctx),
        person_literals=_collect_person_literals(ctx),
        brand_map_rows=[],
        deny_globs=rulepack.deny_globs,
        binary_deny_extensions=rulepack.binary_deny_extensions,
        allow_suffixes=rulepack.allow_suffixes,
        keep=sorted(keep),
        scrub_public_ips=True,
        scrub_urls=True,
    )
    _run_filter_repo(ctx, plan, "_filter_repo_script.py", "history_rewrite_log.txt")
    logger.info("History rewrite complete")


def run_brand_map_rewrite(ctx: RunContext, brand_map_rows: list) -> None:
    """Pass-3 history rewrite: apply the Pass-2 tiered brand map across every
    blob, commit message, and path segment. No author/PII/secret/deletion work
    (Pass-1 already did that) — purely the brand → placeholder substitution."""
    plan = FilterPlan(
        rewrite_authors=False,
        pii_pattern_defs=[],
        secret_literals=[],
        brand_map_rows=brand_map_rows,
        deny_globs=[],
        binary_deny_extensions=[],
    )
    _run_filter_repo(ctx, plan, "_apply_map_script.py", "apply_map_log.txt")
    logger.info("Brand-map history rewrite complete")


def _gitleaks_secret_values(args: list[str], cwd: str, timeout: int = 600) -> tuple[list[str], bool]:
    """Run a gitleaks command writing a JSON report and return (secret_values, ok).

    ``args`` must NOT include the report flags — they are appended here. ``ok`` is
    False if gitleaks failed to produce a report (fatal config/install error), so
    callers can decide whether to continue best-effort or fail closed.
    """
    with tempfile.TemporaryDirectory() as td:
        report = os.path.join(td, "gl.json")
        cfg = os.path.join(td, "gitleaks.toml")
        # Detect everything; override any repo-shipped .gitleaks.toml so a partner
        # repo cannot allowlist its own secrets past collection.
        Path(cfg).write_text(build_gitleaks_config(allowlist_masks=False), encoding="utf-8")
        subprocess.run(
            args + ["--config", cfg, "--ignore-gitleaks-allow",
                    "--report-format", "json", "--report-path", report, "--no-banner"],
            capture_output=True, text=True, timeout=timeout, cwd=cwd,
        )
        # Best-effort collection: a missing / empty / corrupt report means we
        # collected nothing HERE (ok=False → caller logs and continues). It must
        # NOT be reported as a successful empty result — the fail-closed
        # post-rewrite gate (run_history_secret_gate) is the real backstop.
        try:
            items = _read_gitleaks_report(Path(report), context="history collection")
        except RuntimeError:
            return [], False
        return [it.get("Secret", "") for it in items if it.get("Secret")], True


def _collect_secret_literals(ctx: RunContext) -> list[str]:
    """Secret VALUES to scrub from history as exact literals.

    gitleaks is not applied per-history-blob (the rewrite is regex-only), so a
    secret committed-then-deleted in an old commit would survive. Collect such
    values cheaply (Go, ~seconds): (1) a FULL-HISTORY gitleaks pass over
    ``work_dir`` in native git mode (NOT ``--no-git`` → scans every commit/branch's
    BLOB content), (2) a pass over all commit MESSAGE text (gitleaks native mode
    does not scan messages), and (3) the working-tree + history-blob pre-scan
    SecretsDetector / EndpointDetector findings. Tiny/ambiguous values (< 5 chars)
    are dropped. Best-effort: a gitleaks failure here is backstopped by the
    fail-closed post-rewrite secret gate (``run_history_secret_gate``).
    """
    secrets: set[str] = set()
    finding_sources = (
        list(getattr(ctx, "pre_findings", []) or [])
        + list(getattr(ctx, "history_blob_pre_findings", []) or [])
    )
    for f in finding_sources:
        det = getattr(f, "detector", "")
        val = getattr(f, "matched_value", "")
        # RuLegalIdDetector (checksum-valid bare ИНН/ОГРН) is a CODE detector the
        # Scrubber does not re-apply, so its exact-digit findings are collected as
        # literals here to be masked across history (the regex inn/ogrn/kpp/fio
        # patterns are re-applied by the Scrubber via pii_pattern_defs).
        if val and det in ("SecretsDetector", "EndpointDetector", "RuLegalIdDetector"):
            # A public-IP endpoint is masked to a VALID documentation-range IP by
            # the scrubber's public-IP pass; collecting it as an exact literal would
            # instead stamp REDACTED_<hash> over it (a non-IP that breaks a
            # compose/k8s/nginx field). Leave IP literals to the doc-range pass.
            try:
                ipaddress.ip_address(val.strip("[]"))
                continue
            except ValueError:
                pass
            secrets.add(val)

    work = str(ctx.work_dir)
    try:
        # (1) full-history blob content. `--log-opts=--all` is EXPLICIT so coverage
        # spans EVERY branch (heads + remotes), not just HEAD's reachable commits —
        # the deliverable keeps ALL branches, so a secret living only in a non-HEAD
        # branch must be collected regardless of gitleaks' default / a repo
        # `.gitleaks.toml logOpts`.
        vals, ok = _gitleaks_secret_values(
            ["gitleaks", "detect", "--source", work, "--log-opts=--all"], cwd=work
        )
        secrets.update(vals)
        if not ok:
            logger.warning("full-history gitleaks pass produced no report (continuing best-effort)")
        # (2) commit MESSAGE text — gitleaks native mode does not scan messages
        log = subprocess.run(
            ["git", "log", "--all", "--format=%B%x00"],
            cwd=work, capture_output=True, text=True,
        )
        if log.returncode == 0 and log.stdout.strip():
            with tempfile.TemporaryDirectory() as md:
                (Path(md) / "messages.txt").write_text(log.stdout, encoding="utf-8")
                mvals, _ = _gitleaks_secret_values(
                    ["gitleaks", "detect", "--no-git", "--source", md], cwd=md
                )
                secrets.update(mvals)
    except FileNotFoundError:
        logger.warning("gitleaks not found; skipping full-history secret collection")
    except Exception as e:  # noqa: BLE001 — collection is best-effort (gate backstops)
        logger.warning("full-history gitleaks pass failed (continuing): %s", e)

    return _filter_literals(work, [s for s in secrets if len(s) >= 5], secret=True)


def _path_basenames(work: str) -> set[str]:
    """Every file/dir basename (with and without extension) tracked in the work
    tree — exact-replacing such a token in CONTENT desyncs it from the unrenamed
    on-disk name (broken import path / docker build-context / COPY / WORKDIR)."""
    try:
        r = subprocess.run(
            ["git", "ls-files"], cwd=work, capture_output=True, text=True, timeout=60
        )
    except Exception:  # noqa: BLE001
        return set()
    names: set[str] = set()
    for line in r.stdout.splitlines():
        for part in line.replace("\\", "/").split("/"):
            if part:
                names.add(part)
                stem = part.rsplit(".", 1)[0]
                if stem:
                    names.add(stem)
    return names


def _filter_literals(work: str, values, *, secret: bool) -> list[str]:
    """Drop build-load-bearing / non-credential literals from the exact-replace set
    so they don't clobber code. Dropped for BOTH secret + person literals: dotted
    versions (4.0.0.0), public domains / package-with-dots (lodash is handled by the
    dict-word rule; cloud.google.com here), work-tree path basenames, and declared
    code identifiers. SECRET literals additionally drop low-entropy plain
    identifiers / dictionary words (Dashboard, blockchain, acme3) — a real surname
    of that shape must NOT be dropped from PERSON literals, so that rule is
    secret-only. Safe: a real secret/name dropped here is re-caught by the
    fail-closed post-rewrite gitleaks gate / re-flagged by NER → a Pass-2 worklist
    item, never a silent leak. (The word-boundaried matcher in history_ops then
    stops any KEPT identifier literal from clobbering a larger identifier.)"""
    from repo_sanitizer.buildsafe import (
        is_bare_domain,
        is_dotted_version,
        is_identifier,
        looks_low_value_identifier,
    )
    basenames = _path_basenames(work)
    out: list[str] = []
    for v in sorted(set(values), key=len, reverse=True):
        if is_dotted_version(v) or is_bare_domain(v) or v in basenames:
            continue
        if is_identifier(v):
            if _is_declared_identifier(work, v):
                continue
            if secret and looks_low_value_identifier(v):
                continue
        out.append(v)
    return out


def _is_declared_identifier(work: str, value: str) -> bool:
    """True if ``value`` appears as a DECLARED code symbol (class/interface/func/
    type/namespace name) in the working tree — i.e. it is code, not a credential.
    Only called for identifier-shaped values, so the cost is a handful of greps."""
    pat = (
        r"(class|interface|enum|struct|trait|protocol|namespace|object|type|"
        r"func|fun|def|void|record|module)[ \t]+" + value + r"([^A-Za-z0-9_]|$)"
    )
    try:
        r = subprocess.run(
            ["git", "grep", "-I", "-l", "-E", "-e", pat, "--", "."],
            cwd=work, capture_output=True, text=True, timeout=60,
        )
    except Exception:  # noqa: BLE001 — best-effort; treat a grep failure as "not declared"
        return False
    return bool(r.stdout.strip())


def _collect_person_literals(ctx: RunContext) -> list[str]:
    """NER PERSON names to scrub from history as literals.

    The history rewrite (blob_callback) applies regex PII + secret literals but
    NOT the NER model. git-filter-repo resets the working tree from the rewritten
    blobs, so a person name that was redacted in the working tree (Step-4) but not
    by blob_callback would REAPPEAR in the shipped HEAD. Feed NER PER values found
    on the working tree (and, under --ner-scope all, in history blobs) as literals
    so blob_callback masks them everywhere → ANON_PER_<hash>. NER ORG findings are
    NOT collected here — orgs are brands and stay detection-only (the Pass-2
    worklist), exactly like the dictionary/structural brand passes.
    """
    from repo_sanitizer.detectors.base import Category

    names: set[str] = set()
    for f in (list(getattr(ctx, "pre_findings", []) or [])
              + list(getattr(ctx, "history_blob_pre_findings", []) or [])):
        if getattr(f, "detector", "") == "NERDetector" and getattr(f, "category", None) == Category.PII:
            val = (getattr(f, "matched_value", "") or "").strip()
            if len(val) >= 3:
                names.add(val)
    # Same build-load-bearing guard as secrets (versions / domains / path basenames /
    # declared identifiers) — a NER false-positive on `Queue`/`Dashboard` must not
    # clobber code; the low-entropy dict-word rule is secret-only so real short
    # surnames survive.
    return _filter_literals(str(ctx.work_dir), names, secret=False)


def run_history_secret_gate(ctx: RunContext) -> list:
    """FAIL-CLOSED post-rewrite verification: full-history gitleaks over the
    REWRITTEN repo. Any surviving secret (that is not one of our own placeholder
    masks) is returned as a SECRET Finding so the SECRETS gate fails. This is the
    backstop for every way ``_collect_secret_literals`` could miss a value
    (message-only, < 5 chars, repo-config-allowlisted, non-utf8, gitleaks FN on
    the pre-rewrite shape). Raises if gitleaks cannot produce a report — refusing
    to certify "no secrets" on a tool error. ``--ignore-gitleaks-allow`` defeats
    any partner ``# gitleaks:allow`` comment that would otherwise suppress a leak.
    """
    from repo_sanitizer.detectors.base import Category, Finding, Severity

    work = str(ctx.work_dir)

    def _run(args: list[str], cwd: str, label: str) -> list[dict]:
        with tempfile.TemporaryDirectory() as td:
            report = os.path.join(td, "gl.json")
            cfg = os.path.join(td, "gitleaks.toml")
            # allowlist OUR masks (present post-rewrite); useDefault rules otherwise.
            Path(cfg).write_text(build_gitleaks_config(allowlist_masks=True), encoding="utf-8")
            try:
                subprocess.run(
                    args + ["--config", cfg, "--ignore-gitleaks-allow",
                            "--report-format", "json", "--report-path", report, "--no-banner"],
                    capture_output=True, text=True, timeout=600, cwd=cwd,
                )
            except FileNotFoundError as e:
                raise RuntimeError("gitleaks not installed; cannot verify history secrets") from e
            # FAIL CLOSED on a missing / empty / corrupt report — never certify
            # history secret-free from a report gitleaks did not fully write (an
            # empty report read as "[]" would silently pass the shipping gate).
            return _read_gitleaks_report(
                Path(report), context=f"post-rewrite {label}"
            )

    # (1) full-history blob content. `--log-opts=--all` is EXPLICIT so the gate
    # verifies EVERY shipped branch (the deliverable keeps them all), never just
    # HEAD's reachable commits — see the same note in _collect_secret_literals.
    items = list(_run(["gitleaks", "detect", "--source", work, "--log-opts=--all"], work, "blobs"))
    # (2) commit MESSAGE text — native gitleaks does not scan messages, so dump
    # them and scan as a flat file (mirrors the collection pass).
    msg_text = _git_all_commit_messages(work)
    if msg_text and msg_text.strip():
        with tempfile.TemporaryDirectory() as md:
            (Path(md) / "messages.txt").write_text(msg_text, encoding="utf-8")
            for it in _run(["gitleaks", "detect", "--no-git", "--source", md], md, "messages"):
                it["File"] = "<commit-message>"
                items.append(it)

    findings: list = []
    for it in items:
        secret = it.get("Secret", "")
        if not secret:
            continue
        f = Finding(
            detector="SecretsDetector",
            category=Category.SECRET,
            severity=Severity.CRITICAL,
            file_path=f"<history:{it.get('File', '?')}@{str(it.get('Commit', ''))[:8]}>",
            line=int(it.get("StartLine", 0) or 0),
            offset_start=0,
            offset_end=0,
            matched_value=secret,
        )
        f.compute_hash(ctx.salt)
        findings.append(f)
    return findings


def verify_brand_map_applied(ctx: RunContext, brand_map_rows: list, max_report: int = 50) -> list[str]:
    """Re-scan the rewritten history for any of the brand map's OWN patterns.

    Confirms apply-map actually applied the map everywhere — a pattern that still
    matches a blob/path/message means the rewrite skipped it (e.g. an encoding the
    brand pass couldn't decode), so apply-map must NOT report success. This does
    NOT certify brand-COMPLETENESS — a brand the Pass-2 map never listed is the
    mandatory Pass-2 codex/agent audit's job, not something a mechanical pass can
    know. Returns a capped list of 'where' strings (empty = map fully applied).
    """
    from repo_sanitizer.redaction.history_ops import compile_brand_map
    from repo_sanitizer.steps.history_blob_scan import _collect_all_blobs

    compiled = compile_brand_map(brand_map_rows)
    if not compiled:
        return []

    work = ctx.work_dir
    survivors: list[str] = []

    def _hits(text: str) -> bool:
        return any(rx.search(text) for rx, _repl, _pc in compiled)

    # CONTENT: one check per unique blob (SHA-dedup is CORRECT here — identical
    # content yields an identical match result).
    for blob_sha, _path in _collect_all_blobs(work):
        res = subprocess.run(
            ["git", "cat-file", "blob", blob_sha], cwd=str(work), capture_output=True
        )
        if res.returncode == 0 and b"\x00" not in res.stdout[:8192]:
            try:
                text, _enc = decode_bytes_detect(res.stdout)
            except Exception:  # noqa: BLE001
                text = ""
            if text and _hits(text):
                survivors.append(f"blob:{blob_sha[:8]}/{_path}")
                if len(survivors) >= max_report:
                    return survivors

    # PATHS: every DISTINCT path across all commits — NOT via the blob-deduped
    # _collect_all_blobs (two paths sharing one blob would drop a brand path).
    # `git log --all --name-only` lists full paths (dir + file) for every
    # add/modify/delete, so a brand in any dir or file name is checked. The same
    # path set drives the JSON-manifest check below.
    plog = subprocess.run(
        ["git", "log", "--all", "--pretty=format:", "--name-only"],
        cwd=str(work), capture_output=True, text=True,
    )
    distinct_paths = (
        {ln.strip() for ln in plog.stdout.splitlines() if ln.strip()}
        if plog.returncode == 0 else set()
    )
    for path in distinct_paths:
        if _hits(path):
            survivors.append(f"path:{path}")
            if len(survivors) >= max_report:
                return survivors

    # JSON-manifest validity: a brand rewrite that mangles a strict-JSON build
    # manifest (collapsing distinct keys → an invalid `acme1,`) is a Pass-2
    # build-breaker apply-map must catch. Reported as `json-invalid:<path>@<sha>`
    # so it contributes to the non-zero exit alongside brand survivors.
    survivors.extend(
        _json_manifest_failures(work, distinct_paths, max_report - len(survivors))
    )
    if len(survivors) >= max_report:
        return survivors[:max_report]

    msg_text = _git_all_commit_messages(work)
    if msg_text and _hits(msg_text):
        survivors.append("commit-message")
    return survivors


# Strict-JSON build manifests only — NOT JSONC (tsconfig*.json), whose legal
# comments / trailing commas would false-fail json.loads.
_STRICT_JSON_MANIFESTS = {
    "package.json",
    "package-lock.json",
    "composer.json",
    "composer.lock",
}


def _json_manifest_failures(work, distinct_paths: set[str], budget: int) -> list[str]:
    """Return ``json-invalid:<path>@<sha>`` for every strict-JSON build manifest
    whose content fails to parse, enumerating BY PATH (not the SHA-deduped blob
    list — a manifest blob could otherwise be hidden behind a shared blob's
    non-manifest representative path). Each manifest path's historical versions
    are resolved to blob SHAs (deduped — identical bytes parse identically) and
    parsed. ``json.loads`` does NOT flag duplicate keys; that semantic collision
    is the map-build collision warning's job, not this build-breakage check."""
    if budget <= 0:
        return []
    manifest_paths = {
        p for p in distinct_paths if p.rsplit("/", 1)[-1] in _STRICT_JSON_MANIFESTS
    }
    if not manifest_paths:
        return []

    blob_to_path: dict[str, str] = {}
    for path in manifest_paths:
        commits = subprocess.run(
            ["git", "log", "--all", "--format=%H", "--", path],
            cwd=str(work), capture_output=True, text=True,
        )
        if commits.returncode != 0:
            continue
        for commit in commits.stdout.split():
            rp = subprocess.run(
                ["git", "rev-parse", f"{commit}:{path}"],
                cwd=str(work), capture_output=True, text=True,
            )
            sha = rp.stdout.strip()
            if rp.returncode == 0 and sha:
                blob_to_path.setdefault(sha, path)

    failures: list[str] = []
    for sha, path in blob_to_path.items():
        blob = subprocess.run(
            ["git", "cat-file", "blob", sha], cwd=str(work), capture_output=True
        )
        if blob.returncode != 0:
            continue
        try:
            json.loads(blob.stdout.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            failures.append(f"json-invalid:{path}@{sha[:8]}")
            if len(failures) >= budget:
                break
    return failures


def _run_filter_repo(
    ctx: RunContext,
    plan: FilterPlan,
    script_name: str,
    log_name: str,
) -> None:
    """Generate + execute a git-filter-repo pass for ``plan`` over ``ctx.work_dir``."""
    work_dir = ctx.work_dir.resolve()
    script = _build_filter_script(plan)
    script_path = (ctx.artifacts_dir / script_name).resolve()
    script_path.write_text(script, encoding="utf-8")

    cmd = [sys.executable, str(script_path), str(work_dir), ctx.salt.decode()]
    # git-filter-repo parses `git config --list` and may crash on multiline
    # shell helpers from global config; run with isolated config files.
    env = dict(os.environ)
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    env["GIT_CONFIG_GLOBAL"] = os.devnull

    result = subprocess.run(
        cmd, capture_output=True, text=True, cwd=str(work_dir), env=env
    )

    (ctx.artifacts_dir / log_name).write_text(
        f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}\n", encoding="utf-8"
    )

    if result.returncode != 0:
        logger.error("History rewrite failed: %s", result.stderr)
        raise RuntimeError(f"git-filter-repo failed: {result.stderr}")


def _build_filter_script(plan: FilterPlan) -> str:
    """Build the thin git-filter-repo driver script.

    The actual scrubbing logic lives in ``repo_sanitizer.redaction.history_ops``
    (importable + unit-tested without git-filter-repo). This script just imports
    it, builds a ``Scrubber`` from the repr-injected plan data + the salt (argv),
    and wires the bound methods as callbacks. The package's parent dir is pushed
    onto ``sys.path`` so the import works regardless of how the subprocess Python
    resolves modules.
    """
    pkg_parent = repr(str(Path(repo_sanitizer.__file__).resolve().parent.parent))
    pii_defs_repr = repr(list(plan.pii_pattern_defs))
    secret_literals_repr = repr(list(plan.secret_literals))
    person_literals_repr = repr(list(plan.person_literals))
    brand_map_repr = repr(list(plan.brand_map_rows))
    deny_globs_repr = repr(list(plan.deny_globs))
    binary_deny_repr = repr(list(plan.binary_deny_extensions))
    allow_suffixes_repr = repr(list(plan.allow_suffixes))
    rewrite_authors_repr = repr(bool(plan.rewrite_authors))
    keep_repr = repr(list(plan.keep))
    scrub_public_ips_repr = repr(bool(plan.scrub_public_ips))
    scrub_urls_repr = repr(bool(plan.scrub_urls))

    return textwrap.dedent(
        f'''\
        #!/usr/bin/env python3
        """Auto-generated git-filter-repo driver (repo-sanitizer).

        NOTE: when this pass scrubs secret literals, this file embeds real secret
        VALUES (repr-injected). It is an INTERNAL artifact — clean it with the
        rest of out/artifacts; never ship it.
        """
        import sys

        sys.path.insert(0, {pkg_parent})

        try:
            import git_filter_repo as fr
        except ImportError:
            print("git-filter-repo is not installed. Install with: pip install git-filter-repo", file=sys.stderr)
            sys.exit(1)

        try:
            from repo_sanitizer.redaction.history_ops import Scrubber
        except ImportError as exc:
            print(f"repo_sanitizer not importable in filter-repo subprocess: {{exc}}", file=sys.stderr)
            sys.exit(1)

        repo_path = sys.argv[1]
        salt = sys.argv[2].encode()

        scrubber = Scrubber(
            salt,
            pii_pattern_defs={pii_defs_repr},
            secret_literals={secret_literals_repr},
            person_literals={person_literals_repr},
            brand_map_rows={brand_map_repr},
            deny_globs={deny_globs_repr},
            binary_deny_extensions={binary_deny_repr},
            allow_suffixes={allow_suffixes_repr},
            rewrite_authors={rewrite_authors_repr},
            keep={keep_repr},
            scrub_public_ips={scrub_public_ips_repr},
            scrub_urls={scrub_urls_repr},
        )

        args = fr.FilteringOptions.default_options()
        args.force = True
        args.partial = True
        args.replace_refs = "update-no-add"

        repo_filter = fr.RepoFilter(
            args,
            name_callback=(scrubber.author_name if scrubber.rewrite_authors else None),
            email_callback=(scrubber.author_email if scrubber.rewrite_authors else None),
            message_callback=scrubber.message,
            blob_callback=scrubber.blob,
            filename_callback=scrubber.filename,
        )
        repo_filter.run()
        print("Filter-repo completed successfully")
        '''
    )
