"""Ref reconciliation — keep ALL branches (best-effort scrubbed names), drop all
tags, set HEAD to the scrubbed default branch.

Runs right after the git-filter-repo history rewrite (Pass-1 ``sanitize`` and
Pass-3 ``apply-map``) and before packaging. The history rewrite scrubs the
CONTENT, commit messages and author/committer identity across every branch
(filter-repo's default ``--all`` ref scope), but it never touches branch NAMES
and leaves tags + remote-tracking refs in place. This step:

  1. resolves each intake branch's rewritten tip via filter-repo's commit-map
     (robust to the known ``--partial`` "stale local head" case; falls back to
     the in-place head, then the intake tip),
  2. computes a best-effort scrubbed, valid, collision-free ref slug for each
     branch name (reusing the same byte-scrubber the rewrite used),
  3. force-creates ``refs/heads/<slug>`` at the rewritten tip, points HEAD at the
     scrubbed default, then deletes every original-named head, all
     ``refs/remotes/*``, ``refs/tags/*`` and ``refs/replace/*``.

Priority (user): keeping every branch wins. A name that resists scrubbing never
costs the branch — worst case it ships under the deterministic ``branch-<hash>``
fallback slug; a branch is dropped ONLY if it pruned to nothing in the rewrite.
"""

from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path

from repo_sanitizer.context import RunContext
from repo_sanitizer.redaction.history_ops import Scrubber, hash12
from repo_sanitizer.steps._git_utils import list_all_branch_tips

logger = logging.getLogger(__name__)

# Ref-illegal characters for a single path component (git-check-ref-format):
# control chars, space, and ~ ^ : ? * [ ] \  → replaced with '-'. ('/' is the
# hierarchy separator, handled by the caller; '@' is legal except the '@{'
# sequence and a lone '@', both handled separately.)
_ILLEGAL_REF_CHARS = re.compile(r"[\x00-\x20\x7f~^:?*\[\]\\ ]")


def _sanitize_ref_component(comp: str) -> str:
    """Map one scrubbed path component to a valid git ref component (or '')."""
    c = comp.replace("@{", "-")
    c = _ILLEGAL_REF_CHARS.sub("-", c)
    c = c.replace("..", "-")                 # '..' is illegal
    if c.endswith(".lock"):                  # a component may not end with .lock
        c = c[:-5]
    c = c.strip(".")                         # no leading/trailing dot
    c = re.sub(r"-{2,}", "-", c).strip("-")  # tidy
    if c in ("", "@"):
        return ""
    return c


def make_ref_slug(name: str, scrubber: Scrubber, salt: bytes) -> str:
    """Scrub a branch name and reduce it to a valid, non-empty git ref.

    Clean names pass through unchanged (the byte-scrubber only rewrites detected
    tokens). A name that scrubs/sanitizes to nothing falls back to a deterministic
    ``branch-<hash12>`` so the branch is never lost.
    """
    scrubbed = scrubber.message(name.encode("utf-8")).decode("utf-8", "replace")
    comps = [s for s in (_sanitize_ref_component(c) for c in scrubbed.split("/")) if s]
    slug = "/".join(comps).strip("/")
    # A bare "HEAD"/"@" is a valid path component but an AMBIGUOUS branch ref;
    # treat it (and an all-stripped name) as degenerate → deterministic fallback.
    if not slug or slug in ("HEAD", "@"):
        slug = "branch-" + hash12(salt, name.encode("utf-8"))
    return slug


def _ref_conflict(slug: str, used: set[str]) -> bool:
    """True if ``slug`` collides with any name in ``used`` — exact, OR a git
    directory/file conflict (one is a path-prefix of the other, e.g. ``foo`` vs
    ``foo/bar``), which the ref store forbids. Two distinct source branches can
    scrub to such a pair (e.g. brands ``a``/``b`` both → ``Acme1`` over sources
    ``a`` and ``b/x`` → ``Acme1`` and ``Acme1/x``), so dedupe must catch it."""
    sparts = slug.split("/")
    for u in used:
        if u == slug:
            return True
        uparts = u.split("/")
        shorter, longer = (uparts, sparts) if len(uparts) <= len(sparts) else (sparts, uparts)
        if longer[: len(shorter)] == shorter:
            return True
    return False


def _dedupe(slug: str, used: set[str]) -> str:
    """Return a ref name colliding with nothing in ``used`` (exact OR D/F). On
    any conflict, flatten ``/``→``-`` (a flat name cannot cause a directory/file
    conflict) and append ``-2``, ``-3``, … deterministically — so a pathological
    scrub can never make ``update-ref`` reject (and thereby drop) a branch."""
    if not _ref_conflict(slug, used):
        return slug
    base = slug.replace("/", "-") or "branch"
    cand, n = base, 2
    while _ref_conflict(cand, used):
        cand = f"{base}-{n}"
        n += 1
    return cand


def _load_commit_map(work_dir: Path) -> dict[str, str]:
    """Parse filter-repo's ``.git/filter-repo/commit-map`` → ``{old: new}``.

    Format is a header line then ``OLDSHA NEWSHA`` pairs; a pruned commit's NEW
    is all-zeros. Header / malformed lines are skipped. Returns ``{}`` if absent.
    """
    p = work_dir / ".git" / "filter-repo" / "commit-map"
    if not p.exists():
        return {}
    out: dict[str, str] = {}
    hexset = set("0123456789abcdef")
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        old, new = parts[0].strip().lower(), parts[1].strip().lower()
        if len(old) not in (40, 64) or set(old) - hexset:
            continue  # header ("old" "new") or junk
        out[old] = new
    return out


def _is_zero(sha: str) -> bool:
    return bool(sha) and set(sha) == {"0"}


def _build_name_scrubber(ctx: RunContext, brand_map_rows: list | None) -> Scrubber:
    """Build the byte-scrubber used to scrub branch NAMES, matching the pass.

    Pass-3 (``apply-map``, ``brand_map_rows`` given): a brand-only scrubber, so a
    brand surviving in a branch name is renamed exactly like brand content.
    Pass-1 (``sanitize``, no brand map): the rulepack PII patterns + keep-set +
    public-IP / URL passes + the secret/person literals already harvested on
    ``ctx`` (no second gitleaks run — branch names are short and the full literal
    set was already applied to blobs by the rewrite).
    """
    if brand_map_rows:
        return Scrubber(ctx.salt, brand_map_rows=brand_map_rows)

    rulepack = getattr(ctx, "rulepack", None)
    if rulepack is None:
        return Scrubber(ctx.salt)

    from repo_sanitizer.steps.history_rewrite import _collect_person_literals
    from repo_sanitizer.steps.scan import build_brand_terms

    _terms, keep = build_brand_terms(rulepack)
    # Finding-derived secret literals (free — already on ctx; skip the gitleaks re-run).
    secrets: set[str] = set()
    for f in (list(getattr(ctx, "pre_findings", []) or [])
              + list(getattr(ctx, "history_blob_pre_findings", []) or [])):
        if getattr(f, "detector", "") in ("SecretsDetector", "EndpointDetector"):
            val = getattr(f, "matched_value", "")
            if val and len(val) >= 5:
                secrets.add(val)
    return Scrubber(
        ctx.salt,
        pii_pattern_defs=[(p.name, p.pattern.pattern) for p in rulepack.pii_patterns],
        secret_literals=sorted(secrets),
        person_literals=_collect_person_literals(ctx),
        keep=sorted(keep),
        scrub_public_ips=True,
        scrub_urls=True,
    )


def _git(work: str, args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=work, input=stdin, capture_output=True, text=True
    )


def run_ref_reconcile(ctx: RunContext, *, brand_map_rows: list | None = None) -> None:
    """Keep all branches (scrubbed names), drop tags/remotes/replace, set HEAD."""
    work = str(ctx.work_dir)

    # Intake branch set (name → pre-rewrite tip). Fall back to the current refs
    # if intake capture did not run (e.g. a non-clone source).
    intake = dict(ctx.intake_branch_tips or {})
    # Post-rewrite "in-place" tips for the zero/unmapped fallback: the UNION of
    # local heads AND rewritten refs/remotes/origin/* (which --partial leaves in
    # place). A branch captured ONLY from origin/* (local materialization failed)
    # whose tip pruned must still resolve to its surviving rewritten remote ref —
    # consulting local heads alone would silently drop it.
    in_place = list_all_branch_tips(ctx.work_dir)
    if not intake:
        intake = dict(in_place)
    if not intake:
        logger.warning("ref-reconcile: no branches found; nothing to do")
        return

    commit_map = _load_commit_map(ctx.work_dir)

    # 1) Resolve each branch's rewritten tip. Precedence:
    #    - commit-map NON-zero  → authoritative rewritten tip (covers the stale
    #      `--partial` local-head case: the head may still point at the OLD tip).
    #    - commit-map ZERO (tip commit pruned) OR unmapped → trust filter-repo's
    #      in-place ref (local head OR rewritten origin remote), which it
    #      repointed to the surviving ancestor — a pruned TIP does NOT mean the
    #      branch has no surviving commits, so we must NOT drop it.
    #    - unmapped & no surviving ref → unchanged branch (old tip).
    #    - pruned to nothing & no surviving ref → genuinely empty → drop.
    resolved: dict[str, str] = {}   # name -> rewritten tip
    pruned: list[str] = []
    for name, old_tip in intake.items():
        raw = commit_map.get((old_tip or "").lower())   # sha | zero (pruned) | None (unmapped)
        ip = in_place.get(name)                          # filter-repo's current ref (post-rewrite/prune)
        if raw and not _is_zero(raw):
            new_tip = raw
        elif ip:
            new_tip = ip
        elif raw is None:
            new_tip = old_tip
        else:
            new_tip = None
        if not new_tip:
            pruned.append(name)
            logger.warning("ref-reconcile: branch %r pruned to nothing; dropping", name)
            continue
        resolved[name] = new_tip

    # 2) Compute scrubbed, valid, collision-free slugs (default first, then sorted).
    scrubber = _build_name_scrubber(ctx, brand_map_rows)
    default = ctx.intake_default_branch if ctx.intake_default_branch in resolved else ""
    order = ([default] if default else []) + sorted(n for n in resolved if n != default)
    slugs: dict[str, str] = {}
    used: set[str] = set()
    for name in order:
        slug = _dedupe(make_ref_slug(name, scrubber, ctx.salt), used)
        used.add(slug)
        slugs[name] = slug

    # 3a) Force-create/update every kept head at its rewritten tip.
    creates = "".join(f"update refs/heads/{slugs[n]} {resolved[n]}\n" for n in order)
    r = _git(work, ["update-ref", "--stdin"], stdin=creates)
    if r.returncode != 0:
        raise RuntimeError(f"ref-reconcile: creating scrubbed heads failed: {r.stderr}")

    # 3b) Point HEAD at the scrubbed default (before deleting originals, so HEAD
    #     never dangles). Fall back to the first kept slug.
    default_slug = slugs.get(default) or (next(iter(slugs.values()), ""))
    if default_slug:
        _git(work, ["symbolic-ref", "HEAD", f"refs/heads/{default_slug}"])

    # 3c) Delete every ref that is not a kept scrubbed head: original-named heads
    #     whose slug differs, plus ALL remotes / tags / replace refs.
    kept = set(slugs.values())
    all_refs = _git(work, ["for-each-ref", "--format=%(refname)"]).stdout.splitlines()
    dels: list[str] = []
    for ref in (r.strip() for r in all_refs):
        if not ref:
            continue
        drop = False
        if ref.startswith("refs/heads/"):
            drop = ref.removeprefix("refs/heads/") not in kept
        elif ref.startswith(("refs/remotes/", "refs/tags/", "refs/replace/")):
            drop = True
        if drop:
            # `option no-deref` so a symbolic ref (e.g. refs/remotes/origin/HEAD)
            # is deleted as-is, not via its target — otherwise update-ref rejects
            # deleting both the symref and its target in one transaction.
            dels.append(f"option no-deref\ndelete {ref}\n")
    if dels:
        r = _git(work, ["update-ref", "--stdin"], stdin="".join(dels))
        if r.returncode != 0:
            raise RuntimeError(f"ref-reconcile: deleting non-kept refs failed: {r.stderr}")

    # 4) Record for the gate / result.json.
    ctx.branch_rename_map = {**{n: slugs[n] for n in slugs}, **{n: None for n in pruned}}
    ctx.output_branches = sorted(kept)
    ctx.output_default_branch = default_slug
    logger.info(
        "ref-reconcile: %d branch(es) kept%s, tags/remotes dropped, HEAD=%r",
        len(kept),
        f" ({len(pruned)} pruned)" if pruned else "",
        default_slug,
    )
