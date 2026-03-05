from __future__ import annotations

import logging
import os
import subprocess
import sys
import textwrap

from repo_sanitizer.context import RunContext
from repo_sanitizer.rulepack import Rulepack

logger = logging.getLogger(__name__)


def run_history_rewrite(ctx: RunContext) -> None:
    """Rewrite git history using git-filter-repo."""
    work_dir = ctx.work_dir.resolve()
    rulepack: Rulepack = ctx.rulepack

    script = _build_filter_script(ctx, rulepack)
    script_path = (ctx.artifacts_dir / "_filter_repo_script.py").resolve()
    script_path.write_text(script, encoding="utf-8")

    log_path = ctx.artifacts_dir / "history_rewrite_log.txt"

    cmd = [
        sys.executable,
        str(script_path),
        str(work_dir),
        ctx.salt.decode(),
    ]
    # git-filter-repo parses `git config --list` and may crash on multiline
    # shell helpers from global config; run with isolated config files.
    env = dict(os.environ)
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    env["GIT_CONFIG_GLOBAL"] = os.devnull

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(work_dir),
        env=env,
    )

    log_path.write_text(
        f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}\n",
        encoding="utf-8",
    )

    if result.returncode != 0:
        logger.error("History rewrite failed: %s", result.stderr)
        raise RuntimeError(f"git-filter-repo failed: {result.stderr}")

    logger.info("History rewrite complete")


def _build_filter_script(ctx: RunContext, rulepack: Rulepack) -> str:
    deny_patterns_repr = repr(rulepack.deny_globs)
    binary_deny_repr = repr(rulepack.binary_deny_extensions)
    pii_patterns_repr = repr([(p.name, p.pattern.pattern) for p in rulepack.pii_patterns])

    return textwrap.dedent(f'''\
        #!/usr/bin/env python3
        """Auto-generated filter-repo script."""
        import sys
        import hmac
        import re
        from fnmatch import fnmatch

        try:
            import git_filter_repo as fr
        except ImportError:
            print("git-filter-repo is not installed. Install with: pip install git-filter-repo", file=sys.stderr)
            sys.exit(1)

        repo_path = sys.argv[1]
        salt = sys.argv[2].encode()

        DENY_GLOBS = {deny_patterns_repr}
        BINARY_DENY_EXT = {binary_deny_repr}

        EMAIL_RE = re.compile(rb'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+')
        PHONE_RE = re.compile(rb'\\+[1-9]\\d{{6,14}}')

        # All rulepack PII patterns (compiled as byte patterns)
        _PII_PATTERN_DEFS = {pii_patterns_repr}
        PII_PATTERNS = [(name, re.compile(pat.encode(), re.MULTILINE)) for name, pat in _PII_PATTERN_DEFS]

        def _hash(salt_: bytes, value: bytes, length: int = 12) -> str:
            return hmac.new(salt_, value, "sha256").hexdigest()[:length]

        def name_callback(name: bytes) -> bytes:
            h = _hash(salt, name)
            return f"Author_{{h}}".encode()

        def email_callback(email: bytes) -> bytes:
            h = _hash(salt, email)
            return f"author_{{h}}@example.invalid".encode()

        def message_callback(message: bytes) -> bytes:
            result = message
            for m in reversed(list(EMAIL_RE.finditer(result))):
                val = m.group()
                h = _hash(salt, val)
                replacement = f"user_{{h}}@example.com".encode()
                result = result[:m.start()] + replacement + result[m.end():]
            for m in reversed(list(PHONE_RE.finditer(result))):
                result = result[:m.start()] + b"+0000000000" + result[m.end():]
            return result

        def blob_callback(blob, callback_data):
            try:
                data = blob.data
                if b"\\x00" in data[:8192]:
                    return
                text = data
                text = EMAIL_RE.sub(
                    lambda m: f"user_{{_hash(salt, m.group())}}@example.com".encode(),
                    text,
                )
                text = PHONE_RE.sub(b"+0000000000", text)
                for name, pat in PII_PATTERNS:
                    text = pat.sub(
                        lambda m, _n=name: f"[{{_n}}:{{_hash(salt, m.group()[:64])}}]".encode(),
                        text,
                    )
                blob.data = text
            except Exception:
                pass

        def should_remove_path(path_bytes: bytes) -> bool:
            path_str = path_bytes.decode("utf-8", errors="replace")
            name = path_str.split("/")[-1]
            for g in DENY_GLOBS:
                pat = g.split("/")[-1]
                if fnmatch(name, pat):
                    return True
            ext = path_str.rsplit(".", 1)[-1].lower() if "." in path_str else ""
            if ext in BINARY_DENY_EXT:
                return True
            return False

        args = fr.FilteringOptions.default_options()
        args.force = True
        args.partial = True
        args.replace_refs = "update-no-add"

        repo_filter = fr.RepoFilter(
            args,
            name_callback=name_callback,
            email_callback=email_callback,
            message_callback=message_callback,
            blob_callback=blob_callback,
            filename_callback=lambda path: b"" if should_remove_path(path) else path,
        )
        repo_filter.run()
        print("Filter-repo completed successfully")
    ''')
