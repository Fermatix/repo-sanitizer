from __future__ import annotations

import ipaddress
import re

from repo_sanitizer.buildsafe import in_version_context
from repo_sanitizer.detectors.base import (
    Category,
    Detector,
    Finding,
    ScanTarget,
    Severity,
)

INTERNAL_TLDS = (".internal", ".corp", ".local", ".lan", ".intra")

# Standard, NON-identifying hosts that happen to end in an "internal" TLD: the
# Docker/minikube host-gateway aliases, the framework `.env.local` convention (a
# `/.env.local` gitignore glob matches the bare `env.local`), and the k8s
# in-cluster service suffix `*.svc.cluster.local`. None names a company/machine —
# flagging them is a false positive (and the old pipeline then over-redacted
# `/.env.local` → `/.REDACTED_<hash>`, mangling the gitignore). An identifying
# internal domain (`jenkins.acmecorp.local`) is NOT in this set and is still flagged.
_GENERIC_INTERNAL_HOSTS = frozenset({
    "host.docker.internal", "gateway.docker.internal", "vm.docker.internal",
    "host.minikube.internal", "kubernetes.docker.internal", "docker.internal",
    "docker.for.mac.localhost", "docker.for.win.localhost",
    "env.local", "app.local", "dev.local", "test.local", "web.local", "api.local",
    "localhost.local",
})


def _is_generic_internal_host(domain: str) -> bool:
    """True for the standard non-identifying internal hostnames above + the k8s
    in-cluster service suffix `*.svc.cluster.local`."""
    return domain in _GENERIC_INTERNAL_HOSTS or domain.endswith(".svc.cluster.local")

# Dotted IPv4 quad. The lookarounds (not the \b shorthand) ensure an adjacent
# '.digit' suppresses the match, so the leading quad of a version string or OID
# (1.2.3.4.5, 1.3.6.1.4.1.311) is NOT mistaken for an IP. Validity / 999.x
# rejection is still done via ipaddress.ip_address().
IPV4_PATTERN = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")

# IPv6 literal (compressed or full form). Requires a '::' or all 8 groups, so
# it does not match a bare 'h:m:s' time or a C++ 'a:b' scope fragment; every
# candidate is still validated by ipaddress.ip_address(). In CODE files the
# detector only runs inside string/comment zones, so this never touches actual
# C++ '::' scope-resolution tokens.
IPV6_PATTERN = re.compile(
    r"(?<![\w:.])(?:"
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}"
    r"|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}"
    r"|:(?::[0-9A-Fa-f]{1,4}){1,7}"
    r"|::"
    r")(?![\w:.])"
)

# Well-known public DNS — safe placeholders, kept (not flagged) like the doc IPs.
_KEEP_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"}

DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:[a-zA-Z]{2,})\b"
)

# A URL's scheme + optional userinfo + host. Group 1 = scheme, group 2 =
# userinfo (the `user[:pass]` before `@`, if any), group 3 = host — either a
# bracketed IPv6 literal `[…]` or a normal host up to the first `:`/`/`/`?`/`#`/
# whitespace/quote. Used to mask the HOST (+ drop any userinfo) of a
# non-allowlisted URL while leaving the path/query and surrounding file
# structure intact — so masking never produces a `[...]` token that corrupts
# YAML/XML. Splitting userinfo prevents a username surviving under an
# allowlisted host; the IPv6 branch prevents a `[[ipv6:…]]` double-mask.
URL_HOST_PATTERN = re.compile(
    r"(https?://)(?:([^/@\s\"'<>]*)@)?(\[[0-9A-Fa-f:.]+\]|[^/:\s\"'<>?#\\]+)",
    re.IGNORECASE,
)

# Generic single-label URL hosts that identify nobody — localhost + the usual
# docker-compose / k8s service names. KEPT; any OTHER single-label host (e.g. a
# distinctive internal machine name like `prod-payments-db`) is MASKED (it is a
# machine identifier). Operators add their own service names to the keep dict.
GENERIC_SINGLE_LABEL_HOSTS = frozenset({
    "localhost", "local", "test", "localdomain",
    "web", "app", "api", "www", "ui", "admin", "gateway", "proxy", "server",
    "backend", "frontend", "worker", "queue", "broker", "mq", "auth",
    "db", "database", "pg", "postgres", "postgresql", "mysql", "mariadb",
    "mongo", "mongodb", "redis", "cache", "memcached", "elasticsearch",
    "elastic", "kibana", "rabbitmq", "amqp", "kafka", "zookeeper",
    "nginx", "httpd", "mail", "mailhog", "smtp", "minio", "vault", "consul",
    "etcd", "prometheus", "grafana", "traefik", "registry", "node",
})

# Universal public infrastructure whose hostnames identify NOBODY (the same for
# every repo on earth): masking them is pure build-breakage + noise for zero
# anonymity. KEEP these URL hosts; mask every other (company/vendor) host.
# Matched as registrable suffixes (host == s or host endswith "." + s).
# Per-run operators may extend this list. (User decision 2026-06-18: "mask all
# real public URLs except universal infra".)
UNIVERSAL_URL_HOSTS = frozenset({
    # documentation / placeholder domains (incl. our own *.example.invalid masks)
    "example.com", "example.org", "example.net", "example.edu", "example.invalid",
    "invalid", "localhost", "test",
    # W3C / XML / schema namespaces (these URLs are literal identifiers)
    "w3.org", "schema.org", "json-schema.org", "xml.org", "oasis-open.org",
    "purl.org", "ns.adobe.com", "schemas.android.com", "android.com",
    "schemas.microsoft.com", "schemas.xmlsoap.org", "microsoft.com",
    "apache.org", "maven.apache.org",
    # package registries / language ecosystems
    "nuget.org", "pypi.org", "pythonhosted.org", "npmjs.org", "npmjs.com",
    "yarnpkg.com", "maven.org", "sonatype.org", "gradle.org", "jitpack.io",
    "rubygems.org", "crates.io", "golang.org", "go.dev", "sum.golang.org",
    "proxy.golang.org", "packagist.org", "spdx.org",
    # OS / container package repositories
    "nodesource.com", "packages.microsoft.com", "debian.org", "ubuntu.com",
    "alpinelinux.org", "fedoraproject.org", "docker.io", "docker.com",
    "gcr.io", "ghcr.io", "quay.io", "registry.k8s.io", "k8s.io",
    # certificate authorities
    "letsencrypt.org",
    # build installers / framework getters / schema + docs hosts whose URLs are
    # literal build constants that identify nobody (masking them breaks
    # Dockerfile RUN installers, composer/symfony bootstrap, xmlns/schema refs).
    "getcomposer.org", "get.symfony.com", "symfony.com", "getpsalm.org",
    "readthedocs.io", "readthedocs.org", "json.schemastore.org", "schemastore.org",
    "phar.phpunit.de", "deb.nodesource.com", "dl.yarnpkg.com", "sh.rustup.rs",
    # code hosting (the host is public; an identifying org/repo in the PATH is
    # the brand layer's job). NOTE: hosts whose *single-label* subdomain is
    # CUSTOMER-controlled (sourceforge.net `<proj>.`, googlesource.com `<proj>.`,
    # github.io `<user>.`) are deliberately OMITTED — the ≤1-subdomain keep rule
    # would otherwise pass a project/customer host. github/gitlab/bitbucket put
    # the identifying part in the PATH, not a subdomain, so they are safe.
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
    # common build-time CDNs. NOTE: `googleapis.com` is deliberately OMITTED — it
    # is MULTI-TENANT (a customer's GCS bucket is `<bucket>.storage.googleapis.com`),
    # so allowlisting it would keep a customer-identifying host. `gstatic.com` is
    # Google-controlled (no customer subdomains) and stays.
    "jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
    "gstatic.com", "bootstrapcdn.com",
    # very-widespread public SaaS whose host identifies NOBODY (the per-customer
    # identity lives in the URL PATH, scrubbed by the Pass-2 brand map — same as
    # github.com). Masking these is pure over-anonymization + build/semantic
    # breakage (a Notion-integration repo's every `notion.so` call became
    # `<hash>.example.invalid`). The keep-list (§C) wants these KEPT, like Google.
    # SINGLE-TENANT hosts ONLY — MULTI-TENANT clouds whose SUBDOMAIN is the
    # customer (yandexcloud.net `rc1b-…mdb.yandexcloud.net`, bitrix24.ru
    # `<company>.bitrix24.ru`, *.amazonaws.com) are deliberately ABSENT so a
    # customer-identifying deployment host is still masked.
    "notion.so", "notion.site", "notion.com",
    "telegram.org", "telegram.me", "t.me", "telegram.dog",
    "slack.com", "discord.com", "discord.gg", "discordapp.com",
    "figma.com", "gravatar.com",
    "yandex.ru", "ya.ru", "yandex.com",  # fixed Yandex service hosts (mail/metrika/disk); NOT yandexcloud.net
    # 2026-09-05: aligned with rulepack/regex/pii_patterns.yaml `https_url` (1.5.8/1.5.9) — a host the pattern
    # spares must not be host-masked here either, or the artifact still breaks: www.apple.com/DTDs in every
    # plist (50218c4b), files.pythonhosted.org in uv.lock (3b8751ea), docs/CDN/spec hosts. SINGLE-TENANT only.
    "apple.com", "mozilla.org", "gnu.org", "opensource.org", "creativecommons.org", "python.org",
    "nodejs.org", "jquery.com", "fontawesome.com", "sil.org", "xmlsoap.org", "openxmlformats.org",
    "phpunit.de", "php.net", "yuilibrary.com", "phpstan.org", "psalm.dev", "getcomposer.org", "packagist.org",   # PHP tooling docs / schemas (954e2780)
    "aka.ms", "visualstudio.com", "nuget.org", "dotnet.microsoft.com",   # Microsoft short links / docs (a72ff34c)
    "springframework.org", "sun.com", "oracle.com", "docbook.org", "jetbrains.com", "fonts.googleapis.com",
    "redis.io", "postgresql.org", "nginx.org", "nginx.com", "pypa.io", "djangoproject.com",
    "palletsprojects.com", "sqlalchemy.org", "pydantic.dev", "pytest.org", "shadcn.com", "tradingview.com",
    "kubernetes.io", "helm.sh", "rust-lang.org", "rustup.rs", "docs.rs", "laravel.com", "vuejs.org",
    "react.dev", "reactjs.org", "angular.io", "tailwindcss.com", "getbootstrap.com", "swagger.io",
    "openapis.org", "stackoverflow.com", "wikipedia.org", "flutter.dev", "dart.dev", "pub.dev",
    "1c-bitrix.ru", "yastatic.net", "ietf.org", "iana.org", "unicode.org", "whatwg.org",
    "ecma-international.org", "typescriptlang.org", "eslint.org", "prettier.io", "babeljs.io",
    "webpack.js.org", "vitejs.dev", "jestjs.io",
    "editorconfig.org", "protractortest.org", "karma-runner.github.io", "jasmine.github.io", "mochajs.org", "cypress.io",   # OSS test/doc hosts (eaf57629)
    "jshint.com", "sensiolabs.org", "symfony.com",   # 0869f8a8 README, 316d5c6a Dockerfiles
    "docker.com", "docker.io", "dockerproject.org",   # public Docker package hosts (apt.dockerproject.org, e7e90c3b)
    "loopj.com", "square.github.io", "squareup.com", "greenrobot.org",   # Android OSS library homes in vendored licence headers (87753d70)
    "pytorch.org", "arxiv.org", "tensorflow.org", "huggingface.co", "anaconda.org", "conda.io",   # ML package hosts / paper links (ea902925)
})

# EXACT hosts (no subdomain match): their PARENT domain is multi-tenant, so only this one host is kept —
# storage.yandexcloud.net serves the public CA.pem every Dockerfile wgets, but <bucket>.storage.yandexcloud.net
# is a customer bucket; www/oauth2.googleapis.com carry OAuth scope ids the auth code compares literally, but
# <bucket>.storage.googleapis.com is a customer bucket. Same set as the rulepack pattern's exact-host group.
EXACT_URL_HOSTS = frozenset({
    "storage.yandexcloud.net", "ajax.googleapis.com", "www.googleapis.com", "oauth2.googleapis.com",
    "accounts.google.com", "apis.google.com", "connect.facebook.net", "graph.facebook.com",
    "js.stripe.com", "api.stripe.com",
})


def _is_kept_url_host(host: str, keep: set[str]) -> bool:
    """True if a URL host should be KEPT (not masked). KEEP iff: an explicit
    operator keep entry; a non-public IP literal (private/loopback/doc/CGNAT);
    a GENERIC single-label service name (`localhost`, `web`, `db`…); or universal
    infra matched as an allowlisted registrable suffix (any depth — those domains
    are non-multi-tenant, so every subdomain is vendor-controlled). Everything
    else — a company/vendor host, a distinctive single-label machine name, or a
    customer-controlled subdomain of a multi-tenant cloud (which is deliberately
    NOT in the allowlist) — is MASKED. (Userinfo is split off by the pattern, so
    `host` here never carries a `user@` prefix.)"""
    h = host.lower().strip().strip("[]")
    if not h:
        return True
    if h in keep or any(h.endswith("." + k) for k in keep):
        return True
    # keep.txt holds NAMES (`hubspot`, `microsoft`), not domains: the registrable label of the host is what a keep
    # entry means — `app.hubspot.com` became <hash>.example.invalid in an OAuth authorize URL (a72ff34c). Only the
    # label right before the public suffix counts (never `api` / `app` subdomain labels).
    labels = h.split(".")
    if len(labels) >= 2 and labels[-2] in keep:
        return True
    if len(labels) >= 3 and labels[-2] in ("co", "com", "net", "org", "ac", "gov", "edu") and labels[-3] in keep:
        return True
    try:  # IP-literal host: keep private/loopback/doc/CGNAT, mask public
        return not _is_public_ip(ipaddress.ip_address(h))
    except ValueError:
        pass
    if "." not in h:  # single-label: keep only the generic service names
        return h in GENERIC_SINGLE_LABEL_HOSTS
    # Universal infra is NON-multi-tenant — every subdomain is vendor-controlled,
    # so any depth is safe (e.g. acme-v02.api.letsencrypt.org). Multi-tenant
    # clouds whose subdomain is CUSTOMER-controlled (googleapis.com,
    # *.amazonaws.com, github.io, *.herokuapp.com…) are intentionally absent from
    # UNIVERSAL_URL_HOSTS, so they fall through here and get masked.
    if any(h == s or h.endswith("." + s) for s in UNIVERSAL_URL_HOSTS):
        return True
    return h in EXACT_URL_HOSTS


def _is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """A globally-routable address worth redacting.

    Uses ``ip.is_global`` as the primary test, which already keeps private
    (RFC1918), loopback, link-local, reserved, unspecified, CGNAT (RFC6598
    100.64.0.0/10), and the RFC5737/RFC3849 documentation ranges (all
    non-global). Multicast is excluded explicitly (it can be global) and the
    well-known public-DNS placeholders are kept.
    """
    if not ip.is_global:
        return False
    if ip.is_multicast:
        return False
    if str(ip) in _KEEP_IPS:
        return False
    return True


class EndpointDetector(Detector):
    """Detect internal domains and PUBLIC IPs (IPv4 + IPv6).

    Globally-routable IP addresses are deployment fingerprints and get flagged
    (HIGH). Private / loopback / reserved / CGNAT / documentation-range
    addresses are KEPT. ``keep`` exempts allowlisted domains/hosts (and
    specific IP literals).
    """

    def __init__(
        self,
        domain_list: list[str] | None = None,
        keep: set[str] | None = None,
    ) -> None:
        self.domain_list = {d.lower() for d in (domain_list or [])}
        self.keep = keep or set()

    def detect(self, target: ScanTarget) -> list[Finding]:
        findings = []
        findings.extend(self._detect_public_ips(target))
        findings.extend(self._detect_internal_domains(target))
        findings.extend(self._detect_nonallowlisted_urls(target))
        # Dedup overlapping spans: a non-allowlisted URL host that is also an
        # internal/listed domain is flagged at the SAME span by two passes; and a
        # bare-IP finding sits INSIDE a `userinfo@ip` URL-authority finding. Keep
        # the widest finding per overlap (it redacts the whole span, covering the
        # contained one) and drop exact-duplicate / fully-contained findings.
        ordered = sorted(
            findings, key=lambda f: (f.offset_start, -(f.offset_end - f.offset_start))
        )
        kept: list[Finding] = []
        for f in ordered:
            if any(
                k.offset_start <= f.offset_start and f.offset_end <= k.offset_end
                for k in kept
            ):
                continue  # exact-duplicate or fully contained in a wider kept finding
            kept.append(f)
        return kept

    def _detect_public_ips(self, target: ScanTarget) -> list[Finding]:
        findings = []
        for pattern in (IPV4_PATTERN, IPV6_PATTERN):
            for m in pattern.finditer(target.content):
                start, end = m.start(), m.end()
                if not self._in_zones(target, start, end):
                    continue
                value = m.group()
                if value in self.keep:
                    continue
                if pattern is IPV6_PATTERN:
                    # Hex-looking identifiers are valid abbreviated IPv6 addresses: PHP `Ad::$rules` became
                    # `2001:db8::1ff1$rules` (ea8b6d91 shipped two syntax errors; `Ace::`, `Bed::`, `Face::`,
                    # C++ `Db::open` are the same class). A real address carries at least one digit and is
                    # never followed by a scope/static-access sigil.
                    nxt = target.content[end:end + 1]
                    if not any(ch.isdigit() for ch in value) or nxt in ("$", "(", "\\", "<", ">"):
                        continue
                try:
                    ip = ipaddress.ip_address(value)
                except ValueError:
                    continue
                if not _is_public_ip(ip):
                    continue
                # A 4-part dotted version (AssemblyVersion="4.0.0.0") is a valid
                # public IPv4 — not a deployment IP, so don't flag it.
                if pattern is IPV4_PATTERN and in_version_context(target.content, start):
                    continue
                line = target.content[:start].count("\n") + 1
                findings.append(
                    Finding(
                        detector="EndpointDetector",
                        category=Category.ENDPOINT,
                        severity=Severity.HIGH,
                        file_path=target.file_path,
                        line=line,
                        offset_start=start,
                        offset_end=end,
                        matched_value=value,
                    )
                )
        return findings

    def _detect_nonallowlisted_urls(self, target: ScanTarget) -> list[Finding]:
        """Flag a URL's userinfo+host when the host is not universal public infra
        / kept (see _is_kept_url_host) OR userinfo (a username) is present. The
        finding spans userinfo→host, so redaction masks just that — scheme/path/
        query and file structure stay intact → `<hash>.example.invalid`. An
        IP-literal host WITHOUT userinfo is skipped here (``_detect_public_ips``
        masks those, avoiding a duplicate); a `userinfo@ip` authority IS flagged,
        and the overlapping bare-IP finding is dropped by the containment dedup
        in ``detect()``."""
        findings = []
        for m in URL_HOST_PATTERN.finditer(target.content):
            userinfo, host = m.group(2), m.group(3)
            if not userinfo:
                # No userinfo: an IP-literal host is left to _detect_public_ips
                # (avoids a duplicate), and an allowlisted/kept host is skipped.
                try:
                    ipaddress.ip_address(host.strip("[]"))
                    continue
                except ValueError:
                    pass
                if _is_kept_url_host(host, self.keep):
                    continue
            # else: userinfo (a username) is itself an identifier → ALWAYS flag
            # the userinfo+host span, even on an IP host. The overlapping bare-IP
            # finding from _detect_public_ips is dropped by the containment dedup
            # in detect().
            start = m.start(2) if userinfo else m.start(3)
            end = m.end(3)
            if not self._in_zones(target, start, end):
                continue
            line = target.content[:start].count("\n") + 1
            findings.append(
                Finding(
                    detector="EndpointDetector",
                    category=Category.ENDPOINT,
                    severity=Severity.MEDIUM,
                    file_path=target.file_path,
                    line=line,
                    offset_start=start,
                    offset_end=end,
                    matched_value=target.content[start:end],
                )
            )
        return findings

    def _detect_internal_domains(self, target: ScanTarget) -> list[Finding]:
        findings = []
        for m in DOMAIN_PATTERN.finditer(target.content):
            domain = m.group().lower()
            start, end = m.start(), m.end()
            if not self._in_zones(target, start, end):
                continue
            if domain in self.keep or any(
                domain.endswith("." + k) for k in self.keep
            ):
                continue
            if _is_generic_internal_host(domain):
                continue  # docker/minikube/k8s/`.env.local` standard host → not a leak
            is_internal = any(domain.endswith(tld) for tld in INTERNAL_TLDS)
            is_in_list = domain in self.domain_list or any(
                domain.endswith("." + d) for d in self.domain_list
            )
            if is_internal or is_in_list:
                line = target.content[:start].count("\n") + 1
                findings.append(
                    Finding(
                        detector="EndpointDetector",
                        category=Category.ENDPOINT,
                        severity=Severity.MEDIUM,
                        file_path=target.file_path,
                        line=line,
                        offset_start=start,
                        offset_end=end,
                        matched_value=m.group(),
                    )
                )
        return findings

    @staticmethod
    def _in_zones(target: ScanTarget, start: int, end: int) -> bool:
        if not target.is_zoned:
            return True
        return any(z.start <= start and end <= z.end for z in target.zones)
