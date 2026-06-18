from __future__ import annotations

import ipaddress
import re

from repo_sanitizer.detectors.base import (
    Category,
    Detector,
    Finding,
    ScanTarget,
    Severity,
)

INTERNAL_TLDS = (".internal", ".corp", ".local", ".lan", ".intra")

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
    return False


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
                try:
                    ip = ipaddress.ip_address(value)
                except ValueError:
                    continue
                if not _is_public_ip(ip):
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
