"""2026-09-05: the host allowlist agrees with the rulepack `https_url` skip-list — a URL the pattern spares must
not be host-masked either (www.apple.com/DTDs in plists, files.pythonhosted.org in uv.lock), and EXACT hosts of a
multi-tenant parent keep only themselves."""
import pytest

from repo_sanitizer.detectors.endpoint import _is_kept_url_host


@pytest.mark.parametrize("host", [
    "www.apple.com", "files.pythonhosted.org", "pypi.org", "redis.io", "ui.shadcn.com", "demo_feed.tradingview.com",
    "fonts.googleapis.com", "developer.mozilla.org", "dev.1c-bitrix.ru",
    # public package mirrors pinned in lockfiles (9f7b24fe: 1467 yarn.lock lines went to *.example.invalid)
    "registry.npm.taobao.org", "registry.npmmirror.com", "r.cnpmjs.org", "mirrors.aliyun.com",
    "karma-runner.github.io", "carthage.github.io", "www.makeareadme.com",   # OSS docs / README template hosts (2348a140)
    # exact hosts of multi-tenant parents
    "storage.yandexcloud.net", "www.googleapis.com", "oauth2.googleapis.com", "accounts.google.com", "js.stripe.com",
])
def test_public_infra_hosts_are_kept(host):
    assert _is_kept_url_host(host, set())


@pytest.mark.parametrize("host", [
    "my-client-bucket.storage.yandexcloud.net",   # customer bucket under an exact-only host
    "acme-prod.storage.googleapis.com",
    "rc1b-abc.mdb.yandexcloud.net",
    "acme-corp.bitrix24.ru",
    "crm.some-regional-company.ru",
    "client-apple.com",                           # merely ends with a listed suffix
    "www.google.com",                             # /maps/place/<address> identifies a real site
    "npm.client-mirror.ru",                       # a private registry mirror still identifies its owner
])
def test_customer_hosts_are_still_masked(host):
    assert not _is_kept_url_host(host, set())


def test_keep_names_match_the_registrable_label():
    """a72ff34c: keep.txt says `hubspot`; `app.hubspot.com` was masked. A keep NAME keeps every host whose registrable
    label is that name; a subdomain label never counts (`api.<client>.ru` with `api` in keep stays masked)."""
    from repo_sanitizer.detectors.endpoint import _is_kept_url_host
    keep = {"hubspot", "microsoft", "api"}
    assert _is_kept_url_host("app.hubspot.com", keep) and _is_kept_url_host("hubspot.com", keep)
    assert _is_kept_url_host("docs.microsoft.co.uk", keep)
    assert not _is_kept_url_host("api.acmeclient.ru", keep)
    assert not _is_kept_url_host("hubspot-tools.acmeclient.ru", keep)
    assert _is_kept_url_host("aka.ms", set())



@pytest.mark.parametrize("host", [
    # compose / dev-stack service names (be9a6e28, 2b5a2444: `storefront`, `payload`, `cms` became <hash>.example.invalid)
    "storefront", "payload", "cms", "strapi", "keycloak", "meilisearch", "php-fpm", "mailpit", "staging",
    # monorepo tool schema URL and documentation placeholder domains (`turbo.build/schema.json`, `site.com`, `s3.provider.com`)
    "turbo.build", "site.com", "s3.provider.com", "api.yourdomain.com", "example.dev", "www.cbr.ru", "opencollective.com", "tidelift.com", "www.patreon.com", "feross.org",
])
def test_generic_service_names_and_doc_placeholders_are_kept(host):
    assert _is_kept_url_host(host, set())


@pytest.mark.parametrize("host", ["jenkins-acmecorp", "acmecorp-db", "site.acmecorp.com", "s3.acmecorp-cloud.com", "storefront01"])
def test_distinctive_machine_and_company_hosts_stay_masked(host):
    """The generic set is exact-match: a distinctive machine name or a company subdomain is still a finding."""
    assert not _is_kept_url_host(host, set())
