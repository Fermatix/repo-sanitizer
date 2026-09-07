"""Bare internal-TLD hosts: framework env-file names are not machines (ec47e8c1: `.env.production.local` in a Next.js .gitignore)."""
import pytest

from repo_sanitizer.detectors.endpoint import _is_generic_internal_host


@pytest.mark.parametrize("host", ["env.local", "env.production.local", "env.development.local", "env.test.local",
                                  "env.staging.local", "host.docker.internal", "api.default.svc.cluster.local"])
def test_env_file_names_and_standard_aliases_are_generic(host):
    assert _is_generic_internal_host(host)


@pytest.mark.parametrize("host", ["jenkins.acmecorp.local", "env.acmecorp.corp", "gitlab.zorvex.internal", "envoy.local", "prod-db.lan"])
def test_identifying_internal_hosts_stay_findings(host):
    assert not _is_generic_internal_host(host)
