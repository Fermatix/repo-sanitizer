"""Config modules survive, but their literal credentials do not ship."""
from __future__ import annotations

import ast
import json
from pathlib import Path
import subprocess

import pytest
import yaml

from repo_sanitizer.context import RunContext
from repo_sanitizer.redaction.conf_keys import ConfigMasker, MAX_BLOB
from repo_sanitizer.redaction.history_ops import ConfigHistoryScrubber, Scrubber
from repo_sanitizer.rulepack import load_rulepack
from repo_sanitizer.steps.inventory import run_inventory
from repo_sanitizer.steps.redact import run_redact

RULES = Path(__file__).resolve().parents[1] / "examples" / "rules"


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          capture_output=True).stdout


def make_repo(path):
    path.mkdir()
    git(path, "init", "-q", "-b", "main")
    git(path, "config", "user.name", "Fixture Author")
    git(path, "config", "user.email", "fixture@example.invalid")
    files = {
        "settings.py": b'PASSWORD = "pg1"\n',
        "ordinary.py": b'PASSWORD = "pg1"\n',  # same blob, different path policy
        "config.json": b'{"apiKey": "k-1", "port": 5432}\n',
        "config.prod.yaml": b'password: "pw2"\nport: 5432\n',
        "database.php": b"<?php return ['password' => 'db3', 'port' => 5432];\n",
        "application.properties": b'password=pw4\r\nport=5432\r\n',
        "settings.gradle": b"rootProject.name = 'demo'\n",
        "settings.styl": b"pageWidth = 1200px\n",
        "triple/config.py": b'PASSWORD = """t-1"""\nDEBUG = False\n',
        "config.toml": b'password = """t-2\nx-2"""\nport = 5432\n',
        "block/config.yaml": b'password: |\n  y-3\nport: 5432\n',
        "escaped/config.yaml": b"password: 'ab''cd'\nport: 5432\n",
        "xml/application.config": b'<configuration><appSettings><add key="password" value="pw3" /></appSettings></configuration>\n',
        "plist/config.plist": b'<plist><dict><key>password</key><string>pw3</string></dict></plist>\n',
        "continued/application.properties": b'password=ab\\\n  cd\nport=5432\n',
        "formatted/config.json": b'{"password":\n "pw3", "port": 5432}\n',
        "dynamic/config.py": b'BROKER_URL = "amqp://%s:%s@%s/%s"\nDATABASE_URL = "postgres://${DB_USER}:${DB_PASSWORD}@db:5432/app"\n',
        "settings.py.example": b'PASSWORD = "ex1"\r\nDEBUG = False\r\n',
        "legacy/config.py": '# Настройки\r\nPASSWORD = "cp1"\r\n'.encode("cp1251"),
        ".env": b"PASSWORD=env-secret\n",
        "server.key": b"fixture-key\n",
        "certificate.pem": b"fixture-certificate\n",
        "id_rsa": b"fixture-ssh-key\n",
        "local_settings.py": b"PASSWORD='local-secret'\n",
    }
    for name, data in files.items():
        p = path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    git(path, "add", ".")
    git(path, "commit", "-qm", "first config versions")
    git(path, "switch", "-qc", "feature")
    (path / "config.json").write_bytes(b'{"apiKey": "f-2", "port": 5433}\n')
    git(path, "add", ".")
    git(path, "commit", "-qm", "feature config")
    git(path, "switch", "-q", "main")
    (path / "config.json").unlink()  # only historical configs must be scrubbed too
    (path / "settings.py").write_bytes(b'PASSWORD = "pg2"\nDEBUG = False\n')
    git(path, "add", "-A")
    git(path, "commit", "-qm", "new settings and deleted config")
    return path


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("gates", [False, True])
def test_config_history_bundle(tmp_path, enabled, gates):
    from repo_sanitizer.pipeline import run_sanitize

    source = make_repo(tmp_path / "source")
    # Copy the public rulepack and change only the feature flag.
    import shutil
    rules = tmp_path / "rules"
    shutil.copytree(RULES, rules)
    policy = rules / "policies.yaml"
    policy.write_text(policy.read_text().replace("mask_config_values: true", f"mask_config_values: {str(enabled).lower()}"))
    out = tmp_path / "out"
    code = run_sanitize(str(source), out, rules, ner_scope="off", run_gate=gates)
    assert code == 0
    clone = tmp_path / "delivered"
    git(tmp_path, "clone", "-q", str(out / "output" / "sanitized.bundle"), str(clone))
    # Materialize all shipped branches for history inspection.
    git(clone, "branch", "feature", "origin/feature")
    assert set(git(clone, "for-each-ref", "--format=%(refname:short)", "refs/heads").decode().split()) == {"main", "feature"}
    seen_old_config = False
    for commit in git(clone, "rev-list", "--branches").decode().splitlines():
        paths = set(git(clone, "ls-tree", "-r", "--name-only", commit).decode().splitlines())
        assert not paths.intersection({".env", "server.key", "certificate.pem", "id_rsa", "local_settings.py"})
        assert {"settings.py", "database.php", "settings.gradle", "settings.styl", "settings.py.example"} <= paths
        settings = git(clone, "show", f"{commit}:settings.py")
        ast.parse(settings)
        assert (b'PASSWORD = "REDACTED"' in settings) is enabled
        # Config-only short secret masking must not affect an ordinary source
        # file just because it shares the original config's blob ID.
        assert git(clone, "show", f"{commit}:ordinary.py") == b'PASSWORD = "pg1"\n'
        if "config.json" in paths:
            seen_old_config = True
            doc = json.loads(git(clone, "show", f"{commit}:config.json"))
            assert (doc["apiKey"] == "REDACTED") is enabled
            assert doc["port"] in (5432, 5433)
        example = git(clone, "show", f"{commit}:settings.py.example")
        assert example.endswith(b"\r\nDEBUG = False\r\n")
        assert (b'"REDACTED"' in example) is enabled
        legacy = git(clone, "show", f"{commit}:legacy/config.py")
        assert legacy.startswith('# Настройки\r\n'.encode('cp1251'))
        assert (b'"REDACTED"' in legacy) is enabled
        yaml_doc = yaml.safe_load(git(clone, "show", f"{commit}:config.prod.yaml"))
        assert (yaml_doc["password"] == "REDACTED") is enabled
        assert yaml_doc["port"] == 5432
        php = git(clone, "show", f"{commit}:database.php")
        assert (b"'password' => 'REDACTED'" in php) is enabled
        properties = git(clone, "show", f"{commit}:application.properties")
        assert (b"password=REDACTED\r\n" in properties) is enabled
        if enabled:
            import tomllib
            import xml.etree.ElementTree as ET
            triple = git(clone, "show", f"{commit}:triple/config.py")
            assert ast.literal_eval(ast.parse(triple).body[0].value) == "REDACTED"
            assert tomllib.loads(git(clone, "show", f"{commit}:config.toml").decode())["password"] == "REDACTED"
            for path in ("block/config.yaml", "escaped/config.yaml"):
                assert yaml.safe_load(git(clone, "show", f"{commit}:{path}"))["password"].strip() == "REDACTED"
            xml = ET.fromstring(git(clone, "show", f"{commit}:xml/application.config"))
            assert xml.find("./appSettings/add").get("value") == "REDACTED"
            plist = ET.fromstring(git(clone, "show", f"{commit}:plist/config.plist"))
            assert plist.find("./dict/string").text == "REDACTED"
            assert git(clone, "show", f"{commit}:continued/application.properties") == b"password=REDACTED\n\nport=5432\n"
            assert json.loads(git(clone, "show", f"{commit}:formatted/config.json"))["password"] == "REDACTED"
            assert git(clone, "show", f"{commit}:dynamic/config.py") == (source / "dynamic/config.py").read_bytes()
    assert seen_old_config
    report = out / "artifacts" / "config_values_history.json"
    assert report.exists() is enabled
    if enabled:
        stats = json.loads(report.read_text())
        assert stats["values_masked"] >= 9
        assert all(isinstance(v, int) for v in stats.values())
        assert json.loads((out / "artifacts" / "config_values_working_tree.json").read_text())["values_masked"] >= 6


@pytest.mark.parametrize("suffix", [".example", ".sample", ".template", ".dist", ".defaults"])
def test_examples_use_underlying_format(suffix):
    m = ConfigMasker()
    assert m.mask(b"'password' => 'p-1',\n", "config.php" + suffix) == b"'password' => 'REDACTED',\n"
    assert m.mask(b"password=p-2\r\n", "application.properties" + suffix) == b"password=REDACTED\r\n"


def test_limits_encoding_and_idempotence():
    m = ConfigMasker()
    for data, counter in [(b"a" * (MAX_BLOB + 1), "skipped_large"), (b"\x00\xff", "skipped_binary"), (b"\x98", "skipped_encoding")]:
        assert m.mask(data, "config.json") == data
        assert m.stats[counter] == 1
    original = b'PASSWORD="pg1"\r\n'
    once = m.mask(original, "settings.py")
    assert m.mask(once, "settings.py") == once
    assert m.stats["values_masked"] == 1
    # The precise size boundary is processed.
    at_limit = original + b" " * (MAX_BLOB - len(original))
    assert b'PASSWORD="REDACTED"' in m.mask(at_limit, "settings.py")


def test_working_tree_preserves_bytes_and_reports_skips(tmp_path):
    rp = load_rulepack(RULES)
    work = tmp_path / "work"
    work.mkdir()
    (work / "settings.py").write_bytes(b'PASSWORD="pg1"\r\nDEBUG=False\r\n')
    (work / "config.json").write_bytes(b" " * (MAX_BLOB + 1))
    (work / "settings.py.example").symlink_to("settings.py")
    art = tmp_path / "artifacts"
    art.mkdir()
    ctx = RunContext(salt=b"fixture", work_dir=work, out_dir=tmp_path, artifacts_dir=art, rulepack_path=RULES, rulepack=rp)
    run_inventory(ctx)
    run_redact(ctx, [])
    assert (work / "settings.py").read_bytes() == b'PASSWORD="REDACTED"\r\nDEBUG=False\r\n'
    assert (work / "settings.py.example").is_symlink()
    assert ctx.config_values_stats["skipped_large"] == 1
    assert ctx.config_values_stats["values_masked"] == 1


def test_new_callback_does_not_suppress_failure(monkeypatch):
    callback = ConfigHistoryScrubber(Scrubber(b"fixture"))
    class MissingBlob:
        def get_contents_by_identifier(self, _):
            return None
    with pytest.raises(RuntimeError, match="Cannot read history blob"):
        callback.file_info(b"settings.py", b"100644", b"bad", MissingBlob())
    assert callback.file_info(b"submodule", b"160000", b"commit", MissingBlob()) == (b"submodule", b"160000", b"commit")
    class PresentBlob:
        def get_contents_by_identifier(self, _):
            return b'PASSWORD="pg1"\n'
    def broken(*_):
        raise ValueError("mask failed")
    monkeypatch.setattr(callback.masker, "mask", broken)
    with pytest.raises(ValueError, match="mask failed"):
        callback.file_info(b"settings.py", b"100644", b"blob", PresentBlob())


def test_flag_is_opt_in_for_other_rulepacks(tmp_path):
    (tmp_path / "VERSION").write_text("fixture\n")
    (tmp_path / "policies.yaml").write_text("deny_globs: []\n")
    assert load_rulepack(tmp_path).mask_config_values is False
    assert load_rulepack(RULES).mask_config_values is True
    assert load_rulepack(RULES).version == "1.1.0"


def test_unterminated_quote_has_bounded_runtime():
    import sys
    # A subprocess bounds the test even if exponential backtracking regresses.
    code = (
        "from repo_sanitizer.redaction.conf_keys import ConfigMasker;"
        "data=b'password=\"' + bytes([92])*10000 + b'\\n';"
        "assert ConfigMasker().mask(data, 'config.yaml') == data"
    )
    subprocess.run([sys.executable, "-c", code], check=True, timeout=5)


@pytest.mark.parametrize("modes", [(b"120000", b"100644"), (b"100644", b"120000")])
def test_history_cache_includes_file_mode(modes):
    class Helper:
        def __init__(self):
            self.data = {b"original": b'PASSWORD="pg1"\n'}
        def get_contents_by_identifier(self, oid):
            return self.data[oid]
        def insert_file_with_contents(self, contents):
            oid = len(self.data)
            self.data[oid] = contents
            return oid
    helper = Helper()
    callback = ConfigHistoryScrubber(Scrubber(b"fixture"))
    for mode in modes:
        _, _, oid = callback.file_info(b"settings.py", mode, b"original", helper)
        data = helper.data[oid]
        assert (b"REDACTED" in data) is (mode == b"100644")


def test_mixed_literal_and_dynamic_url_credentials():
    m = ConfigMasker()
    assert m.mask(b'url: postgres://${USER}:pw3@${HOST}/db\n', "config.yaml") == b'url: postgres://${USER}:REDACTED@${HOST}/db\n'
    assert m.mask(b'DATABASE_URL="postgres://${USER}:pw3@${HOST}/db"\n', "config.py") == b'DATABASE_URL="postgres://${USER}:REDACTED@${HOST}/db"\n'


@pytest.mark.parametrize("path,value", [
    ("application.properties", "ab;cd"),
    ("application.properties", "p#ss"),
    ("application.properties", "#ab"),
    ("application.properties", "ab #cd"),
    ("application.properties", "ab ;cd"),
    ("config.env", "ab;cd"),
    ("config.ini", "ab;cd"),
    ("config.yaml", "ab#cd"),
])
def test_bare_secret_punctuation_is_not_a_comment(path, value):
    original = f"password={value}\n" if not path.endswith(".yaml") else f"password: {value}\n"
    out = ConfigMasker().mask(original.encode(), path)
    assert value.encode() not in out
    assert b"REDACTED" in out


def test_inline_comments_are_preserved_where_supported():
    m = ConfigMasker()
    assert m.mask(b"password=ab;cd # comment\r\n", ".env.example") == b"password=REDACTED # comment\r\n"
    assert m.mask(b"password=ab;cd ; comment\r\n", "config.ini") == b"password=REDACTED ; comment\r\n"


def test_yaml_alias_and_escaped_xml_value_still_parse():
    m = ConfigMasker()
    data = b"password: &credential 'ab''cd'\ncopy: *credential\n"
    out = m.mask(data, "config.yaml")
    assert yaml.safe_load(out) == {"password": "REDACTED", "copy": "REDACTED"}
    data = b"""<add value="ab'cd" key="password" />"""
    assert m.mask(data, "application.config") == b'<add value="REDACTED" key="password" />'


def test_multiline_yaml_anchor_and_string_tag_are_preserved():
    data = b'password: &credential\n  !!str "ab3cd"\ncopy: *credential\n'
    out = ConfigMasker().mask(data, "config.yaml")
    assert yaml.safe_load(out) == {"password": "REDACTED", "copy": "REDACTED"}
    assert out == b'password: &credential\n  !!str "REDACTED"\ncopy: *credential\n'


@pytest.mark.parametrize("value", [
    '!<tag:yaml.org,2002:str> &c ab3cd',
    '&c # shared credential\n  "ab3cd"',
    '!!int &c 1234567',
])
def test_yaml_tag_anchor_comments_and_typed_scalar(value):
    data = f"password: {value}\ncopy: *c\n".encode()
    masker = ConfigMasker()
    out = masker.mask(data, "config.yaml")
    assert yaml.safe_load(out) == {"password": "REDACTED", "copy": "REDACTED"}
    assert masker.stats["values_masked"] == 1


def test_yaml_embedded_configs_and_environment_sequences():
    data = b'environment:\n  - PASSWORD=pw3\n  - "API_KEY=k-1"\ndata:\n  application.properties: |\n    spring.datasource.password=pw4\n    port=5432\n'
    out = ConfigMasker().mask(data, "config.yaml")
    doc = yaml.safe_load(out)
    assert doc["environment"] == ["PASSWORD=REDACTED", "API_KEY=REDACTED"]
    assert doc["data"]["application.properties"] == "spring.datasource.password=REDACTED\nport=5432\n"


@pytest.mark.parametrize("encoding", ["utf-8", "cp1251"])
def test_yaml_unicode_offsets_and_crlf_blocks(encoding):
    data = '# Настройки\r\npassword: "pw3"\r\ndata:\r\n  application.properties: |\r\n    password=pw4\r\n    port=5432\r\n'.encode(encoding)
    out = ConfigMasker().mask(data, "config.yaml")
    assert out == data.replace(b"pw3", b"REDACTED").replace(b"pw4", b"REDACTED")
    assert yaml.safe_load(out.decode(encoding))["password"] == "REDACTED"


@pytest.mark.parametrize("literal", ["'''ab\\'''", "'ab\\'", "'''ab\\''''", "'''ab\\'''''"])
def test_toml_literal_strings_do_not_escape_quotes(literal):
    import tomllib
    data = f"password = {literal}\nport = 5432\n".encode()
    assert tomllib.loads(data.decode())["port"] == 5432
    out = ConfigMasker().mask(data, "config.toml")
    assert tomllib.loads(out.decode()) == {"password": "REDACTED", "port": 5432}


@pytest.mark.parametrize("line", [
    "ENV PASSWORD=pw3 PORT=5432 DEBUG=true\n",
    'ENV PASSWORD="pw3" PORT=5432 DEBUG=true\n',
    "ENV PASSWORD=pw3 \\\n    PORT=5432 DEBUG=true\n",
    "ENV PORT=5432 \\\n    PASSWORD=pw3 DEBUG=true\n",
])
def test_dockerfile_assignments_preserve_siblings_and_continuations(line):
    expected = line.replace("pw3", "REDACTED").encode()
    assert ConfigMasker().mask(line.encode(), "Dockerfile") == expected


@pytest.mark.parametrize("value", ['ab"cd"', '"ab"cd', "ab\\\ncd", "'ab'\"cd\""])
def test_dockerfile_complete_value_fragments_are_masked(value):
    data = f"ENV PASSWORD={value} PORT=5432\n".encode()
    out = ConfigMasker().mask(data, "Dockerfile")
    assert b"ab" not in out and b"cd" not in out
    assert b"PORT=5432" in out and out.count(b"\n") == data.count(b"\n")
    assert ConfigMasker().mask(out, "Dockerfile") == out


@pytest.mark.parametrize("line", [
    'RUN export PASSWORD="pw3"\n',
    'RUN curl -d password="pw3" localhost\n',
])
def test_dockerfile_other_instructions_keep_quoted_masking(line):
    assert ConfigMasker().mask(line.encode(), "Dockerfile") == line.replace("pw3", "REDACTED").encode()


def test_embedded_templates_preserve_config_expressions():
    masker = ConfigMasker()
    code = b'TOKEN="%s:%s" % (user, token)\n'
    assert masker.mask(code, "settings.py") == code
    data = b'password: "x-${PASSWORD}"\n'
    assert masker.mask(data, "config.yaml") == data


@pytest.mark.parametrize("path", ["settings.gradle", "vendor/pkg/config.json", "dist/config.json"])
def test_inherited_path_exclusions_are_reported(path):
    m = ConfigMasker()
    data = b'{"password":"pw3"}'
    assert m.accepts(path)
    assert m.mask(data, path) == data
    assert m.stats["skipped_path"] == 1


def test_local_batch_masks_config_values(tmp_path):
    from repo_sanitizer.batch.local import run_local_batch
    source = make_repo(tmp_path / "source")
    listing = tmp_path / "repos.txt"
    listing.write_text(str(source) + "\n")
    out = tmp_path / "batch"
    assert run_local_batch(list_file=listing, rulepack=RULES, out=out, workers=1, ner_scope="off") == 0
    clone = tmp_path / "delivery"
    git(tmp_path, "clone", "-q", str(out / "source" / "output" / "sanitized.bundle"), str(clone))
    assert b'PASSWORD = "REDACTED"' in (clone / "settings.py").read_bytes()
    assert not (clone / "server.key").exists()


def test_gitlab_batch_masks_configs_before_delivery(tmp_path, monkeypatch):
    from unittest.mock import Mock
    from repo_sanitizer import pipeline
    from repo_sanitizer.batch import worker
    from repo_sanitizer.batch.config import BatchConfig, GitLabConfig, ScopeConfig, ProcessingConfig, OutputConfig
    from repo_sanitizer.batch.gitlab_client import RepoTask
    source = make_repo(tmp_path / "source")
    run_sanitize = pipeline.run_sanitize
    def without_ner(**kwargs):
        # Exercise real worker + sanitize + packaging; external NER and GitLab
        # publication are the only boundaries replaced for this offline test.
        kwargs["ner_service_url"] = None
        kwargs["ner_scope"] = "off"
        return run_sanitize(**kwargs)
    monkeypatch.setattr(pipeline, "run_sanitize", without_ner)
    client = Mock()
    def inspect_delivery(bundle, _url):
        clone = tmp_path / "delivery"
        git(tmp_path, "clone", "-q", str(bundle), str(clone))
        assert b'PASSWORD = "REDACTED"' in (clone / "settings.py").read_bytes()
        assert not (clone / ".env").exists()
        assert not (clone / "server.key").exists()
    client.push_bundle.side_effect = inspect_delivery
    monkeypatch.setattr(worker, "GitLabClient", lambda **_: client)
    config = BatchConfig(
        gitlab=GitLabConfig("https://gitlab.invalid", "FIXTURE_TOKEN", "source", "delivery"),
        scope=ScopeConfig(),
        processing=ProcessingConfig(work_base_dir=tmp_path / "worker", run_gate=False),
        output=OutputConfig(artifacts_dir=tmp_path / "artifacts"),
        rulepack=str(RULES),
    )
    result = worker.process_repo(RepoTask("fixture", "source", str(source), "https://gitlab.invalid/delivery"), config)
    assert result.success and result.pushed
    client.push_bundle.assert_called_once()
    assert (tmp_path / "artifacts" / "fixture" / "source" / "config_values_history.json").exists()
