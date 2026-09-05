"""Key-name config masking: formats and exceptions from the existing engine."""
from __future__ import annotations

from repo_sanitizer.redaction import conf_keys as ck


def test_path_classifier():
    yes = ["config.yml", "app/config.py", "src/settings.py", "config/database.php", "src/main/resources/application.properties",
           ".env.example", "appsettings.Production.json", "deploy/Dockerfile", "android/app/src/main/res/values/strings.xml",
           "infra/main.tf", "config/initializers/secrets.rb", "settings/local.py"]
    no = ["src/app.py", "README.md", "node_modules/x/config.json", "vendor/pkg/settings.php", "package-lock.json",
          "assets/app.min.js", "docs/config.md".replace(".md", ".rst"), "src/models/user.py"]
    assert all(ck.is_conf_path(p) for p in yes), [p for p in yes if not ck.is_conf_path(p)]
    assert not any(ck.is_conf_path(p) for p in no), [p for p in no if ck.is_conf_path(p)]


def test_mask_formats():
    y = "db_password: \"s3cr3t\"\napi_url: ${API_URL}\ntoken: abcdef123\nmax_tokens: 512\nsecret: !secret db\npassword:\nport: 5432\n"
    out, n = ck.mask_text(y, "config.yml")
    assert out == "db_password: \"REDACTED\"\napi_url: ${API_URL}\ntoken: REDACTED\nmax_tokens: 512\nsecret: !secret db\npassword:\nport: 5432\n" and n == 2
    j = '{"password": "pw1234", "apiKey": "k-1", "name": "svc", "token": ""}'
    out, n = ck.mask_text(j, "appsettings.json")
    assert out == '{"password": "REDACTED", "apiKey": "REDACTED", "name": "svc", "token": ""}' and n == 2   # empty token untouched
    e = "export DB_PASSWORD=hunter22\nDB_HOST=localhost\nAPI_TOKEN=${TOKEN}\nSECRET_KEY=changeme\n"
    out, n = ck.mask_text(e, ".env.example")
    assert out == "export DB_PASSWORD=REDACTED\nDB_HOST=localhost\nAPI_TOKEN=${TOKEN}\nSECRET_KEY=changeme\n" and n == 1
    py = "SECRET_KEY = \"django-x\"\nPASSWORD = os.environ[\"P\"]\npassword = request.form[\"password\"]\nDATABASES = {\"PASSWORD\": \"pg1\", \"PORT\": \"5432\"}\n"
    out, n = ck.mask_text(py, "settings.py")
    assert out == "SECRET_KEY = \"REDACTED\"\nPASSWORD = os.environ[\"P\"]\npassword = request.form[\"password\"]\nDATABASES = {\"PASSWORD\": \"REDACTED\", \"PORT\": \"5432\"}\n" and n == 2
    php = "'password' => env('DB_PASSWORD', 'forge'),\n'secret' => 'abc123',\n"
    out, n = ck.mask_text(php, "config/database.php")
    assert out == "'password' => env('DB_PASSWORD', 'forge'),\n'secret' => 'REDACTED',\n" and n == 1
    xml = "<server><id>r</id><password>pw12</password></server>\n<add key=\"Conn\" value=\"Server=db;User Id=sa;Password=p@ss;\" />\n"
    out, n = ck.mask_text(xml, "pom.xml")
    assert "<password>REDACTED</password>" in out and "Password=REDACTED;" in out and n == 2
    url = "queue: amqp://svc:qwe123@mq.local/v\nhome: https://example.com/x\nbroker_url: amqp://svc:qwe123@mq.local/v\n"
    out, n = ck.mask_text(url, "config.yaml")
    # a non-sensitive key keeps the URL and masks the password part; a DSN key masks the whole userinfo, host stays
    assert out == "queue: amqp://svc:REDACTED@mq.local/v\nhome: https://example.com/x\nbroker_url: amqp://REDACTED@mq.local/v\n" and n == 2


def test_code_files_outside_config_untouched():
    assert ck.is_conf_path("src/auth/service.py") is False
    assert ck.is_conf_path("src/locales/ru.json") is False and ck.is_conf_path("config/locales/ru.yml") is False


def test_non_secret_keys_and_values_untouched():
    y = ("token_endpoint: \"https://auth.example/oauth/token\"\napi_key_header: \"X-API-Key\"\npassword_min_length: 8\n"
         "secret_name: \"prod/db\"\ncredentials: creds/service.json\ngoogle_credentials: \"config/keys/sa.json\"\n"
         "webhook_url: https://hooks.slack.com/services/T000/B000/xyzxyz\npassword: hooks.slack.com/x\n")
    out, n = ck.mask_text(y, "config.yml")
    assert "https://auth.example/oauth/token" in out and "X-API-Key" in out and "password_min_length: 8" in out
    assert "prod/db" in out and "creds/service.json" in out and "config/keys/sa.json" in out
    assert "webhook_url: REDACTED" in out and "password: REDACTED" in out and n == 2


def test_subagent_round_negatives_and_positives():
    y = ("aws_secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\njwt_secret: \"dGhpcy9pcy9hL3NlY3JldA/abc\"\n"
         "existingSecret: pg-creds\nsecretName: tls-main\ncredentials: \"same-origin\"\nDATABASE_URL: \"sqlite:///db.sqlite3\"\n"
         "CELERY_BROKER_URL: \"redis://localhost:6379/0\"\nredis_url: redis://:s3cret@cache:6379/1\nhttp.proxyBypass: localhost\n"
         "password: \"Пароль\"\ntoken: \"Введите токен\"\nsentry_dsn: https://abc123def456@o1.ingest.sentry.io/1\n")
    out, n = ck.mask_text(y, "config.yml")
    assert "aws_secret_access_key: REDACTED" in out and 'jwt_secret: "REDACTED"' in out
    assert "existingSecret: pg-creds" in out and "secretName: tls-main" in out and 'credentials: "same-origin"' in out
    assert 'DATABASE_URL: "sqlite:///db.sqlite3"' in out and 'CELERY_BROKER_URL: "redis://localhost:6379/0"' in out
    assert "redis_url: redis://REDACTED@cache:6379/1" in out and "http.proxyBypass: localhost" in out
    assert 'password: "Пароль"' in out and 'token: "Введите токен"' in out
    assert "sentry_dsn: https://REDACTED@o1.ingest.sentry.io/1" in out and n == 4
    j = '{"password": "Пароль", "token": "Токен"}'
    assert not ck.is_conf_path("src/locales/ru.json")
    assert ck.ConfigMasker().mask(j.encode(), "src/locales/ru.json") == j.encode()
