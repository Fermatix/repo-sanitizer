# repo-sanitizer

Утилита командной строки для анонимизации Git-репозитория перед передачей третьим сторонам или публикацией.

На вход — локальный репозиторий или URL. На выход — `git bundle` с переписанной историей, в котором нет PII, секретов и внутренней инфраструктурной информации ни в одном коммите ни одной ветки.

---

## Содержание

- [Быстрый старт](#быстрый-старт)
- [Установка](#установка)
- [Команды CLI](#команды-cli)
- [Конвейер sanitize](#конвейер-sanitize)
- [Детекторы](#детекторы)
- [Rulepack](#rulepack)
- [Артефакты](#артефакты)
- [Расширение поддержки языков](#расширение-поддержки-языков)
- [Безопасность и детерминированность](#безопасность-и-детерминированность)
- [Разработка](#разработка)
- [Ограничения](#ограничения)

---

## Быстрый старт

```bash
# 1. Установить
pip install repo-sanitizer

# 2. Задать соль (обязательно — не передаётся через CLI)
export REPO_SANITIZER_SALT="$(openssl rand -hex 32)"

# 3. Запустить очистку
repo-sanitizer sanitize ./my-project \
  --rulepack ./rules \
  --out ./sanitized-output

# 4. Проверить результат
cat sanitized-output/artifacts/result.json

# 5. Передать бандл
git clone sanitized-output/output/sanitized.bundle ./verification
```

---

## Установка

### Требования

| Инструмент | Версия | Назначение |
|---|---|---|
| Python | ≥ 3.11 | Рантайм |
| [gitleaks](https://github.com/gitleaks/gitleaks) | любая | Обнаружение секретов |
| git | ≥ 2.35 | Clone, log, bundle |

### Установка Python-пакета

**С uv (рекомендуется):**

```bash
uv add repo-sanitizer
# или глобально:
uv tool install repo-sanitizer
```

**С pip:**

```bash
pip install repo-sanitizer
```

### Установка gitleaks

```bash
# macOS
brew install gitleaks

# Linux
curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/main/scripts/install.sh | sh -s latest

# Windows (Scoop)
scoop install gitleaks
```

### NER-модель (скачивается автоматически)

При первом запуске `transformers` скачивает модель `Davlan/bert-base-multilingual-cased-ner-hrl` (~700 МБ) в `~/.cache/huggingface/`. Для офлайн-среды:

```bash
# Скачать заранее
huggingface-cli download Davlan/bert-base-multilingual-cased-ner-hrl

# Или указать локальный путь в rulepack/policies.yaml:
# ner:
#   model: /path/to/local/model
```

---

## Команды CLI

### `sanitize` — полная очистка

```
repo-sanitizer sanitize <source> [OPTIONS]
```

Запускает полный конвейер: клонирование → инвентаризация → сканирование → редактирование → переписывание истории → проверка гейтов → упаковка в bundle.

> **Покрытие истории:** конвейер обрабатывает **все ветки и теги** — метаданные коммитов (автор, email, текст), содержимое файлов в каждом уникальном блобе, и переписывает историю через git-filter-repo.

**Аргументы:**

| Параметр | Тип | Обязательный | По умолчанию | Описание |
|---|---|---|---|---|
| `source` | строка | да | — | Путь к локальному репозиторию или Git URL |
| `--rulepack` | путь | да | — | Директория с rulepack |
| `--out` | путь | да | — | Выходная директория |
| `--rev` | строка | нет | `HEAD` | Git-ревизия для checkout рабочего дерева |
| `--salt-env` | строка | нет | `REPO_SANITIZER_SALT` | Имя env-переменной с солью |
| `--max-file-mb` | число | нет | `20` | Лимит размера файла в МБ |
| `--history-since` | дата | нет | — | Нижняя граница истории (формат git: `2024-01-01`) |
| `--history-until` | дата | нет | — | Верхняя граница истории |
| `--ner-device` | строка | нет | `cpu` | Устройство для NER-модели: `cpu` \| `cuda` \| `cuda:0` \| `cuda:1` \| `auto` |

**Exit codes:**

| Код | Значение |
|---|---|
| `0` | Все гейты пройдены, бандл создан |
| `1` | Один или несколько гейтов провалены |

**Пример:**

```bash
export REPO_SANITIZER_SALT="my-secret-salt"

repo-sanitizer sanitize https://github.com/org/private-repo \
  --rulepack ./my-rules \
  --out ./output \
  --history-since 2023-01-01
```

---

### `scan` — только сканирование (аудит)

```
repo-sanitizer scan <source> [OPTIONS]
```

Клонирует репозиторий, строит инвентарь, запускает все детекторы на рабочем дереве и истории — **без каких-либо изменений**. Используется для предварительного аудита.

Принимает те же параметры, что и `sanitize` (включая `--ner-device`). Создаёт артефакты `inventory.json`, `scan_report_pre.json`, `history_scan_pre.json`, `history_blob_scan_pre.json`.

**Пример:**

```bash
repo-sanitizer scan ./my-project \
  --rulepack ./rules \
  --out ./audit-output
```

---

### `install-grammars` — установка грамматик tree-sitter

```
repo-sanitizer install-grammars --rulepack PATH
```

Проверяет, установлены ли pip-пакеты грамматик, указанных в `extractors.yaml`, и устанавливает недостающие через `pip install`.

```bash
repo-sanitizer install-grammars --rulepack ./my-rules
# Grammar packages:
#   ✓ tree-sitter-python (python)
#   ✗ tree-sitter-typescript (typescript) — not installed
#   ✗ tree-sitter-go (go) — not installed
# Installing 2 package(s)...
```

> **Без этой команды** конвейер продолжает работать — для файлов без установленной грамматики автоматически используется `FallbackExtractor` (regex-комментарии). В начале сканирования выводится предупреждение, в конце — сводка по покрытию.

---

## Конвейер sanitize

```
sanitize <source> --rulepack PATH --out PATH --salt-env VAR

Шаг 1:  Fetch              → clone/copy источника в out/work/
Шаг 2:  Inventory          → out/artifacts/inventory.json
Шаг 3:  Pre-scan           → out/artifacts/scan_report_pre.json
Шаг 4:  Redact             → out/artifacts/redaction_manifest.json
Шаг 5:  Post-scan          → out/artifacts/scan_report_post.json
Шаг 6:  History-scan       → out/artifacts/history_scan_pre.json       (метаданные коммитов, все ветки)
Шаг 6b: History-blob-scan  → out/artifacts/history_blob_scan_pre.json  (содержимое файлов, все ветки)
Шаг 7:  History-rewrite    → out/artifacts/history_rewrite_log.txt
Шаг 8:  History-post-scan  → out/artifacts/history_scan_post.json
Шаг 8b: History-blob-post  → out/artifacts/history_blob_scan_post.json
Шаг 9:  Gate check         → out/artifacts/result.json
Шаг 10: Package            → out/output/sanitized.bundle
```

### Инвентаризация (шаг 2)

Каждый файл получает категорию и действие:

| Категория | Примеры |
|---|---|
| `code` | `.py`, `.js`, `.ts`, `.go`, `.rs`, … |
| `config` | `.env`, `.yaml`, `.toml`, `.ini` |
| `docs` | `.md`, `.txt`, `.rst`, `.json` |
| `binary` | `.png`, `.exe`, `.zip`, … |

| Действие | Условие |
|---|---|
| `DELETE` | Попал в `deny_globs`, суффикс не разрешён |
| `SCAN` | Попал в `deny_globs`, но суффикс `.example`/`.sample`/`.template`; или обычный текстовый файл |
| `SKIP` | Бинарный с deny-расширением (→ DELETE) или allow-расширением, или превышает `max_file_mb` |

### Redact (шаг 4)

1. Файлы с действием `DELETE` — удаляются.
2. Для файлов с категорией `code` — редактируются **только** комментарии и строковые литералы (через tree-sitter). Идентификаторы и структура кода не трогаются.
3. Замены применяются в обратном порядке по смещению, чтобы не сбивать позиции.

### History-scan (шаг 6)

Сканирует **метаданные всех коммитов во всех ветках и тегах** (`git log --all`): имя автора, email, имя коммиттера, email коммиттера, текст сообщения. Использует те же детекторы, что и рабочее дерево.

### History-blob-scan (шаг 6b)

Сканирует **содержимое файлов в каждом уникальном блобе** во всей истории репозитория (все ветки и теги). Каждый блоб проверяется один раз независимо от того, сколько коммитов на него ссылаются.

Детекторы, используемые для блобов: `RegexPIIDetector`, `DictionaryDetector`, `EndpointDetector`. `SecretsDetector` (gitleaks) и `NERDetector` исключены по соображениям производительности — вызов subprocess на каждый блоб неприемлемо медленен для больших историй.

### History-rewrite (шаг 7)

Использует `git-filter-repo`:
- `author.name` / `committer.name` → `Author_{hash}`
- `author.email` / `committer.email` → `author_{hash}@example.invalid`
- Тексты commit messages — прогоняются через детекторы, PII заменяется
- Blob-callback — email, телефоны и **все паттерны из `regex/pii_patterns.yaml`** применяются к текстовым блобам в истории
- Файлы из `deny_globs` удаляются из всех коммитов

### Гейты (шаг 9)

| Гейт | Условие провала |
|---|---|
| `SECRETS` | Findings `category=SECRET` в post-scan, history-post-scan или history-blob-post-scan |
| `PII_HIGH` | Findings email/phone/person с `severity=HIGH` (те же источники) |
| `FORBIDDEN_FILES` | Deny-файлы присутствуют в output-дереве |
| `CONFIGS` | Config-файлы без разрешённого суффикса присутствуют в output |
| `DICTIONARY` | Совпадения по корпоративным словарям |
| `ENDPOINTS` | Внутренние домены или приватные IP |

---

## Детекторы

Все детекторы реализуют интерфейс:

```python
class Detector(ABC):
    def detect(self, target: ScanTarget) -> list[Finding]
```

`Finding` содержит: `detector`, `category`, `severity`, `file_path`, `line`, `offset_start`, `offset_end`, `value_hash`. **В отчёты никогда не попадают исходные значения** — только HMAC-SHA256(salt, value)[:12].

### SecretsDetector

Обёртка над `gitleaks detect --no-git`. Категория `SECRET`, severity `CRITICAL`.

> **Важно:** если `gitleaks` недоступен в PATH — конвейер немедленно падает с понятной ошибкой.
>
> SecretsDetector **не используется** при сканировании исторических блобов (шаги 6b/8b) из соображений производительности.

### RegexPIIDetector

Паттерны из `rulepack/regex/pii_patterns.yaml`. Встроенный набор:

| Паттерн | Категория | Severity |
|---|---|---|
| Email | `PII` | `HIGH` |
| Телефон (E.164) | `PII` | `HIGH` |
| IPv4 | `PII` | `MEDIUM` |
| JWT | `SECRET` | `CRITICAL` |
| HTTPS URL | `ENDPOINT` | `MEDIUM` |

### DictionaryDetector

Поиск по словарям с помощью алгоритма Aho-Corasick (O(n) по длине текста). Словари — текстовые файлы в `rulepack/dict/`: по одному термину на строку. Строки, начинающиеся с `#`, игнорируются.

### EndpointDetector

Обнаруживает:
- Приватные IP (RFC 1918): `10.x.x.x`, `172.16–31.x.x`, `192.168.x.x`
- Внутренние домены по TLD: `.internal`, `.corp`, `.local`, `.lan`, `.intra`
- Домены из `rulepack/dict/domains.txt`

### NERDetector

Обнаружение имён людей (`PER`) и организаций (`ORG`) через transformer-модель `Davlan/bert-base-multilingual-cased-ner-hrl`. Поддерживает русский и английский языки (F1 ~90%+).

| Метка модели | Категория | Severity |
|---|---|---|
| `PER` | `PII` | `HIGH` |
| `ORG` | `ORG_NAME` | `MEDIUM` |

Фильтрация: score < `ner_min_score` (по умолчанию 0.7) и совпадения короче 3 символов — отбрасываются. Длинные тексты автоматически разбиваются на перекрывающиеся фрагменты.

**GPU-ускорение:** по умолчанию модель запускается на CPU. Для запуска на NVIDIA GPU используйте флаг `--ner-device` или поле `device` в `policies.yaml`:

```bash
# CLI
repo-sanitizer sanitize ./repo --rulepack ./rules --out ./out --ner-device cuda

# Конкретный GPU
repo-sanitizer sanitize ./repo --rulepack ./rules --out ./out --ner-device cuda:1

# Авто-распределение (требует accelerate)
repo-sanitizer sanitize ./repo --rulepack ./rules --out ./out --ner-device auto
```

Если CUDA запрошена, но `torch.cuda.is_available()` возвращает `False` — выводится предупреждение и происходит автоматический откат на CPU.

> **Важно:** если `transformers` не установлен или модель недоступна — конвейер падает с понятной ошибкой.
>
> NERDetector **не используется** при сканировании исторических блобов из соображений производительности.

---

## Rulepack

Rulepack — директория с правилами. Минимальная структура:

```
my-rules/
├── VERSION                    # обязательный файл с версией, например "1.0.0"
├── policies.yaml              # основные политики
├── extractors.yaml            # конфигурация tree-sitter
├── dict/
│   ├── domains.txt            # внутренние домены
│   ├── orgs.txt               # названия организаций
│   ├── clients.txt            # имена клиентов
│   └── codenames.txt          # кодовые названия проектов
└── regex/
    └── pii_patterns.yaml      # regex-паттерны
```

Встроенный rulepack находится в `repo_sanitizer/rules/` и используется по умолчанию.

Полный пример с комментариями ко всем полям: `examples/full-rulepack/`.

### policies.yaml

```yaml
deny_globs:
  - "**/.env"
  - "**/config.*"
  - "**/secrets.*"
  - "**/*.key"
  - "**/*.pem"
  - "**/.mailmap"
  - "**/CODEOWNERS"

allow_suffixes: [".example", ".sample", ".template"]

binary_deny_extensions: [exe, dll, so, jar, zip, gz, tar, rar, 7z, pdf, db, sqlite]
binary_allow_extensions: [png, jpg, gif, svg]

ner:
  model: Davlan/bert-base-multilingual-cased-ner-hrl
  min_score: 0.7
  entity_types: [PER, ORG]
  device: cpu          # cpu | cuda | cuda:0 | cuda:1 | auto

max_file_mb: 20
```

**Приоритеты конфигурации:**

```
CLI-аргументы → переменные окружения → rulepack/policies.yaml → defaults
```

### extractors.yaml

Определяет, какие зоны исходного кода доступны для сканирования и редактирования:

```yaml
treesitter:
  languages:
    - id: python
      grammar_package: tree-sitter-python
      file_extensions: [.py, .pyw]
      extract_zones: [comment_line, comment_block, docstring, string_literal]

    - id: javascript
      grammar_package: tree-sitter-javascript
      file_extensions: [.js, .mjs, .cjs]
      extract_zones: [comment_line, comment_block, string_literal, template_literal]

  zone_policy:
    redact_string_literals: true   # false — трогать только комментарии
    min_string_length: 4

  on_parse_error: fallback         # fallback | skip | fail

fallback_extractor:
  enabled: true
  comment_patterns:
    - pattern: '#.*$'
    - pattern: '//.*$'
    - pattern: '--.*$'
```

### regex/pii_patterns.yaml

```yaml
patterns:
  - name: email
    pattern: '[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
    category: PII
    severity: HIGH

  - name: internal_ticket
    pattern: 'PROJ-\d{4,}'
    category: DICTIONARY
    severity: MEDIUM
```

Паттерны применяются не только при сканировании рабочего дерева, но и в `blob_callback` при переписывании истории — все значения заменяются детерминированными масками `[name:{hash12}]`.

### Словари (dict/*.txt)

```
# domains.txt — по одному домену на строку
corp.internal
mycompany.io
```

```
# codenames.txt
ProjectPhoenix
OperationAlpha
```

---

## Артефакты

После выполнения `sanitize` в выходной директории:

```
out/
├── work/                          # рабочая копия репозитория (изменённая)
├── output/
│   └── sanitized.bundle           # финальный git bundle
└── artifacts/
    ├── inventory.json                  # список файлов с категориями и действиями
    ├── scan_report_pre.json            # findings рабочего дерева до редактирования
    ├── scan_report_post.json           # findings рабочего дерева после редактирования
    ├── redaction_manifest.json         # применённые замены (только хэши, не значения)
    ├── history_scan_pre.json           # findings метаданных коммитов до переписывания
    ├── history_blob_scan_pre.json      # findings содержимого блобов до переписывания
    ├── history_scan_post.json          # findings метаданных коммитов после переписывания
    ├── history_blob_scan_post.json     # findings содержимого блобов после переписывания
    ├── history_rewrite_log.txt         # лог git-filter-repo
    └── result.json                     # статусы гейтов, exit code, SHA-256 бандла
```

### result.json

```json
{
  "exit_code": 0,
  "all_passed": true,
  "gates": {
    "SECRETS":          { "passed": true,  "failing_count": 0 },
    "PII_HIGH":         { "passed": true,  "failing_count": 0 },
    "FORBIDDEN_FILES":  { "passed": true,  "failing_count": 0, "files": [] },
    "CONFIGS":          { "passed": true,  "failing_count": 0, "files": [] },
    "DICTIONARY":       { "passed": true,  "failing_count": 0 },
    "ENDPOINTS":        { "passed": true,  "failing_count": 0 }
  },
  "summary": {
    "total_pre_findings": 12,
    "total_post_findings": 0,
    "total_history_pre_findings": 5,
    "total_history_post_findings": 0,
    "total_history_blob_pre_findings": 8,
    "total_history_blob_post_findings": 0,
    "total_redactions": 17
  },
  "timings": {
    "total_s": 142.3,
    "steps": {
      "fetch": 3.2,
      "inventory": 0.1,
      "scan_pre": 12.4,
      "redact": 2.1,
      "inventory_post": 0.1,
      "scan_post": 11.8,
      "history_scan_pre": 5.3,
      "history_blob_scan_pre": 45.2,
      "history_rewrite": 38.9,
      "history_scan_post": 4.8,
      "history_blob_scan_post": 42.1,
      "gate_check": 0.02,
      "package": 1.8
    },
    "detectors": {
      "scan_report_pre": {
        "SecretsDetector": 5.2,
        "RegexPIIDetector": 3.1,
        "DictionaryDetector": 0.8,
        "EndpointDetector": 0.4,
        "NERDetector": 2.9
      }
    },
    "gates": {
      "SECRETS": 0.0012,
      "PII_HIGH": 0.0008,
      "DICTIONARY": 0.0005,
      "ENDPOINTS": 0.0006,
      "FORBIDDEN_FILES": 0.0003,
      "CONFIGS": 0.0004
    }
  }
}
```

Поле `timings` позволяет понять, где расходуется время: какие шаги конвейера самые долгие, какие детекторы медленнее всего, сколько времени занимает каждый gate.

### Finding (в scan_report_*.json)

```json
{
  "detector": "RegexPIIDetector",
  "category": "PII",
  "severity": "HIGH",
  "file_path": "src/app.py",
  "line": 4,
  "offset_start": 72,
  "offset_end": 93,
  "value_hash": "3a9f1c2b4e7d"
}
```

> Поле `value_hash` — HMAC-SHA256(salt, original\_value)[:12]. Исходное значение в файл **никогда не записывается**.

---

## Расширение поддержки языков

Добавить поддержку нового языка без изменения кода:

```bash
# 1. Установить грамматику
uv add tree-sitter-ruby

# 2. Добавить запись в rulepack/extractors.yaml
```

```yaml
- id: ruby
  grammar_package: tree-sitter-ruby
  file_extensions: [.rb]
  extract_zones: [comment_line, comment_block, string_literal]
```

```bash
# 3. Проверить установку
repo-sanitizer install-grammars --rulepack ./my-rules
```

> **Примечание для пакетов с нестандартным API** (например, `tree-sitter-typescript`): пакет экспортирует `language_typescript()` и `language_tsx()` вместо стандартного `language()`. Это поддерживается автоматически — указывайте `id: typescript` и `id: tsx` в `extractors.yaml`.

---

## Замены (маски)

Все замены детерминированы: одинаковые `salt` + `value` → одинаковый результат.

| Тип | Результат |
|---|---|
| Email | `user_{hash12}@example.com` |
| Телефон | `+0000000000` |
| Имя человека (PER) | `Person_{hash12}` |
| Организация (ORG) | `Org_{hash12}` |
| Домен | `{hash8}.example.invalid` |
| IP-адрес | `192.0.2.{1–254}` |
| Author name | `Author_{hash12}` |
| Author email | `author_{hash12}@example.invalid` |
| Секрет (gitleaks) | `REDACTED_{hash12}` |
| Regex-паттерн (pii_patterns.yaml) | `[name:{hash12}]` |

`{hash12}` = HMAC-SHA256(salt, value).hexdigest()[:12]

---

## Безопасность и детерминированность

**Соль никогда не передаётся через аргументы CLI** — только через переменную окружения, чтобы не попасть в историю shell.

```bash
# Правильно:
export REPO_SANITIZER_SALT="$(openssl rand -hex 32)"
repo-sanitizer sanitize ./repo --rulepack ./rules --out ./out

# Для кастомного имени переменной:
export MY_SALT="..."
repo-sanitizer sanitize ./repo --rulepack ./rules --out ./out --salt-env MY_SALT
```

**Детерминированность:** при одинаковых входных данных, соли и rulepack два прогона производят побайтово идентичный `sanitized.bundle`. SHA-256 бандла записывается в `result.json` для верификации.

**Оригинал не модифицируется:** все операции выполняются на копии в `out/work/`.

---

## Разработка

```bash
# Клонировать
git clone <repo-url>
cd repo-sanitizer

# Установить зависимости (включая dev)
uv sync --dev

# Запустить unit-тесты (быстро, без внешних инструментов)
uv run pytest tests/test_rulepack.py tests/test_redaction.py \
              tests/test_inventory.py tests/test_detectors.py \
              tests/test_extractors.py -v

# Все тесты (включая NER и интеграционные)
uv run pytest -v

# Запустить CLI из исходников
uv run repo-sanitizer --help
```

### Структура проекта

```
repo_sanitizer/
├── cli.py                  # Точка входа (Typer)
├── context.py              # RunContext: salt, пути, rulepack, findings
├── pipeline.py             # Оркестратор шагов
├── rulepack.py             # Загрузка и валидация rulepack
├── steps/
│   ├── fetch.py            # Clone / copy
│   ├── inventory.py        # Обход дерева, классификация
│   ├── scan.py             # Pre-scan и Post-scan рабочего дерева
│   ├── redact.py           # Применение замен
│   ├── history_scan.py     # Скан метаданных коммитов (все ветки)
│   ├── history_blob_scan.py# Скан содержимого блобов (все ветки)
│   ├── history_rewrite.py  # git-filter-repo
│   ├── gate.py             # Проверка гейтов
│   └── package.py          # git bundle create
├── detectors/
│   ├── base.py             # Detector ABC, Finding, ScanTarget, Zone
│   ├── secrets.py          # Обёртка gitleaks
│   ├── regex_pii.py        # Email, phone, IP, JWT, URL
│   ├── dictionary.py       # Aho-Corasick по словарям
│   ├── endpoint.py         # Внутренние домены, приватные IP
│   └── ner.py              # Transformer NER: PER, ORG
├── extractors/
│   ├── treesitter.py       # Tree-sitter extractor
│   └── fallback.py         # Regex-fallback для комментариев
├── redaction/
│   ├── replacements.py     # HMAC-маски
│   ├── applier.py          # Замена span'ов в файле
│   └── git_identity.py     # Нормализация авторов
└── rules/                  # Встроенный rulepack
    ├── VERSION
    ├── policies.yaml
    ├── extractors.yaml
    ├── dict/
    └── regex/
```

### Добавить новый детектор

```python
# repo_sanitizer/detectors/my_detector.py
from repo_sanitizer.detectors.base import Category, Detector, Finding, ScanTarget, Severity

class MyDetector(Detector):
    def detect(self, target: ScanTarget) -> list[Finding]:
        findings = []
        # ... логика поиска ...
        return findings
```

Зарегистрировать в `steps/scan.py` → `build_detectors()`.

### Тесты

| Файл | Что тестирует |
|---|---|
| `test_rulepack.py` | Загрузка rulepack, валидация VERSION, grammar_package |
| `test_redaction.py` | Детерминированность масок, замена span'ов, manifest |
| `test_inventory.py` | Классификация файлов, deny_globs, allow_suffixes |
| `test_detectors.py` | Email, JWT, зоны, zone-filtering |
| `test_extractors.py` | Tree-sitter (Python, JS), fallback, on_parse_error |
| `test_ner.py` | NER (PER/ORG, en+ru) — пропускается без transformers |
| `test_pipeline_snapshot.py` | Полный цикл sanitize на `fixtures/sample_repo/` |
| `test_pipeline_history.py` | Переписывание истории на `fixtures/history_repo/` |

Интеграционные тесты автоматически пропускаются, если `gitleaks` или `git-filter-repo` не установлены.

---

## Ограничения

Следующее **не входит** в скоуп:

- PR/MR данные из GitHub/GitLab API
- Wiki-репозитории
- LFS-объекты (pointer-файлы удаляются, содержимое LFS не выгружается)
- Рекурсивная обработка submodules (URL в `.gitmodules` ловится EndpointDetector)
- Переименование файлов/директорий, содержащих PII в пути
- EXIF-метаданные изображений
- Подписи коммитов (удаляются при переписывании истории, но не анализируются)
