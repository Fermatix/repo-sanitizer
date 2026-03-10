# Архитектура repo-sanitizer

## Обзор

Утилита построена как линейный конвейер шагов с общим состоянием (`RunContext`). Каждый шаг принимает контекст, выполняет работу и записывает результаты обратно в контекст и на диск в `artifacts/`.

```
                         ┌──────────────────────────────────────────────────────┐
                         │                     RunContext                        │
                         │  salt · work_dir · rulepack · inventory               │
                         │  pre_findings · post_findings                         │
                         │  history_pre_findings · history_post_findings         │
                         │  history_blob_pre_findings · history_blob_post_findings│
                         │  redaction_manifest · timings                         │
                         └──────────────────────┬───────────────────────────────┘
                                                │  shared state
          ┌─────────────────────────────────────▼──────────────────────────────┐
          │  pipeline.run_sanitize()                                             │
          │                                                                      │
          │   1.  fetch              → work/                                     │
          │   2.  inventory          → inventory.json                            │
          │   3.  scan (pre)         → scan_report_pre.json                     │
          │   4.  redact             → redaction_manifest.json                   │
          │   5.  scan (post)        → scan_report_post.json                    │
          │   6.  history_scan       → history_scan_pre.json    (все ветки)     │
          │   6b. history_blob_scan  → history_blob_scan_pre.json (все блобы)   │
          │   7.  history_rewrite    → history_rewrite_log.txt                  │
          │   8.  history_scan       → history_scan_post.json                   │
          │   8b. history_blob_scan  → history_blob_scan_post.json              │
          │   9.  gate_check         → result.json                              │
          │  10.  package            → output/sanitized.bundle                  │
          └──────────────────────────────────────────────────────────────────────┘
```

---

## Ключевые абстракции

### RunContext (`context.py`)

Центральный объект состояния, который передаётся в каждый шаг. Создаётся через `RunContext.create()`, которая:
- читает соль из env-переменной (обязательная)
- создаёт директории `work/`, `artifacts/`, `output/`
- хранит всё накопленное состояние конвейера

Поля findings:

| Поле | Шаг заполнения | Содержимое |
|---|---|---|
| `pre_findings` | шаг 3 | Findings рабочего дерева до redact |
| `post_findings` | шаг 5 | Findings рабочего дерева после redact |
| `history_pre_findings` | шаг 6 | Findings метаданных коммитов (все ветки) |
| `history_blob_pre_findings` | шаг 6b | Findings содержимого файлов (все блобы) |
| `history_post_findings` | шаг 8 | Findings метаданных после переписывания |
| `history_blob_post_findings` | шаг 8b | Findings содержимого после переписывания |

Поле `timings` накапливается по ходу конвейера и записывается в `result.json` после завершения:

```
timings
├── total_s                    # суммарное время конвейера
├── steps                      # время каждого шага (fetch, scan_pre, redact, …)
├── detectors                  # время каждого детектора по каждому скану
│   ├── scan_report_pre: {SecretsDetector: 5.2, RegexPIIDetector: 3.1, …}
│   └── history_scan_pre: {…}
└── gates                      # время каждого gate-check (SECRETS, PII_HIGH, …)
```

### Detector (`detectors/base.py`)

```python
class Detector(ABC):
    def detect(self, target: ScanTarget) -> list[Finding]: ...
```

Каждый детектор получает `ScanTarget` (файл + содержимое + опциональные зоны) и возвращает список `Finding`. Детекторы не знают ничего друг о друге и о файловой системе.

`ScanTarget.zones` — список `Zone(start, end)` в байтовых смещениях. Если `zones is None` — сканируется весь файл. Если `zones = []` — ничего не сканируется.

`Finding.matched_value` записывается в `redaction_manifest.json` как `original_value` (исходная подстрока) и `replacement` (итоговое значение). Для NER-находок дополнительно присутствует `ner_label` (`PER` или `ORG`). Идентифицировать запись повторно без соли позволяет `value_hash = HMAC-SHA256(salt, value)[:12]`.

### TreeSitterExtractor (`extractors/treesitter.py`)

Экстрактор зон — не детектор. Возвращает список `Zone` (смещения байт), внутри которых разрешено сканировать и редактировать код. Логика:

```
extract_zones("app.py", content) → list[Zone] | None

None   — файл не является кодом для данного экстрактора → fallback
[]     — файл является кодом, но зон нет (например, только идентификаторы)
[...]  — список span'ов для сканирования
```

При `on_parse_error: fallback` возвращает `None`, чтобы вышестоящий код мог использовать `FallbackExtractor`.

**Загрузка грамматик (приоритет источников):**

```
_get_parser(lang)
    │
    ├── 1. importlib.import_module(grammar_package)
    │         └── успех → tree_sitter.Language(module.language_fn())
    │
    ├── 2. ImportError → _try_language_pack(lang.id)
    │         └── from tree_sitter_language_pack import get_language
    │             get_language(lang.id) → Language object
    │
    └── 3. Оба источника недоступны → RuntimeError (→ FallbackExtractor)
```

Пакеты с нестандартным API (например, `tree-sitter-typescript`, экспортирующий `language_typescript()` вместо `language()`) поддерживаются через внутренний словарь `_GRAMMAR_FN_OVERRIDES`. Нестандартные идентификаторы для `tree-sitter-language-pack` — через `_LANGUAGE_PACK_ID_OVERRIDES`.

`check_grammar_packages(config)` — утилита для проверки установленности грамматик без их загрузки в парсер. Возвращает `GrammarStatus` с полем `via_language_pack=True` если грамматика найдена в `tree-sitter-language-pack`. Используется командой `install-grammars` и функцией `_warn_missing_grammars()` в `steps/scan.py`.

---

## Поток данных через детекторы (рабочее дерево)

```
                     inventory.json
                          │
              ┌───────────▼──────────┐
              │    для каждого SCAN  │
              │      файла           │
              └───────────┬──────────┘
                          │
              ┌───────────▼──────────┐          ┌──────────────────────┐
              │  TreeSitterExtractor │─── None──▶│  FallbackExtractor   │
              │  extract_zones()     │           │  (regex-комментарии) │
              └───────────┬──────────┘           └──────────┬───────────┘
                          │ zones                            │ zones
                          └───────────────┬─────────────────┘
                                          │
                                 ┌────────▼────────┐
                                 │   ScanTarget     │
                                 │  content + zones │
                                 └────────┬─────────┘
                                          │
                    ┌─────────────────────▼──────────────────────┐
                    │           детекторы (5 штук)                │
                    │  SecretsDetector                            │
                    │  RegexPIIDetector                           │
                    │  DictionaryDetector                         │
                    │  EndpointDetector                           │
                    │  NERDetector                                │
                    └─────────────────────┬──────────────────────┘
                                          │ findings
                                          ▼
                               scan_report_pre.json
```

В конце сканирования `_log_extractor_summary()` выводит статистику: сколько файлов обработано через tree-sitter, сколько — через fallback, и какие расширения чаще всего использовали fallback.

---

## Поток данных для исторических блобов (шаги 6b / 8b)

```
git rev-list --objects --all
         │
         ▼  (pipe)
git cat-file --batch-check=%(objecttype) %(objectname) %(rest)
         │
         ▼
_collect_all_blobs() → list[(sha, path)]   ← дедупликация по SHA
         │
         │  для каждого уникального блоба
         ▼
git cat-file blob <sha>
         │
         ├── binary extension? → пропустить
         ├── бинарный? (null-байты в первых 8KB) → пропустить
         ├── размер > max_file_mb? → пропустить
         │
         ▼
ScanTarget(
  file_path="<history:abcd1234/path/to/file.py>",
  content=decoded_text,
  zones=None  # сканируется весь файл целиком
)
         │
         ▼
history_detectors (3 штуки):
  RegexPIIDetector
  DictionaryDetector
  EndpointDetector
         │
         ▼
history_blob_scan_pre.json / history_blob_scan_post.json
```

Каждый уникальный блоб сканируется **один раз**, даже если на него ссылаются многие коммиты. `SecretsDetector` и `NERDetector` исключены из `build_history_detectors()` — вызов subprocess или ML-инференс на каждый блоб неприемлемо медленен для больших историй.

---

## Редактирование файлов

Замены применяются в `redaction/applier.py`. Ключевой инвариант:

**Замены применяются в обратном порядке по `offset_start`** — от конца файла к началу. Это гарантирует, что замена на позиции N не сдвигает смещения для замен на позициях < N.

```python
sorted_findings = sorted(findings, key=lambda f: f.offset_start, reverse=True)
for finding in sorted_findings:
    result = result[:finding.offset_start] + replacement + result[finding.offset_end:]
```

Для файлов категории `code` перед применением проверяется, что span finding'а попадает в зону из TreeSitterExtractor (защита от случайной правки идентификаторов).

---

## History rewrite

`steps/history_rewrite.py` генерирует временный Python-скрипт и запускает его через `subprocess`. Скрипт использует `git_filter_repo.RepoFilter` с пятью callback'ами:

| Callback | Что делает |
|---|---|
| `name_callback` | `author_name → Author_{hash}` |
| `email_callback` | `author_email → author_{hash}@example.invalid` |
| `message_callback` | RegexPII-замены в тексте коммита |
| `blob_callback` | Email, телефоны и **все паттерны из `pii_patterns.yaml`** в текстовых блобах |
| `filename_callback` | `return b""` для deny-файлов (удаляет из всех коммитов) |

Паттерны из `pii_patterns.yaml` сериализуются в генерируемый скрипт как список `(name, pattern_string)` и компилируются в байтовые регулярные выражения. Каждое совпадение заменяется маской `[name:{hash12}]` с HMAC-SHA256.

Скрипт генерируется динамически, чтобы не требовать от `git-filter-repo` доступа к установленному пакету `repo_sanitizer` — он самодостаточен.

---

## Детерминированность

Determinism обеспечивается на трёх уровнях:

1. **Маски** — `HMAC-SHA256(salt, value)[:12]`: одинаковый вход → одинаковый выход.
2. **Порядок замен** — `sorted(findings, key=offset_start, reverse=True)`: стабильный порядок.
3. **git-filter-repo** — переписывает историю детерминированно при одинаковых callback'ах.

Соль хранится отдельно от артефактов. Потеря соли делает невозможным воспроизведение тех же хэшей, но не раскрывает данные.

---

## Конфигурация rulepack

```
Rulepack
├── version: str                    # из VERSION
├── deny_globs: list[str]           # fnmatch-паттерны
├── allow_suffixes: list[str]       # .example / .sample / .template
├── binary_deny_extensions: list    # расширения без точки
├── binary_allow_extensions: list
├── max_file_mb: int
├── ner: NERConfig
│   ├── backend: str            # "hf" (HuggingFace transformers) | "gliner"
│   ├── model: str              # HF Hub ID или локальный путь
│   ├── min_score: float
│   ├── entity_types: list[str]
│   └── device: str             # cpu | cuda | cuda:0 | cuda:1 | auto  (только hf)
├── extractor: ExtractorConfig
│   ├── languages: list[ExtractorLanguage]
│   │   └── {id, grammar_package, file_extensions, extract_zones}
│   ├── redact_string_literals: bool
│   ├── min_string_length: int
│   ├── on_parse_error: str         # fallback | skip | fail
│   ├── fallback_enabled: bool
│   └── fallback_comment_patterns: list[str]
├── pii_patterns: list[PIIPattern]  # из regex/pii_patterns.yaml
└── dictionaries: dict[str, list[str]]  # из dict/*.txt
```

---

## Обработка ошибок

| Ситуация | Поведение |
|---|---|
| `gitleaks` не найден | `RuntimeError` при инициализации `SecretsDetector` → pipeline exit(1) |
| `grammar_package` не установлен | Автоматически пробуется `tree-sitter-language-pack`; если и он недоступен — WARNING в лог + `FallbackExtractor` |
| `transformers`/модель недоступны (`backend: hf`) | `RuntimeError` в `NERDetector._ensure_pipeline()` → pipeline exit(1) |
| `gliner` пакет не установлен (`backend: gliner`) | `RuntimeError` в `NERDetector._ensure_gliner()` → pipeline exit(1) |
| CUDA запрошена, но недоступна | WARNING в лог + автоматический откат на CPU (`_resolve_device()`); только для `backend: hf` |
| Ошибка парсинга tree-sitter | `on_parse_error: fallback` → `FallbackExtractor`; `skip` → пустые зоны; `fail` → исключение |
| Файл не читается | Предупреждение в лог, файл пропускается |
| Соль не задана | `ValueError` в `RunContext.create()` с понятным сообщением |
| git-filter-repo завершился с ошибкой | `RuntimeError` с stderr в сообщении |
| Блоб бинарный или слишком большой | Пропускается молча (счётчики `skipped_binary`, `skipped_large` в лог) |

---

## Как добавить новый шаг конвейера

1. Создать `steps/my_step.py` с функцией `run_my_step(ctx: RunContext) -> ...`
2. Добавить вызов в `pipeline.run_sanitize()` / `run_scan_only()`
3. Записать результат в `ctx.artifacts_dir / "my_step_output.json"`

## Как добавить новый детектор

1. Создать `detectors/my_detector.py`, унаследовав `Detector`
2. Реализовать `detect(self, target: ScanTarget) -> list[Finding]`
3. Зарегистрировать в `steps/scan.py` → `build_detectors(rulepack)`
4. При необходимости добавить в `steps/history_blob_scan.py` → `build_history_detectors(rulepack)` (если детектор допустим для побайтового сканирования блобов)
5. Добавить маску в `redaction/replacements.py` → `CATEGORY_MASKERS`
6. Написать unit-тест в `tests/test_detectors.py`

---

## Batch-режим

Batch-режим добавляет отдельный слой поверх одиночного конвейера для параллельной обработки тысяч репозиториев из GitLab.

### Модули (`repo_sanitizer/batch/`)

| Модуль | Ответственность |
|---|---|
| `config.py` | `BatchConfig` dataclass + `load_batch_config(path)` |
| `gitlab_client.py` | `GitLabClient`: enumerate repos, ensure delivery projects, push bundles |
| `ner_service.py` | FastAPI NER-сервис: загружает модель 1 раз на GPU, отдаёт инференс по HTTP |
| `worker.py` | `process_repo(task, config)` — выполняется в subprocess |
| `orchestrator.py` | `run_batch()` / `list_repos()`: NER service → enumerate → workers → state |

### Фоновый запуск (`scripts/run-batch.sh`)

Вспомогательный bash-скрипт для запуска `batch run` на Linux-серверах без привязки к терминальной сессии. Реализует start / status / logs / stop поверх двух методов изоляции:

| Метод | Условие | Логи |
|---|---|---|
| `systemd-run --user` | systemd доступен (`systemd-run --test` успешен) | `journalctl --user -u repo-sanitizer-batch` |
| `nohup + disown` | systemd недоступен | `batch.log` в корне проекта |

Соль читается из переменной окружения `REPO_SANITIZER_SALT` или из файла `.env` в корне проекта. В аргументы процесса соль не передаётся.

### Поток выполнения

```
repo-sanitizer batch run --config batch.yaml
         │
         ▼
orchestrator.run_batch()
    │
    ├── 1. GitLabClient.list_repos(scope)     ← GitLab API
    │         └── RepoTask[]: partner, name, clone_url, delivery_url
    │
    ├── 2. filter_tasks(state)                ← пропустить done/failed
    │
    ├── 3. GitLabClient.ensure_delivery_project() × N   ← создать если нет
    │
    ├── 4. launch_ner_service(model, device, port)
    │         └── FastAPI процесс, ждём GET /health → "ready"
    │
    ├── 5. ProcessPoolExecutor(workers=N)
    │         ├── Worker-0: process_repo(task_0)
    │         ├── Worker-1: process_repo(task_1)
    │         │   ...
    │         └── Worker-N: process_repo(task_N)
    │               │
    │               ├── run_sanitize(clone_url, ner_service_url=http://127.0.0.1:port)
    │               ├── GitLabClient.push_bundle(bundle_path, delivery_url)
    │               └── _write_batch_result(artifacts_dir/<partner>/<name>/batch_result.json)
    │                        ← записывается всегда (успех или ошибка)
    │
    ├── 6. ner_proc.terminate()
    │         └── batch_state.json (обновляется после каждого репо)
    │
    └── 7. _save_batch_summary()
              └── batch_summary.json (сводка по всему запуску)
```

### NERDetector: режимы работы

`NERDetector` поддерживает три режима:

```
service_url=None, backend="hf"           service_url=None, backend="gliner"      service_url="http://..." (batch)
         │                                          │                                        │
         ▼                                          ▼                                        ▼
_ensure_pipeline()                        _ensure_gliner()                         httpx.post("/ner", {"texts": [chunk]})
→ HuggingFace transformers pipeline       → GLiNER model (pip install gliner)      → NER Service (shared GPU, только hf)
  (требует transformers + torch)            точнее, быстрее, без torch
```

`RunContext.ner_service_url` устанавливается в `pipeline.run_sanitize()` и передаётся в `build_detectors()` → `NERDetector.__init__`. HTTP batch-режим (`service_url != None`) используется только с `backend: hf` — GLiNER не требует выделенного сервиса, он загружается локально в каждом воркере.

### NER HTTP API

```
GET  /health  → {"status": "ready" | "loading"}
POST /ner     → {"texts": ["chunk1", "chunk2"]}
              ← {"results": [[{entity_group, score, word, start, end}, ...], ...]}
```

Формат ответа совпадает с HuggingFace pipeline с `aggregation_strategy="simple"`.

### State файл (`batch_state.json`)

Персистирует прогресс после каждого репозитория. Позволяет возобновить прерванный прогон:

```json
{
  "partner/repo": {"status": "done",   "bundle_sha256": "abc...", "exit_code": 0, "pushed": true, "ts": "..."},
  "partner/repo": {"status": "failed", "error": "...",                                              "ts": "..."}
}
```

Статус `running` от прерванного прогона трактуется как `failed` и перезапускается.

### Артефакты batch-режима

Каждый воркер всегда (в том числе при ошибке) пишет `batch_result.json` в `artifacts_dir/<partner>/<name>/`:

```json
{
  "partner": "acme-corp",
  "name": "backend-api",
  "status": "done",
  "exit_code": 0,
  "bundle_sha256": "abc...",
  "pushed": true,
  "error": "",
  "ts": "2026-03-09T12:34:56+00:00"
}
```

По завершении прогона оркестратор записывает `artifacts_dir/batch_summary.json` с агрегатными счётчиками (`total`, `succeeded`, `failed`, `pushed`) и перечнем всех репозиториев из текущего запуска. Файл перезаписывается при каждом прогоне.

### Рекомендованные параметры для Threadripper + RTX 2080 Ti

```yaml
processing:
  workers: 16          # ≤ кол-во физических ядер
  ner_batch_size: 32   # GPU batch size (подобрать под VRAM)
  ner_service_port: 8765
```

GPU остаётся занята NER-сервисом, CPU-ядра — параллельным git/regex/tree-sitter. I/O (clone/push) перекрывается с CPU-работой соседних воркеров.
