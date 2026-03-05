# Создание rulepack

Rulepack — это директория с правилами, которая полностью определяет, что считается чувствительными данными и как с ними работать.

Полный пример со всеми возможными параметрами и комментариями: `examples/full-rulepack/`.

## Минимальный рабочий rulepack

```bash
mkdir -p my-rules/{dict,regex}

# Обязательный файл версии
echo "1.0.0" > my-rules/VERSION

# Минимальные политики
cat > my-rules/policies.yaml << 'EOF'
deny_globs:
  - "**/.env"
  - "**/*.key"
  - "**/*.pem"

allow_suffixes: [".example", ".sample", ".template"]

binary_deny_extensions: [exe, dll, zip, db]
binary_allow_extensions: [png, jpg, gif, svg]

max_file_mb: 20
EOF

# Минимальный extractors.yaml
cat > my-rules/extractors.yaml << 'EOF'
treesitter:
  languages:
    - id: python
      grammar_package: tree-sitter-python
      file_extensions: [.py]
      extract_zones: [comment_line, docstring, string_literal]
  zone_policy:
    redact_string_literals: true
    min_string_length: 4
  on_parse_error: fallback

fallback_extractor:
  enabled: true
  comment_patterns:
    - pattern: '#.*$'
    - pattern: '//.*$'
EOF

# Минимальные regex-паттерны
cat > my-rules/regex/pii_patterns.yaml << 'EOF'
patterns:
  - name: email
    pattern: '[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
    category: PII
    severity: HIGH
EOF

# Пустые словари
touch my-rules/dict/domains.txt
touch my-rules/dict/orgs.txt
touch my-rules/dict/clients.txt
touch my-rules/dict/codenames.txt
```

---

## policies.yaml — полная схема

### deny_globs

Список glob-паттернов (в стиле `fnmatch`). Файл, попавший в deny_glob:
- удаляется (`DELETE`), если у него нет разрешённого суффикса
- сканируется (`SCAN`), если суффикс входит в `allow_suffixes`

Матчинг учитывает **базовое имя файла без allow-суффикса**. Например, `.env.template` матчится на `**/.env` и получает `SCAN`.

```yaml
deny_globs:
  - "**/.env"           # точный файл .env в любой директории
  - "**/config.*"       # любой файл с именем config.* (config.yaml, config.prod.json, …)
  - "**/secrets.*"
  - "**/*.key"          # любой .key файл
  - "**/*.pem"
  - "**/.mailmap"
  - "**/CODEOWNERS"
```

### allow_suffixes

Суффиксы, которые разрешают сохранить файл из deny_globs и просканировать его:

```yaml
allow_suffixes: [".example", ".sample", ".template", ".dist"]
```

Пример: `config.yaml` → DELETE, но `config.yaml.example` → SCAN.

### binary_deny_extensions / binary_allow_extensions

Расширения **без точки**. Применяются к файлам, классифицированным как бинарные:

```yaml
binary_deny_extensions:
  - exe
  - dll
  - so
  - jar
  - zip
  - gz
  - tar
  - rar
  - 7z
  - pdf
  - db
  - sqlite

binary_allow_extensions:
  - png
  - jpg
  - jpeg
  - gif
  - svg
  - ico
```

### NER-настройки

```yaml
ner:
  # Модель из HuggingFace Hub или локальный путь
  model: Davlan/bert-base-multilingual-cased-ner-hrl

  # Минимальный confidence score для сохранения сущности (0.0 – 1.0)
  min_score: 0.7

  # Какие entity-типы обнаруживать
  entity_types: [PER, ORG]
```

Для офлайн-среды скачайте модель заранее и укажите локальный путь:

```yaml
ner:
  model: /opt/models/bert-multilingual-ner
  min_score: 0.8
```

---

## extractors.yaml — полная схема

### Добавление языка

Установите pip-пакет грамматики и добавьте запись:

```bash
uv add tree-sitter-go
```

```yaml
treesitter:
  languages:
    - id: go
      grammar_package: tree-sitter-go
      file_extensions: [.go]
      extract_zones: [comment_line, comment_block, string_literal]
```

После добавления нового языка убедитесь, что пакет установлен:

```bash
repo-sanitizer install-grammars --rulepack ./my-rules
```

Если пакет не установлен — конвейер продолжит работу с `FallbackExtractor` для файлов этого языка, но выведет предупреждение.

### Особые случаи: tree-sitter-typescript

Пакет `tree-sitter-typescript` экспортирует `language_typescript()` и `language_tsx()` вместо стандартного `language()`. Используйте разные `id`:

```yaml
- id: typescript
  grammar_package: tree-sitter-typescript
  file_extensions: [.ts]
  extract_zones: [comment_line, comment_block, string_literal]

- id: tsx
  grammar_package: tree-sitter-typescript
  file_extensions: [.tsx]
  extract_zones: [comment_line, comment_block, string_literal, template_literal]
```

### extract_zones — доступные значения

| Значение | Что захватывает |
|---|---|
| `comment_line` | `// ...` и `# ...` (однострочные комментарии) |
| `comment_block` | `/* ... */` (блочные комментарии) |
| `docstring` | Docstrings Python (`"""..."""` как первый statement) |
| `string_literal` | Строковые литералы (`"..."`, `'...'`) |
| `template_literal` | Template literals JS/TS (`` `...` ``) |

### zone_policy

```yaml
zone_policy:
  # Включать ли строковые литералы в зоны редактирования
  # false → только комментарии и docstrings
  redact_string_literals: true

  # Минимальная длина строки для включения в зону
  min_string_length: 4
```

### on_parse_error

| Значение | Поведение при ошибке парсинга |
|---|---|
| `fallback` | Использовать FallbackExtractor (regex-комментарии) |
| `skip` | Не сканировать файл вообще |
| `fail` | Бросить исключение, остановить конвейер |

### fallback_extractor

```yaml
fallback_extractor:
  enabled: true
  comment_patterns:
    - pattern: '#.*$'      # Python, Ruby, Shell
    - pattern: '//.*$'     # C, Java, JS, Go
    - pattern: '--.*$'     # Lua, SQL
    - pattern: ';.*$'      # Assembly, INI
```

Паттерны — Python regex с флагом `re.MULTILINE`. Каждое совпадение становится зоной.

---

## regex/pii_patterns.yaml — полная схема

```yaml
patterns:
  - name: email                     # уникальное имя паттерна
    pattern: '[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
    category: PII                   # PII | SECRET | ENDPOINT | DICTIONARY
    severity: HIGH                  # CRITICAL | HIGH | MEDIUM | LOW | INFO

  - name: slack_token
    pattern: 'xox[baprs]-[0-9A-Za-z-]+'
    category: SECRET
    severity: CRITICAL

  - name: jira_ticket
    pattern: '[A-Z]{2,10}-\d{1,6}'
    category: DICTIONARY
    severity: MEDIUM

  - name: internal_url
    pattern: 'https?://[a-z0-9.-]*\.corp\.[a-z]+'
    category: ENDPOINT
    severity: MEDIUM
```

Паттерны применяются:
- При сканировании рабочего дерева (шаги 3, 5) — к тексту в зонах для code-файлов, ко всему файлу для docs/config.
- При сканировании блобов истории (шаги 6b, 8b) — ко всему содержимому каждого блоба.
- При переписывании истории (шаг 7) — в `blob_callback` через байтовые регулярные выражения; совпадение заменяется на `[name:{hash12}]`.

**Важно:** паттерны применяются как `re.compile(pattern)` — без флагов. Добавьте `(?i)` в начало для case-insensitive.

---

## Словари (dict/*.txt)

Один термин на строку. Строки, начинающиеся с `#`, — комментарии.

```
# domains.txt
corp.internal
mycompany.io
staging.mycompany.io
```

```
# codenames.txt
# Список кодовых названий проектов
ProjectPhoenix
OperationAlpha
InitiativeZero
```

```
# clients.txt
Клиент А
Client B Corp
SomeEnterprise Ltd
```

Поиск выполняется алгоритмом Aho-Corasick (case-insensitive) — работает за O(длина текста) независимо от числа терминов.

Домены из `dict/domains.txt` дополнительно используются `EndpointDetector` при сканировании.

---

## Приоритеты конфигурации

```
CLI --max-file-mb 50
    ↓ если не задан
env REPO_SANITIZER_MAX_FILE_MB=30
    ↓ если не задан
rulepack/policies.yaml: max_file_mb: 20
    ↓ если не задан
default: 20
```

---

## Контроль версий rulepack

Рекомендуется хранить rulepack в отдельном Git-репозитории:

```
company-sanitizer-rules/
├── VERSION          # bumping при изменении правил
├── CHANGELOG.md     # что изменилось и почему
├── policies.yaml
├── extractors.yaml
├── dict/
│   ├── domains.txt
│   └── clients.txt
└── regex/
    └── pii_patterns.yaml
```

При изменении словарей или паттернов — поднять версию в `VERSION`. Это позволяет отслеживать, с каким rulepack был создан конкретный бандл (версия логируется в артефактах).
