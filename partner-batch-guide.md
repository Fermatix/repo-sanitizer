# Partner Batch Guide

Инструкция по запуску repo-sanitizer batch на стороне партнёра.

---

## Минимальные требования к оборудованию

- **GPU:** NVIDIA RTX 2080 Ti (11 GB VRAM) — минимально достаточно для NER-модели (~1.1 GB VRAM)
- **CPU:** рекомендуется ≥ 16 физических ядер (Threadripper или аналог)
- **Диск:** ≥ 50 GB свободного места в `/tmp` для временных рабочих директорий
- **ОС:** Linux (Ubuntu 22.04+)

---

## Шаг 1. Установить зависимости

```bash
# Python-пакет
pip install repo-sanitizer

# gitleaks (обязателен — без него пайплайн не запустится)
sudo apt install gitleaks        # Ubuntu/Debian
# или: https://github.com/gitleaks/gitleaks/releases

# git-filter-repo
pip install git-filter-repo

# NER (опционально, но нужен для GPU-инференса)
pip install transformers torch
```

---

## Шаг 2. Переменные окружения

Создайте файл `.env` в корне проекта (он в `.gitignore`, наружу не утечёт):

```bash
# .env
REPO_SANITIZER_SALT=<секретная строка — сгенерируйте один раз и сохраните>
GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx
```

Сгенерировать salt:

```bash
openssl rand -hex 32
```

> **Важно:** `REPO_SANITIZER_SALT` должен быть **одинаковым** во всех запусках — иначе одинаковые значения получат разные замены и результаты нельзя будет сопоставить.

Права на GitLab-токен:

| Группа | Требуемые права |
|---|---|
| `source_group` | `read_api`, `read_repository` |
| `delivery_group` | `api`, `write_repository` |

---

## Шаг 3. Настроить `examples/batch.yaml`

Откройте `examples/batch.yaml` и заполните два блока, помеченных `# You can configure this`:

```yaml
gitlab:
  url: https://gitlab.com               # ваш GitLab-хост
  token_env: GITLAB_TOKEN               # имя переменной с токеном (не меняйте)
  source_group: your-group/subgroup     # ← ЗАПОЛНИТЬ: группа с исходными репозиториями
  delivery_group: your-delivery/subgroup # ← ЗАПОЛНИТЬ: группа для доставки результатов
  clone_depth: 0                        # не трогать (нужна полная история)

scope:
  all: true                             # обработать все репо в source_group
  # Или ограничить список:
  # partners:
  #   - partner-name
  # repos:
  #   - partner-name/repo-name

processing:
  workers: 16                           # ≤ количеству физических ядер CPU
  ner_batch_size: 32                    # для RTX 2080 Ti — оставить 32
  ner_service_port: 8765
  work_base_dir: /tmp/repo-san-work
  keep_work_dirs: false
```

> Блок `rulepack` и всё в `processing`/`output` — **не менять**.

---

## Шаг 4. Запустить

```bash
chmod +x scripts/run-batch.sh

# Запустить в фоне (сессия SSH закроется — процесс продолжит работу)
./scripts/run-batch.sh start examples/batch.yaml
```

Управление запущенным процессом:

```bash
./scripts/run-batch.sh logs     # следить за логами в реальном времени
./scripts/run-batch.sh status   # проверить: запущен / завершён
./scripts/run-batch.sh stop     # остановить досрочно
```

---

## Шаг 5. Как понять, что всё прошло успешно

**Итоговый файл:** `./batch-artifacts/batch_summary.json`

```json
{
  "total": 42,
  "succeeded": 42,
  "failed": 0,
  "pushed": 42
}
```

`failed: 0` и `pushed == total` — всё ок.

**На каждый репозиторий:** `./batch-artifacts/<partner>/<repo>/batch_result.json`

```json
{
  "status": "done",
  "exit_code": 0,
  "pushed": true,
  "bundle_sha256": "abc123..."
}
```

**Если есть ошибки** — повторить только упавшие:

```bash
./scripts/run-batch.sh start examples/batch.yaml -- --retry-failed
```

**Артефакты хранятся** в `./batch-artifacts/<partner>/<repo>/`:

| Файл | Содержимое |
|---|---|
| `result.json` | Результаты гейтов и SHA-256 бандла |
| `scan_report_pre.json` | Что было найдено до редактирования |
| `inventory.json` | Какие файлы обработаны / удалены |
