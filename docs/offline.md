# Использование в офлайн-среде

Для работы в изолированной сети или air-gapped среде необходимо заранее подготовить все зависимости.

## Шаг 1: Подготовка пакетов Python

На машине с интернетом:

```bash
# Скачать все зависимости в папку
pip download repo-sanitizer -d ./packages/
# или для конкретной версии Python:
pip download repo-sanitizer \
  --python-version 3.13 \
  --platform manylinux_2_28_x86_64 \
  -d ./packages/
```

На офлайн-машине:

```bash
pip install --no-index --find-links ./packages/ repo-sanitizer
```

## Шаг 2: NER-модель

Выберите один из двух backend'ов.

### Вариант А: HuggingFace backend (требует transformers + torch)

На машине с интернетом:

```bash
pip install huggingface-hub
huggingface-cli download Davlan/bert-base-multilingual-cased-ner-hrl \
  --local-dir ./models/bert-multilingual-ner
```

Скопировать `./models/bert-multilingual-ner/` на офлайн-машину, затем в rulepack:

```yaml
# policies.yaml
ner:
  backend: hf
  model: /path/to/models/bert-multilingual-ner
  min_score: 0.7
  entity_types: [PER, ORG]
```

### Вариант Б: GLiNER backend (рекомендуется, не требует torch)

На машине с интернетом:

```bash
pip install huggingface-hub
huggingface-cli download urchade/gliner_multi-v2.1 \
  --local-dir ./models/gliner-multi
```

Скопировать `./models/gliner-multi/` на офлайн-машину, затем в rulepack:

```yaml
# policies.yaml
ner:
  backend: gliner
  model: /path/to/models/gliner-multi
  min_score: 0.5
  entity_types: [PER, ORG]
```

Также скачать офлайн пакет `gliner`:

```bash
pip download gliner -d ./packages/
# на офлайн-машине:
pip install --no-index --find-links ./packages/ gliner
```

## Шаг 3: gitleaks

Скачать бинарник с [releases](https://github.com/gitleaks/gitleaks/releases) для нужной ОС и поместить в PATH.

## Шаг 4: git-filter-repo

```bash
# Скачать как wheel и установить офлайн
pip download git-filter-repo -d ./packages/
```

## Верификация

```bash
gitleaks version
python -c "import git_filter_repo; print('ok')"
python -c "from transformers import pipeline; print('ok')"
repo-sanitizer --help
```

---

## Batch-режим: дополнительные зависимости

Для `repo-sanitizer batch run` нужны дополнительные пакеты:

```bash
# На машине с интернетом
pip download python-gitlab fastapi "uvicorn[standard]" httpx -d ./packages/

# На офлайн-машине
pip install --no-index --find-links ./packages/ python-gitlab fastapi "uvicorn[standard]" httpx
```

В batch-режиме GitLab доступен по сети (self-hosted GitLab), поэтому полная air-gap изоляция обычно не требуется — только NER-модель и pip-пакеты нужно подготовить заранее.
