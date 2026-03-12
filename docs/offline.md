# Offline / air-gapped setup

To run in an isolated network, prepare all dependencies in advance on a machine with internet access, then transfer them to the offline machine.

---

## Step 1: Python packages

**On an internet-connected machine:**

```bash
# Download all dependencies to a local folder
pip download repo-sanitizer -d ./packages/

# For a specific Python version and platform:
pip download repo-sanitizer \
  --python-version 3.13 \
  --platform manylinux_2_28_x86_64 \
  -d ./packages/
```

**On the offline machine:**

```bash
pip install --no-index --find-links ./packages/ repo-sanitizer
```

---

## Step 2: NER model

Choose one backend.

### Option A: HuggingFace backend (requires transformers + torch)

**On an internet-connected machine:**

```bash
pip install huggingface-hub
huggingface-cli download Davlan/bert-base-multilingual-cased-ner-hrl \
  --local-dir ./models/bert-multilingual-ner
```

Copy `./models/bert-multilingual-ner/` to the offline machine, then set the local path in the rulepack:

```yaml
# policies.yaml
ner:
  backend: hf
  model: /path/to/models/bert-multilingual-ner
  min_score: 0.7
  entity_types: [PER, ORG]
```

### Option B: GLiNER backend (recommended — no torch required)

**On an internet-connected machine:**

```bash
pip install huggingface-hub
huggingface-cli download urchade/gliner_multi-v2.1 \
  --local-dir ./models/gliner-multi

# Also download the gliner package itself
pip download gliner -d ./packages/
```

Copy `./models/gliner-multi/` and `./packages/` to the offline machine:

```bash
# Install gliner package
pip install --no-index --find-links ./packages/ gliner
```

```yaml
# policies.yaml
ner:
  backend: gliner
  model: /path/to/models/gliner-multi
  min_score: 0.5
  entity_types: [PER, ORG]
```

---

## Step 3: gitleaks

Download the binary from the [gitleaks releases page](https://github.com/gitleaks/gitleaks/releases) for your OS and architecture. Place it somewhere in `PATH`.

---

## Step 4: git-filter-repo

```bash
# On an internet-connected machine
pip download git-filter-repo -d ./packages/

# On the offline machine
pip install --no-index --find-links ./packages/ git-filter-repo
```

---

## Verification

```bash
gitleaks version
python -c "import git_filter_repo; print('ok')"
python -c "from transformers import pipeline; print('ok')"  # hf backend only
repo-sanitizer --help
```

---

## Batch mode: additional dependencies

`repo-sanitizer batch run` requires extra packages for GitLab integration and the NER HTTP service:

```bash
# On an internet-connected machine
pip download python-gitlab fastapi "uvicorn[standard]" httpx -d ./packages/

# On the offline machine
pip install --no-index --find-links ./packages/ \
  python-gitlab fastapi "uvicorn[standard]" httpx
```

> In batch mode, GitLab is typically accessed over the internal network (self-hosted GitLab), so full air-gap isolation is usually not needed — only the NER model and pip packages need to be prepared in advance.
