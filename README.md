# Repository Sanitizer

Sanitize Git repositories and export bundles with rewritten history. Detection
and replacement follow a rulepack: file policies, patterns and dictionaries.

## Required: Installation

Use macOS or Linux. You need Git, an SSH client, OpenSSL, `gitleaks` and `uv`.
Python 3.11+ is supported; these commands use Python 3.13, installed by `uv` if
needed.

**macOS**, with [Homebrew](https://brew.sh/) installed:

```bash
brew install git uv gitleaks openssl
```

The SSH client is included with macOS.

**Ubuntu / Debian**:

```bash
sudo apt-get update
sudo apt-get install -y git curl openssh-client ca-certificates openssl build-essential
curl -LsSf https://astral.sh/uv/install.sh | sh
. "$HOME/.local/bin/env"
mkdir -p "$HOME/.local/bin"
gitleaks_version=8.30.1
gitleaks_arch="$(uname -m)"
case "$gitleaks_arch" in
  x86_64) gitleaks_arch=x64 ;;
  aarch64) gitleaks_arch=arm64 ;;
esac
curl -fL "https://github.com/gitleaks/gitleaks/releases/download/v${gitleaks_version}/gitleaks_${gitleaks_version}_linux_${gitleaks_arch}.tar.gz" \
  | tar -xz -C "$HOME/.local/bin" gitleaks
export PATH="$HOME/.local/bin:$PATH"
```

**Then, on either platform**:

```bash
git clone https://github.com/Fermatix/repo-sanitizer.git
cd repo-sanitizer
uv sync --locked --python 3.13
```

Run subsequent commands from this directory. `uv run` uses the project
environment; activation is unnecessary.

## Required: Quickstart

Create `repos.txt` with one SSH URL per line. Your SSH key must have read access
to these repositories:

```text
# Blank lines and lines starting with # are ignored

git@git.example.com:group/service-api.git
git@git.example.com:group/mobile-app.git
```

```bash
# 1. Set the salt once for this run
export REPO_SANITIZER_SALT="$(openssl rand -hex 32)"

# 2. Sanitize with the bundled rules
uv run repo-sanitizer sanitize-batch ./repos.txt \
  --rulepack ./examples/rules \
  --out ./sanitized-output

# 3. Check results
cat sanitized-output/batch_summary.json
```

Bundles are written to `sanitized-output/<repository>/output/sanitized.bundle`.
Check that all intended repositories are `done`, with `failed` and `pending` both
zero. Review bundles before sharing; keep the salt and reports private.

---

## Optional reference

### Additional parsers

The `grammars` extra supplies additional tree-sitter language parsers:

```bash
uv sync --locked --extra grammars
```

### Parallelism

The batch chooses its worker count automatically. Add `--workers 2` to the batch
command to limit processing to two worker processes.

### Verification

Add `--gate` to a fresh sanitization run to enable the final verification checks.
The CLI skips these checks by default. With `--gate`, a failed blocking check
makes the run exit nonzero; a bundle may still exist when verification fails.

To check an existing bundle independently:

```bash
uv run repo-sanitizer gate sanitized-output/service-api/output/sanitized.bundle \
  --rulepack ./examples/rules --out audit-output/service-api --ner-scope off
cat audit-output/service-api/artifacts/result.json
```

Check that `all_passed` is `true`. Review advisory findings, skipped content and
any remaining items in the scan reports. Passing gates describes the configured
checks and detection scope, not a guarantee that every sensitive value was found.

Restore the bundle to inspect the rewritten code and history:

```bash
git clone sanitized-output/service-api/output/sanitized.bundle verification-service-api
```

### Resume and rerun

Keep the same salt for related runs; do not regenerate it when resuming. Store it
in your private secret store if you need to reuse it in another shell. The same
salt and input value produce consistent replacements.

Rerun the sanitization command with the same list, rules and salt to resume. State is
stored in `<out>/.sanitize_batch_state.json`; completed entries are skipped.
Add `--retry-failed` to retry failed entries.

Use a fresh output directory when the source, rules, salt or detection settings
change. Resume does not refresh completed results. Output keys use the repository
basename; duplicate names receive suffixes such as `-2`. Keep the list stable
when resuming so those keys still refer to the same sources.

### Other inputs

HTTPS URLs, local Git repositories and Git bundles can also appear in `repos.txt`:

```text
https://github.com/example-org/mobile-app.git

# Without an SSH key, include your username and token in the HTTPS URL
https://username:TOKEN@git.example.com/group/legacy-service.git

/home/user/repos/internal-tool
/home/user/bundles/service-api.bundle
```

For private HTTPS repositories, a credential helper is another option. Batch
preflight tries existing access, then SSH; in an interactive terminal it can
ask for HTTPS credentials. Unresolved access stops the batch before processing.
Workers do not prompt. `--no-preflight` skips this initial check.

Inputs must be Git repositories or Git bundles; Mercurial is not supported.

For one repository, use `sanitize` with the same rulepack and salt:

```bash
uv run repo-sanitizer sanitize git@git.example.com:group/service-api.git \
  --rulepack ./examples/rules --out sanitized-output/single --ner-scope off --gate
```

### NER

Named-entity recognition (NER) adds model-based name detection. Before enabling
the bundled model, download it:

```bash
uv run hf download Babelscape/wikineural-multilingual-ner
```

The model is cached locally. See [offline setup](docs/offline.md) for preparing
an environment without network access.

`sanitize-batch` defaults to `--ner-scope off`. Single-repository `sanitize`,
`scan` and `gate` default to `head`. The available scopes are:

| Scope | Coverage |
|---|---|
| `off` | Rule-based detectors only; no NER model loaded |
| `head` | NER on the checked-out working tree |
| `all` | Also scan commit metadata and historical file blobs with NER |

The bundled rulepack selects `Babelscape/wikineural-multilingual-ner` and
`cuda:0`. Override the device explicitly on a machine without CUDA:

```bash
uv run repo-sanitizer sanitize-batch repos.txt \
  --rulepack ./examples/rules --out sanitized-output/ner \
  --workers 2 --ner-scope head --ner-device cpu --gate
```

A batch with NER enabled starts one shared service. `--ner-service-url URL` uses
an existing service; `--ner-service-port` changes the automatically started
service's port (default `8765`). Whole-history NER can take substantially longer.
NER-only names detected in history are reported for follow-up, not automatically
rewritten throughout history.

### Rules and output scope

The Quickstart uses `examples/rules` directly. For custom policies, patterns or
dictionaries, see [rulepack authoring](docs/rulepack-authoring.md) and pass your
rulepack directory with `--rulepack`.

The pipeline rewrites commit identities, configured sensitive values and
matching historical content, and removes denied files. It preserves branches
with sanitized names where needed; tags and other non-branch refs are removed.
Commit hashes change. No repository is overwritten at its source.

The bundled rulepack enables `mask_config_values: true`: an additional pass
masks literal sensitive values in supported application config files while
preserving keys, structure, environment references and ordinary settings.
Files covered by deny rules, such as `.env`, private keys and environment-specific
overlays, are removed unless an allowed example/template suffix applies.

That extra config pass handles UTF-8/CP1251 text up to 2 MiB per file/blob.
Unsupported or excluded paths, binary/NUL-containing, larger or undecodable
candidates are skipped by this pass. Inspect its counters in
`artifacts/config_values_working_tree.json` and
`artifacts/config_values_history.json`. Other detectors still apply within their
own scope and limits. Custom rulepacks must explicitly enable this config pass.

Dictionary and brand findings can require a reviewed replacement map. `apply-map`
applies that map to historical blobs, commit messages and paths. It is a separate
step; a first-pass bundle can still have unresolved brand findings.

Large or binary content may be skipped according to the rulepack. Git LFS object
payloads, recursively processing submodules, wiki repositories and hosting API
PR/MR metadata are outside this workflow. Repository builds are not verified by
the sanitizer's gates.

### Commands

All commands below run through `uv run repo-sanitizer`. Use `<command> --help`
for the current options.

| Command | Purpose |
|---|---|
| `sanitize-batch <list>` | Process a list into local result directories |
| `sanitize <source>` | Process one repository |
| `scan <source>` | Write scan reports without redaction or history rewrite |
| `gate <source>` | Check an already-sanitized repository or bundle |
| `apply-map <source>` | Apply a supplied `--brand-map` to rewritten history |
| `expand-variants` | Expand a name into spelling variants for a map |
| `ner-service` | Run a shared NER service |
| `batch list` / `batch run` | Discover/process GitLab repositories using a config |

### Documentation

| Document | Contents |
|---|---|
| [Pipeline](docs/pipeline.md) | Stages, detectors and artifacts |
| [Rulepacks](docs/rulepack-authoring.md) | Policies, extractors, patterns and dictionaries |
| [GitLab batch](docs/batch.md) | Discovery, parallel processing and delivery configuration |
| [Architecture](docs/architecture.md) | Internal data flow and history rewriting |
| [Offline setup](docs/offline.md) | Preparing dependencies and models without runtime downloads |

### Development

```bash
uv sync --locked --extra grammars --group dev
uv run pytest
```

Integration tests need Git and `gitleaks`. NER tests can load model weights;
provide the corresponding cache or network access when running those tests.
