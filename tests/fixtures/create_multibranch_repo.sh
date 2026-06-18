#!/usr/bin/env bash
# Creates a multi-branch, tagged test repo for the ref-reconcile / keep-all-branches
# tests. All data is synthetic. Layout:
#   main                  : default branch, commits with PII content + a secret .env
#   develop               : benign NAME (survives verbatim); a commit whose CONTENT
#                           and message carry an email (proves cross-branch scrub)
#   feature/jane@corp.com : email in the BRANCH NAME (proves name scrubbing)
#   v1.0 (lightweight) + v2.0 (annotated, PII message) : tags (proves tags are dropped)
# HEAD is left on main.
set -euo pipefail

DEST="${1:?Usage: create_multibranch_repo.sh <dest_dir>}"
rm -rf "$DEST"
mkdir -p "$DEST"
cd "$DEST"

git init -b main
git config user.name "John Doe"
git config user.email "john@corp.com"

# main: commit A (secret .env) + commit B
cat > .env << 'EOF'
SECRET_TOKEN=sk-supersecret123456
DB_PASSWORD=hunter2
EOF
cat > main.py << 'EOF'
"""Main module."""
print("Hello World")
EOF
git add -A
git commit -q -m "Initial commit by john.doe@corp.com"

rm .env
cat > main.py << 'EOF'
"""Updated main module."""
print("Hello World v2")
EOF
git add -A
git commit -q -m "Cleanup configs"

# develop: benign name; unique commit with an email in content + message
git checkout -q -b develop
cat > app.py << 'EOF'
# contact: jane@corp.com
def run():
    return "ok"
EOF
git add -A
git commit -q -m "feature work by jane@corp.com"

# feature/jane@corp.com: email in the BRANCH NAME
git checkout -q main
git checkout -q -b 'feature/jane@corp.com'
echo "x" > side.txt
git add -A
git commit -q -m "side branch commit"

# tags on main
git checkout -q main
git tag v1.0
git tag -a v2.0 -m "release prepared by jane@corp.com"

echo "Multi-branch repo created at $DEST"
