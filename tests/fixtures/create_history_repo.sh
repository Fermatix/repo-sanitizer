#!/usr/bin/env bash
# Creates a test git repo with two commits for history rewriting tests.
set -euo pipefail

DEST="${1:?Usage: create_history_repo.sh <dest_dir>}"
rm -rf "$DEST"
mkdir -p "$DEST"
cd "$DEST"

git init
git config user.name "John Doe"
git config user.email "john@corp.com"

# Commit A: has .env, .mailmap, and a source file
cat > .env << 'EOF'
SECRET_TOKEN=sk-supersecret123456
DB_PASSWORD=hunter2
EOF

cat > .mailmap << 'EOF'
John Doe <john@corp.com> <jd@old.com>
EOF

cat > main.py << 'EOF'
"""Main module."""
# Written by John Doe
print("Hello World")
EOF

git add -A
git commit -m "Initial commit by john.doe@corp.com"

# Commit B: remove .env and .mailmap, update main.py
rm .env .mailmap

cat > main.py << 'EOF'
"""Updated main module."""
print("Hello World v2")
EOF

git add -A
git commit -m "Cleanup: removed configs. Contact john.doe@example.com for details"

echo "History repo created at $DEST"
