#!/usr/bin/env bash
# Creates a test git repo where:
#   - a SECRET lives only in an OLD commit's blob (file kept, token line removed)
#   - a BRAND ("Extyl") appears in a commit message, an old+current blob, AND a
#     directory name (app/extyl/) — to exercise apply-map across blobs/msgs/paths.
set -euo pipefail

DEST="${1:?Usage: create_brand_history_repo.sh <dest_dir>}"
rm -rf "$DEST"
mkdir -p "$DEST"
cd "$DEST"

git init -q
git config user.name "Jane Roe"
git config user.email "jane@corp.example"

mkdir -p app/extyl
# Unquoted high-entropy api_key value: gitleaks (generic-api-key) detects it,
# but the rulepack generic_api_key regex requires quotes → it does NOT. So this
# exercises the NEW full-history gitleaks secret-literal collection path.
cat > app/extyl/service.py << 'EOF'
# Extyl internal service config
API_KEY=Xb7Kp2Lm9Qr4Ts8Wv3Yz6Ac1Df5Gh0Jk
OWNER_EMAIL = "ops@extyl.io"
EOF
git add -A
git commit -qm "Add Extyl config with API_KEY"

# Remove the secret line but keep the file AND the brand → the token now exists
# only in the first commit's blob (history), the brand persists everywhere.
cat > app/extyl/service.py << 'EOF'
# Extyl internal service config
OWNER_EMAIL = "ops@example.com"
EOF
git add -A
# The secret here lives ONLY in the commit MESSAGE — gitleaks native git mode
# does not scan messages, so this exercises the message-text collection path.
git commit -qm "Drop token from Extyl config; rotated api_key=Qm9Wd3Lp7Tk2Rs8Yv4Xb1Nc6Hd0Jf5Gg"

echo "Brand history repo created at $DEST"
