#!/usr/bin/env bash
# Creates a test git repo whose files exercise the Pass-1 over-redaction fixes:
# build-critical infrastructure (public URLs, loopback/private IPs, .sln GUIDs,
# SSH git remotes, hash digit-runs) MUST survive, while real PII/secret/public-IP
# MUST be masked. Used by test_pipeline_history.py::test_buildfiles_*.
set -euo pipefail

DEST="${1:?Usage: create_buildfiles_repo.sh <dest_dir>}"
rm -rf "$DEST"
mkdir -p "$DEST"
cd "$DEST"

git init -q
git config user.name "Build Bot"
git config user.email "ci@corp.com"

# docker-compose: loopback/private host binds (KEEP) + a public IP (MASK)
cat > docker-compose.yml << 'EOF'
services:
  web:
    ports:
      - "127.0.0.1:8080:80"
      - "192.168.1.10:5432:5432"
      - "52.14.226.9:9000:9000"
EOF

# .sln with a realistic hex GUID (KEEP — uuid pattern removed)
cat > App.sln << 'EOF'
Project("{9A19103F-16F7-4668-BE54-5B6A7B8C9D0E}") = "App", "App\App.csproj", "{B2C3D4E5-6789-4ABC-DEF0-123456789ABC}"
EndProject
EOF

# Dockerfile: public package-infra URL (KEEP)
cat > Dockerfile << 'EOF'
FROM node:18
RUN curl -sL https://deb.nodesource.com/setup_18.x | bash -
EOF

# composer.json: SSH git remote (KEEP) — valid JSON manifest
cat > composer.json << 'EOF'
{
  "name": "app/app",
  "repositories": [
    { "type": "vcs", "url": "git@github.com:org/repo.git" }
  ]
}
EOF

# NuGet.Config: public feed URL (KEEP)
cat > NuGet.Config << 'EOF'
<configuration>
  <packageSources>
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
EOF

# checksum file: a long digit run (KEEP — phone patterns must not corrupt it)
cat > checksums.txt << 'EOF'
module-a 884951234567894951234567890 verified
EOF

# real PII (MASK) + a secret-bearing URL (MASK) + a company URL host (MASK,
# while the public package-infra URLs above stay)
cat > CONTACT.md << 'EOF'
Maintainer email: real.dev@company.com
Support phone: +7 (495) 123-45-67
API base: https://api.acmevendor.io/v1/orders
Callback: https://hook.acmevendor.io/cb?token=liveSECRETtoken1234567890
EOF

git add -A
git -c commit.gpgsign=false commit -qm "Initial build files"

echo "Build-files repo created at $DEST"
