#!/usr/bin/env bash
# Builds the demo copy of the web console into ../../../demo-copy (served at https://rexguard.github.io/SentrAI/demo-copy/).
# No sign-in, no core: every page reads snapshot.json (made-up demo data) and nothing can be changed. See README.md.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/../../../demo-copy"
BASE="${DEMO_COPY_BASE:-/SentrAI/demo-copy/}"
cd "$HERE/../app"
[ -d node_modules ] || npm ci --no-audit --no-fund
VITE_DEMO_COPY=1 VITE_BASE="$BASE" npx vite build --outDir "$OUT" --emptyOutDir
cp "$HERE/snapshot.json" "$OUT/snapshot.json"
echo "Demo copy built in $OUT (base $BASE)"
