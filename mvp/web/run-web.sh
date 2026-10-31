#!/usr/bin/env bash
# Starts the new web console next to SentrAI (Streamlit keeps running as before). Start SentrAI first (../run.sh).
# Builds the console when its source changed, then serves it on http://127.0.0.1:5173, passing /api to the core.
# Sign in with the same account as the Streamlit console.   ./run-web.sh [core-url]
set -euo pipefail
CORE="${1:-http://127.0.0.1:${SENTRAI_CORE_PORT:-8000}}"
cd "$(dirname "$0")/app"
command -v npm >/dev/null || { echo "Node.js (npm) is needed: https://nodejs.org" >&2; exit 2; }
[ -d node_modules ] || npm ci
if [ ! -f dist/index.html ] || [ -n "$(find src index.html vite.config.ts -newer dist/index.html -type f | head -1)" ]; then
  npm run build
fi
echo "Web console: http://127.0.0.1:5173  (core: $CORE)"
VITE_CORE_URL="$CORE" exec npx vite preview
