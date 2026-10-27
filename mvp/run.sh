#!/usr/bin/env bash
# Starts SentrAI on Linux or macOS (the bash twin of run.ps1).
#
#   core       FastAPI risk engine + agents     http://127.0.0.1:8000  (--core-port)
#   collector  tails the logs you approved -> core
#   notifier   Telegram bot (console mode if TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID are not set)
#   dashboard  Streamlit                        http://127.0.0.1:8501  (--dashboard-port)
#
# Each component runs in the background; its output goes to mvp/.run_logs/<name>.log
# (tail -f that file instead of watching a window). PIDs are saved to mvp/.run_pids.json
# so stop.sh stops only these.
#
#   ./run.sh                            real time: one real hour is one hour on the timers
#   ./run.sh --speed 60                 faster timers for testing (1 real minute = 1 hour)
#   ./run.sh --no-dashboard --no-browser
#   ./run.sh --core-bind 0.0.0.0        let machines on the network reach the core (agents joining this panel).
#                                       Default 127.0.0.1 (this computer only). The API needs its token, but runs
#                                       over plain http here: private test networks only (or set SENTRAI_CORE_HOST)
#   ./run.sh --core-port 8100           when 8000 is taken (or set SENTRAI_CORE_PORT; the dashboard
#                                       port can come from SENTRAI_DASHBOARD_PORT the same way)
#
# For a server that should keep SentrAI running, use deploy/install.sh (systemd services) instead.
#
# Needs python3 with the venv module (Debian/Ubuntu: sudo apt install python3-venv).
set -euo pipefail

# Settings named before the CactAI -> SentrAI rename still count: CACTAI_X fills in an unset SENTRAI_X.
for v in $(compgen -e | grep '^CACTAI_' || true); do
    n="SENTRAI_${v#CACTAI_}"; [ -n "${!n+x}" ] || export "$n=${!v}"
done

DEMO_SPEED="${DEMO_SPEED:-1}"
NO_DASHBOARD=0
NO_BROWSER=0
CORE_PORT="${SENTRAI_CORE_PORT:-8000}"
CORE_BIND="${SENTRAI_CORE_HOST:-127.0.0.1}"
DASH_PORT="${SENTRAI_DASHBOARD_PORT:-8501}"
while [ $# -gt 0 ]; do
    case "$1" in
        --speed) DEMO_SPEED="$2"; shift 2 ;;
        --no-dashboard) NO_DASHBOARD=1; shift ;;
        --no-browser) NO_BROWSER=1; shift ;;
        --core-port) CORE_PORT="$2"; shift 2 ;;
        --core-bind) CORE_BIND="$2"; shift 2 ;;
        --dashboard-port) DASH_PORT="$2"; shift 2 ;;
        -h|--help) sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
done
for p in "$CORE_PORT" "$DASH_PORT"; do
    case "$p" in ''|*[!0-9]*) echo "Ports must be numbers (got '$p')" >&2; exit 2 ;; esac
done
if [ "$CORE_PORT" = "$DASH_PORT" ]; then
    echo "Core and dashboard need two different ports." >&2; exit 2
fi
CORE="http://127.0.0.1:$CORE_PORT"
DASH="http://127.0.0.1:$DASH_PORT"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$ROOT/.run_pids.json"
LOG_DIR="$ROOT/.run_logs"
PYTHON="${PYTHON:-python3}"

if [ -f "$PID_FILE" ]; then
    echo "SentrAI seems to be running already (found .run_pids.json). Run ./stop.sh first." >&2
    exit 1
fi

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# Creates <component>/.venv once and reinstalls packages whenever requirements.txt changes.
ensure_venv() {
    local dir="$ROOT/$1"
    local py="$dir/.venv/bin/python"
    local stamp="$dir/.venv/requirements.installed"
    if [ ! -x "$py" ]; then
        echo "Creating venv for $1 ..."
        "$PYTHON" -m venv "$dir/.venv"
        "$py" -m pip install -q --upgrade pip
    fi
    local want have=""
    want="$(hash_file "$dir/requirements.txt")"
    [ -f "$stamp" ] && have="$(tr -d '[:space:]' < "$stamp")"
    if [ "$want" != "$have" ]; then
        echo "Installing packages for $1 ..."
        if "$py" -m pip install -q -r "$dir/requirements.txt"; then echo "$want" > "$stamp"
        else echo "pip could not install everything for $1 (see above)." >&2; fi
    fi
}

port_in_use() {
    "$PYTHON" - "$1" <<'EOF'
import socket, sys
# "In use" means something is listening (like Get-NetTCPConnection -State Listen in run.ps1).
try:
    socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=1).close()
except OSError:
    sys.exit(1)
sys.exit(0)
EOF
}

for p in "$CORE_PORT" "$DASH_PORT"; do
    if port_in_use "$p"; then
        echo "Port $p is already in use. Stop whatever is using it (or run ./stop.sh), or pick" >&2
        echo "another port with --core-port / --dashboard-port, and try again." >&2
        exit 1
    fi
done

for c in core lab dashboard notifier; do ensure_venv "$c"; done
PY_CORE="$ROOT/core/.venv/bin/python"
PY_LAB="$ROOT/lab/.venv/bin/python"
PY_DASH="$ROOT/dashboard/.venv/bin/python"
PY_NOTIF="$ROOT/notifier/.venv/bin/python"

# First run on this machine: ask for the settings (logs, rules, responder, alerts) once.
"$PY_LAB" "$ROOT/sentrai_config.py"

# Files older versions kept elsewhere move into the data root, and INDEX.md there lists every file.
"$PY_LAB" "$ROOT/sentrai_paths.py" index >/dev/null || echo "Could not write the data index (python sentrai_paths.py index)." >&2

# The core API token (made and saved on first use). Every component gets the same one.
SENTRAI_API_TOKEN="$("$PY_LAB" "$ROOT/sentrai_config.py" token | tail -n 1)"
[ -n "$SENTRAI_API_TOKEN" ] || { echo "Could not read the API token (python sentrai_config.py token)." >&2; exit 1; }
export SENTRAI_API_TOKEN

# Who may sign in to the dashboard; on a new machine, a one-time setup code for creating the Owner.
SIGN_IN="$("$PY_LAB" "$ROOT/sentrai_config.py" admin)" || { echo "Could not set up the dashboard sign-in." >&2; exit 1; }

export PYTHONUTF8=1 PYTHONIOENCODING=utf-8 PYTHONUNBUFFERED=1
export DEMO_SPEED SENTRAI_CORE_URL="$CORE" SENTRAI_PUBLIC_URL="${SENTRAI_PUBLIC_URL:-$CORE}"

mkdir -p "$LOG_DIR"
SETSID=""; command -v setsid >/dev/null 2>&1 && SETSID=setsid  # not on macOS; stop then kills the pid only
STARTED=()

start_component() {  # name workdir command...
    local name="$1" dir="$2"; shift 2
    # setsid puts the component in its own process group, so stop.sh can stop it
    # together with anything it spawned.
    ( cd "$dir" && exec $SETSID "$@" ) >"$LOG_DIR/$name.log" 2>&1 < /dev/null &
    local pid=$!
    printf '  started %-10s (pid %s, log .run_logs/%s.log)\n' "$name" "$pid" "$name"
    STARTED+=("{\"name\": \"$name\", \"pid\": $pid}")
    # Save after every start, so stop.sh can clean up even if a later step fails.
    (IFS=,; echo "[${STARTED[*]}]") > "$PID_FILE"
}

wait_http() {  # url [seconds]
    local deadline=$(( $(date +%s) + ${2:-40} ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if "$PYTHON" -c "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen(sys.argv[1], timeout=2).status == 200 else 1)" "$1" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

echo
if [ "$DEMO_SPEED" = 1 ]; then echo "SentrAI  (real time)"
else echo "SentrAI  (DEMO_SPEED=$DEMO_SPEED -> 1 real minute = $(awk "BEGIN{printf \"%.2f\", $DEMO_SPEED/60}") hours on the timers)"; fi

start_component core "$ROOT/core" "$PY_CORE" -m uvicorn app.main:app --host "$CORE_BIND" --port "$CORE_PORT"
wait_http "$CORE/health" || echo "Core did not come up on :$CORE_PORT. Check .run_logs/core.log" >&2
start_component collector "$ROOT/lab" "$PY_LAB" -m collector.collector
start_component notifier "$ROOT/notifier" "$PY_NOTIF" notifier.py

if [ "$NO_DASHBOARD" = 0 ]; then
    start_component dashboard "$ROOT/dashboard" "$PY_DASH" -m streamlit run app.py \
        --server.port "$DASH_PORT" --server.headless true --browser.gatherUsageStats false
    if wait_http "$DASH" 60 && [ "$NO_BROWSER" = 0 ]; then
        if command -v xdg-open >/dev/null 2>&1; then xdg-open "$DASH" >/dev/null 2>&1 || true
        elif command -v open >/dev/null 2>&1; then open "$DASH" || true; fi
    fi
fi

DATA_ROOT="$("$PY_LAB" -c 'import sys; sys.path.insert(0, sys.argv[1]); import sentrai_paths; print(sentrai_paths.root())' "$ROOT" || true)"

echo
echo "All components started."
echo "Core API:  $CORE"
echo "Dashboard: $DASH"
[ "$NO_DASHBOARD" = 1 ] || printf '%s\n' "$SIGN_IN"
echo "Logs:      mvp/.run_logs/  (tail -f .run_logs/core.log)"
[ -z "$DATA_ROOT" ] || echo "Data:      $DATA_ROOT  (INDEX.md there lists every file)"
echo "Stop everything with ./stop.sh"
