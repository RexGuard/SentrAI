#!/usr/bin/env bash
# Starts the whole SentrAI demo on Linux or macOS (the bash twin of run_demo.ps1).
#
#   core       FastAPI risk engine + agents     http://127.0.0.1:8000  (--core-port)
#   target     Aegis Academy portal (fake)      http://127.0.0.1:5000
#   collector  tails the portal logs -> core
#   notifier   Telegram bot (console mode if TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID are not set)
#   dashboard  Streamlit                        http://127.0.0.1:8501  (--dashboard-port)
#
# Each component runs in the background; its output goes to mvp/.demo_logs/<name>.log
# (tail -f that file instead of watching a window). PIDs are saved to mvp/.demo_pids.json
# so stop_demo.sh stops only these.
#
#   ./run_demo.sh                       live mode, 1 real minute = 1 demo hour
#   ./run_demo.sh --demo-speed 600      faster inaction penalty (1 real minute = 10 demo hours)
#   ./run_demo.sh --mode replay         no collector; use replay/simulate.py instead of live attacks
#   ./run_demo.sh --no-dashboard --no-browser
#   ./run_demo.sh --tripwires           turn on the tripwires: honeypot, honeytokens, tarpit (--spines works too)
#   ./run_demo.sh --core-port 8100      when 8000 is taken (or set CACTAI_CORE_PORT; the dashboard
#                                       port can come from CACTAI_DASHBOARD_PORT the same way)
#
# For a server that should keep SentrAI running, use deploy/install.sh (systemd services) instead.
#
# Needs python3 with the venv module (Debian/Ubuntu: sudo apt install python3-venv).
set -euo pipefail

MODE=live
DEMO_SPEED=60
NO_DASHBOARD=0
NO_BROWSER=0
SPINES=0
CORE_PORT="${CACTAI_CORE_PORT:-8000}"
DASH_PORT="${CACTAI_DASHBOARD_PORT:-8501}"
TARGET_PORT=5000  # fixed: the attack scripts refuse any other port
while [ $# -gt 0 ]; do
    case "$1" in
        --mode) MODE="$2"; shift 2 ;;
        --demo-speed) DEMO_SPEED="$2"; shift 2 ;;
        --no-dashboard) NO_DASHBOARD=1; shift ;;
        --no-browser) NO_BROWSER=1; shift ;;
        --tripwires|--spines) SPINES=1; shift ;;
        --core-port) CORE_PORT="$2"; shift 2 ;;
        --dashboard-port) DASH_PORT="$2"; shift 2 ;;
        -h|--help) sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
done
case "$MODE" in live|replay) ;; *) echo "--mode must be live or replay" >&2; exit 2 ;; esac
for p in "$CORE_PORT" "$DASH_PORT"; do
    case "$p" in ''|*[!0-9]*) echo "Ports must be numbers (got '$p')" >&2; exit 2 ;; esac
done
if [ "$CORE_PORT" = "$DASH_PORT" ] || [ "$CORE_PORT" = "$TARGET_PORT" ] || [ "$DASH_PORT" = "$TARGET_PORT" ]; then
    echo "Core, dashboard and target ($TARGET_PORT) need three different ports." >&2; exit 2
fi
CORE="http://127.0.0.1:$CORE_PORT"
DASH="http://127.0.0.1:$DASH_PORT"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$ROOT/.demo_pids.json"
LOG_DIR="$ROOT/.demo_logs"
PYTHON="${PYTHON:-python3}"

if [ -f "$PID_FILE" ]; then
    echo "A demo seems to be running already (found .demo_pids.json). Run ./stop_demo.sh first." >&2
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
# "In use" means something is listening (like Get-NetTCPConnection -State Listen in run_demo.ps1).
try:
    socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=1).close()
except OSError:
    sys.exit(1)
sys.exit(0)
EOF
}

for p in "$CORE_PORT" "$TARGET_PORT" "$DASH_PORT"; do
    if port_in_use "$p"; then
        echo "Port $p is already in use. Stop whatever is using it (or run ./stop_demo.sh), or pick" >&2
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
"$PY_LAB" "$ROOT/cactai_config.py"

# The core API token (made and saved on first use). Every component gets the same one, and the
# scripts you run later (scenario.py, replay) read it from the settings file.
CACTAI_API_TOKEN="$("$PY_LAB" "$ROOT/cactai_config.py" token | tail -n 1)"
[ -n "$CACTAI_API_TOKEN" ] || { echo "Could not read the API token (python cactai_config.py token)." >&2; exit 1; }
export CACTAI_API_TOKEN

export PYTHONUTF8=1 PYTHONIOENCODING=utf-8 PYTHONUNBUFFERED=1
export DEMO_SPEED CACTAI_CORE_URL="$CORE" CACTAI_PUBLIC_URL="${CACTAI_PUBLIC_URL:-$CORE}"

mkdir -p "$LOG_DIR"
SETSID=""; command -v setsid >/dev/null 2>&1 && SETSID=setsid  # not on macOS; stop then kills the pid only
STARTED=()

start_component() {  # name workdir command...
    local name="$1" dir="$2"; shift 2
    # setsid puts the component in its own process group, so stop_demo.sh can stop it
    # together with anything it spawned.
    ( cd "$dir" && exec $SETSID "$@" ) >"$LOG_DIR/$name.log" 2>&1 < /dev/null &
    local pid=$!
    printf '  started %-10s (pid %s, log .demo_logs/%s.log)\n' "$name" "$pid" "$name"
    STARTED+=("{\"name\": \"$name\", \"pid\": $pid}")
    # Save after every start, so stop_demo.sh can clean up even if a later step fails.
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
echo "SentrAI demo  (mode: $MODE, DEMO_SPEED=$DEMO_SPEED -> 1 real minute = $(awk "BEGIN{printf \"%.2f\", $DEMO_SPEED/60}") demo hours)"

start_component core "$ROOT/core" "$PY_CORE" -m uvicorn app.main:app --host 127.0.0.1 --port "$CORE_PORT"
wait_http "$CORE/health" || echo "Core did not come up on :$CORE_PORT. Check .demo_logs/core.log" >&2
# Fresh audit chain and incident state for this take.
"$PYTHON" -c "import sys, urllib.request; urllib.request.urlopen(urllib.request.Request(sys.argv[1] + '/demo/reset', method='POST'), timeout=5)" "$CORE" 2>/dev/null || true

LAB_DIR="$ROOT/lab"
LOGS_DIR="$("$PY_LAB" "$ROOT/cactai_config.py" get CACTAI_LAB_LOGS)"
case "$LOGS_DIR" in
    "$LAB_DIR"*) [ -d "$LOGS_DIR" ] && find "$LOGS_DIR" -maxdepth 1 -name '*.jsonl' -delete ;;
esac

[ "$SPINES" = 1 ] && export CACTAI_SPINES=1  # tripwires in the portal (target_app/spines.py)
start_component target "$LAB_DIR" "$PY_LAB" -m target_app
wait_http "http://127.0.0.1:5000/healthz" || echo "Target app did not come up on :5000. Check .demo_logs/target.log" >&2

if [ "$MODE" = live ]; then
    start_component collector "$LAB_DIR" "$PY_LAB" -m collector.collector
fi
start_component notifier "$ROOT/notifier" "$PY_NOTIF" notifier.py

if [ "$NO_DASHBOARD" = 0 ]; then
    start_component dashboard "$ROOT/dashboard" "$PY_DASH" -m streamlit run app.py \
        --server.port "$DASH_PORT" --server.headless true --browser.gatherUsageStats false
    if wait_http "$DASH" 60 && [ "$NO_BROWSER" = 0 ]; then
        if command -v xdg-open >/dev/null 2>&1; then xdg-open "$DASH" >/dev/null 2>&1 || true
        elif command -v open >/dev/null 2>&1; then open "$DASH" || true; fi
    fi
fi

echo
echo "All components started. Next, from mvp/lab:"
if [ "$MODE" = live ]; then
    echo "  .venv/bin/python scenario.py                         # full story, narrated"
    echo "  or step by step:"
    echo "  .venv/bin/python -m attacks.benign"
    echo "  .venv/bin/python -m attacks.brute_force --count 8 --delay 0.3"
    echo "  .venv/bin/python -m attacks.sqli --count 3"
    [ "$SPINES" = 1 ] && echo "  .venv/bin/python -m attacks.spines                  # tripwires: honeypot + honeytokens (or scenario.py --tripwires)"
else
    echo "  .venv/bin/python -m replay.simulate                  # scripted replay (say so on camera)"
fi
echo
echo "Portal:    http://127.0.0.1:5000"
echo "Core API:  $CORE"
echo "Dashboard: $DASH"
echo "Logs:      mvp/.demo_logs/  (tail -f .demo_logs/core.log)"
echo "Stop everything with ./stop_demo.sh"
