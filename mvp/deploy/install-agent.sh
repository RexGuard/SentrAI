#!/usr/bin/env bash
# Installs the SentrAI agent on a machine that reports to a central SentrAI panel (run as root,
# from a checkout of the repo). The panel scores and decides; this machine sends its logs and puts
# the panel's blocks for it into its own firewall. Only outgoing HTTPS, no open port. While the
# panel cannot be reached, local rules block clear attacks for an hour at a time and report back.
#
#   On the panel:   Machines > Add machine (or POST /fleet/join-codes) gives a one-time join code
#                   and the panel's certificate pin.
#   Here:           sudo ./deploy/install-agent.sh --panel https://panel.example.com:8443 --code ABCD-EFGH-JKLM \
#                       --pin sha256:...
#
# Options:
#   --panel URL       the panel's core address (https://; required on a first install)
#   --code CODE       the one-time join code (required on a first install)
#   --name NAME       this machine's name on the panel (default: its host name)
#   --pin PIN         the panel's certificate pin (sha256:...), shown with the join code
#   --ca FILE         the panel's certificate file, instead of a pin
#   --allow-http      accept a plain http:// panel (private test networks only)
#   --enforce         really change the firewall (default: dry run, the commands are only logged)
#   --protect IP      never block this IP or network here (repeatable; the panel's own address is always kept)
#   --prefix DIR      where the code goes (default /opt/cactai)
#   --user NAME       system account the agent runs as (default cactai)
#   --no-start        install and enable, but do not start it
#
# What it creates:
#   /etc/cactai/agent.env              settings (root:cactai 0640)
#   /var/lib/cactai/agent/             machine key, read positions, blocks in force (cactai 0700)
#   /etc/systemd/system/cactai-agent.service
# The agent also approves this machine's nginx, SSH login, Suricata and database logs (collector --add-system-logs).
# Remove it with: systemctl disable --now cactai-agent && rm /etc/systemd/system/cactai-agent.service
set -euo pipefail

PREFIX=/opt/cactai
SVC_USER=cactai
PANEL=""
CODE=""
NAME=""
CA=""
PIN=""
ALLOW_HTTP=0
ENFORCE=0
START=1
PROTECT=()
while [ $# -gt 0 ]; do
    case "$1" in
        --panel) PANEL="$2"; shift 2 ;;
        --code) CODE="$2"; shift 2 ;;
        --name) NAME="$2"; shift 2 ;;
        --pin) PIN="$2"; shift 2 ;;
        --ca) CA="$2"; shift 2 ;;
        --allow-http) ALLOW_HTTP=1; shift ;;
        --enforce) ENFORCE=1; shift ;;
        --protect) PROTECT+=("$2"); shift 2 ;;
        --prefix) PREFIX="$2"; shift 2 ;;
        --user) SVC_USER="$2"; shift 2 ;;
        --no-start) START=0; shift ;;
        -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
done

die() { echo "install-agent.sh: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root (sudo ./deploy/install-agent.sh)"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -f "$SRC/lab/agent/agent.py" ] || die "run it from a SentrAI checkout (mvp/deploy/install-agent.sh)"
PYTHON="${PYTHON:-python3}"
"$PYTHON" -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null || die "python 3.10 or newer is required"
"$PYTHON" -c 'import ensurepip, venv' 2>/dev/null \
    || die "python's venv module is missing (Debian/Ubuntu: apt install python3-venv)"
MVP="$PREFIX/mvp"
[ "$MVP" != "$SRC" ] || die "--prefix must differ from this checkout"
STATE=/var/lib/cactai/agent
ENV_FILE=/etc/cactai/agent.env
if [ ! -f "$STATE/agent.json" ]; then
    [ -n "$PANEL" ] && [ -n "$CODE" ] || die "a first install needs --panel URL and --code CODE (from the panel's Machines page)"
fi

# --- account and folders ----------------------------------------------------
if ! id "$SVC_USER" >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/cactai --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
    echo "Created system user $SVC_USER"
fi
LOG_GROUPS=()
for g in adm systemd-journal; do
    getent group "$g" >/dev/null && LOG_GROUPS+=("$g")
done
install -d -m 0755 /var/lib/cactai
install -d -o "$SVC_USER" -g "$SVC_USER" -m 0700 "$STATE" "$STATE/logs"
install -d -m 0750 -o root -g "$SVC_USER" /etc/cactai

# --- code and venv (the agent uses the lab venv, plus the core's firewall module) ---
echo "Copying code to $MVP ..."
install -d -m 0755 "$PREFIX" "$MVP"
[ -d "$MVP/lab" ] && find "$MVP/lab" -mindepth 1 -maxdepth 1 ! -name .venv -exec rm -rf {} +
rm -rf "$MVP/core/app"
tar -C "$SRC" -cf - --exclude=.venv --exclude=__pycache__ --exclude=.pytest_cache \
    --exclude=./lab/logs --exclude=./lab/scout/sources.json --exclude=./lab/scout/pending.json \
    ./lab ./core/app ./cactai_config.py ./cactai_llm.py | tar -C "$MVP" -xf - --no-same-owner
chown -R root:root "$MVP"
chmod -R u=rwX,go=rX "$MVP"
if [ ! -x "$MVP/lab/.venv/bin/python" ]; then
    echo "Creating venv ..."
    "$PYTHON" -m venv "$MVP/lab/.venv"
    "$MVP/lab/.venv/bin/python" -m pip install -q --upgrade pip
fi
"$MVP/lab/.venv/bin/python" -m pip install -q -r "$MVP/lab/requirements.txt"

# --- settings ---------------------------------------------------------------
protected="127.0.0.1,::1,localhost"
for ip in "${PROTECT[@]}"; do protected+=",$ip"; done
if [ ! -f "$ENV_FILE" ] || [ ${#PROTECT[@]} -gt 0 ] || [ "$ENFORCE" = 1 ]; then
    cat > "$ENV_FILE" <<EOF
# SentrAI agent settings (install-agent.sh). Restart after a change: systemctl restart cactai-agent
CACTAI_AGENT_FILE=$STATE/agent.json
CACTAI_CONFIG=$STATE/config.json
CACTAI_COLLECTOR_STATE=$STATE/collector-state.json
CACTAI_SCOUT_SOURCES=$STATE/sources.json
CACTAI_LAB_LOGS=$STATE/logs
CACTAI_FIREWALL=auto
CACTAI_FIREWALL_ENFORCE=$ENFORCE
PROTECTED_IPS=$protected
# While the panel cannot be reached: block clear attacks here for this long, at most this many an hour.
CACTAI_AGENT_LOCAL_RULES=on
CACTAI_AGENT_LOCAL_TTL_MIN=60
CACTAI_AGENT_LOCAL_MAX_PER_HOUR=10
EOF
    chown root:"$SVC_USER" "$ENV_FILE"
    chmod 0640 "$ENV_FILE"
fi
if [ -n "$CA" ]; then
    install -o root -g "$SVC_USER" -m 0640 "$CA" /etc/cactai/panel-ca.pem
    CA=/etc/cactai/panel-ca.pem
fi

as_agent() {  # run as the service account with the agent's settings
    (cd "$MVP/lab" && set -a && . "$ENV_FILE" && set +a && \
        setpriv --reuid="$SVC_USER" --regid="$SVC_USER" --init-groups \
        env HOME=/var/lib/cactai "$MVP/lab/.venv/bin/python" "$@")
}

# --- join -------------------------------------------------------------------
if [ -n "$CODE" ]; then
    args=(-m agent join --panel "$PANEL" --code "$CODE")
    [ -n "$NAME" ] && args+=(--name "$NAME")
    [ -n "$PIN" ] && args+=(--pin "$PIN")
    [ -n "$CA" ] && args+=(--ca "$CA")
    [ "$ALLOW_HTTP" = 1 ] && args+=(--allow-http)
    as_agent "${args[@]}" || die "could not join the panel (see the message above)"
fi
as_agent -m collector.collector --add-system-logs || echo "No web, SSH, Suricata or database logs found yet; approve logs later with Scout."

# --- service ----------------------------------------------------------------
sed -e "s|@PREFIX@|$PREFIX|g" -e "s|@USER@|$SVC_USER|g" -e "s|@LOGGROUPS@|${LOG_GROUPS[*]}|g" \
    "$SRC/deploy/cactai-agent.service" > /etc/systemd/system/cactai-agent.service
systemctl daemon-reload
systemctl enable cactai-agent >/dev/null
if [ "$START" = 1 ]; then
    systemctl restart cactai-agent
    echo "SentrAI agent started: journalctl -u cactai-agent -f"
fi
[ "$ENFORCE" = 1 ] || echo "Blocks are a dry run (logged only). Reinstall with --enforce to change the firewall."
