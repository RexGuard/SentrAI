#!/usr/bin/env bash
# Installs SentrAI on a Linux server as systemd services (run as root, from a checkout of the repo).
#
#   sudo ./deploy/install.sh                          install or upgrade with the defaults below
#   sudo ./deploy/install.sh --core-port 8100         when 8000 is taken
#   sudo ./deploy/install.sh --protect 203.0.113.10   never block your own admin IP (repeatable),
#                                                     and open the dashboard to that IP only
#
# Options (each is optional; on an upgrade only the ones you pass change /etc/sentrai/sentrai.env):
#   --prefix DIR           where the code goes (default /opt/sentrai; copied from this checkout)
#   --user NAME            system account the services run as (default sentrai)
#   --core-port N          core API port (default 8000)
#   --core-bind ADDR       core API address (default 127.0.0.1; the collector, dashboard and
#                          notifier reach it there)
#   --dashboard-port N     dashboard port (default 8501)
#   --dashboard-bind ADDR  dashboard address (default 127.0.0.1, or 0.0.0.0 when it is opened to
#                          --dashboard-allow addresses)
#   --protect IP           add an IP to PROTECTED_IPS, the list SentrAI never blocks (repeatable).
#                          Unless --dashboard-allow or --dashboard-local is given, the dashboard is
#                          opened to these IPs too.
#   --dashboard-allow IP   open the dashboard to this IP or network only (repeatable): it listens on
#                          all addresses, a firewall rule drops everyone else, and it uses HTTPS
#   --dashboard-local      keep the dashboard on this server only (reach it through an SSH tunnel)
#   --admin-email EMAIL    the dashboard Owner's email (asked on a first install when not given; with no
#                          password typed, the Owner is created in the browser with a setup code)
#   --reset-password       make a new password for that account (or the first Owner), shown once at the
#                          end; its authenticator app is added again at the next sign-in
#   --no-questions         never ask; with a terminal and without this, the installer asks for the
#                          dashboard port, who may open it, and on a new machine the Owner account
#   --no-notifier          do not enable the Telegram notifier service
#   --no-start             install and enable, but do not start or restart anything
#   --remote-copy URL      send every audit record and log line to a SentrAI witness on another
#                          machine (deploy/install-witness.sh), as they happen; "off" stops it
#   --remote-copy-token-file FILE   the witness's append token (needed with --remote-copy)
#   --remote-copy-ca FILE  the witness's certificate, when it is self-signed
#   --seal-journal         keep the system journal on disk and seal it (journald Forward Secure
#                          Sealing): prints a verification key once, to store away from this server
#   --panel [PORT]         make this server a central panel: agents on other machines join it over
#                          HTTPS on PORT (default 8443) with a self-signed certificate they pin, and
#                          each machine is scored on its own. That port only answers agents' machine
#                          keys; the API and dashboard stay as set above. "--panel off" closes it.
#   --panel-url URL        the address agents use (default https://<this server's name>:PORT)
#
# What it creates:
#   /etc/sentrai/sentrai.env           ports, addresses and paths (root:sentrai 0640, kept on upgrade)
#   /var/lib/sentrai/                 state: settings, approved log list, Scout trails (sentrai 0750)
#   /var/lib/sentrai/core/            the audit record and its fingerprint key (core only, 0700)
#   /var/lib/sentrai/collector/       the collector's read positions and line chain (collector only, 0700)
#   /etc/systemd/system/sentrai*.service and sentrai.target
#   /usr/local/bin/sentrai-scout      runs Scout as the service account (no terminal needed)
#   /usr/local/bin/sentrai-admin      shows or resets the dashboard sign-in (sudo sentrai-admin --reset)
#   /usr/local/sbin/sentrai-dashboard-firewall   the dashboard's firewall rule (run by its service)
#   /etc/sentrai/tls/                 a self-signed HTTPS certificate, when the dashboard is opened
# Least privilege: the account itself has no extra groups. Only the core and collector services
# get the adm and systemd-journal groups (to read /var/log/auth.log, nginx logs and the journal);
# only the core may change the firewall; each service sees only its own state folder (see the
# sentrai-*.service files). The only firewall change made here is the dashboard rule
# (plus a matching allow in ufw or firewalld when one is active). Nothing touches nginx or sshd.
# Remove everything again with ./deploy/uninstall.sh.
set -euo pipefail

PREFIX=/opt/sentrai
SVC_USER=sentrai
NOTIFIER=1
START=1
PROTECT=()
ALLOW=()
DASH_LOCAL=0
ADMIN_EMAIL=""
RESET_PW=0
ASK=1
SEAL=0
REMOTE=""
REMOTE_TOKEN=""
REMOTE_CA=""
PANEL=""
PANEL_URL=""
declare -A SET=()  # env values given on the command line
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        --user) SVC_USER="$2"; shift 2 ;;
        --core-port) SET[SENTRAI_CORE_PORT]="$2"; shift 2 ;;
        --core-bind) SET[SENTRAI_CORE_HOST]="$2"; shift 2 ;;
        --dashboard-port) SET[SENTRAI_DASHBOARD_PORT]="$2"; shift 2 ;;
        --dashboard-bind) SET[SENTRAI_DASHBOARD_HOST]="$2"; shift 2 ;;
        --protect) PROTECT+=("$2"); shift 2 ;;
        --dashboard-allow) ALLOW+=("$2"); shift 2 ;;
        --dashboard-local) DASH_LOCAL=1; shift ;;
        --admin-email) ADMIN_EMAIL="$2"; shift 2 ;;
        --reset-password) RESET_PW=1; shift ;;
        --no-questions|-y) ASK=0; shift ;;
        --no-notifier) NOTIFIER=0; shift ;;
        --no-start) START=0; shift ;;
        --seal-journal) SEAL=1; shift ;;
        --remote-copy) REMOTE="$2"; shift 2 ;;
        --remote-copy-token-file) REMOTE_TOKEN="$2"; shift 2 ;;
        --remote-copy-ca) REMOTE_CA="$2"; shift 2 ;;
        --panel) case "${2:-}" in [0-9]*|off) PANEL="$2"; shift 2 ;; *) PANEL=8443; shift ;; esac ;;
        --panel-url) PANEL_URL="$2"; shift 2 ;;
        -h|--help) sed -n '2,57p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
done
for k in SENTRAI_CORE_PORT SENTRAI_DASHBOARD_PORT; do
    v="${SET[$k]:-}"
    case "$v" in '') ;; *[!0-9]*) echo "$k must be a number (got '$v')" >&2; exit 2 ;; esac
done

case "$PANEL" in ''|off) ;; *[!0-9]*) echo "--panel takes a port number or off (got '$PANEL')" >&2; exit 2 ;; esac
case "$PANEL_URL" in ''|https://*) ;; *) echo "--panel-url must start with https:// (got '$PANEL_URL')" >&2; exit 2 ;; esac

case "$ADMIN_EMAIL" in ''|*@*) ;; *) echo "--admin-email needs an email address (got '$ADMIN_EMAIL')" >&2; exit 2 ;; esac

die() { echo "install.sh: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root (sudo ./deploy/install.sh)"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"  # the mvp/ folder of this checkout
[ -f "$SRC/core/app/main.py" ] || die "run it from a SentrAI checkout (mvp/deploy/install.sh)"
# An install from before the CactAI -> SentrAI rename moves to the new names first.
. "$SRC/deploy/migrate-from-cactai.sh"
migrate_from_cactai server
PYTHON="${PYTHON:-python3}"
"$PYTHON" -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null || die "python 3.10 or newer is required"
"$PYTHON" -c 'import ensurepip, venv' 2>/dev/null \
    || die "python's venv module is missing (Debian/Ubuntu: apt install python3-venv)"

ENV_FILE=/etc/sentrai/sentrai.env
STATE=/var/lib/sentrai
MVP="$PREFIX/mvp"
[ "$MVP" != "$SRC" ] || die "--prefix must differ from this checkout"

# --- questions: the web dashboard ------------------------------------------
# Asked only with a terminal, and only for what the command line left open. Enter keeps the value
# in [brackets]: the current one on an upgrade, else a sensible default.
existing() { if [ -f "$ENV_FILE" ]; then sed -n "s/^$1=//p" "$ENV_FILE" | tail -1; fi; }
saved_config="$(existing SENTRAI_CONFIG)"; saved_config="${saved_config:-$STATE/config.json}"
ADMIN_PASSWORD=""
if [ "$ASK" = 1 ] && [ -t 0 ]; then
    echo "SentrAI setup: the web dashboard. Press Enter to keep the value in [brackets]."
    if [ -z "${SET[SENTRAI_DASHBOARD_PORT]:-}" ]; then
        cur="$(existing SENTRAI_DASHBOARD_PORT)"
        while :; do
            read -r -p "  Dashboard port [${cur:-8501}]: " a || a=""
            case "$a" in '') break ;; *[!0-9]*) echo "    Please enter a number." ;; *) SET[SENTRAI_DASHBOARD_PORT]="$a"; break ;; esac
        done
    fi
    if [ "${#ALLOW[@]}" = 0 ] && [ "$DASH_LOCAL" = 0 ]; then
        cur="$(existing SENTRAI_DASHBOARD_ALLOW)"
        if [ -z "$cur" ]; then
            for ip in "${PROTECT[@]}"; do case "$ip" in 127.*|::1|localhost) ;; *) cur="${cur:+$cur,}$ip" ;; esac; done
        fi
        # The address this SSH session comes from is usually the admin's own.
        if [ -z "$cur" ]; then cur="$(who -m 2>/dev/null | sed -n 's/.*(\([0-9a-fA-F.:]*\)).*/\1/p' | head -1 || true)"; fi
        echo "  Who may open the dashboard? Your IP address(es), comma-separated. Everyone else is"
        echo "  blocked. Or type local to keep it on this server (reach it through an SSH tunnel)."
        read -r -p "  Allowed IPs [${cur:-local}]: " a || a=""
        a="${a:-${cur:-local}}"
        if [ "$a" = local ]; then DASH_LOCAL=1; else IFS=', ' read -r -a ALLOW <<< "$a"; fi
    fi
    # The Owner account, only on a machine with no one yet. People after that join by invite (Team page).
    if [ ! -f "$(dirname "$saved_config")/accounts.json" ] \
        && ! grep -q '"SENTRAI_DASHBOARD_PASSWORD_HASH": "pbkdf2' "$saved_config" 2>/dev/null; then
        echo "  The dashboard's Owner account. Press Enter to skip and create it in the browser with a setup code."
        if [ -z "$ADMIN_EMAIL" ]; then
            while :; do
                read -r -p "  Owner email: " a || a=""
                case "$a" in '') break ;; *@*.*) ADMIN_EMAIL="$a"; break ;; *) echo "    Please enter an email address." ;; esac
            done
        fi
        while [ -n "$ADMIN_EMAIL" ]; do
            read -r -s -p "  Owner password, at least 12 characters: " p1 || p1=""; echo
            if [ "${#p1}" -lt 12 ]; then echo "    Use at least 12 characters."; continue; fi
            read -r -s -p "  Type it again: " p2 || p2=""; echo
            if [ "$p1" = "$p2" ]; then ADMIN_PASSWORD="$p1"; break; fi
            echo "    The two passwords differ; try again."
        done
    fi
fi

# --- service account -------------------------------------------------------
if ! id "$SVC_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$STATE" --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
    echo "Created system user $SVC_USER"
fi
# Least privilege: the log-reading groups go to the core and collector services only
# (SupplementaryGroups= in their units), not to the account, so the dashboard and notifier
# cannot read logs. Older installs added the account to them; take that back.
LOG_GROUPS=()
for g in adm systemd-journal; do
    if getent group "$g" >/dev/null; then
        LOG_GROUPS+=("$g")
        if id -nG "$SVC_USER" | tr ' ' '\n' | grep -qx "$g"; then gpasswd -d "$SVC_USER" "$g" >/dev/null; fi
    fi
done
install -d -o "$SVC_USER" -g "$SVC_USER" -m 0750 "$STATE" "$STATE/scout" "$STATE/scout/trails" "$STATE/lab-logs"
install -d -o "$SVC_USER" -g "$SVC_USER" -m 0700 "$STATE/core" "$STATE/collector" "$STATE/notifier"
install -d -o root -g "$SVC_USER" -m 0750 /etc/sentrai

# --- settings (ports, addresses, paths) ------------------------------------
set_env() {  # KEY VALUE: replace the line or append it
    if grep -q "^$1=" "$ENV_FILE"; then sed -i "s|^$1=.*|$1=$2|" "$ENV_FILE"
    else echo "$1=$2" >> "$ENV_FILE"; fi
}
get_env() { sed -n "s/^$1=//p" "$ENV_FILE" | tail -1; }
if [ ! -f "$ENV_FILE" ]; then
    cat > "$ENV_FILE" <<EOF
# SentrAI service settings, read by every sentrai-* service (systemctl restart sentrai.target after a change).
# Detection, response, alert and AI settings live in SENTRAI_CONFIG and are edited on the dashboard.
SENTRAI_CORE_HOST=127.0.0.1
SENTRAI_CORE_PORT=8000
SENTRAI_DASHBOARD_HOST=127.0.0.1
SENTRAI_DASHBOARD_PORT=8501
SENTRAI_CORE_URL=http://127.0.0.1:8000
SENTRAI_PUBLIC_URL=http://127.0.0.1:8000
# Real time: one real hour is one hour on the SLA and block timers (DEMO_SPEED above 1 speeds them up for testing).
DEMO_SPEED=1
PROTECTED_IPS=127.0.0.1,::1,localhost
SENTRAI_CONFIG=$STATE/config.json
SENTRAI_DB=$STATE/core/sentrai.db
SENTRAI_COLLECTOR_STATE=$STATE/collector/state.json
SENTRAI_LAB_LOGS=$STATE/lab-logs
SENTRAI_SCOUT_SOURCES=$STATE/scout/sources.json
SENTRAI_SCOUT_TRAILS=$STATE/scout/trails
EOF
    echo "Wrote $ENV_FILE"
fi
chown root:"$SVC_USER" "$ENV_FILE"
chmod 0640 "$ENV_FILE"
for k in "${!SET[@]}"; do set_env "$k" "${SET[$k]}"; done
# The notifier keeps the last audit fingerprint it delivered here (its code folder is read-only to it).
[ -n "$(get_env NOTIFIER_WITNESS_FILE)" ] || set_env NOTIFIER_WITNESS_FILE "$STATE/notifier/last_witness.txt"
if [ "${#PROTECT[@]}" -gt 0 ]; then
    ips="$(get_env PROTECTED_IPS)"
    for ip in "${PROTECT[@]}"; do
        case ",$ips," in *",$ip,"*) ;; *) ips="${ips:+$ips,}$ip" ;; esac
    done
    set_env PROTECTED_IPS "$ips"
fi
# --- who may reach the dashboard -------------------------------------------
is_ip() { "$PYTHON" -c 'import ipaddress, sys; ipaddress.ip_network(sys.argv[1], strict=False)' "$1" 2>/dev/null; }
is_local() { case "$1" in 127.*|::1|localhost) return 0 ;; *) return 1 ;; esac; }
if [ "$DASH_LOCAL" = 1 ]; then
    set_env SENTRAI_DASHBOARD_ALLOW ""
    [ -n "${SET[SENTRAI_DASHBOARD_HOST]:-}" ] || set_env SENTRAI_DASHBOARD_HOST 127.0.0.1
else
    if [ "${#ALLOW[@]}" = 0 ]; then  # default: the admin IPs given with --protect
        for ip in "${PROTECT[@]}"; do is_local "$ip" || ALLOW+=("$ip"); done
    fi
    if [ "${#ALLOW[@]}" -gt 0 ]; then
        for ip in "${ALLOW[@]}"; do is_ip "$ip" || die "--dashboard-allow / --protect: '$ip' is not an IP address"; done
        command -v nft >/dev/null 2>&1 || command -v iptables >/dev/null 2>&1 \
            || die "opening the dashboard needs nft or iptables (or use --dashboard-local)"
        set_env SENTRAI_DASHBOARD_ALLOW "$(IFS=,; echo "${ALLOW[*]}")"
        [ -n "${SET[SENTRAI_DASHBOARD_HOST]:-}" ] || set_env SENTRAI_DASHBOARD_HOST 0.0.0.0
    fi
fi
DASH_ALLOW="$(get_env SENTRAI_DASHBOARD_ALLOW)"

CORE_HOST="$(get_env SENTRAI_CORE_HOST)"; CORE_PORT="$(get_env SENTRAI_CORE_PORT)"
DASH_HOST="$(get_env SENTRAI_DASHBOARD_HOST)"; DASH_PORT="$(get_env SENTRAI_DASHBOARD_PORT)"
[ "$CORE_PORT" != "$DASH_PORT" ] || die "core and dashboard need different ports"
case "$CORE_HOST" in 0.0.0.0|::|'[::]') reach=127.0.0.1 ;; *:*) reach="[$CORE_HOST]" ;; *) reach="$CORE_HOST" ;; esac
CORE_URL="http://$reach:$CORE_PORT"
set_env SENTRAI_CORE_URL "$CORE_URL"
if [ -n "${SET[SENTRAI_CORE_PORT]:-}${SET[SENTRAI_CORE_HOST]:-}" ]; then set_env SENTRAI_PUBLIC_URL "$CORE_URL"; fi

# --- ports ------------------------------------------------------------------
port_owner() {  # prints the process listening on a TCP port, if any
    ss -Hltnp "sport = :$1" 2>/dev/null | sed -n 's/.*users:((\("[^"]*"\).*/\1/p' | head -1
}
if [ "$START" = 1 ] && command -v ss >/dev/null 2>&1; then
    # An upgrade frees its own ports first (naming the services too: stopping the target alone can return
    # before they are down), then gives the old processes a few seconds to let go of them.
    systemctl stop sentrai.target sentrai-core sentrai-collector sentrai-dashboard sentrai-notifier 2>/dev/null || true
    for p in "$CORE_PORT" "$DASH_PORT"; do
        for _ in 1 2 3 4 5 6 7 8 9 10; do [ -n "$(ss -Hltn "sport = :$p" 2>/dev/null)" ] || break; sleep 1; done
    done
    for p in "$CORE_PORT" "$DASH_PORT"; do
        who="$(port_owner "$p")"
        if [ -n "$who" ] || ss -Hltn "sport = :$p" 2>/dev/null | grep -q .; then
            die "port $p is already in use${who:+ by $who}; pick another with --core-port / --dashboard-port"
        fi
    done
fi

# --- state folders (upgrade) ------------------------------------------------
# Older installs kept the audit record and the collector's positions in $STATE itself, where every
# service could write them. Move them into the folders only their own service can open.
if [ "$(get_env SENTRAI_DB)" = "$STATE/sentrai.db" ] || [ -z "$(get_env SENTRAI_COLLECTOR_STATE)" ]; then
    systemctl stop sentrai.target 2>/dev/null || true
    if [ "$(get_env SENTRAI_DB)" = "$STATE/sentrai.db" ]; then
        for f in sentrai.db sentrai.db-wal sentrai.db-shm anchor.key protection.json archive; do
            if [ -e "$STATE/$f" ] && [ ! -e "$STATE/core/$f" ]; then mv "$STATE/$f" "$STATE/core/$f"; fi
        done
        set_env SENTRAI_DB "$STATE/core/sentrai.db"
        echo "Moved the audit record to $STATE/core/"
    fi
    if [ -z "$(get_env SENTRAI_COLLECTOR_STATE)" ]; then
        if [ -e "$STATE/collector-state.json" ] && [ ! -e "$STATE/collector/state.json" ]; then
            mv "$STATE/collector-state.json" "$STATE/collector/state.json"
        fi
        set_env SENTRAI_COLLECTOR_STATE "$STATE/collector/state.json"
    fi
    chown -R "$SVC_USER:$SVC_USER" "$STATE/core" "$STATE/collector"
fi

# --- off-box copy (--remote-copy) -------------------------------------------
# The witness's append token goes where only the core service can read it (/var/lib/sentrai/core).
if [ "$REMOTE" = off ]; then
    set_env SENTRAI_REMOTE_COPY_URL ""
elif [ -n "$REMOTE" ]; then
    case "$REMOTE" in http://*|https://*) ;; *) die "--remote-copy needs an http(s):// URL (got '$REMOTE')" ;; esac
    [ -n "$REMOTE_TOKEN" ] || [ -s "$STATE/core/remote-copy.token" ] \
        || die "--remote-copy needs --remote-copy-token-file (the witness's append.token)"
    if [ -n "$REMOTE_TOKEN" ]; then
        [ -s "$REMOTE_TOKEN" ] || die "--remote-copy-token-file: $REMOTE_TOKEN is missing or empty"
        install -o "$SVC_USER" -g "$SVC_USER" -m 0600 "$REMOTE_TOKEN" "$STATE/core/remote-copy.token"
    fi
    if [ -n "$REMOTE_CA" ]; then
        [ -s "$REMOTE_CA" ] || die "--remote-copy-ca: $REMOTE_CA is missing or empty"
        install -m 0644 "$REMOTE_CA" /etc/sentrai/witness-ca.pem
        set_env SENTRAI_REMOTE_COPY_CA /etc/sentrai/witness-ca.pem
    fi
    set_env SENTRAI_REMOTE_COPY_URL "$REMOTE"
    set_env SENTRAI_REMOTE_COPY_TOKEN_FILE "$STATE/core/remote-copy.token"
    code="$(curl -s -o /dev/null -w '%{http_code}' ${REMOTE_CA:+--cacert "$REMOTE_CA"} "$REMOTE/health" 2>/dev/null || true)"
    [ "$code" = 200 ] || echo "WARNING: the witness at $REMOTE did not answer (got '${code:-nothing}'); SentrAI keeps retrying." >&2
fi

# --- code and venvs ---------------------------------------------------------
echo "Copying code to $MVP ..."
install -d -m 0755 "$PREFIX" "$MVP"
# Replace the code but keep the venvs, so an upgrade only reinstalls packages that changed.
find "$MVP" -mindepth 1 -maxdepth 1 ! -name core ! -name lab ! -name dashboard ! -name notifier -exec rm -rf {} +
for c in core lab dashboard notifier; do
    [ -d "$MVP/$c" ] && find "$MVP/$c" -mindepth 1 -maxdepth 1 ! -name .venv -exec rm -rf {} +
done
tar -C "$SRC" -cf - \
    --exclude=.venv --exclude=__pycache__ --exclude=.pytest_cache --exclude=.run_logs \
    --exclude=.run_pids.json --exclude=./lab/logs --exclude=./core/data \
    --exclude=./lab/scout/sources.json --exclude=./lab/scout/pending.json \
    --exclude=./research --exclude=./pitch --exclude=./deck --exclude=./assets \
    . | tar -C "$MVP" -xf - --no-same-owner
chown -R root:root "$MVP"
chmod -R u=rwX,go=rX "$MVP"
# Scout learns from the example trails too; copy them once, never over trails recorded here.
for f in "$MVP"/lab/scout/trails/*.jsonl; do
    if [ -e "$f" ] && [ ! -e "$STATE/scout/trails/$(basename "$f")" ]; then
        install -o "$SVC_USER" -g "$SVC_USER" -m 0640 "$f" "$STATE/scout/trails/"
    fi
done

hash_file() { sha256sum "$1" | cut -d' ' -f1; }
for c in core lab dashboard notifier; do
    dir="$MVP/$c"
    if [ ! -x "$dir/.venv/bin/python" ]; then
        echo "Creating venv for $c ..."
        "$PYTHON" -m venv "$dir/.venv"
        "$dir/.venv/bin/python" -m pip install -q --upgrade pip
    fi
    want="$(hash_file "$dir/requirements.txt")"
    have="$(cat "$dir/.venv/requirements.installed" 2>/dev/null || true)"
    if [ "$want" != "$have" ]; then
        echo "Installing packages for $c ..."
        "$dir/.venv/bin/python" -m pip install -q -r "$dir/requirements.txt"
        echo "$want" > "$dir/.venv/requirements.installed"
    fi
    "$dir/.venv/bin/python" -m compileall -q "$dir" -x '/\.venv/' >/dev/null || true
done
"$MVP/core/.venv/bin/python" -m compileall -q "$MVP"/*.py >/dev/null || true

# --- Scout wrapper ----------------------------------------------------------
SCOUT_GROUPS=""  # Scout reads logs to find them, so it gets the same groups as the collector
for g in "${LOG_GROUPS[@]}"; do SCOUT_GROUPS+="-G $g "; done
cat > /usr/local/bin/sentrai-scout <<EOF
#!/usr/bin/env bash
# Runs Scout (python -m scout) as $SVC_USER with the service settings. Without a terminal it
# never waits for answers; its proposals wait on the dashboard's Collector page.
#   sudo sentrai-scout find --root /var/log "where are the login and web logs?"
#   sudo sentrai-scout pending | approve <id> | reject <id>
set -euo pipefail
[ "\$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
set -a; . $ENV_FILE; set +a
cd $MVP/lab
exec runuser -u $SVC_USER $SCOUT_GROUPS-- env HOME=$STATE $MVP/lab/.venv/bin/python -m scout "\$@"
EOF
chmod 0755 /usr/local/bin/sentrai-scout

# --- dashboard sign-in --------------------------------------------------------
cat > /usr/local/bin/sentrai-admin <<EOF
#!/usr/bin/env bash
# Lists who may sign in to the dashboard; on a new machine, prints a one-time setup code for the Owner.
#   sudo sentrai-admin          sudo sentrai-admin --reset [--email you@example.com]   (new password, authenticator again)
set -euo pipefail
[ "\$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
set -a; . $ENV_FILE; set +a
exec runuser -u $SVC_USER -- env HOME=$STATE $MVP/lab/.venv/bin/python $MVP/sentrai_config.py admin "\$@"
EOF
chmod 0755 /usr/local/bin/sentrai-admin
admin_args=()
if [ -n "$ADMIN_EMAIL" ]; then admin_args+=(--email "$ADMIN_EMAIL"); fi
if [ "$RESET_PW" = 1 ]; then admin_args+=(--reset); fi
if [ -n "$ADMIN_PASSWORD" ] && [ -n "$ADMIN_EMAIL" ]; then
    SIGN_IN="$(printf '%s\n' "$ADMIN_PASSWORD" | /usr/local/bin/sentrai-admin "${admin_args[@]}" --password-stdin)" \
        || die "could not set up the dashboard sign-in"
else
    SIGN_IN="$(/usr/local/bin/sentrai-admin "${admin_args[@]}" </dev/null)" || die "could not set up the dashboard sign-in"
fi
unset ADMIN_PASSWORD
# The API token every service sends to the core. Make it now: the core, collector and notifier may
# not write the settings file (their sandbox), so none of them could save a new one.
(set -a && . "$ENV_FILE" && set +a && cd "$MVP" && \
    runuser -u "$SVC_USER" -- env HOME="$STATE" "$MVP/lab/.venv/bin/python" sentrai_config.py token >/dev/null) \
    || die "could not make the API token"

# --- dashboard HTTPS and firewall rule -------------------------------------
install -m 0755 "$SRC/deploy/dashboard-firewall.sh" /usr/local/sbin/sentrai-dashboard-firewall
TLS=/etc/sentrai/tls
if [ -n "$DASH_ALLOW" ]; then
    if [ ! -f "$TLS/cert.pem" ] && command -v openssl >/dev/null 2>&1; then
        install -d -o root -g "$SVC_USER" -m 0750 "$TLS"
        cn="$(hostname -f 2>/dev/null || hostname)"; cn="${cn:0:64}"  # a certificate name holds at most 64 characters
        openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=$cn" \
            -keyout "$TLS/key.pem" -out "$TLS/cert.pem" >/dev/null 2>&1 || rm -f "$TLS/key.pem" "$TLS/cert.pem"
        chown root:"$SVC_USER" "$TLS"/*.pem 2>/dev/null || true
        chmod 0640 "$TLS"/*.pem 2>/dev/null || true
    fi
    if [ -f "$TLS/cert.pem" ]; then  # Streamlit reads these two from the environment
        set_env STREAMLIT_SERVER_SSL_CERT_FILE "$TLS/cert.pem"
        set_env STREAMLIT_SERVER_SSL_KEY_FILE "$TLS/key.pem"
    else
        echo "WARNING: openssl is missing, so the dashboard uses plain HTTP; the password crosses the network unencrypted." >&2
    fi
    # ufw and firewalld drop the port on their own; allow it there for these addresses as well.
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        for ip in ${DASH_ALLOW//,/ }; do
            ufw allow proto tcp from "$ip" to any port "$DASH_PORT" comment sentrai-dashboard >/dev/null
        done
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        for ip in ${DASH_ALLOW//,/ }; do
            fam=ipv4; case "$ip" in *:*) fam=ipv6 ;; esac
            firewall-cmd -q --permanent \
                --add-rich-rule="rule family=$fam source address=$ip port port=$DASH_PORT protocol=tcp accept" || true
        done
        firewall-cmd -q --reload || true
    fi
else
    sed -i '/^STREAMLIT_SERVER_SSL_/d' "$ENV_FILE"
    /usr/local/sbin/sentrai-dashboard-firewall remove
fi
SCHEME=http
if grep -q '^STREAMLIT_SERVER_SSL_CERT_FILE=' "$ENV_FILE"; then SCHEME=https; fi

# --- central panel: the agents' HTTPS port (--panel) -------------------------
# The core opens a second port (app/serve.py) that only answers agents' machine keys. Agents pin this
# certificate (its SHA-256 comes with every join code), so it may stay self-signed.
open_panel_port() {  # PORT [remove]: ufw and firewalld drop it on their own
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        if [ "${2:-}" = remove ]; then ufw delete allow proto tcp to any port "$1" >/dev/null 2>&1 || true
        else ufw allow proto tcp to any port "$1" comment sentrai-panel >/dev/null; fi
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        if [ "${2:-}" = remove ]; then firewall-cmd -q --permanent --remove-port="$1/tcp" || true
        else firewall-cmd -q --permanent --add-port="$1/tcp" || true; fi
        firewall-cmd -q --reload || true
    fi
}
if [ "$PANEL" = off ]; then
    old="$(get_env SENTRAI_PANEL_PORT)"
    [ -n "$old" ] && open_panel_port "$old" remove
    sed -i '/^SENTRAI_PANEL_/d' "$ENV_FILE"
elif [ -n "$PANEL" ]; then
    command -v openssl >/dev/null 2>&1 || die "openssl is needed for the panel's HTTPS port"
    install -d -o root -g "$SVC_USER" -m 0750 "$TLS"
    if [ ! -f "$TLS/panel-cert.pem" ]; then
        # Named after the address agents use (--panel-url), else this server's name. Agents check the pin,
        # not the name, but a matching name lets a browser or curl check it too.
        name="$("$PYTHON" -c 'import sys, urllib.parse; print(urllib.parse.urlsplit(sys.argv[1]).hostname or "")' "$PANEL_URL")"
        [ -n "$name" ] || name="$(hostname -f 2>/dev/null || hostname)"
        if "$PYTHON" -c 'import ipaddress, sys; ipaddress.ip_address(sys.argv[1])' "$name" 2>/dev/null; then san="IP:$name"
        else san="DNS:$name"; fi
        openssl req -x509 -newkey rsa:2048 -nodes -days 1825 -subj "/CN=${name:0:64}" -addext "subjectAltName=$san" \
            -keyout "$TLS/panel-key.pem" -out "$TLS/panel-cert.pem" >/dev/null 2>&1 \
            || die "could not make the panel's certificate"
    fi
    chown root:"$SVC_USER" "$TLS"/panel-*.pem
    chmod 0640 "$TLS"/panel-*.pem
    old="$(get_env SENTRAI_PANEL_PORT)"
    [ -n "$old" ] && [ "$old" != "$PANEL" ] && open_panel_port "$old" remove
    set_env SENTRAI_PANEL_PORT "$PANEL"
    set_env SENTRAI_PANEL_HOST 0.0.0.0
    set_env SENTRAI_PANEL_CERT "$TLS/panel-cert.pem"
    set_env SENTRAI_PANEL_KEY "$TLS/panel-key.pem"
    set_env SENTRAI_PANEL_URL "${PANEL_URL:-https://$(hostname -f 2>/dev/null || hostname):$PANEL}"
    set_env SENTRAI_RISK_SCOPE host
    open_panel_port "$PANEL"
fi

# --- sealed journal (--seal-journal) ----------------------------------------
# journald signs the journal at intervals with a key that moves forward and forgets the old one,
# so entries already sealed cannot be rewritten without "journalctl --verify" noticing. The
# verification key is printed once and is not kept here: store it away from this server.
SEAL_KEY=""
if [ "$SEAL" = 1 ]; then
    install -d -m 0755 /etc/systemd/journald.conf.d
    printf '[Journal]\nStorage=persistent\nSeal=yes\n' > /etc/systemd/journald.conf.d/50-sentrai-seal.conf
    install -d -m 2755 -g systemd-journal /var/log/journal 2>/dev/null || install -d -m 2755 /var/log/journal
    systemd-tmpfiles --create --prefix /var/log/journal >/dev/null 2>&1 || true
    systemctl restart systemd-journald
    journalctl --flush >/dev/null 2>&1 || true
    if ls /var/log/journal/*/fss >/dev/null 2>&1; then
        echo "The journal is already sealed; its verification key was shown when sealing was set up."
    else
        SEAL_KEY="$(journalctl --setup-keys --quiet 2>/dev/null)" || die "journalctl --setup-keys failed"
        systemctl restart systemd-journald
    fi
fi

# --- systemd ----------------------------------------------------------------
UNITS=(sentrai-core sentrai-collector sentrai-dashboard sentrai-notifier)
for u in "${UNITS[@]}"; do
    sed -e "s|@PREFIX@|$PREFIX|g" -e "s|@USER@|$SVC_USER|g" -e "s|@LOGGROUPS@|${LOG_GROUPS[*]}|g" \
        "$SRC/deploy/$u.service" > "/etc/systemd/system/$u.service"
done
if [ "$NOTIFIER" = 0 ]; then
    sed 's/ sentrai-notifier.service//' "$SRC/deploy/sentrai.target" > /etc/systemd/system/sentrai.target
else
    cp "$SRC/deploy/sentrai.target" /etc/systemd/system/sentrai.target
fi
systemctl daemon-reload
systemctl enable sentrai.target "${UNITS[@]:0:3}" >/dev/null
if [ "$NOTIFIER" = 1 ]; then systemctl enable sentrai-notifier >/dev/null
else systemctl disable --now sentrai-notifier >/dev/null 2>&1 || true; fi

if [ "$START" = 1 ]; then
    systemctl restart sentrai.target
    echo -n "Waiting for the core on $CORE_URL "
    for _ in $(seq 1 60); do
        if "$PYTHON" -c "import sys, urllib.request; urllib.request.urlopen(sys.argv[1] + '/health', timeout=2)" "$CORE_URL" 2>/dev/null; then
            echo "ok"; break
        fi
        echo -n "."; sleep 1
    done
    systemctl --no-pager --lines=0 status "${UNITS[@]}" 2>/dev/null | grep -E '^[●○×] |Active:' || true
fi

cat <<EOF

SentrAI is installed.
  Status:     systemctl status 'sentrai-*'      Logs: journalctl -u sentrai-core -f
  Restart:    systemctl restart sentrai.target  (after editing $ENV_FILE)
  Core API:   $CORE_URL
  Find logs:  sudo sentrai-scout find --root /var/log "where are the login and web logs?"
EOF
echo
if [ -n "$DASH_ALLOW" ]; then
    addr="$(hostname -I 2>/dev/null | awk '{print $1}')"
    echo "  Dashboard:  $SCHEME://${addr:-<this server>}:$DASH_PORT   (or this server's public address)"
    echo "              open to $DASH_ALLOW only; the firewall drops everyone else."
    if [ "$SCHEME" = https ]; then
        echo "              The certificate is self-signed: the browser warns once; continue to the site."
    fi
else
    case "$DASH_HOST" in
        127.0.0.1|localhost|::1)
            echo "  Dashboard:  http://127.0.0.1:$DASH_PORT, on this server only. From your computer:"
            echo "    ssh -L $DASH_PORT:127.0.0.1:$DASH_PORT <you>@<this server>   then open http://127.0.0.1:$DASH_PORT"
            echo "    (or install again with --dashboard-allow <your IP> to open it to your IP directly)" ;;
        *)
            echo "  Dashboard:  http://$DASH_HOST:$DASH_PORT"
            echo "  WARNING: it listens on $DASH_HOST with no firewall rule, so anyone who can reach port"
            echo "  $DASH_PORT gets the sign-in page. Use --dashboard-allow <your IP> to limit it." ;;
    esac
fi
printf '%s\n' "$SIGN_IN" | sed 's/^/  /'
echo "  People:     invite them on the dashboard's Team page. Locked out: sudo sentrai-admin --reset"
REMOTE_URL="$(get_env SENTRAI_REMOTE_COPY_URL)"
if [ -n "$REMOTE_URL" ]; then
    echo "  Off-box copy: every audit record and log line goes to $REMOTE_URL as it happens."
    echo "              Status: curl $CORE_URL/audit/remote-copy"
fi
if [ -n "$SEAL_KEY" ]; then
    echo
    echo "  Journal sealing is on. Verification key (shown only now; keep it OFF this server):"
    echo "    $SEAL_KEY"
    echo "  Check the journal later with:  journalctl --verify --verify-key=<that key>"
fi
PANEL_PORT="$(get_env SENTRAI_PANEL_PORT)"
if [ -n "$PANEL_PORT" ]; then
    pin="$(openssl x509 -in "$(get_env SENTRAI_PANEL_CERT)" -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)"
    echo "  Central panel: agents join at $(get_env SENTRAI_PANEL_URL) (only machine keys are answered there)."
    echo "    Certificate pin: sha256:$pin   (the Machines page shows it with every join code)"
    echo "    On each machine: sudo ./mvp/deploy/install-agent.sh --panel $(get_env SENTRAI_PANEL_URL) --code <code> --pin sha256:$pin"
fi
case "$CORE_HOST" in
    127.0.0.1|localhost|::1) ;;
    *) echo "  WARNING: the core API listens on $CORE_HOST:$CORE_PORT with no login; limit it in the firewall." ;;
esac
reinstall_other_after_cactai panel "$SRC/deploy"
