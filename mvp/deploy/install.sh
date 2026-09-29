#!/usr/bin/env bash
# Installs SentrAI on a Linux server as systemd services (run as root, from a checkout of the repo).
#
#   sudo ./deploy/install.sh                          install or upgrade with the defaults below
#   sudo ./deploy/install.sh --core-port 8100         when 8000 is taken
#   sudo ./deploy/install.sh --protect 203.0.113.10   never block your own admin IP (repeatable),
#                                                     and open the dashboard to that IP only
#
# Options (each is optional; on an upgrade only the ones you pass change /etc/cactai/cactai.env):
#   --prefix DIR           where the code goes (default /opt/cactai; copied from this checkout)
#   --user NAME            system account the services run as (default cactai)
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
#   --admin-email EMAIL    the dashboard sign-in email (asked on a first install when not given)
#   --reset-password       make a new dashboard password (shown once at the end)
#   --no-notifier          do not enable the Telegram notifier service
#   --no-start             install and enable, but do not start or restart anything
#
# What it creates:
#   /etc/cactai/cactai.env           ports, addresses and paths (root:cactai 0640, kept on upgrade)
#   /var/lib/cactai/                 state: settings, audit DB, approved log list, Scout trails (cactai 0750)
#   /etc/systemd/system/cactai*.service and cactai.target
#   /usr/local/bin/cactai-scout      runs Scout as the service account (no terminal needed)
#   /usr/local/bin/cactai-admin      shows or resets the dashboard sign-in (sudo cactai-admin --reset)
#   /usr/local/sbin/cactai-dashboard-firewall   the dashboard's firewall rule (run by its service)
#   /etc/cactai/tls/                 a self-signed HTTPS certificate, when the dashboard is opened
# The service account joins the adm and systemd-journal groups (when they exist) so it can read
# /var/log/auth.log, nginx logs and the journal. The only firewall change is the dashboard rule
# (plus a matching allow in ufw or firewalld when one is active). Nothing touches nginx or sshd.
# Remove everything again with ./deploy/uninstall.sh.
set -euo pipefail

PREFIX=/opt/cactai
SVC_USER=cactai
NOTIFIER=1
START=1
PROTECT=()
ALLOW=()
DASH_LOCAL=0
ADMIN_EMAIL=""
RESET_PW=0
declare -A SET=()  # env values given on the command line
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        --user) SVC_USER="$2"; shift 2 ;;
        --core-port) SET[CACTAI_CORE_PORT]="$2"; shift 2 ;;
        --core-bind) SET[CACTAI_CORE_HOST]="$2"; shift 2 ;;
        --dashboard-port) SET[CACTAI_DASHBOARD_PORT]="$2"; shift 2 ;;
        --dashboard-bind) SET[CACTAI_DASHBOARD_HOST]="$2"; shift 2 ;;
        --protect) PROTECT+=("$2"); shift 2 ;;
        --dashboard-allow) ALLOW+=("$2"); shift 2 ;;
        --dashboard-local) DASH_LOCAL=1; shift ;;
        --admin-email) ADMIN_EMAIL="$2"; shift 2 ;;
        --reset-password) RESET_PW=1; shift ;;
        --no-notifier) NOTIFIER=0; shift ;;
        --no-start) START=0; shift ;;
        -h|--help) sed -n '2,42p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
done
for k in CACTAI_CORE_PORT CACTAI_DASHBOARD_PORT; do
    v="${SET[$k]:-}"
    case "$v" in '') ;; *[!0-9]*) echo "$k must be a number (got '$v')" >&2; exit 2 ;; esac
done

case "$ADMIN_EMAIL" in ''|*@*) ;; *) echo "--admin-email needs an email address (got '$ADMIN_EMAIL')" >&2; exit 2 ;; esac

die() { echo "install.sh: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root (sudo ./deploy/install.sh)"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"  # the mvp/ folder of this checkout
[ -f "$SRC/core/app/main.py" ] || die "run it from a SentrAI checkout (mvp/deploy/install.sh)"
PYTHON="${PYTHON:-python3}"
"$PYTHON" -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null || die "python 3.10 or newer is required"
"$PYTHON" -c 'import ensurepip, venv' 2>/dev/null \
    || die "python's venv module is missing (Debian/Ubuntu: apt install python3-venv)"

ENV_FILE=/etc/cactai/cactai.env
STATE=/var/lib/cactai
MVP="$PREFIX/mvp"
[ "$MVP" != "$SRC" ] || die "--prefix must differ from this checkout"

# --- service account -------------------------------------------------------
if ! id "$SVC_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$STATE" --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
    echo "Created system user $SVC_USER"
fi
for g in adm systemd-journal; do
    if getent group "$g" >/dev/null; then usermod -aG "$g" "$SVC_USER"; fi
done
install -d -o "$SVC_USER" -g "$SVC_USER" -m 0750 "$STATE" "$STATE/scout" "$STATE/scout/trails" "$STATE/lab-logs"
install -d -o root -g "$SVC_USER" -m 0750 /etc/cactai

# --- settings (ports, addresses, paths) ------------------------------------
set_env() {  # KEY VALUE: replace the line or append it
    if grep -q "^$1=" "$ENV_FILE"; then sed -i "s|^$1=.*|$1=$2|" "$ENV_FILE"
    else echo "$1=$2" >> "$ENV_FILE"; fi
}
get_env() { sed -n "s/^$1=//p" "$ENV_FILE" | tail -1; }
if [ ! -f "$ENV_FILE" ]; then
    cat > "$ENV_FILE" <<EOF
# SentrAI service settings, read by every cactai-* service (systemctl restart cactai.target after a change).
# Detection, response, alert and AI settings live in CACTAI_CONFIG and are edited on the dashboard.
CACTAI_CORE_HOST=127.0.0.1
CACTAI_CORE_PORT=8000
CACTAI_DASHBOARD_HOST=127.0.0.1
CACTAI_DASHBOARD_PORT=8501
CACTAI_CORE_URL=http://127.0.0.1:8000
CACTAI_PUBLIC_URL=http://127.0.0.1:8000
# Real time: one real hour is one hour on the SLA and block timers (the demo runs faster).
DEMO_SPEED=1
PROTECTED_IPS=127.0.0.1,::1,localhost
CACTAI_CONFIG=$STATE/config.json
CACTAI_DB=$STATE/cactai.db
CACTAI_LAB_LOGS=$STATE/lab-logs
CACTAI_LAB_DB=$STATE/portal.sqlite3
CACTAI_SCOUT_SOURCES=$STATE/scout/sources.json
CACTAI_SCOUT_TRAILS=$STATE/scout/trails
EOF
    echo "Wrote $ENV_FILE"
fi
chown root:"$SVC_USER" "$ENV_FILE"
chmod 0640 "$ENV_FILE"
for k in "${!SET[@]}"; do set_env "$k" "${SET[$k]}"; done
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
    set_env CACTAI_DASHBOARD_ALLOW ""
    [ -n "${SET[CACTAI_DASHBOARD_HOST]:-}" ] || set_env CACTAI_DASHBOARD_HOST 127.0.0.1
else
    if [ "${#ALLOW[@]}" = 0 ]; then  # default: the admin IPs given with --protect
        for ip in "${PROTECT[@]}"; do is_local "$ip" || ALLOW+=("$ip"); done
    fi
    if [ "${#ALLOW[@]}" -gt 0 ]; then
        for ip in "${ALLOW[@]}"; do is_ip "$ip" || die "--dashboard-allow / --protect: '$ip' is not an IP address"; done
        command -v nft >/dev/null 2>&1 || command -v iptables >/dev/null 2>&1 \
            || die "opening the dashboard needs nft or iptables (or use --dashboard-local)"
        set_env CACTAI_DASHBOARD_ALLOW "$(IFS=,; echo "${ALLOW[*]}")"
        [ -n "${SET[CACTAI_DASHBOARD_HOST]:-}" ] || set_env CACTAI_DASHBOARD_HOST 0.0.0.0
    fi
fi
DASH_ALLOW="$(get_env CACTAI_DASHBOARD_ALLOW)"

CORE_HOST="$(get_env CACTAI_CORE_HOST)"; CORE_PORT="$(get_env CACTAI_CORE_PORT)"
DASH_HOST="$(get_env CACTAI_DASHBOARD_HOST)"; DASH_PORT="$(get_env CACTAI_DASHBOARD_PORT)"
[ "$CORE_PORT" != "$DASH_PORT" ] || die "core and dashboard need different ports"
case "$CORE_HOST" in 0.0.0.0|::|'[::]') reach=127.0.0.1 ;; *:*) reach="[$CORE_HOST]" ;; *) reach="$CORE_HOST" ;; esac
CORE_URL="http://$reach:$CORE_PORT"
set_env CACTAI_CORE_URL "$CORE_URL"
if [ -n "${SET[CACTAI_CORE_PORT]:-}${SET[CACTAI_CORE_HOST]:-}" ]; then set_env CACTAI_PUBLIC_URL "$CORE_URL"; fi

# --- ports ------------------------------------------------------------------
port_owner() {  # prints the process listening on a TCP port, if any
    ss -Hltnp "sport = :$1" 2>/dev/null | sed -n 's/.*users:((\("[^"]*"\).*/\1/p' | head -1
}
if [ "$START" = 1 ] && command -v ss >/dev/null 2>&1; then
    systemctl stop cactai.target 2>/dev/null || true  # an upgrade frees its own ports first
    for p in "$CORE_PORT" "$DASH_PORT"; do
        who="$(port_owner "$p")"
        if [ -n "$who" ] || ss -Hltn "sport = :$p" 2>/dev/null | grep -q .; then
            die "port $p is already in use${who:+ by $who}; pick another with --core-port / --dashboard-port"
        fi
    done
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
    --exclude=.venv --exclude=__pycache__ --exclude=.pytest_cache --exclude=.demo_logs \
    --exclude=.demo_pids.json --exclude=./lab/logs --exclude=./core/data \
    --exclude=./lab/scout/sources.json --exclude=./lab/scout/pending.json --exclude=./lab/portal.sqlite3 \
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
cat > /usr/local/bin/cactai-scout <<EOF
#!/usr/bin/env bash
# Runs Scout (python -m scout) as $SVC_USER with the service settings. Without a terminal it
# never waits for answers; its proposals wait on the dashboard's Collector page.
#   sudo cactai-scout find --root /var/log "where are the login and web logs?"
#   sudo cactai-scout pending | approve <id> | reject <id>
set -euo pipefail
[ "\$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
set -a; . $ENV_FILE; set +a
cd $MVP/lab
exec runuser -u $SVC_USER -- env HOME=$STATE $MVP/lab/.venv/bin/python -m scout "\$@"
EOF
chmod 0755 /usr/local/bin/cactai-scout

# --- dashboard sign-in --------------------------------------------------------
cat > /usr/local/bin/cactai-admin <<EOF
#!/usr/bin/env bash
# Shows the dashboard sign-in email, or makes a new password (printed once).
#   sudo cactai-admin          sudo cactai-admin --reset          sudo cactai-admin --email you@example.com
set -euo pipefail
[ "\$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
set -a; . $ENV_FILE; set +a
exec runuser -u $SVC_USER -- env HOME=$STATE $MVP/lab/.venv/bin/python $MVP/cactai_config.py admin "\$@"
EOF
chmod 0755 /usr/local/bin/cactai-admin
CONFIG="$(get_env CACTAI_CONFIG)"
if [ -z "$ADMIN_EMAIL" ] && [ -t 0 ] && ! grep -q '"CACTAI_DASHBOARD_PASSWORD_HASH": "pbkdf2' "$CONFIG" 2>/dev/null; then
    read -r -p "Dashboard sign-in email [admin@sentrai.local]: " ADMIN_EMAIL || true
    case "$ADMIN_EMAIL" in ''|*@*) ;; *) echo "Not an email address; using admin@sentrai.local"; ADMIN_EMAIL="" ;; esac
fi
admin_args=()
if [ -n "$ADMIN_EMAIL" ]; then admin_args+=(--email "$ADMIN_EMAIL"); fi
if [ "$RESET_PW" = 1 ]; then admin_args+=(--reset); fi
SIGN_IN="$(/usr/local/bin/cactai-admin "${admin_args[@]}")" || die "could not set up the dashboard sign-in"

# --- dashboard HTTPS and firewall rule -------------------------------------
install -m 0755 "$SRC/deploy/dashboard-firewall.sh" /usr/local/sbin/cactai-dashboard-firewall
TLS=/etc/cactai/tls
if [ -n "$DASH_ALLOW" ]; then
    if [ ! -f "$TLS/cert.pem" ] && command -v openssl >/dev/null 2>&1; then
        install -d -o root -g "$SVC_USER" -m 0750 "$TLS"
        openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=$(hostname -f 2>/dev/null || hostname)" \
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
    /usr/local/sbin/cactai-dashboard-firewall remove
fi
SCHEME=http
if grep -q '^STREAMLIT_SERVER_SSL_CERT_FILE=' "$ENV_FILE"; then SCHEME=https; fi

# --- systemd ----------------------------------------------------------------
UNITS=(cactai-core cactai-collector cactai-dashboard cactai-notifier)
for u in "${UNITS[@]}"; do
    sed -e "s|@PREFIX@|$PREFIX|g" -e "s|@USER@|$SVC_USER|g" "$SRC/deploy/$u.service" > "/etc/systemd/system/$u.service"
done
if [ "$NOTIFIER" = 0 ]; then
    sed 's/ cactai-notifier.service//' "$SRC/deploy/cactai.target" > /etc/systemd/system/cactai.target
else
    cp "$SRC/deploy/cactai.target" /etc/systemd/system/cactai.target
fi
systemctl daemon-reload
systemctl enable cactai.target "${UNITS[@]:0:3}" >/dev/null
if [ "$NOTIFIER" = 1 ]; then systemctl enable cactai-notifier >/dev/null
else systemctl disable --now cactai-notifier >/dev/null 2>&1 || true; fi

if [ "$START" = 1 ]; then
    systemctl restart cactai.target
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
  Status:     systemctl status 'cactai-*'      Logs: journalctl -u cactai-core -f
  Restart:    systemctl restart cactai.target  (after editing $ENV_FILE)
  Core API:   $CORE_URL
  Find logs:  sudo cactai-scout find --root /var/log "where are the login and web logs?"
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
echo "  Change it:  sudo cactai-admin --reset   (or on the dashboard: Configuration, 6. Access)"
case "$CORE_HOST" in
    127.0.0.1|localhost|::1) ;;
    *) echo "  WARNING: the core API listens on $CORE_HOST:$CORE_PORT with no login; limit it in the firewall." ;;
esac
