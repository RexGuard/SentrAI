#!/usr/bin/env bash
# Installs a SentrAI witness: the off-box copy that can only be added to (run as root on a SECOND
# machine, one the watched server's admins and root cannot log in to).
#
#   sudo ./deploy/install-witness.sh --name 198.51.100.20
#
# Then, on the watched server, point SentrAI at it with the line this prints:
#   sudo ./deploy/install.sh --remote-copy https://198.51.100.20:8600 --remote-copy-token-file ...
#
# Options:
#   --name HOST_OR_IP   how the watched server reaches this machine (goes in the HTTPS certificate)
#   --port N            port (default 8600)
#   --allow IP          only this address may connect (repeatable; firewall rule via nft/iptables)
#   --no-tls            plain HTTP (only on a private network you trust)
#
# What it creates:
#   /opt/sentrai-witness/witness.py      the witness (standard library only, no venv)
#   /var/lib/sentrai-witness/            the copy (owner sentrai-witness, 0700)
#   /etc/sentrai-witness/append.token    the token the watched server gets: add records only
#   /etc/sentrai-witness/read.token      the auditor's token: read and compare (keep it off the server)
#   /etc/sentrai-witness/tls/            a self-signed certificate; cert.pem goes to the watched server
#   /etc/systemd/system/sentrai-witness.service
set -euo pipefail

PORT=8600
NAME=""
TLS=1
ALLOW=()
while [ $# -gt 0 ]; do
    case "$1" in
        --name) NAME="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --allow) ALLOW+=("$2"); shift 2 ;;
        --no-tls) TLS=0; shift ;;
        -h|--help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
done

die() { echo "install-witness.sh: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' || die "python 3.10 or newer is required"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -f "$SRC/witness/witness.py" ] || die "run it from a SentrAI checkout (mvp/deploy/install-witness.sh)"
NAME="${NAME:-$(hostname -I 2>/dev/null | awk '{print $1}')}"
[ -n "$NAME" ] || die "--name is required"

USER_=sentrai-witness
DATA=/var/lib/sentrai-witness
ETC=/etc/sentrai-witness
if ! id "$USER_" >/dev/null 2>&1; then
    useradd --system --home-dir "$DATA" --no-create-home --shell /usr/sbin/nologin "$USER_"
fi
install -d -o "$USER_" -g "$USER_" -m 0700 "$DATA"
install -d -o root -g "$USER_" -m 0750 "$ETC"
install -d -m 0755 /opt/sentrai-witness
install -m 0644 "$SRC/witness/witness.py" /opt/sentrai-witness/witness.py

for t in append read; do  # kept on upgrade
    if [ ! -s "$ETC/$t.token" ]; then
        python3 /opt/sentrai-witness/witness.py token > "$ETC/$t.token"
    fi
    chown root:"$USER_" "$ETC/$t.token"; chmod 0640 "$ETC/$t.token"
done

ARGS="--data $DATA --port $PORT --append-token-file $ETC/append.token --read-token-file $ETC/read.token"
SCHEME=http
if [ "$TLS" = 1 ]; then
    command -v openssl >/dev/null 2>&1 || die "openssl is needed for HTTPS (or pass --no-tls)"
    install -d -o root -g "$USER_" -m 0750 "$ETC/tls"
    if [ ! -f "$ETC/tls/cert.pem" ]; then
        case "$NAME" in *[!0-9.:]*) san="DNS:$NAME" ;; *) san="IP:$NAME" ;; esac
        openssl req -x509 -newkey rsa:2048 -nodes -days 1825 -subj "/CN=$NAME" -addext "subjectAltName=$san" \
            -keyout "$ETC/tls/key.pem" -out "$ETC/tls/cert.pem" 2>/dev/null
    fi
    chown root:"$USER_" "$ETC/tls/key.pem" "$ETC/tls/cert.pem"; chmod 0640 "$ETC/tls/key.pem"; chmod 0644 "$ETC/tls/cert.pem"
    ARGS="$ARGS --tls-cert $ETC/tls/cert.pem --tls-key $ETC/tls/key.pem"
    SCHEME=https
fi

cat > /etc/systemd/system/sentrai-witness.service <<EOF
[Unit]
Description=SentrAI witness (append-only off-box copy)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/env python3 /opt/sentrai-witness/witness.py serve $ARGS
User=$USER_
Group=$USER_
Restart=on-failure
RestartSec=5
# Least privilege: writes only its copy, nothing else.
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6
SystemCallArchitectures=native
SystemCallFilter=@system-service
UMask=0077
ReadWritePaths=$DATA

[Install]
WantedBy=multi-user.target
EOF

if [ "${#ALLOW[@]}" -gt 0 ]; then
    if command -v nft >/dev/null 2>&1; then
        nft delete table inet sentrai_witness 2>/dev/null || true
        nft add table inet sentrai_witness
        nft add chain inet sentrai_witness input '{ type filter hook input priority -5 ; policy accept ; }'
        for ip in "${ALLOW[@]}"; do
            case "$ip" in *:*) fam=ip6 ;; *) fam=ip ;; esac
            nft add rule inet sentrai_witness input $fam saddr "$ip" tcp dport "$PORT" accept
        done
        nft add rule inet sentrai_witness input tcp dport "$PORT" drop
        echo "Firewall: only ${ALLOW[*]} may reach port $PORT (nft table inet sentrai_witness; not kept across reboots)."
    else
        echo "WARNING: nft is missing, so --allow was not applied; limit port $PORT in your firewall." >&2
    fi
fi

systemctl daemon-reload
systemctl enable --now sentrai-witness >/dev/null
systemctl restart sentrai-witness

cat <<EOF

The SentrAI witness is running on $SCHEME://$NAME:$PORT and keeps its copy in $DATA.

On the watched server, copy these two files over (scp), then run the installer there:
  $ETC/append.token$( [ "$TLS" = 1 ] && echo "      and  $ETC/tls/cert.pem" )
  sudo ./deploy/install.sh --remote-copy $SCHEME://$NAME:$PORT --remote-copy-token-file ./append.token$( [ "$TLS" = 1 ] && echo " --remote-copy-ca ./cert.pem" )

Keep $ETC/read.token OFF the watched server: it reads the copy back. To compare later:
  python -m app.remote_copy compare --url $SCHEME://$NAME:$PORT --read-token-file read.token
EOF
