#!/usr/bin/env bash
# Stops and removes the SentrAI services and code that install.sh added.
#
#   sudo ./deploy/uninstall.sh                 keeps /etc/cactai and /var/lib/cactai (settings, audit trail)
#   sudo ./deploy/uninstall.sh --purge         also deletes those and the cactai user
#   --prefix DIR / --user NAME                 if install.sh was run with them
set -euo pipefail

PREFIX=/opt/cactai
SVC_USER=cactai
PURGE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        --user) SVC_USER="$2"; shift 2 ;;
        --purge) PURGE=1; shift ;;
        -h|--help) sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
done
[ "$(id -u)" = 0 ] || { echo "run as root (sudo ./deploy/uninstall.sh)" >&2; exit 1; }

systemctl disable --now cactai.target cactai-core cactai-collector cactai-dashboard cactai-notifier 2>/dev/null || true
rm -f /etc/systemd/system/cactai.target /etc/systemd/system/cactai-{core,collector,dashboard,notifier}.service
systemctl daemon-reload
rm -f /usr/local/bin/cactai-scout /usr/local/bin/cactai-admin
if [ -x /usr/local/sbin/cactai-dashboard-firewall ]; then /usr/local/sbin/cactai-dashboard-firewall remove; fi
rm -f /usr/local/sbin/cactai-dashboard-firewall
if command -v ufw >/dev/null 2>&1; then  # the allow rules install.sh added for the dashboard
    ufw status numbered 2>/dev/null | grep sentrai-dashboard | sed -n 's/^\[ *\([0-9]*\)\].*/\1/p' | sort -rn \
        | while read -r n; do ufw --force delete "$n" >/dev/null; done
fi
[ -f "$PREFIX/mvp/core/app/main.py" ] && rm -rf "$PREFIX"
if [ "$PURGE" = 1 ]; then
    rm -rf /etc/cactai /var/lib/cactai
    if id "$SVC_USER" >/dev/null 2>&1; then userdel "$SVC_USER"; fi
    echo "SentrAI removed, with its settings, audit trail and user."
else
    echo "SentrAI removed. Settings and the audit trail are still in /etc/cactai and /var/lib/cactai (--purge deletes them)."
fi
