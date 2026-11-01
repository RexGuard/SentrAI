#!/usr/bin/env bash
# Stops and removes the SentrAI services and code that install.sh added.
#
#   sudo ./deploy/uninstall.sh                 keeps /etc/sentrai and /var/lib/sentrai (settings, audit trail)
#   sudo ./deploy/uninstall.sh --purge         also deletes those and the sentrai user
#   --prefix DIR / --user NAME                 if install.sh was run with them
set -euo pipefail

PREFIX=/opt/sentrai
SVC_USER=sentrai
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
# An install from before the CactAI -> SentrAI rename is moved to the new names, then removed as usual.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/migrate-from-cactai.sh"
migrate_from_cactai server
reinstall_other_after_cactai panel "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

systemctl disable --now sentrai.target sentrai-core sentrai-collector sentrai-dashboard sentrai-web sentrai-notifier \
    sentrai-update-check.timer 2>/dev/null || true
rm -f /etc/systemd/system/sentrai.target /etc/systemd/system/sentrai-{core,collector,dashboard,web,notifier}.service \
    /etc/systemd/system/sentrai-update-check.{service,timer}
systemctl daemon-reload
rm -f /usr/local/bin/sentrai-scout /usr/local/bin/sentrai-admin
# sudo sentrai-update stays while an agent on this machine still uses it.
[ -f /etc/systemd/system/sentrai-agent.service ] || rm -f /usr/local/sbin/sentrai-update
if [ -x /usr/local/sbin/sentrai-dashboard-firewall ]; then /usr/local/sbin/sentrai-dashboard-firewall remove; fi
rm -f /usr/local/sbin/sentrai-dashboard-firewall
if command -v ufw >/dev/null 2>&1; then  # the allow rules install.sh added for the dashboard and panel
    ufw status numbered 2>/dev/null | grep -E "(sentrai|cactai)-(dashboard|panel)" | sed -n 's/^\[ *\([0-9]*\)\].*/\1/p' | sort -rn \
        | while read -r n; do ufw --force delete "$n" >/dev/null; done || true  # none there is fine
fi
[ -f "$PREFIX/mvp/core/app/main.py" ] && rm -rf "$PREFIX"
if [ "$PURGE" = 1 ]; then
    rm -rf /etc/sentrai /var/lib/sentrai /var/backups/sentrai
    if id "$SVC_USER" >/dev/null 2>&1; then userdel "$SVC_USER"; fi
    echo "SentrAI removed, with its settings, audit trail and user."
else
    echo "SentrAI removed. Settings and the audit trail are still in /etc/sentrai and /var/lib/sentrai (--purge deletes them)."
fi
