#!/usr/bin/env bash
# Removes SentrAI Gate from this machine.
#   sudo bash uninstall.sh           keep settings and lists
#   sudo bash uninstall.sh --purge   remove those too
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "Run this with sudo." >&2; exit 1; }
purge=0
[ "${1:-}" = "--purge" ] && purge=1

if [ -d /run/systemd/system ]; then
  systemctl disable --now sentrai-gate >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/sentrai-gate.service
  systemctl daemon-reload || true
fi
# In case it was started by hand.
if [ -f /run/sentrai-gate/pid ]; then
  kill "$(cat /run/sentrai-gate/pid)" 2>/dev/null || true
  sleep 1
fi
rm -rf /sys/fs/bpf/sentrai-gate /run/sentrai-gate
rm -f /usr/local/bin/sentrai-gate

if [ "$purge" -eq 1 ]; then
  rm -rf /etc/sentrai-gate /var/lib/sentrai-gate /var/log/sentrai-gate
  echo "SentrAI Gate is removed, with its settings, lists and logs."
else
  echo "SentrAI Gate is removed. Traffic is no longer filtered."
  echo "Settings and lists are kept in /etc/sentrai-gate (remove with --purge)."
fi
