#!/usr/bin/env bash
# Removes the SentrAI agent that install-agent.sh added: its service, the blocks it put in this
# machine's firewall and its code. The machine key stays (so a reinstall needs no new join code)
# until --purge. A SentrAI panel installed on the same machine (install.sh) is left alone.
#
#   sudo ./deploy/uninstall-agent.sh               remove the service, its blocks and its code
#   sudo ./deploy/uninstall-agent.sh --purge       also delete the machine key, settings and the cactai user
#   --keep-blocks                                  leave the firewall blocks in place
#   --prefix DIR / --user NAME                     if install-agent.sh was run with them
# On the panel, revoke the machine on the Machines page as well.
set -euo pipefail

PREFIX=/opt/cactai
SVC_USER=cactai
PURGE=0
KEEP_BLOCKS=0
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        --user) SVC_USER="$2"; shift 2 ;;
        --purge) PURGE=1; shift ;;
        --keep-blocks) KEEP_BLOCKS=1; shift ;;
        -h|--help) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
done
[ "$(id -u)" = 0 ] || { echo "run as root (sudo ./deploy/uninstall-agent.sh)" >&2; exit 1; }

STATE=/var/lib/cactai/agent
ENV_FILE=/etc/cactai/agent.env
MVP="$PREFIX/mvp"
PANEL=0  # install.sh put the panel here too: its code, folders and user stay
if [ -f /etc/systemd/system/cactai-core.service ]; then PANEL=1; fi

systemctl disable --now cactai-agent 2>/dev/null || true
rm -f /etc/systemd/system/cactai-agent.service
systemctl daemon-reload

# Take out exactly the blocks the agent put in (listed in its state file), with its own commands,
# so nothing else in the firewall is touched.
if [ "$KEEP_BLOCKS" = 0 ] && [ -f "$STATE/agent.json" ] && [ -x "$MVP/lab/.venv/bin/python" ]; then
    (cd "$MVP/lab" && set -a && { [ ! -f "$ENV_FILE" ] || . "$ENV_FILE"; } && set +a && \
        CACTAI_FIREWALL_ENFORCE=1 "$MVP/lab/.venv/bin/python" - "$STATE/agent.json" <<'EOF'
import json, sys
from agent import agent
data = json.load(open(sys.argv[1], encoding="utf-8"))
e = agent.make_enforcer(data)
blocked = sorted(e.applied)
e.sync(set())
for line in e.log:
    print("  " + line)
if blocked:
    print("Removed the agent's firewall blocks: " + ", ".join(blocked))
data["blocked"] = []
data["panel_blocked"] = []
data.pop("local", None)  # the local rules' blocks went with the rest
json.dump(data, open(sys.argv[1], "w", encoding="utf-8"), indent=2)
EOF
    ) || echo "WARNING: could not remove the agent's firewall blocks; check: nft list table inet cactai" >&2
fi
# The agent's nftables table holds nothing but its blocks; on a machine without a panel it can go.
if [ "$KEEP_BLOCKS" = 0 ] && [ "$PANEL" = 0 ] && command -v nft >/dev/null 2>&1; then
    nft delete table inet cactai 2>/dev/null || true
fi

if [ "$PANEL" = 0 ] && [ -f "$MVP/lab/agent/agent.py" ]; then rm -rf "$PREFIX"; fi

if [ "$PURGE" = 1 ]; then
    rm -rf "$STATE"
    rm -f "$ENV_FILE" /etc/cactai/panel-ca.pem
    if [ "$PANEL" = 0 ]; then
        rmdir /etc/cactai /var/lib/cactai 2>/dev/null || true
        if id "$SVC_USER" >/dev/null 2>&1; then userdel "$SVC_USER"; fi
    fi
    echo "SentrAI agent removed, with its machine key and settings. Revoke it on the panel's Machines page too."
else
    echo "SentrAI agent removed. Its machine key is still in $STATE (--purge deletes it)."
fi
