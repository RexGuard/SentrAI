#!/usr/bin/env bash
# Lets only the addresses in CACTAI_DASHBOARD_ALLOW reach the dashboard port; every other address is
# dropped. install.sh copies this to /usr/local/sbin/cactai-dashboard-firewall, and the dashboard
# service runs it (as root) each time it starts, so the rule comes back after a reboot. It fails,
# and the dashboard stays down, when neither nft nor iptables is there: better closed than open.
#
#   cactai-dashboard-firewall          apply the rule from /etc/cactai/cactai.env
#   cactai-dashboard-firewall remove   take it away again (uninstall.sh does this)
#
# The rule sits in its own nftables table (inet cactai_dashboard) or iptables chain (CACTAI-DASH)
# and only drops: it never accepts traffic that the rest of the firewall would block.
set -euo pipefail

ENV_FILE="${CACTAI_ENV_FILE:-/etc/cactai/cactai.env}"
TABLE=cactai_dashboard
CHAIN=CACTAI-DASH

remove() {
    if command -v nft >/dev/null 2>&1; then nft delete table inet "$TABLE" 2>/dev/null || true; fi
    for t in iptables ip6tables; do
        command -v "$t" >/dev/null 2>&1 || continue
        while "$t" -w -D INPUT -j "$CHAIN" 2>/dev/null; do :; done
        "$t" -w -F "$CHAIN" 2>/dev/null || true
        "$t" -w -X "$CHAIN" 2>/dev/null || true
    done
}

if [ "${1:-}" = remove ]; then remove; exit 0; fi

env_value() { sed -n "s/^$1=//p" "$ENV_FILE" | tail -1; }
PORT="$(env_value CACTAI_DASHBOARD_PORT)"; PORT="${PORT:-8501}"
ALLOW="$(env_value CACTAI_DASHBOARD_ALLOW)"
case "$PORT" in ''|*[!0-9]*) echo "cactai-dashboard-firewall: bad port '$PORT'" >&2; exit 1 ;; esac

V4=(); V6=()
for ip in ${ALLOW//,/ }; do
    case "$ip" in
        *[!0-9a-fA-F.:/]*) echo "cactai-dashboard-firewall: skipping bad address '$ip'" >&2 ;;
        *:*) V6+=("$ip") ;;
        *) V4+=("$ip") ;;
    esac
done

remove
if command -v nft >/dev/null 2>&1; then
    join() { local IFS=,; echo "$*"; }
    {
        echo "table inet $TABLE {"
        echo "  chain input {"
        echo "    type filter hook input priority -10; policy accept;"
        echo "    iifname \"lo\" tcp dport $PORT return"
        [ "${#V4[@]}" -gt 0 ] && echo "    ip saddr { $(join "${V4[@]}") } tcp dport $PORT return"
        [ "${#V6[@]}" -gt 0 ] && echo "    ip6 saddr { $(join "${V6[@]}") } tcp dport $PORT return"
        echo "    tcp dport $PORT drop"
        echo "  }"
        echo "}"
    } | nft -f -
    echo "Dashboard port $PORT: open to ${ALLOW:-this server only} (nftables table inet $TABLE)"
elif command -v iptables >/dev/null 2>&1; then
    for t in iptables ip6tables; do
        command -v "$t" >/dev/null 2>&1 || continue
        "$t" -w -N "$CHAIN"
        "$t" -w -A "$CHAIN" -i lo -p tcp --dport "$PORT" -j RETURN
        if [ "$t" = iptables ]; then list=("${V4[@]}"); else list=("${V6[@]}"); fi
        for ip in "${list[@]}"; do "$t" -w -A "$CHAIN" -s "$ip" -p tcp --dport "$PORT" -j RETURN; done
        "$t" -w -A "$CHAIN" -p tcp --dport "$PORT" -j DROP
        "$t" -w -I INPUT 1 -j "$CHAIN"
    done
    echo "Dashboard port $PORT: open to ${ALLOW:-this server only} (iptables chain $CHAIN)"
else
    echo "cactai-dashboard-firewall: neither nft nor iptables is installed; not starting an open dashboard" >&2
    exit 1
fi
