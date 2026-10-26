#!/usr/bin/env bash
# CI check of the upgrade from the CactAI names (run with sudo from mvp/, on a clean runner):
# install the panel and an agent with the last version before the rename (cactai-* services,
# /etc/cactai, /var/lib/cactai, the cactai user, nft table inet cactai), put a block in place,
# then run today's install.sh once and check that everything moved to the sentrai names: the
# services, folders, settings, account, audit record, API token and the block itself.
set -euo pipefail

OLD="${OLD:?a folder holding mvp/ from the last commit before the rename}"
PANEL=http://127.0.0.1:8000
AGENT_URL=https://127.0.0.1:8443
ADMIN_IP=198.51.100.5
BLOCKED=45.155.205.240
NAME=homelab-1

fail() { echo "FAILED: $*" >&2; exit 1; }
wait_for() {  # WHAT SECONDS COMMAND...
    local what="$1" secs="$2"; shift 2
    for _ in $(seq 1 "$secs"); do
        if "$@" >/dev/null 2>&1; then echo "ok: $what"; return 0; fi
        sleep 1
    done
    fail "timed out waiting for: $what"
}
dump() {
    echo "--- journal ---"
    journalctl --no-pager -n 80 -u 'cactai-*' -u 'sentrai-*' || true
    nft list ruleset 2>/dev/null | head -60 || true
}
trap 'rc=$?; [ "$rc" = 0 ] || dump; exit "$rc"' EXIT

[ "$(id -u)" = 0 ] || fail "run with sudo"
[ -f deploy/install.sh ] || fail "run from mvp/"

# --- the old version ------------------------------------------------------------------------
[ -f "$OLD/mvp/deploy/install.sh" ] || fail "no old checkout in $OLD"
"$OLD/mvp/deploy/install.sh" --no-questions --admin-email ci@example.com --protect "$ADMIN_IP" \
    --panel 8443 --panel-url "$AGENT_URL"
wait_for "cactai-core is running" 30 systemctl is-active --quiet cactai-core
wait_for "old core answers" 60 curl -sf "$PANEL/health"
OLD_TOKEN="$(cd /opt/cactai/mvp && set -a && . /etc/cactai/cactai.env && set +a && \
    runuser -u cactai -- env HOME=/var/lib/cactai lab/.venv/bin/python cactai_config.py token)"
[ -n "$OLD_TOKEN" ] || fail "no API token from the old version"
api() { curl -sf -H "Authorization: Bearer $OLD_TOKEN" -H 'Content-Type: application/json' "$@"; }
JOIN="$(api -X POST "$PANEL/fleet/join-codes" -d "{\"operator\": \"ci\", \"name\": \"$NAME\"}")"
CODE="$(echo "$JOIN" | python3 -c 'import json, sys; print(json.load(sys.stdin)["code"])')"
PIN="$(echo "$JOIN" | python3 -c 'import json, sys; print(json.load(sys.stdin)["pin"])')"
"$OLD/mvp/deploy/install-agent.sh" --panel "$AGENT_URL" --code "$CODE" --pin "$PIN" --name "$NAME" \
    --protect "$ADMIN_IP" --enforce
wait_for "cactai-agent is running" 30 systemctl is-active --quiet cactai-agent
AUDIT_BEFORE="$(api "$PANEL/audit" | python3 -c 'import json, sys; print(len(json.load(sys.stdin)))')"
# A block already in force, in the old table and as an old iptables rule.
nft add table inet cactai
nft add set inet cactai blocked4 '{ type ipv4_addr ; }'
nft add element inet cactai blocked4 "{ $BLOCKED }"
iptables -w -I INPUT -s "$BLOCKED" -m comment --comment cactai -j DROP
echo "ok: old version installed (panel and agent)"

# --- today's install.sh, run once ---------------------------------------------------------------
./deploy/install.sh --no-questions
for u in sentrai-core sentrai-collector sentrai-dashboard sentrai-agent; do
    wait_for "$u is running" 60 systemctl is-active --quiet "$u"
done
wait_for "core answers" 60 curl -sf "$PANEL/health"
for u in cactai.target cactai-core cactai-collector cactai-dashboard cactai-notifier cactai-agent; do
    ! systemctl cat "$u" >/dev/null 2>&1 || fail "$u is still installed"
done
for d in /etc/cactai /var/lib/cactai /opt/cactai /usr/local/bin/cactai-admin /usr/local/bin/cactai-scout \
         /usr/local/sbin/cactai-dashboard-firewall; do
    [ ! -e "$d" ] || fail "$d is still there"
done
! id cactai >/dev/null 2>&1 || fail "the cactai account is still there"
[ "$(systemctl show -p User --value sentrai-core)" = sentrai ] || fail "core does not run as sentrai"
[ "$(stat -c '%U' /var/lib/sentrai/core)" = sentrai ] || fail "state folder is not owned by sentrai"
[ -f /etc/sentrai/sentrai.env ] || fail "no /etc/sentrai/sentrai.env"
! grep -q -i cactai /etc/sentrai/sentrai.env /etc/sentrai/agent.env || fail "old names left in the settings"
grep -q '^SENTRAI_PANEL_PORT=8443' /etc/sentrai/sentrai.env || fail "the panel port was lost"
grep -q '^SENTRAI_FIREWALL_ENFORCE=1' /etc/sentrai/agent.env || fail "the agent's --enforce was lost"
[ -f /var/lib/sentrai/core/sentrai.db ] || fail "the audit record was not renamed to sentrai.db"
echo "ok: services, folders, settings and account moved"

# The same token and audit record; the agent is still the one machine that joined.
NEW_TOKEN="$(cd /opt/sentrai/mvp && set -a && . /etc/sentrai/sentrai.env && set +a && \
    runuser -u sentrai -- env HOME=/var/lib/sentrai lab/.venv/bin/python sentrai_config.py token)"
[ "$NEW_TOKEN" = "$OLD_TOKEN" ] || fail "the API token changed"
AUDIT_AFTER="$(api "$PANEL/audit" | python3 -c 'import json, sys; print(len(json.load(sys.stdin)))')"
[ "$AUDIT_AFTER" -ge "$AUDIT_BEFORE" ] || fail "audit records were lost ($AUDIT_BEFORE -> $AUDIT_AFTER)"
curl -sf -H "X-CactAI-Token: $OLD_TOKEN" "$PANEL/incidents" >/dev/null || fail "the old token header is refused"
n="$(api "$PANEL/fleet/agents" | python3 -c 'import json, sys; print(len(json.load(sys.stdin)))')"
[ "$n" = 1 ] || fail "expected the one joined agent, got $n"
echo "ok: same API token, audit record and agent"

# The block came along; the old firewall names are gone.
! nft list table inet cactai >/dev/null 2>&1 || fail "nft table inet cactai is still there"
nft list set inet sentrai blocked4 | grep -q "$BLOCKED" || fail "the nftables block was not carried over"
iptables -w -C INPUT -s "$BLOCKED" -m comment --comment sentrai -j DROP || fail "the iptables block was not renamed"
! iptables -w -C INPUT -s "$BLOCKED" -m comment --comment cactai -j DROP 2>/dev/null || fail "old iptables rule left"
! nft list table inet cactai_dashboard >/dev/null 2>&1 || fail "the old dashboard rule is still there"
nft list table inet sentrai_dashboard | grep -q "$ADMIN_IP" || fail "the dashboard rule does not allow $ADMIN_IP"
echo "ok: firewall blocks carried over to the sentrai names"

./deploy/install.sh --no-questions >/dev/null  # a second run has nothing left to move
iptables -w -D INPUT -s "$BLOCKED" -m comment --comment sentrai -j DROP
./deploy/uninstall-agent.sh --purge
./deploy/uninstall.sh --purge
! id sentrai >/dev/null 2>&1 || fail "sentrai user still there"
echo "Upgrade from the CactAI names: all checks passed"
