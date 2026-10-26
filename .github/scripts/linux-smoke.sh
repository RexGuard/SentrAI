#!/usr/bin/env bash
# CI check of the Linux install on a real Ubuntu runner with systemd (run with sudo from mvp/):
# install the panel with install.sh, join this machine to it with install-agent.sh, send a real
# attack through a web log, approve the block and see it land in nftables, undo it, switch the
# agent to iptables and block again, then uninstall both and check everything is gone.
set -euo pipefail

PANEL=http://127.0.0.1:8000
ADMIN_IP=198.51.100.5        # stands in for the admin's own address (documentation range)
ATTACKER=45.155.205.233      # any public address works; the runner never talks to it
ATTACKER2=45.155.205.234
NAME=homelab-1
LOG=/var/log/nginx/access.log

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
    journalctl --no-pager -n 60 -u cactai-core -u cactai-collector -u cactai-dashboard -u cactai-notifier -u cactai-agent || true
    nft list ruleset 2>/dev/null | head -60 || true
}
trap 'rc=$?; [ "$rc" = 0 ] || dump; exit "$rc"' EXIT

[ "$(id -u)" = 0 ] || fail "run with sudo"
[ -f deploy/install.sh ] || fail "run from mvp/"

# An nginx access log where Ubuntu keeps it, with Ubuntu's owner and mode (the agent reads it
# through the adm group, the way it would on a real web server).
install -d -m 0755 /var/log/nginx
touch "$LOG"
chown www-data:adm "$LOG" 2>/dev/null || chown root:adm "$LOG"
chmod 0640 "$LOG"

# --- panel --------------------------------------------------------------------------------
./deploy/install.sh --no-questions --admin-email ci@example.com --protect "$ADMIN_IP"
for u in cactai-core cactai-collector cactai-dashboard; do
    wait_for "$u is running" 30 systemctl is-active --quiet "$u"
done
wait_for "core answers" 60 curl -sf "$PANEL/health"
wait_for "dashboard answers over HTTPS" 90 curl -skf https://127.0.0.1:8501/_stcore/health
nft list table inet cactai_dashboard | grep -q "$ADMIN_IP" || fail "dashboard firewall rule does not allow $ADMIN_IP"
[ "$(stat -c '%U:%G %a' /etc/cactai/cactai.env)" = "root:cactai 640" ] || fail "cactai.env owner/mode"
[ "$(stat -c '%a' /var/lib/cactai/core)" = 700 ] || fail "core state folder is not 0700"
TOKEN="$(cd /opt/cactai/mvp && set -a && . /etc/cactai/cactai.env && set +a && \
    runuser -u cactai -- env HOME=/var/lib/cactai lab/.venv/bin/python cactai_config.py token)"
[ -n "$TOKEN" ] || fail "no API token"
api() { curl -sf -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"; }

# A central panel scores each machine on its own.
grep -q '^CACTAI_RISK_SCOPE=host' /etc/cactai/cactai.env || echo CACTAI_RISK_SCOPE=host >> /etc/cactai/cactai.env
systemctl restart cactai.target
wait_for "core is back" 60 curl -sf "$PANEL/health"

CODE="$(api -X POST "$PANEL/fleet/join-codes" -d "{\"operator\": \"ci\", \"name\": \"$NAME\"}" \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["code"])')"
echo "join code $CODE"

# --- agent: first install is a dry run ------------------------------------------------------
./deploy/install-agent.sh --panel "$PANEL" --code "$CODE" --name "$NAME" --allow-http --protect "$ADMIN_IP"
wait_for "cactai-agent is running" 30 systemctl is-active --quiet cactai-agent
machine_reported() {
    api "$PANEL/machines" | python3 -c "import json, sys; m = [x for x in json.load(sys.stdin) if x['host'] == '$NAME']; sys.exit(not (m and m[0].get('services_at')))"
}
wait_for "the machine reports to the panel" 60 machine_reported
grep -q '^CACTAI_FIREWALL_ENFORCE=0' /etc/cactai/agent.env || fail "first install is not a dry run"
grep -q "$LOG" /var/lib/cactai/agent/sources.json || fail "the installer did not approve $LOG"
grep -q "$ADMIN_IP" /etc/cactai/agent.env || fail "--protect was not kept"
[ "$(stat -c '%U %a' /var/lib/cactai/agent)" = "cactai 700" ] || fail "agent state folder owner/mode"
[ "$(systemctl show -p User --value cactai-agent)" = cactai ] || fail "agent does not run as cactai"

# --- upgrade in place with --enforce (no code: the machine stays joined) ----------------------
./deploy/install-agent.sh --enforce
grep -q '^CACTAI_FIREWALL_ENFORCE=1' /etc/cactai/agent.env || fail "--enforce was not saved"
grep -q "$ADMIN_IP" /etc/cactai/agent.env || fail "--protect was lost on upgrade"
wait_for "cactai-agent is running after the upgrade" 30 systemctl is-active --quiet cactai-agent
n="$(api "$PANEL/fleet/agents" | python3 -c 'import json, sys; print(len(json.load(sys.stdin)))')"
[ "$n" = 1 ] || fail "the upgrade joined a second time ($n agents)"

# --- a real attack through the web log --------------------------------------------------------
attack() {  # IP: SQL injection and XSS probes in nginx's combined format
    local ip="$1" d
    d="$(date -u +%d/%b/%Y:%H:%M:%S)"
    for i in $(seq 1 10); do
        echo "$ip - - [$d +0000] \"GET /login.php?id=$i%27%20UNION%20SELECT%20username,password%20FROM%20users--%20 HTTP/1.1\" 403 162 \"-\" \"sqlmap/1.7\"" >> "$LOG"
        echo "$ip - - [$d +0000] \"GET /search?q=%3Cscript%3Ealert($i)%3C/script%3E HTTP/1.1\" 404 162 \"-\" \"Mozilla/5.0\"" >> "$LOG"
    done
}
incident_for() {  # IP: prints the id of the open SQL injection incident from IP on this machine
    api "$PANEL/incidents" | python3 -c "import json, sys
ids = [i['id'] for i in json.load(sys.stdin) if i['src_ip'] == '$1' and i['host'] == '$NAME' and i['category'] == 'sql_injection']
print(ids[0]) if ids else sys.exit(1)"
}
approve() {  # IP: approve the block for that address, as an operator on the dashboard would
    local iid
    wait_for "the panel opened an incident for $1" 60 incident_for "$1"
    iid="$(incident_for "$1")"
    api -X POST "$PANEL/incidents/$iid/decision" -d '{"operator": "ci", "decision": "approve", "justification": "CI"}' >/dev/null
    echo "$iid"
}
nft_has() { nft list set inet cactai blocked4 | grep -q "$1"; }
ipt_has() { iptables -w -C INPUT -s "$1" -m comment --comment cactai -j DROP; }

attack "$ATTACKER"
IID="$(approve "$ATTACKER" | tail -1)"
wait_for "the panel lists $ATTACKER for $NAME" 30 sh -c "curl -sf -H 'Authorization: Bearer $TOKEN' '$PANEL/blocklist?host=$NAME' | grep -q '$ATTACKER'"
wait_for "nftables drops $ATTACKER" 60 nft_has "$ATTACKER"
nft list chain inet cactai input | grep -q 'ip saddr @blocked4 drop' || fail "no drop rule for the blocked set"

# Undo it on the panel: the agent takes the block out again.
api -X POST "$PANEL/incidents/$IID/rollback" -d '{"operator": "ci"}' >/dev/null
for _ in $(seq 1 60); do nft_has "$ATTACKER" || break; sleep 1; done
! nft_has "$ATTACKER" || fail "the block stayed after the rollback"
echo "ok: rollback removed the block"

# A stop must stop the agent itself.
systemctl stop cactai-agent
sleep 1
! pgrep -f -- '-m agent run' >/dev/null || fail "the agent kept running after systemctl stop"

# --- iptables instead of nftables ---------------------------------------------------------------
sed -i 's/^CACTAI_FIREWALL=.*/CACTAI_FIREWALL=iptables/' /etc/cactai/agent.env
systemctl start cactai-agent
wait_for "cactai-agent is running on iptables" 30 systemctl is-active --quiet cactai-agent
attack "$ATTACKER2"
approve "$ATTACKER2" >/dev/null
wait_for "iptables drops $ATTACKER2" 60 ipt_has "$ATTACKER2"

if journalctl -q --no-pager -u cactai-core -u cactai-collector -u cactai-notifier -u cactai-agent | grep "Read-only file system"; then
    fail "a service tried to write outside its own folder (above)"
fi

# --- uninstall: service, code and blocks go; the key stays until --purge -------------------------
./deploy/uninstall-agent.sh
! systemctl cat cactai-agent >/dev/null 2>&1 || fail "agent service still installed"
! ipt_has "$ATTACKER2" 2>/dev/null || fail "iptables block left behind"
[ -f /var/lib/cactai/agent/agent.json ] || fail "uninstall deleted the machine key without --purge"
[ -f /opt/cactai/mvp/core/app/main.py ] || fail "agent uninstall removed the panel's code"
systemctl is-active --quiet cactai-core || fail "agent uninstall stopped the panel"
./deploy/uninstall-agent.sh --purge
[ ! -e /var/lib/cactai/agent ] || fail "--purge left /var/lib/cactai/agent"

./deploy/uninstall.sh --purge
for u in cactai-core cactai-collector cactai-dashboard cactai-notifier; do
    ! systemctl cat "$u" >/dev/null 2>&1 || fail "$u still installed"
done
[ ! -e /opt/cactai ] || fail "/opt/cactai still there"
! nft list table inet cactai_dashboard >/dev/null 2>&1 || fail "dashboard firewall rule left behind"
! id cactai >/dev/null 2>&1 || fail "cactai user still there"
echo "Linux install: all checks passed"
