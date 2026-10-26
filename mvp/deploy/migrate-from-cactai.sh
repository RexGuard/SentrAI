# Moves an install made before the CactAI -> SentrAI rename over to the new names. Sourced by
# install.sh, install-agent.sh, install-witness.sh and the uninstall scripts; it does nothing on a
# machine without the old names, and running it twice changes nothing the second time.
#
#   migrate_from_cactai server|witness
#
# server:  stops and removes the old cactai-* units, moves /etc/cactai and /var/lib/cactai to
#          /etc/sentrai and /var/lib/sentrai (renaming cactai.env and cactai.db, and CACTAI_* settings
#          to SENTRAI_*), renames the cactai account to sentrai (same uid, so file owners stay right),
#          carries the blocks in the old firewall table or rules over to the new names and removes
#          the old commands. /opt/cactai (code and venvs only) is deleted; the installer copies the
#          code again. Sets OLD_PANEL=1 / OLD_AGENT=1 when the panel / agent was installed, so the
#          installer that ran can upgrade the other one too (reinstall_other_after_cactai).
# witness: the same for the witness (cactai-witness -> sentrai-witness).
# Firewall rules added for ufw or firewalld keep their old comment; they still allow the same ports.

OLD_PANEL=0
OLD_AGENT=0

_mig_say() { echo "Upgrade from CactAI names: $*"; }

_mig_move() {  # OLD NEW: rename a folder, or merge it into a NEW one that exists already
    [ -e "$1" ] || return 0
    if [ ! -e "$2" ]; then mv "$1" "$2"
    else cp -a -n "$1/." "$2/" && rm -rf "$1"; fi
    _mig_say "moved $1 to $2"
}

_mig_rewrite() {  # FILE...: old names and paths inside settings files
    local f
    for f in "$@"; do
        [ -f "$f" ] || continue
        sed -i -e 's/CACTAI_/SENTRAI_/g' -e 's#/etc/cactai#/etc/sentrai#g' -e 's#/var/lib/cactai#/var/lib/sentrai#g' \
            -e 's#/opt/cactai#/opt/sentrai#g' -e 's#cactai\.db#sentrai.db#g' -e 's#/\.cactai/#/.sentrai/#g' \
            -e '/^[[:space:]]*#/s/cactai/sentrai/g' "$f"  # comments name the old units (cactai-agent, cactai.target)
    done
    return 0
}

_mig_user() {  # OLD NEW: rename the system account and its group, keeping the uid and gid
    id "$1" >/dev/null 2>&1 || return 0
    if id "$2" >/dev/null 2>&1; then userdel "$1" 2>/dev/null || true; return 0; fi
    usermod -l "$2" "$1"
    if getent group "$1" >/dev/null && ! getent group "$2" >/dev/null; then groupmod -n "$2" "$1"; fi
    usermod -d "$3" "$2" 2>/dev/null || true
    _mig_say "renamed the $1 account to $2"
}

_mig_nft_merge() {  # the addresses in the old table's sets, added to the same sets in table inet sentrai
    local set type elems
    for set in blocked4 blocked6; do
        nft list set inet cactai "$set" >/dev/null 2>&1 || continue
        type=ipv4_addr; [ "$set" = blocked6 ] && type=ipv6_addr
        nft add set inet sentrai "$set" "{ type $type ; }" || return 1
        elems="$(nft -j list set inet cactai "$set" | python3 -c '
import json, sys
out = []
for item in json.load(sys.stdin)["nftables"]:
    for e in item.get("set", {}).get("elem", []):
        e = e.get("elem", {}).get("val", e) if isinstance(e, dict) else e
        if isinstance(e, str):
            out.append(e)
print(", ".join(out))')" || return 1
        if [ -n "$elems" ]; then nft add element inet sentrai "$set" "{ $elems }" || return 1; fi
    done
    return 0
}

_mig_firewall() {  # the host firewall blocks: same addresses, new table name / rule comment
    local tmp
    if command -v nft >/dev/null 2>&1; then
        if nft list table inet cactai >/dev/null 2>&1; then
            if nft list table inet sentrai >/dev/null 2>&1; then
                # A sentrai table is already there (an earlier install): add the old blocks to its sets.
                if _mig_nft_merge; then
                    nft delete table inet cactai && _mig_say "added the old firewall blocks to table inet sentrai"
                else
                    echo "WARNING: could not copy the blocks in nft table inet cactai; left it in place" >&2
                fi
            else
                tmp="$(mktemp)"
                nft list table inet cactai | sed '1s/^table inet cactai /table inet sentrai /' > "$tmp"
                if nft -f "$tmp"; then
                    nft delete table inet cactai && _mig_say "moved the firewall blocks to table inet sentrai"
                else
                    echo "WARNING: could not copy nft table inet cactai; left it in place" >&2
                fi
                rm -f "$tmp"
            fi
        fi
        nft delete table inet cactai_witness 2>/dev/null || true  # install-witness.sh makes the new one
    fi
    local tool rule
    for tool in iptables ip6tables; do
        command -v "$tool" >/dev/null 2>&1 || continue
        "$tool" -w -S INPUT 2>/dev/null | grep -e '--comment "\{0,1\}cactai"\{0,1\} ' | while read -r _ _ rule; do
            # shellcheck disable=SC2086  # the rule's words, as iptables -S printed them
            "$tool" -w -I INPUT $(echo "$rule" | sed -E 's/--comment "?cactai"?/--comment sentrai/') \
                && "$tool" -w -D INPUT $(echo "$rule" | tr -d '"')
        done || true  # no old rules is fine
    done
    return 0
}

migrate_from_cactai() {
    local kind="$1" u
    if [ "$kind" = witness ]; then
        [ -e /etc/systemd/system/cactai-witness.service ] || [ -d /var/lib/cactai-witness ] \
            || [ -d /etc/cactai-witness ] || return 0
        systemctl disable --now cactai-witness 2>/dev/null || true
        rm -f /etc/systemd/system/cactai-witness.service
        systemctl daemon-reload
        _mig_firewall
        _mig_move /var/lib/cactai-witness /var/lib/sentrai-witness
        _mig_move /etc/cactai-witness /etc/sentrai-witness
        _mig_user cactai-witness sentrai-witness /var/lib/sentrai-witness
        rm -rf /opt/cactai-witness
        return 0
    fi

    [ -e /etc/systemd/system/cactai.target ] || [ -e /etc/systemd/system/cactai-agent.service ] \
        || [ -d /etc/cactai ] || [ -d /var/lib/cactai ] || [ -d /opt/cactai ] || id cactai >/dev/null 2>&1 || return 0
    [ -e /etc/systemd/system/cactai-core.service ] && OLD_PANEL=1
    [ -e /etc/systemd/system/cactai-agent.service ] && OLD_AGENT=1

    systemctl disable --now cactai.target 2>/dev/null || true
    for u in core collector dashboard notifier agent; do
        systemctl disable --now "cactai-$u" 2>/dev/null || true
        rm -f "/etc/systemd/system/cactai-$u.service"
    done
    rm -f /etc/systemd/system/cactai.target
    systemctl daemon-reload

    # The dashboard rule goes with its old command; install.sh puts the new one in before the dashboard starts.
    if [ -x /usr/local/sbin/cactai-dashboard-firewall ]; then /usr/local/sbin/cactai-dashboard-firewall remove || true; fi
    rm -f /usr/local/sbin/cactai-dashboard-firewall /usr/local/bin/cactai-admin /usr/local/bin/cactai-scout
    _mig_firewall

    _mig_move /etc/cactai /etc/sentrai
    [ -f /etc/sentrai/cactai.env ] && [ ! -f /etc/sentrai/sentrai.env ] && mv /etc/sentrai/cactai.env /etc/sentrai/sentrai.env
    _mig_rewrite /etc/sentrai/*.env

    _mig_move /var/lib/cactai /var/lib/sentrai
    local s=/var/lib/sentrai f
    for f in "$s/core/cactai.db" "$s/core/cactai.db-wal" "$s/core/cactai.db-shm" \
             "$s/cactai.db" "$s/cactai.db-wal" "$s/cactai.db-shm"; do
        [ -e "$f" ] && [ ! -e "${f/cactai.db/sentrai.db}" ] && mv "$f" "${f/cactai.db/sentrai.db}"
    done
    # Settings, log sources and read positions name the old folders; the audit record and keys are left as they are.
    _mig_rewrite "$s"/*.json "$s"/scout/*.json "$s"/collector/*.json "$s"/agent/*.json

    _mig_user cactai sentrai /var/lib/sentrai
    [ -f /etc/systemd/journald.conf.d/50-cactai-seal.conf ] \
        && mv /etc/systemd/journald.conf.d/50-cactai-seal.conf /etc/systemd/journald.conf.d/50-sentrai-seal.conf
    rm -rf /opt/cactai
    _mig_say "done; the services come back under their sentrai-* names"
    return 0
}

reinstall_other_after_cactai() {  # ME (panel|agent) DIR: upgrade the other part that was here under the old names
    if [ "$1" = panel ] && [ "$OLD_AGENT" = 1 ] && [ ! -e /etc/systemd/system/sentrai-agent.service ]; then
        echo "The SentrAI agent on this machine was installed under the old names; upgrading it too ..."
        "$2/install-agent.sh" || echo "WARNING: upgrade the agent with: sudo $2/install-agent.sh" >&2
    elif [ "$1" = agent ] && [ "$OLD_PANEL" = 1 ] && [ ! -e /etc/systemd/system/sentrai-core.service ]; then
        echo "The SentrAI panel on this machine was installed under the old names; upgrading it too ..."
        "$2/install.sh" --no-questions || echo "WARNING: upgrade the panel with: sudo $2/install.sh" >&2
    fi
}
