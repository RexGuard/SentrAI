#!/usr/bin/env bash
# Updates an installed SentrAI (the panel, an agent, or both on one machine) to the newest code,
# keeping every setting, account, port and flag it was installed with. Installed as
# /usr/local/sbin/sentrai-update by install.sh and install-agent.sh.
#
#   sudo sentrai-update                  update to the newest main (or the branch/tag saved with --ref)
#   sudo sentrai-update --check          only say whether a newer version is out (exit 10 if so)
#   sudo sentrai-update --rollback       go back to the version before the last update
#
# What an update does:
#   1. fetches the code (git, or GitHub's download when git is missing) into /opt/sentrai/source
#   2. stops SentrAI and saves the code, its Python packages, /etc/sentrai, the service files and
#      the data (except collected logs) to /var/backups/sentrai/<time>/ (the newest 2 are kept)
#   3. runs the new install.sh --update and/or install-agent.sh: new code, changed packages, file
#      moves, service files; settings and sign-in stay as they are, no new setup code
#   4. checks it works: the core answers /health, the dashboard and agents' port answer, and no
#      service keeps restarting. If not, everything from step 2 is put back and the old version runs.
#
# Options:
#   --ref REF        branch, tag or commit to follow (saved for next time; default main)
#   --repo URL       where to fetch from (saved; default the repo it was installed from)
#   --from DIR       install from this local checkout instead of fetching (no network needed)
#   --force          reinstall even when it is already up to date
#   --check          only compare with the newest version; writes $SENTRAI_HOME/update-check.json,
#                    which the dashboard reads for its "Update available" notice
#   --quiet          with --check: print nothing (for the daily timer)
#   --rollback       put back the newest backup (after an update that passed its checks but misbehaves)
#   --no-rollback    keep the new version even when the checks fail (to look at it)
# Log of every run: /var/log/sentrai-update.log
set -euo pipefail

# The installers replace this file while it runs; run from a private copy so bash never reads a
# half-replaced script.
if [ -z "${SENTRAI_UPDATE_COPY:-}" ]; then
    copy="$(mktemp /tmp/sentrai-update.XXXXXX)"
    cp "$0" "$copy"
    SENTRAI_UPDATE_COPY="$copy" SENTRAI_UPDATE_SELF="$(readlink -f "$0")" exec bash "$copy" "$@"
fi
trap 'rm -f "$SENTRAI_UPDATE_COPY"' EXIT

DEFAULT_REPO=https://github.com/RexGuard/SentrAI.git
SETTINGS=/etc/sentrai/update.env
BACKUPS=/var/backups/sentrai
KEEP=2
LOG=/var/log/sentrai-update.log
REF="" REPO="" FROM="" FORCE=0 CHECK=0 QUIET=0 ROLLBACK_ONLY=0 AUTO_ROLLBACK=1
while [ $# -gt 0 ]; do
    case "$1" in
        --ref) REF="$2"; shift 2 ;;
        --repo) REPO="$2"; shift 2 ;;
        --from) FROM="$2"; shift 2 ;;
        --force) FORCE=1; shift ;;
        --check) CHECK=1; shift ;;
        --quiet|-q) QUIET=1; shift ;;
        --rollback) ROLLBACK_ONLY=1; shift ;;
        --no-rollback) AUTO_ROLLBACK=0; shift ;;
        -h|--help) sed -n '2,32p' "$SENTRAI_UPDATE_SELF" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
done

say() { [ "$QUIET" = 1 ] || echo "$@"; }
die() { echo "sentrai-update: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root (sudo sentrai-update)"
PYTHON="${PYTHON:-python3}"

# --- what is installed here ---------------------------------------------------------------
unit_file() { [ -f "/etc/systemd/system/$1.service" ]; }
PANEL=0; AGENT=0
unit_file sentrai-core && PANEL=1
unit_file sentrai-agent && AGENT=1
[ "$PANEL$AGENT" != 00 ] || die "SentrAI is not installed here (no sentrai-core or sentrai-agent service); install it first"
main_unit=sentrai-core; [ "$PANEL" = 1 ] || main_unit=sentrai-agent
# --prefix and --user as installed: the unit runs <prefix>/mvp/<part>/.venv/bin/python as <user>
PREFIX="$(sed -n 's|^ExecStart=\(.*\)/mvp/[a-z]*/\.venv/bin/python.*|\1|p' "/etc/systemd/system/$main_unit.service" | head -1)"
PREFIX="${PREFIX:-/opt/sentrai}"
SVC_USER="$(sed -n 's/^User=//p' "/etc/systemd/system/$main_unit.service" | head -1)"
SVC_USER="${SVC_USER:-sentrai}"
MVP="$PREFIX/mvp"
SOURCE="$PREFIX/source"
STATE=/var/lib/sentrai
if [ "$PANEL" = 1 ]; then
    home="$(sed -n 's/^SENTRAI_HOME=//p' /etc/sentrai/sentrai.env 2>/dev/null | tail -1)"
    STATE="${home:-$STATE}"
fi
CHECK_FILE="$STATE/update-check.json"

version_of() {  # FILE KEY: a line of a VERSION file
    [ -f "$1" ] && sed -n "s/^$2=//p" "$1" | tail -1 || true
}
INSTALLED="$(version_of "$MVP/VERSION" commit)"

# --- where updates come from (saved in update.env) -----------------------------------------
saved() { [ -f "$SETTINGS" ] && sed -n "s/^$1=//p" "$SETTINGS" | tail -1 || true; }
https_url() {  # git@github.com:owner/repo(.git) -> https://github.com/owner/repo.git (root has no SSH key)
    case "$1" in git@*:*) local h="${1#git@}"; echo "https://${h%%:*}/${h#*:}" ;; *) echo "$1" ;; esac
}
REPO="${REPO:-$(saved SENTRAI_UPDATE_REPO)}"
REPO="${REPO:-$(version_of "$MVP/VERSION" repo)}"
if [ -z "$REPO" ] && [ -n "${SENTRAI_UPDATE_SELF:-}" ]; then  # run from a checkout: that checkout's origin
    REPO="$(git -c safe.directory='*' -C "$(dirname "$SENTRAI_UPDATE_SELF")" remote get-url origin 2>/dev/null || true)"
fi
REPO="$(https_url "${REPO:-$DEFAULT_REPO}")"
REF="${REF:-$(saved SENTRAI_UPDATE_REF)}"
REF="${REF:-main}"
save_settings() {
    install -d -m 0750 -o root -g "$SVC_USER" /etc/sentrai
    printf '# Where sudo sentrai-update fetches from (--repo / --ref change these)\nSENTRAI_UPDATE_REPO=%s\nSENTRAI_UPDATE_REF=%s\n' \
        "$REPO" "$REF" > "$SETTINGS"
    chmod 0644 "$SETTINGS"
}

github_slug() {  # https://github.com/owner/repo(.git) -> owner/repo
    case "$1" in https://github.com/*) local s="${1#https://github.com/}"; echo "${s%.git}" ;; *) return 1 ;; esac
}
latest_commit() {  # the commit REF points at in REPO, without downloading the code
    if [[ "$REF" =~ ^[0-9a-f]{40}$ ]]; then echo "$REF"; return; fi
    if command -v git >/dev/null 2>&1; then
        local out
        out="$(git ls-remote "$REPO" "refs/heads/$REF" "refs/tags/$REF" "refs/tags/$REF^{}")" || return 1
        # a tag's own commit (^{}) wins over the tag object
        { echo "$out" | grep '\^{}$' || echo "$out"; } | head -1 | cut -f1
    else
        local slug; slug="$(github_slug "$REPO")" || { echo "git is needed for $REPO (apt install git)" >&2; return 1; }
        "$PYTHON" - "$slug" "$REF" <<'EOF'
import sys, urllib.request
req = urllib.request.Request(f"https://api.github.com/repos/{sys.argv[1]}/commits/{sys.argv[2]}",
                             headers={"Accept": "application/vnd.github.sha", "User-Agent": "sentrai-update"})
print(urllib.request.urlopen(req, timeout=30).read().decode().strip())
EOF
    fi
}

# --- --check: is a newer version out? ------------------------------------------------------
if [ "$CHECK" = 1 ]; then
    err="" errfile="$(mktemp)"
    latest="$(latest_commit 2>"$errfile")" || err="$(cat "$errfile")"
    rm -f "$errfile"
    if [ -z "$err" ] && [ -z "$latest" ]; then err="$REPO has no branch or tag named $REF"; fi
    available=false
    if [ -n "$latest" ] && [ "$latest" != "$INSTALLED" ]; then available=true; fi
    "$PYTHON" - "$CHECK_FILE" "$INSTALLED" "$latest" "$REF" "$REPO" "$available" "$err" <<'EOF'
import json, os, sys, time
path, installed, latest, ref, repo, available, err = sys.argv[1:]
out = {"checked": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "installed": installed, "latest": latest,
       "ref": ref, "repo": repo, "available": available == "true", "error": err.strip()[-300:]}
tmp = path + ".new"
with open(tmp, "w") as f:
    json.dump(out, f, indent=2)
os.chmod(tmp, 0o644)
os.replace(tmp, path)
EOF
    if [ -n "$err" ]; then say "Could not check for updates: $err"; exit 1; fi
    if [ "$available" = true ]; then
        say "An update is available: ${INSTALLED:0:7}${INSTALLED:+ -> }${latest:0:7} ($REF). Run: sudo sentrai-update"
        exit 10
    fi
    say "SentrAI is up to date (${latest:0:7}, $REF)."
    exit 0
fi

# Everything below changes the machine: one run at a time, all of it in the log.
exec 9>/run/sentrai-update.lock
flock -n 9 || die "another sentrai-update is running"
touch "$LOG"; chmod 0600 "$LOG"
exec > >(tee -a "$LOG") 2>&1
echo "=== sentrai-update $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="

# --- backup and restore --------------------------------------------------------------------
UNITS=() RUNNING=()  # enabled services, and those of them running now (only these must run afterwards)
for u in sentrai-core sentrai-collector sentrai-dashboard sentrai-notifier sentrai-agent; do
    if unit_file "$u" && systemctl is-enabled --quiet "$u" 2>/dev/null; then
        UNITS+=("$u")
        systemctl is-active --quiet "$u" && RUNNING+=("$u")
    fi
done
stop_all() { systemctl stop sentrai.target sentrai-core sentrai-collector sentrai-dashboard sentrai-notifier sentrai-agent 2>/dev/null || true; }
start_all() {
    [ "$PANEL" = 1 ] && systemctl start sentrai.target
    [ "$AGENT" = 1 ] && systemctl start sentrai-agent
    return 0
}
SYSTEM_FILES=(etc/sentrai etc/systemd/system/sentrai.target etc/systemd/system/sentrai-update-check.timer
              usr/local/bin/sentrai-scout usr/local/bin/sentrai-admin usr/local/sbin/sentrai-dashboard-firewall
              usr/local/sbin/sentrai-update)
make_backup() {  # DIR
    local dir="$1" files=() f
    install -d -m 0700 "$BACKUPS" "$dir"
    echo "Saving the current version to $dir ..."
    tar -C "$PREFIX" -cf "$dir/code.tar" mvp
    for f in "${SYSTEM_FILES[@]/#//}" /etc/systemd/system/sentrai-*.service; do [ -e "$f" ] && files+=("${f#/}"); done
    tar -C / -cf "$dir/system.tar" "${files[@]}"
    # The data, except collected logs and the core's own backups (they stay where they are anyway).
    if [ -d /var/lib/sentrai ]; then
        tar -C /var/lib -cf "$dir/data.tar" --exclude=sentrai/lab-logs --exclude=sentrai/agent/logs \
            --exclude=sentrai/core/backups sentrai
    fi
    printf 'commit=%s\nsaved=%s\n' "${INSTALLED:-unknown}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$dir/INFO"
}
restore_backup() {  # DIR
    local dir="$1"
    echo "Putting back the version saved in $dir ..."
    stop_all
    rm -rf "$MVP"
    tar -C "$PREFIX" -xpf "$dir/code.tar"
    # Service files and helpers the newer version added go; the saved ones come back.
    rm -f /etc/systemd/system/sentrai*.service /etc/systemd/system/sentrai*.timer /etc/systemd/system/sentrai.target
    rm -rf /etc/sentrai
    tar -C / -xpf "$dir/system.tar"
    if [ -f "$dir/data.tar" ]; then
        # SQLite side files the newer version left (-wal, -shm, -journal) belong to its copy of a
        # database; next to the saved one they make it "malformed". Drop them, then put the data back.
        find /var/lib/sentrai \( -name '*.db-wal' -o -name '*.db-shm' -o -name '*.db-journal' \) -type f -delete 2>/dev/null || true
        tar -C /var/lib -xpf "$dir/data.tar"
    fi
    systemctl daemon-reload
    systemctl enable "${UNITS[@]}" >/dev/null 2>&1 || true
    if [ -f /etc/systemd/system/sentrai-update-check.timer ]; then systemctl enable --now sentrai-update-check.timer >/dev/null 2>&1 || true; fi
    start_all
}
prune_backups() {
    local old
    old="$(ls -1d "$BACKUPS"/*/ 2>/dev/null | sort | head -n "-$KEEP" || true)"
    [ -z "$old" ] || echo "$old" | xargs rm -rf
}

# --- health -------------------------------------------------------------------------------
probe() {  # URL: answers 2xx (self-signed certificates are fine here)
    "$PYTHON" - "$1" <<'EOF' 2>/dev/null
import ssl, sys, urllib.request
urllib.request.urlopen(sys.argv[1], timeout=3, context=ssl._create_unverified_context())
EOF
}
wait_probe() {  # WHAT URL SECONDS
    for _ in $(seq 1 "$3"); do
        if probe "$2"; then echo "  ok: $1"; return 0; fi
        sleep 1
    done
    echo "  FAILED: $1 did not answer at $2 within $3 s"
    return 1
}
restarts() { systemctl show -p NRestarts --value "$1" 2>/dev/null || echo 0; }
healthy() {
    echo "Checking that SentrAI works ..."
    local env=/etc/sentrai/sentrai.env u ok=0
    declare -A before=()
    if [ "$PANEL" = 1 ]; then
        local core dport dscheme=http pport
        core="$(sed -n 's/^SENTRAI_CORE_URL=//p' "$env" | tail -1)"
        wait_probe "the core" "${core:-http://127.0.0.1:8000}/health" 60 || ok=1
        dport="$(sed -n 's/^SENTRAI_DASHBOARD_PORT=//p' "$env" | tail -1)"
        grep -q '^STREAMLIT_SERVER_SSL_CERT_FILE=' "$env" && dscheme=https
        if [ "$ok" = 0 ] && systemctl is-enabled --quiet sentrai-dashboard; then
            wait_probe "the dashboard" "$dscheme://127.0.0.1:${dport:-8501}/_stcore/health" 90 || ok=1
        fi
        pport="$(sed -n 's/^SENTRAI_PANEL_PORT=//p' "$env" | tail -1)"
        if [ "$ok" = 0 ] && [ -n "$pport" ]; then wait_probe "the agents' port" "https://127.0.0.1:$pport/health" 30 || ok=1; fi
    fi
    [ "$ok" = 0 ] || return 1
    # Running is not enough: nothing may crash and restart over the next 20 seconds. A service that
    # was not running before the update either is reported, not held against the new version.
    for u in "${UNITS[@]}"; do before[$u]="$(restarts "$u")"; done
    sleep 20
    for u in "${UNITS[@]}"; do
        if [[ " ${RUNNING[*]} " != *" $u "* ]]; then
            systemctl is-active --quiet "$u" && echo "  ok: $u is running" \
                || echo "  note: $u is not running (it was not running before the update either)"
        elif ! systemctl is-active --quiet "$u"; then echo "  FAILED: $u is not running"; ok=1
        elif [ "$(restarts "$u")" != "${before[$u]}" ]; then echo "  FAILED: $u keeps restarting"; ok=1
        else echo "  ok: $u is running"; fi
    done
    [ "$ok" = 0 ] || journalctl --no-pager -n 30 "${UNITS[@]/#/-u}" || true
    return "$ok"
}

# --- --rollback: back to the version before the last update --------------------------------
if [ "$ROLLBACK_ONLY" = 1 ]; then
    last=""
    for d in "$BACKUPS"/*/; do case "$d" in *.restored/) ;; *) [ -d "$d" ] && last="$d" ;; esac; done  # newest last
    [ -n "$last" ] || die "no saved version in $BACKUPS"
    restore_backup "${last%/}"
    healthy || die "the saved version does not pass its checks either; see $LOG"
    echo "Rolled back to $(version_of "$MVP/VERSION" commit | cut -c1-7) (saved $(version_of "${last%/}/INFO" saved))."
    mv "${last%/}" "${last%/}.restored"
    exit 0
fi

# --- 1. get the code -----------------------------------------------------------------------
if [ -n "$FROM" ]; then
    FROM="$(cd "$FROM" && pwd)"
    [ -f "$FROM/mvp/deploy/install.sh" ] || die "--from $FROM is not a SentrAI checkout (no mvp/deploy/install.sh)"
    NEW_SRC="$FROM"
    NEW="$(git -c safe.directory='*' -C "$FROM" rev-parse HEAD 2>/dev/null || echo local)"
    REF="$FROM"  # what the summary names; nothing is saved
    FORCE=1
else
    if [ "$FORCE" = 0 ] && latest="$(latest_commit 2>/dev/null)" && [ -n "$latest" ] && [ "$latest" = "$INSTALLED" ]; then
        echo "SentrAI is already up to date (${latest:0:7}, $REF). --force reinstalls it anyway."
        exit 0
    fi
    say "Fetching $REF from $REPO ..."
    if command -v git >/dev/null 2>&1; then
        [ -d "$SOURCE/.git" ] || { rm -rf "$SOURCE"; git init -q "$SOURCE"; }
        git -C "$SOURCE" fetch -q --depth 1 "$REPO" "$REF" || die "could not fetch $REF from $REPO (see above)"
        git -C "$SOURCE" reset -q --hard FETCH_HEAD
        git -C "$SOURCE" clean -qfdx
        NEW="$(git -C "$SOURCE" rev-parse HEAD)"
    else
        slug="$(github_slug "$REPO")" || die "git is needed to fetch from $REPO (apt install git)"
        NEW="$(latest_commit)" || die "could not ask GitHub for $REF"
        tmp="$(mktemp -d)"
        "$PYTHON" - "https://codeload.github.com/$slug/tar.gz/$NEW" "$tmp/code.tgz" <<'EOF' || die "could not download $slug@$NEW"
import sys, urllib.request
urllib.request.urlretrieve(sys.argv[1], sys.argv[2])
EOF
        rm -rf "$SOURCE"; install -d "$SOURCE"
        tar -C "$SOURCE" -xzf "$tmp/code.tgz" --strip-components=1
        rm -rf "$tmp"
    fi
    NEW_SRC="$SOURCE"
    save_settings
fi
[ -f "$NEW_SRC/mvp/deploy/install.sh" ] || die "$REF has no mvp/deploy/install.sh"

if [ "$NEW" = "$INSTALLED" ] && [ "$FORCE" = 0 ]; then
    echo "SentrAI is already up to date (${NEW:0:7}, $REF). --force reinstalls it anyway."
    exit 0
fi
echo "Updating SentrAI: ${INSTALLED:-unknown}${INSTALLED:+ ($(version_of "$MVP/VERSION" installed))} -> $NEW"

# --- 2. save what runs now -----------------------------------------------------------------
stop_all
BACKUP="$BACKUPS/$(date -u +%Y%m%d-%H%M%S)-${INSTALLED:0:7}"
make_backup "$BACKUP" || { start_all; die "could not save the current version; nothing was changed"; }

# --- 3. install the new code with the settings already here --------------------------------
export SENTRAI_SOURCE_COMMIT="$NEW" SENTRAI_SOURCE_REF="$REF" SENTRAI_SOURCE_REPO="$REPO"
rc=0
if [ "$PANEL" = 1 ]; then
    "$NEW_SRC/mvp/deploy/install.sh" --update --prefix "$PREFIX" --user "$SVC_USER" || rc=$?
fi
if [ "$rc" = 0 ] && [ "$AGENT" = 1 ]; then
    "$NEW_SRC/mvp/deploy/install-agent.sh" --prefix "$PREFIX" --user "$SVC_USER" || rc=$?
fi

# --- 4. check, else roll back --------------------------------------------------------------
if [ "$rc" = 0 ] && healthy; then
    prune_backups
    echo
    echo "SentrAI updated to ${NEW:0:7} ($REF). The previous version is saved in $BACKUP"
    echo "  (sudo sentrai-update --rollback puts it back)."
    # Clears the dashboard's "Update available" notice.
    [ "$PANEL" = 1 ] && env -u SENTRAI_UPDATE_COPY "$SENTRAI_UPDATE_SELF" --check --quiet >/dev/null 2>&1 || true
    exit 0
fi
[ "$rc" = 0 ] || echo "The installer stopped with an error ($rc)."
if [ "$AUTO_ROLLBACK" = 0 ]; then
    die "the new version failed its checks; left in place (--no-rollback). Undo with: sudo sentrai-update --rollback"
fi
restore_backup "$BACKUP"
if healthy; then
    mv "$BACKUP" "$BACKUP.restored"
    die "the new version ${NEW:0:7} failed its checks, so the previous one (${INSTALLED:0:7}) is running again. Details: $LOG"
fi
die "the update failed AND the previous version does not start; the saved copy is in $BACKUP. Details: $LOG"
