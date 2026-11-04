# shellcheck shell=bash
# Shared by install-panel.sh and install-agent.sh (sourced): what sentrai-update needs on every machine.

# record_version APP SRC: which code is installed ($APP/VERSION); sentrai-update compares it with the newest.
# sentrai-update passes the commit it fetched; a run from a git checkout reads it from there.
record_version() {
    local root="$2/.." commit ref repo
    git_() { git -c safe.directory='*' -C "$root" "$@" 2>/dev/null; }
    commit="${SENTRAI_SOURCE_COMMIT:-$(git_ rev-parse HEAD || echo unknown)}"
    ref="${SENTRAI_SOURCE_REF:-$(git_ rev-parse --abbrev-ref HEAD || true)}"
    repo="${SENTRAI_SOURCE_REPO:-$(git_ remote get-url origin || true)}"
    repo="$(printf '%s' "$repo" | sed 's|://[^@/]*@|://|')"  # never keep a token from the clone URL
    printf 'commit=%s\nref=%s\nrepo=%s\ninstalled=%s\n' "$commit" "$ref" "$repo" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$1/VERSION"
    chmod 0644 "$1/VERSION"
}

# install_updater DEPLOY: sudo sentrai-update (deploy/update.sh)
install_updater() {
    install -m 0755 "$1/update.sh" /usr/local/sbin/sentrai-update
}

# move_old_install PREFIX: versions before the move out of mvp/ installed the code in PREFIX/mvp.
# Rename it to PREFIX/app once, keeping the Python venvs, so an update only reinstalls what changed.
# The service files written after this point run the code from PREFIX/app.
move_old_install() {
    [ -d "$1/mvp" ] || return 0
    # Both there (an older version was installed again with --ref): the services say which one runs.
    if [ -e "$1/app" ] && grep -qs "$1/mvp/" /etc/systemd/system/sentrai-core.service /etc/systemd/system/sentrai-agent.service; then
        rm -rf "$1/app"
    fi
    if [ -e "$1/app" ]; then
        rm -rf "$1/mvp"
    else
        echo "Moving the installed code from $1/mvp to $1/app ..."
        mv "$1/mvp" "$1/app"
    fi
}
