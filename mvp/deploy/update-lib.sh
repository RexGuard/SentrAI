# shellcheck shell=bash
# Shared by install.sh and install-agent.sh (sourced): what sentrai-update needs on every machine.

# record_version MVP SRC: which code is installed ($MVP/VERSION); sentrai-update compares it with the newest.
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

# install_updater SRC: sudo sentrai-update (deploy/update.sh)
install_updater() {
    install -m 0755 "$1/deploy/update.sh" /usr/local/sbin/sentrai-update
}
