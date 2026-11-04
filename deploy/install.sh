#!/usr/bin/env bash
# Old name of the panel installer, kept so older commands and older copies of sentrai-update still
# work. New installs: sudo ./deploy/install-panel.sh   (agents: sudo ./deploy/install-agent.sh)
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/install-panel.sh" "$@"
