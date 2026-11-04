#!/usr/bin/env bash
# Old name of the panel uninstaller, kept so older commands still work.
# Use: sudo ./deploy/uninstall-panel.sh   (agents: sudo ./deploy/uninstall-agent.sh)
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/uninstall-panel.sh" "$@"
