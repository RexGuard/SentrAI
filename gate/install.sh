#!/usr/bin/env bash
# SentrAI Gate installer. One Linux machine, no account, no sign-in.
#
#   curl -fsSL https://raw.githubusercontent.com/RexGuard/SentrAI/main/gate/install.sh | sudo bash
#
# Options (after "sudo bash -s --" when piping):
#   --interface eth0     network card to guard (default: the one facing the internet)
#   --profile game       ready-made settings (default: picked from what this machine runs)
#   --level busy         how busy the machine is (default: normal)
#   --observe            watch only: count what would be dropped, drop nothing
#   --allow 1.2.3.4      also put this address on the allow list (repeatable)
#   --ref main           branch or tag to install from
#   --from-source        build here even if a ready-made program is available
#   --no-start           install but do not start
set -euo pipefail

REPO="RexGuard/SentrAI"
REF="main"
GO_VERSION="1.24.7"
iface="" profile="" level="normal" observe=0 start=1 from_source=0
allow=()

say()  { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
die()  { printf 'Install stopped: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --interface) iface="${2:?}"; shift 2 ;;
    --profile) profile="${2:?}"; shift 2 ;;
    --level) level="${2:?}"; shift 2 ;;
    --observe) observe=1; shift ;;
    --allow) allow+=("${2:?}"); shift 2 ;;
    --ref) REF="${2:?}"; shift 2 ;;
    --from-source) from_source=1; shift ;;
    --no-start) start=0; shift ;;
    -h|--help) sed -n '2,15p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run this with sudo."
[ "$(uname -s)" = "Linux" ] || die "SentrAI Gate runs on Linux only."
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "this processor type ($(uname -m)) is not supported yet." ;;
esac
kmajor="$(uname -r | cut -d. -f1)"; kminor="$(uname -r | cut -d. -f2 | sed 's/[^0-9].*//')"
if [ "$kmajor" -lt 5 ] || { [ "$kmajor" -eq 5 ] && [ "${kminor:-0}" -lt 10 ]; }; then
  die "the kernel here is $(uname -r). SentrAI Gate needs 5.10 or newer."
fi

fetch() { # url, destination
  if command -v curl >/dev/null 2>&1; then curl -fsSL --retry 3 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then wget -q -O "$2" "$1"
  else die "this machine has neither curl nor wget."; fi
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
bin="$work/sentrai-gate"

# Where is the source? Next to this script when run from a checkout.
here=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "$(dirname "${BASH_SOURCE[0]}")/go.mod" ]; then
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

build() { # source directory
  local go=go
  if ! command -v go >/dev/null 2>&1 || ! go version | grep -Eq 'go1\.(2[3-9]|[3-9][0-9])'; then
    say "Fetching the Go build tool (used once, then removed)..."
    fetch "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" "$work/go.tgz"
    tar -C "$work" -xzf "$work/go.tgz"
    go="$work/go/bin/go"
  fi
  local version
  version="$(git -C "$1" describe --tags --always 2>/dev/null || echo "$REF")"
  ( cd "$1" && CGO_ENABLED=0 GOTOOLCHAIN=local GOCACHE="$work/cache" GOPATH="$work/gopath" GOFLAGS=-modcacherw \
      "$go" build -trimpath \
      -ldflags "-s -w -X github.com/RexGuard/SentrAI/gate/internal/engine.Version=${version}" \
      -o "$bin" ./cmd/sentrai-gate ) || die "the build failed."
}

step "Getting SentrAI Gate"
if [ -n "$here" ]; then
  say "Building from this folder: $here"
  build "$here"
else
  got=0
  if [ "$from_source" -eq 0 ] && [ "$REF" = "main" ]; then
    base="https://github.com/${REPO}/releases/download/gate-latest"
    if fetch "$base/sentrai-gate-linux-${arch}" "$bin" 2>/dev/null &&
       fetch "$base/sentrai-gate-linux-${arch}.sha256" "$work/sum" 2>/dev/null; then
      if [ "$(sha256sum "$bin" | cut -d' ' -f1)" = "$(cut -d' ' -f1 "$work/sum")" ]; then
        got=1; say "Downloaded the ready-made program."
      else
        say "The download did not match its checksum. Building from source instead."
      fi
    fi
  fi
  if [ "$got" -eq 0 ]; then
    say "Building from source (branch or tag: $REF)..."
    fetch "https://codeload.github.com/${REPO}/tar.gz/${REF}" "$work/src.tgz" ||
      die "could not download the source for $REF."
    mkdir "$work/src"
    tar -C "$work/src" -xzf "$work/src.tgz" --strip-components=1 --wildcards '*/gate/*'
    here="$work/src/gate"
    build "$here"
  fi
fi
chmod 755 "$bin"
"$bin" version >/dev/null || die "the program does not run on this machine."

step "Installing"
was_running=0
if [ -d /run/systemd/system ] && systemctl is-active --quiet sentrai-gate; then was_running=1; fi
install -m 755 "$bin" /usr/local/bin/sentrai-gate
mkdir -p /etc/sentrai-gate /var/lib/sentrai-gate /var/log/sentrai-gate
say "Program: /usr/local/bin/sentrai-gate ($(/usr/local/bin/sentrai-gate version))"

args=(config init --level "$level")
[ -n "$iface" ] && args+=(--interface "$iface")
[ -n "$profile" ] && args+=(--profile "$profile")
[ "$observe" -eq 1 ] && args+=(--observe)
sentrai-gate "${args[@]}"

# Never lock out the person installing.
me="$(sentrai-gate whoami || true)"
if [ -n "$me" ]; then
  sentrai-gate allow add "$me" "installed from here" >/dev/null
  say "Your address $me is on the allow list, so the gate can never lock you out."
elif [ -n "${SSH_TTY:-}${SUDO_USER:-}" ] && [ ! -t 0 ] && [ "$observe" -eq 0 ] && [ ! -s /etc/sentrai-gate/allow.list ]; then
  say "Could not tell which address you are connected from."
  say "Add it once the install is done: sudo sentrai-gate allow add <your address>"
fi
for a in "${allow[@]}"; do sentrai-gate allow add "$a" >/dev/null && say "Allowed: $a"; done

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  if [ -n "$here" ] && [ -f "$here/sentrai-gate.service" ]; then
    install -m 644 "$here/sentrai-gate.service" /etc/systemd/system/sentrai-gate.service
  else
    fetch "https://raw.githubusercontent.com/${REPO}/${REF}/gate/sentrai-gate.service" /etc/systemd/system/sentrai-gate.service
  fi
  systemctl daemon-reload
  have_systemd=1
else
  have_systemd=0
fi

step "Checking this machine"
sentrai-gate doctor || die "this machine cannot run the gate yet. Fix the lines marked FAIL and run the installer again."

if [ "$start" -eq 0 ]; then
  say ""; say "Installed, not started. Start it with: sudo sentrai-gate start"
  exit 0
fi

step "Starting"
if [ "$have_systemd" -eq 1 ]; then
  systemctl enable sentrai-gate >/dev/null 2>&1 || true
  if [ "$was_running" -eq 1 ]; then systemctl restart sentrai-gate; else systemctl start sentrai-gate; fi
  for _ in 1 2 3 4 5 6 7 8; do
    [ -f /run/sentrai-gate/status.json ] && break
    sleep 1
  done
  if ! systemctl is-active --quiet sentrai-gate || [ ! -f /run/sentrai-gate/status.json ]; then
    journalctl -u sentrai-gate -n 20 --no-pager 2>/dev/null || true
    die "the gate did not start. The lines above say why."
  fi
  journalctl -u sentrai-gate -n 6 --no-pager -o cat 2>/dev/null || true
else
  say "This machine has no systemd, so the gate is not started for you."
  say "Run it yourself with: sudo sentrai-gate run"
  exit 0
fi

cat <<'DONE'

SentrAI Gate is running.

  sentrai-gate stats            live screen
  sentrai-gate status           one-screen summary
  sudo sentrai-gate allow add   never drop a sender you trust
  sudo sentrai-gate stop        stop filtering at once
  sentrai-gate help             everything else

Settings: /etc/sentrai-gate/config.yaml
DONE
