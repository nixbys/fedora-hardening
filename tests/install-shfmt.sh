#!/usr/bin/env bash
# tests/install-shfmt.sh - Install shfmt for the lint toolchain on any Fedora release.
#
# Fedora 44 ships shfmt 3.7.0 as an RPM; Fedora 45 no longer packages it. To keep
# formatting identical across releases, fall back to building the SAME pinned
# version with Fedora's own Go toolchain (modules are verified against the Go
# checksum database).
#
# Usage: install-shfmt.sh [dest-dir]   (default /usr/local/bin; root needed for dnf)

set -euo pipefail

SHFMT_VERSION="3.7.0"
DEST="${1:-/usr/local/bin}"
SUDO=()
((EUID == 0)) || SUDO=(sudo)

if command -v shfmt >/dev/null 2>&1; then
    echo "shfmt already installed: $(command -v shfmt)"
    exit 0
fi

if "${SUDO[@]}" dnf install -y --setopt=install_weak_deps=False shfmt >/dev/null 2>&1; then
    echo "shfmt installed from the Fedora RPM"
    exit 0
fi

echo "shfmt RPM unavailable on this release — building v${SHFMT_VERSION} with Fedora's Go"
command -v go >/dev/null 2>&1 ||
    "${SUDO[@]}" dnf install -y --setopt=install_weak_deps=False golang >/dev/null
mkdir -p "$DEST"
GOBIN="$DEST" GOPATH="${TMPDIR:-/tmp}/shfmt-gopath" GOFLAGS=-modcacherw \
    go install "mvdan.cc/sh/v3/cmd/shfmt@v${SHFMT_VERSION}"
"$DEST/shfmt" --version
