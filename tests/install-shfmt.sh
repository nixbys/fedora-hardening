#!/usr/bin/env bash
# tests/install-shfmt.sh - Install the pinned shfmt for the lint toolchain.
#
# Fedora no longer packages shfmt (44 still had 3.7.0). Build the pinned version
# with Fedora's own Go toolchain (modules are verified against the Go checksum
# database), so formatting is identical everywhere. The weekly Reference watch
# reports newer stable releases.
#
# Usage: install-shfmt.sh [dest-dir]   (default /usr/local/bin; root needed for dnf)
set -euo pipefail
SHFMT_VERSION="3.7.0" # 3.14.1 after the open branches merge (it reformats ((!x)) as ((! x)))
DEST="${1:-/usr/local/bin}"
SUDO=()
((EUID == 0)) || SUDO=(sudo)
if [[ "$(shfmt --version 2>/dev/null)" == "v${SHFMT_VERSION}" ]]; then
    echo "shfmt v${SHFMT_VERSION} already installed: $(command -v shfmt)"
    exit 0
fi
echo "building shfmt v${SHFMT_VERSION} with Fedora's Go"
command -v go >/dev/null 2>&1 ||
    "${SUDO[@]}" dnf install -y --setopt=install_weak_deps=False golang >/dev/null
mkdir -p "$DEST"
GOBIN="$DEST" GOPATH="${TMPDIR:-/tmp}/shfmt-gopath" GOFLAGS=-modcacherw \
    go install "mvdan.cc/sh/v3/cmd/shfmt@v${SHFMT_VERSION}"
"$DEST/shfmt" --version
