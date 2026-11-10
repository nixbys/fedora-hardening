#!/usr/bin/env bash
# setup-dev.sh - Initialize the development environment for fedora-harden.sh
#
# The supported development platform is Fedora 44 (the release the script targets).
# All tooling comes from Fedora 44 RPMs, so local runs, pre-commit hooks and CI use
# the same tool versions:
#   ShellCheck shfmt yamllint ruff hadolint gitleaks pre-commit python3-mcp podman
#
# On an rpm-ostree host (Silverblue, Kinoite, Bazzite, ...) run this inside a
# Fedora 44 toolbox:
#   toolbox create --image registry.fedoraproject.org/fedora-toolbox:44 fh-dev
#   toolbox enter fh-dev && ./setup-dev.sh

set -Eeuo pipefail

# Colors (only when stdout is a terminal)
if [[ -t 1 ]]; then
    C_RED=$'\033[0;31m' C_GRN=$'\033[0;32m' C_YEL=$'\033[0;33m' C_BLU=$'\033[0;34m' C_RST=$'\033[0m'
else
    C_RED="" C_GRN="" C_YEL="" C_BLU="" C_RST=""
fi

log_info() { printf '%s[ℹ]%s %s\n' "$C_BLU" "$C_RST" "$*"; }
log_ok() { printf '%s[✓]%s %s\n' "$C_GRN" "$C_RST" "$*"; }
log_warn() { printf '%s[⚠]%s %s\n' "$C_YEL" "$C_RST" "$*"; }
log_err() { printf '%s[✗]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; }

# Configuration
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
TARGET_FEDORA="44"
PYTHON_MIN_VERSION="3.10"
# command:rpm pairs for the Fedora toolchain
FEDORA_TOOLS=(
    git:git
    python3:python3
    podman:podman
    shellcheck:ShellCheck
    yamllint:yamllint
    ruff:ruff
    hadolint:hadolint
    gitleaks:gitleaks
    pre-commit:pre-commit
)
OPTIONAL_RPMS=(python3-mcp)
SKIP_OPTIONAL=0
DRY_RUN=0

show_help() {
    cat <<EOF
Set up the development environment for the fedora-hardening project

USAGE:
    ./setup-dev.sh [OPTIONS]

OPTIONS:
    --skip-optional    Skip optional packages (${OPTIONAL_RPMS[*]})
    --dry-run          Show what would be installed
    --help             Show this help

PLATFORM:
    Fedora ${TARGET_FEDORA}. Tools are installed as Fedora RPMs with dnf:
      $(printf '%s ' "${FEDORA_TOOLS[@]#*:}")
    Optional: ${OPTIONAL_RPMS[*]} (for the Claude MCP server)
    On rpm-ostree hosts, run inside a fedora-toolbox:${TARGET_FEDORA} toolbox.

EOF
}

# Parse arguments
while (($# > 0)); do
    case "$1" in
        --skip-optional)
            SKIP_OPTIONAL=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h | --help)
            show_help
            exit 0
            ;;
        *)
            log_err "Unknown option: $1"
            show_help
            exit 2
            ;;
    esac
done

cmd_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Run a command, or print it in --dry-run mode.
do_run() {
    if ((DRY_RUN)); then
        echo "  Would run: $*"
        return 0
    fi
    "$@"
}

# Use sudo only when not already root.
as_root() {
    if ((EUID == 0)); then
        do_run "$@"
    else
        do_run sudo "$@"
    fi
}

verify_tool() {
    local cmd="$1" name="$2"
    if cmd_exists "$cmd"; then
        log_ok "$name: available"
        return 0
    fi
    log_warn "$name: not found"
    return 1
}

python_version_ok() {
    python3 - "$PYTHON_MIN_VERSION" <<'PY'
import sys
want = tuple(int(x) for x in sys.argv[1].split("."))
sys.exit(0 if sys.version_info[:len(want)] >= want else 1)
PY
}

main() {
    log_info "Fedora Hardening - Development Environment Setup"
    log_info "=================================================="

    local os_id="unknown" os_version="" os_name="unknown"
    if [[ -r /etc/os-release ]]; then
        # shellcheck source=/dev/null
        os_id="$(. /etc/os-release && echo "${ID:-unknown}")"
        # shellcheck source=/dev/null
        os_version="$(. /etc/os-release && echo "${VERSION_ID:-}")"
        # shellcheck source=/dev/null
        os_name="$(. /etc/os-release && echo "${PRETTY_NAME:-unknown}")"
    fi
    log_info "Platform: $os_name"

    if [[ -e /run/ostree-booted ]]; then
        log_err "This is an rpm-ostree host; development tools are not layered onto it."
        log_info "Create and enter a Fedora ${TARGET_FEDORA} toolbox, then re-run this script:"
        log_info "  toolbox create --image registry.fedoraproject.org/fedora-toolbox:${TARGET_FEDORA} fh-dev"
        log_info "  toolbox enter fh-dev"
        exit 1
    fi
    if [[ "$os_id" != fedora ]]; then
        log_err "Unsupported platform '$os_id'. The development platform is Fedora ${TARGET_FEDORA}."
        log_info "Use a Fedora ${TARGET_FEDORA} machine, VM, or container (registry.fedoraproject.org/fedora:${TARGET_FEDORA})."
        exit 1
    fi
    if [[ "$os_version" != "$TARGET_FEDORA" ]]; then
        log_warn "Fedora $os_version detected; the project targets Fedora ${TARGET_FEDORA}."
        log_warn "Tool versions (e.g. shfmt) may differ from CI. tests/run-suite.sh always runs"
        log_warn "the static tier in a Fedora ${TARGET_FEDORA} container for that reason."
    fi

    # Toolchain RPMs (single dnf transaction for everything missing)
    log_info ""
    log_info "Checking Fedora toolchain..."
    local spec cmd rpm missing=()
    for spec in "${FEDORA_TOOLS[@]}"; do
        cmd="${spec%%:*}" rpm="${spec#*:}"
        if cmd_exists "$cmd"; then
            log_ok "$rpm: installed"
        else
            missing+=("$rpm")
        fi
    done
    if ((!SKIP_OPTIONAL)); then
        for rpm in "${OPTIONAL_RPMS[@]}"; do
            rpm -q "$rpm" >/dev/null 2>&1 || missing+=("$rpm")
        done
    fi
    if ((${#missing[@]})); then
        log_info "Installing with dnf: ${missing[*]}"
        if ! as_root dnf install -y "${missing[@]}"; then
            log_err "dnf install failed"
            exit 1
        fi
    fi

    # shfmt: RPM on Fedora 44; on 45+ the same pinned version is built with Go.
    if ! cmd_exists shfmt; then
        if ((DRY_RUN)); then
            echo "  Would run: tests/install-shfmt.sh ${HOME}/.local/bin"
        elif ! "$SCRIPT_DIR/tests/install-shfmt.sh" "${HOME}/.local/bin"; then
            log_warn "shfmt could not be installed"
        fi
        case ":$PATH:" in *":${HOME}/.local/bin:"*) ;; *) export PATH="${HOME}/.local/bin:$PATH" ;; esac
    fi

    if ! ((DRY_RUN)) && ! python_version_ok; then
        log_err "Python ${PYTHON_MIN_VERSION}+ is required"
        exit 1
    fi

    # Git hooks (only inside a git checkout)
    log_info ""
    log_info "Setting up pre-commit hooks..."
    if ! git -C "$SCRIPT_DIR" rev-parse --git-dir >/dev/null 2>&1; then
        log_warn "$SCRIPT_DIR is not a git checkout - skipping hook installation"
    elif ((DRY_RUN)); then
        echo "  Would run: pre-commit install --hook-type pre-commit --hook-type commit-msg"
    elif (cd "$SCRIPT_DIR" && pre-commit install --hook-type pre-commit --hook-type commit-msg >/dev/null); then
        log_ok "Pre-commit and commit-msg hooks installed"
    else
        log_warn "Pre-commit hook installation failed"
    fi

    # Verification
    log_info ""
    log_info "Verification..."
    local success=1
    for spec in "${FEDORA_TOOLS[@]}"; do
        verify_tool "${spec%%:*}" "${spec#*:}" || success=0
    done
    verify_tool shfmt "shfmt" || success=0

    log_info ""
    if ((DRY_RUN)); then
        log_info "Dry run complete - nothing was installed."
    elif ((success)); then
        log_ok "Development environment ready!"
        log_info ""
        log_info "Next steps:"
        log_info "  1. Run the test suite:  ./tests/run-suite.sh"
        log_info "  2. Quick check:         ./test-in-podman.sh --quick --dry-run"
        log_info "  3. Read DEVELOPMENT.md for the full workflow"
    else
        log_warn "Setup finished with missing tools (see above)."
        exit 1
    fi
}

main "$@"
