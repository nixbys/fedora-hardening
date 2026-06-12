#!/usr/bin/env bash
# setup-dev.sh - Initialize development environment for fedora-harden.sh
# This script installs all necessary tools for efficient development

set -Eeuo pipefail

# Colors
C_RED=$'\033[0;31m'
C_GRN=$'\033[0;32m'
C_YEL=$'\033[0;33m'
C_BLU=$'\033[0;34m'
C_RST=$'\033[0m'

# Functions
log_info() { printf '%s[ℹ]%s %s\n' "$C_BLU" "$C_RST" "$*"; }
log_ok()   { printf '%s[✓]%s %s\n' "$C_GRN" "$C_RST" "$*"; }
log_warn() { printf '%s[⚠]%s %s\n' "$C_YEL" "$C_RST" "$*"; }
log_err()  { printf '%s[✗]%s %s\n' "$C_RED" "$C_RST" "$*"; }

# Configuration
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
PYTHON_MIN_VERSION="3.8"
SKIP_OPTIONAL=0
DRY_RUN=0

# Parse arguments
while (( $# > 0 )); do
    case "$1" in
        --skip-optional) SKIP_OPTIONAL=1; shift ;;
        --dry-run)       DRY_RUN=1; shift ;;
        --help)          show_help; exit 0 ;;
        *)               log_err "Unknown option: $1"; show_help; exit 1 ;;
    esac
done

show_help() {
    cat <<EOF
Setup development environment for fedora-hardening project

USAGE:
    ./setup-dev.sh [OPTIONS]

OPTIONS:
    --skip-optional    Skip optional tools
    --dry-run         Show what would be installed
    --help            Show this help

WHAT IT INSTALLS:
    Core tools (required):
    - Python 3.8+ (for development tools)
    - Git (version control)
    - Podman (container runtime)
    - Bash (script runtime)

    Development tools:
    - pre-commit (commit hooks)
    - shellcheck (shell script linting)
    - shfmt (shell script formatting)
    - yamllint (YAML validation)
    - hadolint (Dockerfile linting)
    - commitizen (commit message validation)

    Optional:
    - MCP SDK (for Claude integration)

EOF
}

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "${ID:-unknown}"
    else
        uname -s | tr '[:upper:]' '[:lower:]'
    fi
}

# Check if command exists
cmd_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install package (OS-specific)
install_package() {
    local pkg="$1"
    local os="$2"

    case "$os" in
        fedora)
            log_info "Installing $pkg with dnf..."
            if (( DRY_RUN )); then
                echo "  Would run: sudo dnf install -y $pkg"
            else
                sudo dnf install -y "$pkg"
            fi
            ;;
        ubuntu|debian)
            log_info "Installing $pkg with apt..."
            if (( DRY_RUN )); then
                echo "  Would run: sudo apt-get install -y $pkg"
            else
                sudo apt-get install -y "$pkg"
            fi
            ;;
        arch)
            log_info "Installing $pkg with pacman..."
            if (( DRY_RUN )); then
                echo "  Would run: sudo pacman -S $pkg"
            else
                sudo pacman -S "$pkg"
            fi
            ;;
        *)
            log_warn "Unknown OS: $os - Please install $pkg manually"
            return 1
            ;;
    esac
}

# Main setup
main() {
    log_info "Fedora Hardening - Development Environment Setup"
    log_info "=================================================="

    local os
    os="$(detect_os)"
    log_info "Detected OS: $os"

    # Check Python version
    if cmd_exists python3; then
        local py_version
        py_version="$(python3 --version | awk '{print $2}')"
        log_ok "Python 3 found: $py_version"
    else
        log_err "Python 3 not found"
        log_info "Installing Python 3..."
        install_package "python3" "$os"
    fi

    # Core requirements
    log_info ""
    log_info "Checking core requirements..."

    local tools=(
        "bash:Bash shell"
        "git:Git version control"
        "podman:Container runtime"
    )

    for tool_spec in "${tools[@]}"; do
        local tool="${tool_spec%%:*}"
        local desc="${tool_spec##*:}"

        if cmd_exists "$tool"; then
            log_ok "$desc: installed"
        else
            log_warn "$desc: not found"
            log_info "Installing $tool..."
            install_package "$tool" "$os"
        fi
    done

    # Development tools with pip
    log_info ""
    log_info "Installing Python development tools..."

    local py_tools=(
        "pre-commit"
        "shellcheck-py"
        "yamllint"
        "commitizen"
    )

    if (( DRY_RUN )); then
        echo "  Would run: pip install ${py_tools[*]}"
    else
        if pip install "${py_tools[@]}" >/dev/null 2>&1; then
            log_ok "Development tools installed"
        else
            log_warn "Some tools failed to install - trying individually"
            for tool in "${py_tools[@]}"; do
                if pip install "$tool" >/dev/null 2>&1; then
                    log_ok "  $tool: installed"
                else
                    log_warn "  $tool: installation failed"
                fi
            done
        fi
    fi

    # Optional tools
    if (( !SKIP_OPTIONAL )); then
        log_info ""
        log_info "Installing optional tools..."

        # hadolint (for Dockerfile)
        if ! cmd_exists hadolint; then
            log_info "Installing hadolint..."
            if (( DRY_RUN )); then
                echo "  Would download hadolint from GitHub"
            else
                local hado_url="https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64"
                if command -v wget >/dev/null; then
                    sudo wget -qO /usr/local/bin/hadolint "$hado_url"
                    sudo chmod +x /usr/local/bin/hadolint
                    log_ok "hadolint installed"
                else
                    log_warn "wget not found - skipping hadolint"
                fi
            fi
        fi

        # MCP SDK (optional)
        log_info "Installing MCP SDK (optional)..."
        if (( DRY_RUN )); then
            echo "  Would run: pip install mcp"
        else
            if pip install mcp >/dev/null 2>&1; then
                log_ok "MCP SDK installed"
            else
                log_warn "MCP SDK installation failed (optional, not critical)"
            fi
        fi
    fi

    # Setup pre-commit hooks
    log_info ""
    log_info "Setting up pre-commit hooks..."
    if (( DRY_RUN )); then
        echo "  Would run: pre-commit install"
        echo "  Would run: pre-commit install --hook-type commit-msg"
    else
        if cd "$SCRIPT_DIR" && pre-commit install >/dev/null 2>&1; then
            log_ok "Pre-commit hooks installed"
        else
            log_warn "Pre-commit installation failed"
        fi

        if pre-commit install --hook-type commit-msg >/dev/null 2>&1; then
            log_ok "Commit message hooks installed"
        else
            log_warn "Commit message hook installation failed"
        fi
    fi

    # Verification
    log_info ""
    log_info "Verification..."
    local success=1

    verify_tool "bash" "Bash" || success=0
    verify_tool "git" "Git" || success=0
    verify_tool "podman" "Podman" || success=0
    verify_tool "python3" "Python 3" || success=0

    if cmd_exists pre-commit; then
        log_ok "Pre-commit: available"
    else
        log_warn "Pre-commit: not available"
        success=0
    fi

    if cmd_exists shellcheck; then
        log_ok "Shellcheck: available"
    else
        log_warn "Shellcheck: not available"
        success=0
    fi

    # Final summary
    log_info ""
    if (( success )); then
        log_ok "Development environment ready!"
        log_info ""
        log_info "Next steps:"
        log_info "  1. Run tests: ./test-in-podman.sh --quick --dry-run"
        log_info "  2. Make changes and commit: git commit -m 'fix: description'"
        log_info "  3. Read DEVELOPMENT.md for full workflow guide"
        log_info ""
        log_info "MCP Server (optional):"
        log_info "  python3 mcp_server_fedora_harden.py"
    else
        log_warn "Setup complete with some warnings. See above for details."
        log_info ""
        log_info "You can still develop, but some tools may not work optimally."
        log_info "Install missing tools manually if needed."
    fi
}

verify_tool() {
    local cmd="$1"
    local name="$2"

    if cmd_exists "$cmd"; then
        log_ok "$name: available"
        return 0
    else
        log_warn "$name: not found"
        return 1
    fi
}

# Run main
main "$@"
