#!/usr/bin/env bash
# test-in-podman.sh - Run fedora-harden.sh in a minimal, resource-efficient podman container
#
# Usage:
#   # Full system test with systemd (slower, more realistic)
#   ./test-in-podman.sh
#
#   # Quick logic test without systemd (faster, lower resource usage)
#   ./test-in-podman.sh --quick
#
#   # Dry-run test (safest for testing)
#   ./test-in-podman.sh --dry-run
#
#   # Custom options
#   ./test-in-podman.sh --memory 256m --cpus 1 --dry-run
#
# Resource defaults:
#   - Memory: 512 MB (can be reduced to 256 MB for quick tests)
#   - CPUs: 2 (can be reduced to 1 for quick tests)
#   - No swap (prevents OOM thrashing)

set -Eeuo pipefail

# Configuration
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
SCRIPT_NAME="$(basename "$0")"
IMAGE_TAG="fedora-harden:test"
IMAGE_TAG_QUICK="fedora-harden:test-only"
CONTAINER_NAME="fedora-harden-test-$$"
MEMORY_LIMIT="512m"
CPU_LIMIT="2"
VARIANT="full"
DRY_RUN=0
INTERACTIVE=0
RUN_SECTION=""
EXTRA_ARGS=()

# Color output
C_RED=$'\033[0;31m'
C_GRN=$'\033[0;32m'
C_YEL=$'\033[0;33m'
C_BLU=$'\033[0;34m'
C_RST=$'\033[0m'

# Helper functions
log_info() { printf '%s[ℹ]%s %s\n' "$C_BLU" "$C_RST" "$*"; }
log_ok()   { printf '%s[✓]%s %s\n' "$C_GRN" "$C_RST" "$*"; }
log_warn() { printf '%s[⚠]%s %s\n' "$C_YEL" "$C_RST" "$*"; }
log_err()  { printf '%s[✗]%s %s\n' "$C_RED" "$C_RST" "$*"; }

usage() {
    cat <<'EOF'
Run fedora-harden.sh in a minimal podman container for testing

USAGE:
    test-in-podman.sh [OPTIONS]

OPTIONS:
    --quick              Ultra-minimal test without systemd (fastest, ~256 MB)
    --dry-run            Test with --dry-run flag (no changes made)
    --interactive, -it   Run interactive shell in container
    --list-sections      List available hardening sections
    --only <section#>    Run only specific section (e.g., --only 5,7,10)
    --skip <section#>    Skip sections (e.g., --skip 12,19)
    --memory <size>      Set memory limit (default: 512m, try 256m for quick)
    --cpus <n>           Set CPU limit (default: 2, try 1 for minimal)
    --no-build           Skip building image, use existing
    --help               Show this help

EXAMPLES:
    # Fast test without systemd (good for CI/automated testing)
    ./test-in-podman.sh --quick --dry-run

    # Full system test in dry-run mode
    ./test-in-podman.sh --dry-run

    # Test section 5 (firewalld) with minimal resources
    ./test-in-podman.sh --quick --only 5

    # Run interactive shell to manually test
    ./test-in-podman.sh --quick -it

    # Full test with 256 MB memory (minimal systems)
    ./test-in-podman.sh --memory 256m --dry-run

EOF
    exit "${1:-0}"
}

# Parse arguments
while (( $# > 0 )); do
    case "$1" in
        --quick)         VARIANT="quick"; MEMORY_LIMIT="256m"; CPU_LIMIT="1"; shift ;;
        --dry-run)       DRY_RUN=1; shift ;;
        -it|--interactive) INTERACTIVE=1; shift ;;
        --list-sections) EXTRA_ARGS+=(--list); shift ;;
        --only)          RUN_SECTION="$2"; EXTRA_ARGS+=(--only "$2"); shift 2 ;;
        --skip)          EXTRA_ARGS+=(--skip "$2"); shift 2 ;;
        --memory)        MEMORY_LIMIT="$2"; shift 2 ;;
        --cpus)          CPU_LIMIT="$2"; shift 2 ;;
        --no-build)      SKIP_BUILD=1; shift ;;
        -h|--help)       usage 0 ;;
        *)               log_err "Unknown option: $1"; usage 1 ;;
    esac
done

# Select image tag based on variant
if [[ "$VARIANT" == "quick" ]]; then
    IMAGE_TAG="$IMAGE_TAG_QUICK"
    log_info "Using quick (no-systemd) variant for faster testing"
else
    log_info "Using full variant with systemd"
fi

# Step 1: Build container image if needed
if [[ "${SKIP_BUILD:-0}" == 0 ]]; then
    log_info "Building container image: $IMAGE_TAG"
    log_info "This may take 1-2 minutes on first run (cached after that)..."

    if podman build -f "$SCRIPT_DIR/Dockerfile.test" \
        --target "$([ "$VARIANT" = "quick" ] && echo "test-only" || echo "base")" \
        -t "$IMAGE_TAG" "$SCRIPT_DIR" >/dev/null 2>&1; then
        log_ok "Container image built successfully"
    else
        log_err "Failed to build container image"
        exit 1
    fi
fi

# Step 2: Prepare podman run command
log_info "Starting container: $CONTAINER_NAME"
log_info "Resource limits: memory=$MEMORY_LIMIT, cpus=$CPU_LIMIT"

# Build base podman run command with resource constraints
PODMAN_CMD=(
    podman run
    --rm
    --name "$CONTAINER_NAME"
    # Resource limits for efficiency
    --memory "$MEMORY_LIMIT"
    --memory-swap "$MEMORY_LIMIT"  # Prevent swapping (faster, more predictable)
    --cpus "$CPU_LIMIT"
    --pids-limit 1024  # Prevent resource exhaustion from fork bombs
    # Storage limits (prevent container from filling disk)
    --storage-opt size=5G
    # Security (rootless-friendly)
    --cap-drop=ALL
    --cap-add=DAC_OVERRIDE
    --cap-add=SETFCAP
    --cap-add=NET_ADMIN
    # Mounts
    --volume "$SCRIPT_DIR/fedora-harden.sh:/root/fedora-harden.sh:ro"
    --volume "/tmp/fedora-harden-test-$$:/var/log/fedora-harden:rw"
    --volume "/tmp/fedora-harden-backups-$$:/root/harden-backups:rw"
)

# Add interactive flag if requested
if (( INTERACTIVE )); then
    PODMAN_CMD+=(-it)
    IMAGE_TAG_TO_USE="$IMAGE_TAG"
    # Interactive mode: just drop into shell
    podman run "${PODMAN_CMD[@]}" "$IMAGE_TAG_TO_USE" /bin/bash
    exit $?
fi

# Step 3: Run the hardening script
if [[ "$VARIANT" == "quick" ]]; then
    # Quick variant: run script directly without systemd
    log_info "Running fedora-harden.sh (--quick mode)"
    PODMAN_CMD+=(--entrypoint=/root/fedora-harden.sh)
    SCRIPT_ARGS=(--yes)  # Auto-assume yes for testing
    (( DRY_RUN )) && SCRIPT_ARGS+=(--dry-run)
    SCRIPT_ARGS+=("${EXTRA_ARGS[@]}")

    if podman run "${PODMAN_CMD[@]}" "$IMAGE_TAG" "${SCRIPT_ARGS[@]}" 2>&1 | tee "/tmp/fedora-harden-test-$$.log"; then
        log_ok "Test completed successfully"
        EXIT_CODE=0
    else
        EXIT_CODE=$?
        log_warn "Test completed with exit code: $EXIT_CODE"
    fi
else
    # Full variant: run with systemd (more realistic but slower)
    log_info "Running fedora-harden.sh (full systemd mode)"
    log_warn "Note: Full variant is slower but more realistic. Use --quick for fast CI testing."

    # Create a wrapper script to run inside container
    WRAPPER_SCRIPT="/tmp/fedora-harden-wrapper-$$.sh"
    cat > "$WRAPPER_SCRIPT" <<'WRAPPER_EOF'
#!/bin/bash
set -Eeuo pipefail

# Wait for systemd to start
sleep 2

# Run the hardening script
SCRIPT_ARGS=(--yes)
[[ "${DRY_RUN:-0}" == "1" ]] && SCRIPT_ARGS+=(--dry-run)

# Add any extra arguments (sections, etc.)
if [[ -n "${RUN_SECTION:-}" ]]; then
    SCRIPT_ARGS+=(--only "$RUN_SECTION")
fi

# Run script with logging
if /root/fedora-harden.sh "${SCRIPT_ARGS[@]}" 2>&1 | tee /var/log/fedora-harden/test.log; then
    echo "✓ Test completed"
    exit 0
else
    EXIT_CODE=$?
    echo "⚠ Test completed with exit code: $EXIT_CODE"
    exit "$EXIT_CODE"
fi
WRAPPER_EOF
    chmod +x "$WRAPPER_SCRIPT"

    # Mount wrapper script and run
    PODMAN_CMD+=(--volume "$WRAPPER_SCRIPT:/root/test-wrapper.sh:ro")

    if podman run "${PODMAN_CMD[@]}" "$IMAGE_TAG" /root/test-wrapper.sh 2>&1 | tee "/tmp/fedora-harden-test-$$.log"; then
        log_ok "Test completed successfully"
        EXIT_CODE=0
    else
        EXIT_CODE=$?
        log_warn "Test completed with exit code: $EXIT_CODE"
    fi

    rm -f "$WRAPPER_SCRIPT"
fi

# Step 4: Collect and display results
log_info "Test artifacts:"
log_info "  Script log: /tmp/fedora-harden-test-$$.log"
log_info "  Hardening log: /tmp/fedora-harden-test-$$/harden-*.log"
log_info "  Session reports: /tmp/fedora-harden-test-$$/sessions/"

# Cleanup
rm -rf "/tmp/fedora-harden-test-$$" "/tmp/fedora-harden-backups-$$"

exit "${EXIT_CODE:-0}"
