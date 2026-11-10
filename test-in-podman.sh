#!/usr/bin/env bash
# test-in-podman.sh - Run fedora-harden.sh in an isolated, resource-limited podman container
#
# Usage:
#   ./test-in-podman.sh --dry-run            # systemd container, no changes made
#   ./test-in-podman.sh --quick --dry-run    # no-systemd container (fastest)
#   ./test-in-podman.sh                      # REAL run inside a throwaway systemd container
#   ./test-in-podman.sh --quick -it          # interactive shell
#
# The working-tree fedora-harden.sh is bind-mounted read-only into the container.
# Logs and session reports are written to a host artifact directory that is kept
# after the run (path printed at the end) so they can be inspected.

set -Eeuo pipefail

# Configuration
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
IMAGE_TAG_FULL="localhost/fedora-harden:test"
IMAGE_TAG_QUICK="localhost/fedora-harden:test-only"
CONTAINER_NAME="fedora-harden-test-$$"
MEMORY_LIMIT="1g"
CPU_LIMIT="2"
VARIANT="full"
DRY_RUN=0
INTERACTIVE=0
KEEP_CONTAINER=0
SKIP_BUILD=0
LIST_ONLY=0
ARTIFACT_DIR="${ARTIFACT_DIR:-}"
EXTRA_ARGS=()
CONTAINER_STARTED=0

# Color output (only when stdout is a terminal)
if [[ -t 1 ]]; then
    C_RED=$'\033[0;31m' C_GRN=$'\033[0;32m' C_YEL=$'\033[0;33m' C_BLU=$'\033[0;34m' C_RST=$'\033[0m'
else
    C_RED="" C_GRN="" C_YEL="" C_BLU="" C_RST=""
fi

log_info() { printf '%s[ℹ]%s %s\n' "$C_BLU" "$C_RST" "$*"; }
log_ok() { printf '%s[✓]%s %s\n' "$C_GRN" "$C_RST" "$*"; }
log_warn() { printf '%s[⚠]%s %s\n' "$C_YEL" "$C_RST" "$*"; }
log_err() { printf '%s[✗]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; }

usage() {
    cat <<'EOF'
Run fedora-harden.sh in an isolated podman container for testing

USAGE:
    test-in-podman.sh [OPTIONS]

OPTIONS:
    --quick              No-systemd container (fastest; services cannot start)
    --dry-run            Pass --dry-run to the script (no changes made)
    --interactive, -it   Open an interactive shell in the container instead
    --list-sections      List available hardening sections and exit
    --only <list>        Run only these sections (e.g. --only 5,7,10)
    --skip <list>        Skip these sections (e.g. --skip 12,19)
    --memory <size>      Memory limit (default: 1g; quick default: 256m)
    --cpus <n>           CPU limit (default: 2; quick default: 1)
    --artifacts <dir>    Host directory for logs/session reports (default: mktemp)
    --keep               Keep the container after the run (for inspection)
    --no-build           Skip building the image, use the existing one
    --help               Show this help

Without --dry-run the script makes REAL changes — but only inside the
throwaway container, never on the host.

EXAMPLES:
    ./test-in-podman.sh --quick --dry-run
    ./test-in-podman.sh --dry-run --only 5,7,10
    ./test-in-podman.sh --artifacts ./out
    ./test-in-podman.sh --quick -it
EOF
    exit "${1:-0}"
}

need_arg() {
    if [[ -z "${2:-}" || "${2}" == -* ]]; then
        log_err "Option $1 requires an argument"
        usage 2
    fi
}

# Parse arguments
MEMORY_SET=0
CPUS_SET=0
while (($# > 0)); do
    case "$1" in
        --quick)
            VARIANT="quick"
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -it | --interactive)
            INTERACTIVE=1
            shift
            ;;
        --list-sections)
            LIST_ONLY=1
            shift
            ;;
        --only | --skip)
            need_arg "$1" "${2:-}"
            EXTRA_ARGS+=("$1" "$2")
            shift 2
            ;;
        --memory)
            need_arg "$1" "${2:-}"
            MEMORY_LIMIT="$2" MEMORY_SET=1
            shift 2
            ;;
        --cpus)
            need_arg "$1" "${2:-}"
            CPU_LIMIT="$2" CPUS_SET=1
            shift 2
            ;;
        --artifacts)
            need_arg "$1" "${2:-}"
            ARTIFACT_DIR="$2"
            shift 2
            ;;
        --keep)
            KEEP_CONTAINER=1
            shift
            ;;
        --no-build)
            SKIP_BUILD=1
            shift
            ;;
        -h | --help) usage 0 ;;
        *)
            log_err "Unknown option: $1"
            usage 2
            ;;
    esac
done

if ! command -v podman >/dev/null 2>&1; then
    log_err "podman not found — install it with: sudo dnf install podman"
    exit 1
fi

if [[ "$VARIANT" == "quick" ]]; then
    IMAGE_TAG="$IMAGE_TAG_QUICK"
    BUILD_TARGET="test-only"
    ((MEMORY_SET)) || MEMORY_LIMIT="256m"
    ((CPUS_SET)) || CPU_LIMIT="1"
    log_info "Using quick (no-systemd) variant"
else
    IMAGE_TAG="$IMAGE_TAG_FULL"
    BUILD_TARGET="base"
    log_info "Using full variant with systemd as PID 1"
fi

# shellcheck disable=SC2329  # invoked via trap
cleanup() {
    if ((CONTAINER_STARTED && !KEEP_CONTAINER)); then
        podman rm -f -t 5 "$CONTAINER_NAME" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# Step 1: Build container image if needed
if ((!SKIP_BUILD)); then
    log_info "Building container image: $IMAGE_TAG (target: $BUILD_TARGET)"
    build_log="$(mktemp "${TMPDIR:-/tmp}/fedora-harden-build.XXXXXX.log")"
    if podman build -f "$SCRIPT_DIR/Dockerfile.test" --target "$BUILD_TARGET" \
        -t "$IMAGE_TAG" "$SCRIPT_DIR" >"$build_log" 2>&1; then
        log_ok "Container image built"
        rm -f "$build_log"
    else
        log_err "Failed to build container image — last lines of $build_log:"
        tail -n 20 "$build_log" >&2
        exit 1
    fi
elif ! podman image exists "$IMAGE_TAG"; then
    log_err "Image $IMAGE_TAG not found (remove --no-build to build it)"
    exit 1
fi

# Step 2: Artifact directory (kept after the run)
if [[ -z "$ARTIFACT_DIR" ]]; then
    ARTIFACT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/fedora-harden-test.XXXXXX")"
fi
mkdir -p "$ARTIFACT_DIR/logs" "$ARTIFACT_DIR/sessions"
ARTIFACT_DIR="$(cd -- "$ARTIFACT_DIR" && pwd -P)"

# Common podman options. Rootless podman maps container root to the invoking user, so
# the container cannot modify the host even though the script runs as "root" inside.
RUN_OPTS=(
    --name "$CONTAINER_NAME"
    --hostname fedora-harden-test
    --memory "$MEMORY_LIMIT"
    --memory-swap "$MEMORY_LIMIT"
    --cpus "$CPU_LIMIT"
    --pids-limit 2048
    --volume "$SCRIPT_DIR/fedora-harden.sh:/root/fedora-harden.sh:ro,z"
    --volume "$ARTIFACT_DIR/logs:/var/log/fedora-harden:rw,z"
    --volume "$ARTIFACT_DIR/sessions:/root/sessions:rw,z"
)

SCRIPT_ARGS=(--yes)
((DRY_RUN)) && SCRIPT_ARGS+=(--dry-run)
SCRIPT_ARGS+=("${EXTRA_ARGS[@]}")
((LIST_ONLY)) && SCRIPT_ARGS=(--list)

log_info "Container: $CONTAINER_NAME  (memory=$MEMORY_LIMIT, cpus=$CPU_LIMIT)"
((DRY_RUN)) || ((LIST_ONLY)) || ((INTERACTIVE)) ||
    log_warn "REAL run (no --dry-run): changes are applied inside the throwaway container only."

OUTPUT_LOG="$ARTIFACT_DIR/output.log"
EXIT_CODE=0

if [[ "$VARIANT" == "quick" ]]; then
    if ((INTERACTIVE)); then
        exec podman run --rm -it "${RUN_OPTS[@]}" --entrypoint /bin/bash "$IMAGE_TAG"
    fi
    log_info "Running: fedora-harden.sh ${SCRIPT_ARGS[*]}"
    CONTAINER_STARTED=1
    podman run "${RUN_OPTS[@]}" --entrypoint /root/fedora-harden.sh \
        "$IMAGE_TAG" "${SCRIPT_ARGS[@]}" </dev/null 2>&1 | tee "$OUTPUT_LOG" || EXIT_CODE=${PIPESTATUS[0]}
    podman diff "$CONTAINER_NAME" >"$ARTIFACT_DIR/fs-diff.txt" 2>/dev/null || true
else
    log_info "Booting systemd container..."
    # NET_ADMIN lets firewalld manage nftables inside the container's own network
    # namespace (rootless podman: it grants nothing on the host).
    podman run -d --systemd=always --cap-add NET_ADMIN,NET_RAW "${RUN_OPTS[@]}" "$IMAGE_TAG" >/dev/null
    CONTAINER_STARTED=1

    # Wait for systemd to finish booting ("degraded" is normal inside a container).
    state=""
    for _ in $(seq 1 60); do
        state="$(podman exec "$CONTAINER_NAME" systemctl is-system-running 2>/dev/null || true)"
        [[ "$state" == "running" || "$state" == "degraded" ]] && break
        sleep 1
    done
    log_info "systemd state: ${state:-unknown}"

    if ((INTERACTIVE)); then
        podman exec -it "$CONTAINER_NAME" /bin/bash || true
        exit 0
    fi

    log_info "Running: fedora-harden.sh ${SCRIPT_ARGS[*]}"
    podman exec "$CONTAINER_NAME" /root/fedora-harden.sh "${SCRIPT_ARGS[@]}" \
        </dev/null 2>&1 | tee "$OUTPUT_LOG" || EXIT_CODE=${PIPESTATUS[0]}

    podman exec "$CONTAINER_NAME" journalctl --no-pager -b >"$ARTIFACT_DIR/journal.log" 2>&1 || true
    podman exec "$CONTAINER_NAME" systemctl --failed --no-pager >"$ARTIFACT_DIR/failed-units.txt" 2>&1 || true
    podman diff "$CONTAINER_NAME" >"$ARTIFACT_DIR/fs-diff.txt" 2>/dev/null || true
fi

# Step 3: Results
if ((EXIT_CODE == 0)); then
    log_ok "Script exited 0"
else
    log_warn "Script exited with code $EXIT_CODE"
fi
log_info "Artifacts (kept): $ARTIFACT_DIR"
log_info "  output.log     — console output"
log_info "  logs/          — harden-*.log and *-errors.log"
log_info "  sessions/      — session reports"
log_info "  fs-diff.txt    — files changed inside the container"
((KEEP_CONTAINER)) && log_info "Container kept: podman exec -it $CONTAINER_NAME bash"

exit "$EXIT_CODE"
