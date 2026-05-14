#!/usr/bin/env bash
# =============================================================================
#  Fedora 44+ Security Hardening Script (multi-release + desktop aware)
#  Based on: Fedora44-KDE-Security-Hardening-Guide.md (April 2026)
#  Efficiency-tuned and low-I/O focused (v1.9 - May 2026)
#
#  FEATURES:
#    • 21 hardening sections with automatic release/profile detection
#    • Dual-mode support: mutable (dnf) and immutable (rpm-ostree) systems
#    • Fedora release detection: Workstation, Server, IoT, Cloud, CoreOS,
#      Kinoite, Silverblue, and Atomic desktop variants
#    • Firefox Flatpak hardening with arkenfox + 4 security extensions
#    • Comprehensive error handling (EXIT/ERR traps + resource cleanup)
#    • Performance optimized: 4 caching layers, batched operations, smart waits
#    • Session-level memoization: command, package, user home, and rpm-ostree pending layer
#    • Automatic feature gating based on system capabilities
#    • Dependency self-healing for required commands/packages (best effort)
#    • Idempotent Flatpak installs: skip if latest, update if stale, soft-fail
#    • Idempotent rpm-ostree layering: skips already-requested staged packages
#    • Safe firewalld service registration: auto-creates missing custom service XML
#    • Graceful startup privilege confirmation (sudo/root context)
#    • Approval-gated remediation with selective item implementation
#    • Audit PDF/TXT export for later import and deferred remediation
#    • Structured error log capture for post-run analysis and remediation loops
#    • rpm-ostree-aware Fail2Ban setup (defers activation safely until reboot)
#    • Deterministic command exit-code capture (set -e safe for rpm-ostree and firewall-cmd)
#    • Comprehensive file operation error handling (chmod, chown, cp, install, sed safe)
#
#  USAGE:
#    sudo ./fedora-harden.sh [options]
#
#  OPTIONS:
#    -u, --user <name>      Target username for SSH/chage/home-dir hardening
#    -y, --yes              Assume "yes" to all prompts (non-interactive)
#    -n, --dry-run          Print what would run; make no changes
#        --gui              Enable graphical prompts (kdialog/zenity) when available
#        --gui-full         Full windowed frontend: GUI progress + GUI status output
#        --import-audit <p> Import a generated audit PDF/TXT and choose items later
#        --skip <list>      Comma-separated sections to skip (e.g. 7,8,17)
#        --only <list>      Comma-separated sections to run exclusively
#        --list             List all section numbers & names and exit
#    -h, --help             Show this help and exit
#
#  SECTIONS (execution order optimized for dependency flow):
#     2  System updates
#     3  Automatic updates (dnf5-automatic or rpm-ostreed)
#     4  SELinux verification + tools
#     5  firewalld hardening (drop-default policy)
#     6  Secure Boot verification (GRUB password is manual — printed as a note)
#     7  SSH hardening (key-based auth, hardened cipher suite)
#     8  USBGuard (interactive — can lock out input devices if misconfigured)
#     9  Password & PAM policy (pwquality, faillock, account aging)
#    10  Kernel sysctl hardening (network, VM, filesystem protections)
#    11  auditd rules (identity, privilege escalation, kernel module tracking)
#    12  rkhunter + AIDE (rootkit detection + file integrity monitoring)
#    13  Flatpak / Flathub (app sandboxing foundation)
#    14  DNS over TLS (systemd-resolved with Quad9 + Cloudflare)
#    15  KDE-specific CLI settings (screen lock, Bluetooth, recent documents)
#    16  Firefox Flatpak + arkenfox + extensions (uBlock, Privacy Badger, etc.)
#    17  WireGuard tool install (tunnel config is manual)
#    18  Fail2Ban (intrusion detection + auto-ban)
#    19  Disable unnecessary services (avahi, cups, bluetooth, modemmanager)
#    20  File permission hardening (shadow files, /tmp, compiler access)
#    21  ClamAV install + freshclam (antivirus engine + signature updates)
#    22  OpenSCAP scanner install + initial scan (compliance framework)
#
#  SECTIONS NOT AUTOMATED (by design):
#     1  LUKS — must be chosen during Anaconda install
#     6b GRUB password — requires interactive grub2-mkpasswd-pbkdf2
#    15  KDE GUI-only screens (Privacy, KWallet master password, Activity tracking)
#    17  WireGuard tunnel config (requires peer keys & endpoint configuration)
#    23  Ongoing maintenance checklist (scheduled human task)
#
#  PLATFORM SUPPORT:
#    ✓ Fedora Workstation (mutable, dnf)
#    ✓ Fedora Server (mutable, dnf)
#    ✓ Fedora IoT (immutable, rpm-ostree)
#    ✓ Fedora Cloud (mutable images/variants)
#    ✓ Fedora CoreOS (immutable, rpm-ostree)
#    ✓ Fedora Kinoite (immutable, rpm-ostree + KDE)
#    ✓ Fedora Silverblue (immutable, rpm-ostree)
#    Auto-detection: Reads /etc/os-release metadata + /run/ostree-booted
#    Desktop detection: session and installed tooling/packages (KDE/GNOME/Sway)
#
#  PERFORMANCE OPTIMIZATIONS:
#    • Caching layers: command availability, package status, user home dirs
#    • Batched I/O: multi-pattern sed in single pass
#    • Smart waits: firewalld readiness backoff instead of fixed sleeps
#    • Package pre-checks: avoid redundant package status queries
#    • Flatpak update-state check (flatpak resolver, no download): skip already-current apps
#    • Safe arithmetic counters: pre-increment (++ x) avoids set -e false exits
#    • Resource cleanup: EXIT trap guarantees /tmp cleanup
#    • Session run stamp reuse for report/log/backup naming
#
#  ERROR HANDLING:
#    • EXIT trap: Cleans up all temporary files on script exit
#    • ERR trap: Logs line number + failing command context + exit code
#    • Resource safety: Guaranteed cleanup of /tmp operations
#    • Fallback strategies: curl → wget, plus best-effort dependency install
#    • Audit workflow: PDF/TXT export on decline, later import via --import-audit
#
# =============================================================================

set -Eeuo pipefail

# ---------- Globals ---------------------------------------------------------
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
PROJECT_NAME="$(basename "$SCRIPT_DIR")"
RUN_STAMP="$(date +%Y%m%d-%H%M%S)"
RUN_DATE_YMD="${RUN_STAMP%%-*}"
RUN_STAMP_HUMAN="${RUN_STAMP/-/ }"
RUN_STAMP_ISO=""
HOST_LABEL=""
KERNEL_LABEL=""
LOG_DIR="/var/log/fedora-harden"
LOG_FILE="${LOG_DIR}/harden-${RUN_STAMP}.log"
BACKUP_DIR="/root/harden-backups-${RUN_STAMP}"

printf -v RUN_STAMP_ISO '%(%Y-%m-%dT%H:%M:%S%z)T' -1 2>/dev/null || RUN_STAMP_ISO="$(date -Iseconds)"
HOST_LABEL="${HOSTNAME:-}"
if [[ -z "$HOST_LABEL" && -r /etc/hostname ]]; then
    IFS= read -r HOST_LABEL </etc/hostname || true
fi
if [[ -z "$HOST_LABEL" && -r /proc/sys/kernel/hostname ]]; then
    IFS= read -r HOST_LABEL </proc/sys/kernel/hostname || true
fi
[[ -z "$HOST_LABEL" ]] && HOST_LABEL="unknown"
if [[ -r /proc/sys/kernel/osrelease ]]; then
    IFS= read -r KERNEL_LABEL </proc/sys/kernel/osrelease || true
fi
[[ -z "$KERNEL_LABEL" ]] && KERNEL_LABEL="$(uname -r 2>/dev/null || echo unknown)"

TARGET_USER=""
ASSUME_YES=0
DRY_RUN=0
SKIP_LIST=""
ONLY_LIST=""
IMPORT_AUDIT_PATH=""
FORCE_GUI=0
FORCE_GUI_FULL=0
GUI_MODE=0
GUI_FULL_MODE=0
GUI_TOOL=""
GUI_PROGRESS_REF=""
GUI_PROGRESS_PIPE_FD=""
GUI_PROGRESS_PID=""
GUI_LAST_STATUS=""
GUI_CANCEL_REQUESTED=0
LOG_READY=0
PRECHECK_FAILED=0
EXPECTED_ABORT=0
IS_OSTREE=0
IS_KINOITE=0
IS_SILVERBLUE=0
IS_SERVER=0
IS_WORKSTATION=0
IS_IOT=0
IS_CLOUD=0
IS_COREOS=0
IS_ATOMIC_DESKTOP=0
IS_FEDORA=0
HAS_KDE=0
HAS_GNOME=0
HAS_DESKTOP=0
DESKTOP_ENVS=""
FEDORA_VARIANT="unknown"
FEDORA_MAJOR=0
UI_SECTION_DONE=0
UI_SECTION_TOTAL=21

# Error tracking & remediation infrastructure
ERROR_LOG=""                                # Structured error log file path
ERROR_CAPTURE_FILE=""                       # Temp file for capturing command stderr
declare -ga ERROR_DETAILS=()                # Array: "line|cmd|exit_code|stderr|timestamp"
declare -gi LAST_ERROR_COUNT=0              # Track errors for remediation loop
declare -gi REMEDIATION_PASS=0              # Current pass through remediation
declare -gi MAX_REMEDIATION_PASSES=3        # Max auto-remediation attempts
                                             # Prevents infinite loops; persistent errors typically need manual intervention
LAST_RUN_CMD=""                             # Last command dispatched via run()

# ---------- Report / Actionable-items globals --------------------------------
declare -ga ACTIONABLE_ITEMS=()
declare -ga REMEDIATED_ITEMS=()
declare -ga SELECTED_ACTIONABLE_ITEMS=()
declare -ga DEFERRED_ACTIONABLE_ITEMS=()
USER_DOWNLOADS_DIR=""
USER_PROJECT_DIR=""
USER_RESULTS_DIR=""
USER_LOGS_DIR=""
REPORT_DATE="$RUN_STAMP"
declare -ga TEMP_FILES=()          # All temp paths to auto-clean on EXIT

# Colors (disabled if not a tty)
if [[ -t 1 ]]; then
    C_RED=$'\033[0;31m'; C_GRN=$'\033[0;32m'; C_YEL=$'\033[0;33m'
    C_BLU=$'\033[0;34m'; C_CYN=$'\033[0;36m'; C_BLD=$'\033[1m'; C_RST=$'\033[0m'
else
    C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_CYN=""; C_BLD=""; C_RST=""
fi

# draw_banner() - Render startup banner for improved terminal readability.
# Uses concise host/date metadata so long runs are easier to track at a glance.
draw_banner() {
    printf '\n%s╔══════════════════════════════════════════════════════════════╗%s\n' "$C_CYN" "$C_RST"
    printf '%s║%s Fedora Hardening Orchestrator                              %s║%s\n' "$C_CYN" "$C_BLD" "$C_CYN" "$C_RST"
    local who
    who="${SUDO_USER:-${USER:-root}}"
    printf '%s║%s %s@%s  %s                                        %s║%s\n' \
        "$C_CYN" "$C_RST" "$who" "$HOST_LABEL" "$RUN_STAMP_HUMAN" "$C_CYN" "$C_RST"
    printf '%s╚══════════════════════════════════════════════════════════════╝%s\n' "$C_CYN" "$C_RST"
}

# progress_bar() - Build a fixed-width textual progress bar.
# Usage: progress_bar <current> <total> [width]
progress_bar() {
    local current="$1" total="$2" width="${3:-28}"
    (( total <= 0 )) && total=1
    (( current < 0 )) && current=0
    (( current > total )) && current=total
    local filled=$(( current * width / total ))
    local empty=$(( width - filled ))
    printf '['
    printf '%*s' "$filled" '' | tr ' ' '#'
    printf '%*s' "$empty" '' | tr ' ' '-'
    printf ']'
}

# setup_ui_mode() - Configure GUI prompt mode if requested and available.
# Prefers kdialog on KDE systems, then zenity, otherwise falls back to TTY prompts.
setup_ui_mode() {
    local has_display=0
    local prefers_kde=0
    [[ -n "${DISPLAY:-}" || -n "${WAYLAND_DISPLAY:-}" ]] && has_display=1
    [[ "${XDG_CURRENT_DESKTOP:-}${DESKTOP_SESSION:-}" =~ [Kk][Dd][Ee]|[Pp]lasma ]] && prefers_kde=1

    # If GUI mode is requested, try to satisfy missing GUI dialog dependencies.
    if (( has_display && (FORCE_GUI || FORCE_GUI_FULL) )); then
        if (( prefers_kde )); then
            cmd_exists kdialog || ensure_command_dep kdialog "GUI dialog mode" kdialog
        fi
        if ! cmd_exists kdialog; then
            cmd_exists zenity || ensure_command_dep zenity "GUI dialog fallback" zenity
        fi
    fi

    if (( has_display )) && cmd_exists kdialog; then
        GUI_TOOL="kdialog"
    elif (( has_display )) && cmd_exists zenity; then
        GUI_TOOL="zenity"
    fi

    if (( FORCE_GUI )); then
        if [[ -n "$GUI_TOOL" ]]; then
            GUI_MODE=1
            info "GUI mode enabled using $GUI_TOOL dialogs."
        else
            GUI_MODE=0
            warn "--gui requested, but no supported GUI dialog tool was found. Falling back to terminal prompts."
            warn "Install 'kdialog' (KDE) or 'zenity' (GTK) to use GUI prompts."
        fi
    fi

    if (( FORCE_GUI_FULL )); then
        FORCE_GUI=1
        if [[ -n "$GUI_TOOL" ]]; then
            if [[ "$GUI_TOOL" == "kdialog" ]]; then
                cmd_exists qdbus || ensure_command_dep qdbus "kdialog full progress mode" qt6-qttools qt5-qttools
            fi
            GUI_MODE=1
            GUI_FULL_MODE=1
            info "Full GUI frontend enabled using $GUI_TOOL."
        else
            GUI_MODE=0
            GUI_FULL_MODE=0
            warn "--gui-full requested, but no supported GUI dialog tool was found. Falling back to terminal output."
            warn "Install 'kdialog' or 'zenity' and rerun with --gui-full."
        fi
    fi
}

# calc_section_total() - Estimate number of sections that will run for progress display.
# Uses current --only/--skip filters against the fixed execution plan.
calc_section_total() {
    local planned=(2 3 6 13 4 5 7 9 10 11 14 18 15 16 17 21 22 12 19 20 8)
    local s n=0
    for s in "${planned[@]}"; do
        [[ -n "$ONLY_LIST" ]] && ! in_list "$s" "$ONLY_LIST" && continue
        [[ -n "$SKIP_LIST" ]] && in_list "$s" "$SKIP_LIST" && continue
        (( ++n ))
    done
    (( n > 0 )) && UI_SECTION_TOTAL="$n" || UI_SECTION_TOTAL="${#planned[@]}"
    UI_SECTION_DONE=0
}

# gui_alert() - Show concise GUI notifications for summary and fatal errors.
# Usage: gui_alert <info|warning|error> <message>
gui_alert() {
    local level="$1" message="$2"
    (( GUI_MODE )) || return 0
    case "$GUI_TOOL" in
        kdialog)
            case "$level" in
                info) kdialog --title "$SCRIPT_NAME" --msgbox "$message" ;;
                warning) kdialog --title "$SCRIPT_NAME" --sorry "$message" ;;
                error) kdialog --title "$SCRIPT_NAME" --error "$message" ;;
            esac
            ;;
        zenity)
            case "$level" in
                info) zenity --info --title="$SCRIPT_NAME" --text="$message" --width=460 ;;
                warning) zenity --warning --title="$SCRIPT_NAME" --text="$message" --width=460 ;;
                error) zenity --error --title="$SCRIPT_NAME" --text="$message" --width=460 ;;
            esac
            ;;
    esac
}

# prompt_input() - Request free-form input from user in GUI or terminal mode.
# Usage: prompt_input <prompt> [default_value]
prompt_input() {
    local prompt="$1" default_value="${2:-}" value=""

    if (( GUI_MODE )); then
        case "$GUI_TOOL" in
            kdialog)
                value="$(kdialog --title "$SCRIPT_NAME" --inputbox "$prompt" "$default_value" 2>/dev/null || true)"
                ;;
            zenity)
                value="$(zenity --entry --title="$SCRIPT_NAME" --text="$prompt" --entry-text="$default_value" --width=520 2>/dev/null || true)"
                ;;
        esac
    else
        read -r -p "$(printf '%s[??]%s  %s ' "$C_YEL" "$C_RST" "$prompt")" value || true
    fi

    printf '%s' "$value"
}

# gui_progress_start() - Start full-GUI progress stream with minimal I/O overhead.
gui_progress_start() {
    (( GUI_FULL_MODE )) || return 0

    case "$GUI_TOOL" in
        kdialog)
            if cmd_exists qdbus; then
                GUI_PROGRESS_REF="$(kdialog --title "$SCRIPT_NAME" --progressbar "Initializing hardening..." "$UI_SECTION_TOTAL")"
                if [[ -n "$GUI_PROGRESS_REF" ]]; then
                    qdbus "$GUI_PROGRESS_REF" showCancelButton true >/dev/null 2>&1 || true
                    qdbus "$GUI_PROGRESS_REF" setLabelText "Preparing section execution..." >/dev/null 2>&1 || true
                    qdbus "$GUI_PROGRESS_REF" Set "" value 0 >/dev/null 2>&1 || true
                fi
            else
                warn "qdbus not found; kdialog progress updates are limited."
            fi
            ;;
        zenity)
            coproc GUI_ZENITY_PROGRESS {
                zenity --progress \
                    --title="$SCRIPT_NAME" \
                    --text="Preparing section execution..." \
                    --percentage=0 \
                    --auto-close \
                    --width=640
            }
            GUI_PROGRESS_PIPE_FD="${GUI_ZENITY_PROGRESS[1]:-}"
            GUI_PROGRESS_PID="$COPROC_PID"
            ;;
    esac
}

# gui_progress_update() - Stream progress updates directly to GUI widgets.
# Usage: gui_progress_update <current> <total> <message>
gui_progress_update() {
    local current="$1" total="$2" message="$3"
    (( GUI_FULL_MODE )) || return 0
    (( total <= 0 )) && total=1
    (( current < 0 )) && current=0
    (( current > total )) && current=total
    local pct=$(( current * 100 / total ))
    GUI_LAST_STATUS="$message"

    case "$GUI_TOOL" in
        kdialog)
            [[ -n "$GUI_PROGRESS_REF" ]] || return 0
            if cmd_exists qdbus && [[ "$(qdbus "$GUI_PROGRESS_REF" wasCancelled 2>/dev/null || echo false)" == "true" ]]; then
                GUI_CANCEL_REQUESTED=1
                return 0
            fi
            qdbus "$GUI_PROGRESS_REF" Set "" value "$current" >/dev/null 2>&1 || true
            qdbus "$GUI_PROGRESS_REF" setLabelText "$message" >/dev/null 2>&1 || true
            ;;
        zenity)
            [[ -n "$GUI_PROGRESS_PIPE_FD" ]] || return 0
            if ! printf '%s\n# %s\n' "$pct" "$message" >&"$GUI_PROGRESS_PIPE_FD" 2>/dev/null; then
                GUI_CANCEL_REQUESTED=1
            fi
            ;;
    esac
}

# gui_progress_close() - Gracefully close full-GUI progress resources.
gui_progress_close() {
    (( GUI_FULL_MODE )) || return 0

    case "$GUI_TOOL" in
        kdialog)
            if [[ -n "$GUI_PROGRESS_REF" ]]; then
                qdbus "$GUI_PROGRESS_REF" close >/dev/null 2>&1 || true
                GUI_PROGRESS_REF=""
            fi
            ;;
        zenity)
            if [[ -n "$GUI_PROGRESS_PIPE_FD" ]]; then
                exec {GUI_PROGRESS_PIPE_FD}>&- || true
                GUI_PROGRESS_PIPE_FD=""
            fi
            if [[ -n "$GUI_PROGRESS_PID" ]]; then
                wait "$GUI_PROGRESS_PID" 2>/dev/null || true
                GUI_PROGRESS_PID=""
            fi
            ;;
    esac
}

# gui_status_event() - Route status messages to GUI widgets without file polling.
# Usage: gui_status_event <info|ok|warning|error> <message>
gui_status_event() {
    local level="$1" message="$2"
    (( GUI_FULL_MODE )) || return 0

    case "$level" in
        info|ok)
            gui_progress_update "$UI_SECTION_DONE" "$UI_SECTION_TOTAL" "$message"
            ;;
        warning)
            gui_progress_update "$UI_SECTION_DONE" "$UI_SECTION_TOTAL" "$message"
            gui_alert warning "$message"
            ;;
        error)
            gui_progress_update "$UI_SECTION_DONE" "$UI_SECTION_TOTAL" "$message"
            gui_alert error "$message"
            ;;
    esac
}

# gui_check_cancel() - Poll for GUI cancel requests across supported frontends.
gui_check_cancel() {
    (( GUI_FULL_MODE )) || return 1
    (( GUI_CANCEL_REQUESTED )) && return 0

    case "$GUI_TOOL" in
        kdialog)
            if cmd_exists qdbus && [[ -n "$GUI_PROGRESS_REF" ]] && [[ "$(qdbus "$GUI_PROGRESS_REF" wasCancelled 2>/dev/null || echo false)" == "true" ]]; then
                GUI_CANCEL_REQUESTED=1
                return 0
            fi
            ;;
    esac
    return 1
}

# abort_if_cancelled() - Gracefully terminate when user cancels from GUI frontend.
abort_if_cancelled() {
    if gui_check_cancel; then
        err "Execution cancelled by user from GUI frontend."
        exit 130
    fi
}

# ---------- Logging helpers -------------------------------------------------
# init_log_target() - Ensure log destination exists, with /tmp fallback when needed.
init_log_target() {
    (( LOG_READY )) && return 0

    local d
    d="${LOG_FILE%/*}"
    if mkdir -p "$d" 2>/dev/null && : >>"$LOG_FILE" 2>/dev/null; then
        chmod 640 "$LOG_FILE" 2>/dev/null || true
        LOG_READY=1
    else
        LOG_FILE="/tmp/${SCRIPT_NAME%.*}-${RUN_STAMP}.log"
        : >>"$LOG_FILE" 2>/dev/null || return 1
        chmod 640 "$LOG_FILE" 2>/dev/null || true
        LOG_READY=1
    fi
    
    # Initialize error log with same base directory
    if (( LOG_READY )); then
        ERROR_LOG="${LOG_FILE%.log}-errors.log"
        : >>"$ERROR_LOG" 2>/dev/null || ERROR_LOG="/tmp/$(basename "$LOG_FILE" .log)-errors.log"
        chmod 640 "$ERROR_LOG" 2>/dev/null || true
        
        # Create temp file for capturing stderr from commands
        ERROR_CAPTURE_FILE="/tmp/fedora-harden-stderr-$$.tmp"
        register_tmp "$ERROR_CAPTURE_FILE"
    fi
    return 0
}

# log() - Write timestamped message to persistent log file for audit trail.
# All log entries are appended with date/time for complete audit history.
# Usage: log "message text"
log() {
    init_log_target || return 0
    local ts
    printf -v ts '%(%F %T)T' -1 2>/dev/null || ts="$(date '+%F %T')"
    printf '%s %s\n' "$ts" "$*" >> "$LOG_FILE" 2>/dev/null || true
}

# info() - Write informational message to stdout and log (blue color).
# Used for status updates and intermediate steps.
# Usage: info "message text"
info() {
    (( ! GUI_FULL_MODE )) && printf '%s[INFO]%s  %s\n' "$C_BLU" "$C_RST" "$*"
    log "[INFO]  $*"
    gui_status_event info "$*"
}

# ok() - Write success message to stdout and log (green color).
# Indicates successful completion of a task or verification.
# Usage: ok "message text"
ok() {
    (( ! GUI_FULL_MODE )) && printf '%s[ OK ]%s  %s\n' "$C_GRN" "$C_RST" "$*"
    log "[OK]    $*"
    gui_status_event ok "$*"
}

# warn() - Write warning message to stdout and log (yellow color).
# Alerts about non-critical issues, skipped steps, or prerequisites.
# Usage: warn "message text"
warn() {
    (( ! GUI_FULL_MODE )) && printf '%s[WARN]%s  %s\n' "$C_YEL" "$C_RST" "$*"
    log "[WARN]  $*"
    gui_status_event warning "$*"
}

# err() - Write error message to stderr and log (red color).
# Indicates a problem that may prevent further execution.
# Usage: err "message text"
err() {
    (( ! GUI_FULL_MODE )) && printf '%s[FAIL]%s  %s\n' "$C_RED" "$C_RST" "$*" >&2
    log "[ERROR] $*"
    gui_status_event error "$*"
}

# capture_error_context() - Log detailed error information including command, exit code, and stderr.
# Stores structured error data for later analysis and automatic remediation.
# Called by trap_err and soft-fail handlers to capture full error context.
# Usage: capture_error_context <line> <cmd> <exit_code> [stderr_file]
capture_error_context() {
    local line="$1" cmd="$2" ec="$3" stderr_file="${4:-}"
    local ts stderr_content
    
    init_log_target || return 0
    ts=$(date '+%F %T') || ts="(date failed)"
    
    # Read stderr if captured in file
    if [[ -n "$stderr_file" && -f "$stderr_file" ]]; then
        stderr_content=$(<"$stderr_file")
        stderr_content="${stderr_content//\"/\\\"}"  # Escape quotes
        stderr_content="${stderr_content//$'\n'/ | }"  # Replace newlines with |
    else
        stderr_content="(no stderr captured)"
    fi
    
    # Store as: "line|cmd|exit_code|stderr|timestamp"
    ERROR_DETAILS+=("${line}|${cmd}|${ec}|${stderr_content}|${ts}")
    
    # Write to structured error log
    {
        printf '{"timestamp":"%s","line":%d,"exit_code":%d,"command":"%s","stderr":"%s"}\n' \
            "$ts" "$line" "$ec" "${cmd//\"/\\\"}" "$stderr_content"
    } >> "$ERROR_LOG" 2>/dev/null || true
    
    log "[DEBUG] Error at line $line: cmd='$cmd' exit=$ec"
}

# section() - Print formatted section header with visual divider and log entry.
# Displays section number and title with colored borders for visual clarity.
# All section headers are logged for audit trail with timestamps.
# Usage: section <number> <title...>
section(){
    abort_if_cancelled
    local n="$1"; shift
    (( ++UI_SECTION_DONE ))
    local pct=$(( UI_SECTION_DONE * 100 / UI_SECTION_TOTAL ))
    local pb
    pb="$(progress_bar "$UI_SECTION_DONE" "$UI_SECTION_TOTAL" 28)"
    if (( ! GUI_FULL_MODE )); then
        printf '\n%s══════════════════════════════════════════════════════════════%s\n' "$C_CYN" "$C_RST"
        printf '%s Section %s: %s%s\n' "$C_BLD" "$n" "$*" "$C_RST"
        printf '%s Progress:%s %s %d/%d (%d%%)\n' "$C_BLU" "$C_RST" "$pb" "$UI_SECTION_DONE" "$UI_SECTION_TOTAL" "$pct"
        printf '%s══════════════════════════════════════════════════════════════%s\n' "$C_CYN" "$C_RST"
    fi
    gui_progress_update "$UI_SECTION_DONE" "$UI_SECTION_TOTAL" "Section $n: $*"
    log "==== Section $n: $* ===="
}

# run() - Execute shell command or simulate execution in --dry-run mode.
# In dry-run mode, logs the command for preview without executing it.
# All commands are logged to audit file regardless of execution.
# Captures stderr from failed commands for later error analysis and remediation.
# Usage: run "command" "with" "args"
run() {
    abort_if_cancelled
    LAST_RUN_CMD="$*"
    if (( DRY_RUN )); then
        (( ! GUI_FULL_MODE )) && printf '%s[DRY ]%s  %s\n' "$C_YEL" "$C_RST" "$*"
        (( GUI_FULL_MODE )) && gui_status_event info "DRY RUN: $*"
        log "[DRY]   $*"
        return 0
    fi
    log "[RUN]   $*"
    # shellcheck disable=SC2294
    local rc=0
    if (( GUI_FULL_MODE )); then
        : >"$ERROR_CAPTURE_FILE" 2>/dev/null || true
        eval "$@" >>"$LOG_FILE" 2>>"$ERROR_CAPTURE_FILE" || rc=$?
    else
        # Capture stderr for error analysis
        : >"$ERROR_CAPTURE_FILE" 2>&1
        eval "$@" 2>>"$ERROR_CAPTURE_FILE" || rc=$?
    fi
    # Log stderr if command failed (applies to GUI and non-GUI modes).
    if (( rc != 0 )) && [[ -f "$ERROR_CAPTURE_FILE" && -s "$ERROR_CAPTURE_FILE" ]]; then
        log "[STDERR] $*"
        local line
        while IFS= read -r line; do
            log "[STDERR]   $line"
        done <"$ERROR_CAPTURE_FILE"
        capture_error_context "${BASH_LINENO[0]}" "$*" "$rc" "$ERROR_CAPTURE_FILE"
    fi
    return "$rc"
}

# have_cmd() - Check if a command exists in PATH.
# Returns 0 (success) if command is available, 1 (failure) otherwise.
# Usage: have_cmd <command_name>
have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

# pkg_upgrade() - Upgrade system packages using appropriate mechanism for platform.
# On immutable systems (rpm-ostree), changes are staged for next reboot.
# On mutable systems, updates are applied immediately via dnf.
pkg_upgrade() {
    if (( IS_OSTREE )); then
        run "rpm-ostree upgrade"
        warn "rpm-ostree upgrades are applied on reboot. Reboot when this script completes."
    else
        run "dnf upgrade --refresh -y"
    fi
}

# _load_ostree_staged_packages() - Populate _PKG_PENDING_CACHE from the live rpm-ostree
# staged/pending layer (runs once per script execution).  Prevents "Package X is already
# requested" errors when pkg_install is called after a prior run that layered packages
# but the system has not yet been rebooted.
_OSTREE_STAGED_LOADED=0
_load_ostree_staged_packages() {
    (( _OSTREE_STAGED_LOADED )) && return 0
    (( IS_OSTREE )) || return 0
    _OSTREE_STAGED_LOADED=1
    local pkg
    # Parse LayeredPackages tokens in one awk pass to avoid extra sed/tr/grep forks.
    while IFS= read -r pkg; do
        [[ -n "$pkg" ]] && _PKG_PENDING_CACHE[$pkg]=1
    done < <(
        local out rc=0
        out=$(rpm-ostree status 2>&1) || rc=$?
        if (( rc != 0 )); then
            warn "Failed to query rpm-ostree staged packages"
            return 1
        fi
        echo "$out" | awk '
            /LayeredPackages:/ {
                sub(/.*LayeredPackages:[[:space:]]*/, "", $0)
                for (i=1; i<=NF; i++) {
                    if ($i !~ /^\(/) print $i
                }
            }
        '
    )
}

# pkg_install() - Install packages via appropriate package manager (skips if already cached).
# Automatically selects dnf for mutable systems or rpm-ostree for immutable.
# Skips already-installed packages using cache to reduce redundant operations.
# On rpm-ostree systems, also checks the live staged/pending layer so that packages
# queued in a prior run (before reboot) are not re-requested, preventing the
# "Package X is already requested" error.
# Honors --dry-run in both mutable and immutable code paths.
# Usage: pkg_install <package1> [package2] ...
pkg_install() {
    local pkgs=("$@") needed=() pkg
    (( ${#pkgs[@]} == 0 )) && return 0

    # On rpm-ostree, pre-load staged packages so we don't re-request them.
    (( IS_OSTREE )) && _load_ostree_staged_packages

    # Filter already-cached/installed packages from install list (caching optimization)
    for pkg in "${pkgs[@]}"; do
        # On rpm-ostree, skip packages already queued (this run or a prior pending layer).
        if (( IS_OSTREE )) && [[ "${_PKG_PENDING_CACHE[$pkg]:-0}" -eq 1 ]]; then
            info "Package '${pkg}' already in rpm-ostree pending layer — skipping."
            continue
        fi
        pkg_cached "$pkg" || needed+=("$pkg")
    done

    (( ${#needed[@]} == 0 )) && { info "All packages already installed (cached)."; return 0; }

    if (( DRY_RUN )); then
        if (( IS_OSTREE )); then
            info "Would run: rpm-ostree install ${needed[*]}"
        else
            info "Would run: dnf install -y ${needed[*]}"
        fi
        return 0
    fi

    if (( IS_OSTREE )); then
        local out rc
        log "[RUN]   rpm-ostree install ${needed[*]}"
        # Capture output and exit code without triggering set -e abort on failure
        out="$(rpm-ostree install "${needed[@]}" 2>&1)" || rc=$?
        rc=${rc:-0}
        [[ -n "${out}" ]] && printf '%s\n' "$out" >>"$LOG_FILE"

        if (( rc != 0 )); then
            # Idempotent rpm-ostree no-op cases should not abort under strict mode.
            if [[ "$out" =~ already[[:space:]]requested|already[[:space:]]provided|No[[:space:]]packages[[:space:]]in[[:space:]]transaction|is[[:space:]]already[[:space:]]provided ]]; then
                warn "rpm-ostree reports package(s) already queued/provided; treating as up-to-date."
            else
                capture_error_context "${BASH_LINENO[0]:-?}" "rpm-ostree install ${needed[*]}" "$rc" "/dev/null" || true
                return "$rc"
            fi
        fi

        # Mark requested packages as pending to avoid redundant layering attempts this run.
        for pkg in "${needed[@]}"; do
            _PKG_PENDING_CACHE[$pkg]=1
        done
        warn "Layered packages are applied on reboot. Reboot when this script completes."
    else
        run "dnf install -y ${needed[*]}"
        # Keep package cache coherent after successful mutable-system installs.
        for pkg in "${needed[@]}"; do
            _PKG_CACHE[$pkg]=0
        done
        # New binaries may now exist; refresh command cache.
        unset _CMD_CACHE
        declare -gA _CMD_CACHE=()
    fi
}

# install_dep_candidates() - Best-effort install of dependency package candidates.
# Attempts each package and continues even if one candidate fails.
install_dep_candidates() {
    local pkg attempted=0
    (( DRY_RUN )) && { info "Would install dependency package(s): $*"; return 0; }
    for pkg in "$@"; do
        [[ -z "$pkg" ]] && continue
        attempted=1
        pkg_install "$pkg" || true
    done
    (( attempted )) && return 0
    return 1
}

# flatpak_install_or_update() - Idempotent Flatpak install/update (never aborts the script).
# • Already installed and up-to-date  → skip (uses flatpak's own resolver, no download).
# • Already installed, update available → flatpak update on origin remote (soft-fail).
# • Not installed                       → flatpak install (soft-fail; queues
#   an action item on failure so the user is notified without script abort).
# Up-to-date detection uses `flatpak update --no-pull` (checks locally cached remote
# metadata without any network I/O) instead of raw commit-hash comparison.  Commit hashes
# from `flatpak info --show-commit` and `flatpak remote-info --show-commit` use different
# SHA representations and never match even when the app is current, which caused a false
# "update available" → no-op update loop on every run.
# Usage: flatpak_install_or_update <remote> <app-id>
flatpak_install_or_update() {
    local remote="$1" app_id="$2"

    if (( DRY_RUN )); then
        info "Would ensure Flatpak ${app_id} from ${remote} is installed and up-to-date."
        return 0
    fi

    if flatpak info "${app_id}" &>/dev/null; then
        # Resolve the actual origin remote the app was installed from.
        local origin update_check
        origin=$(flatpak info --show-origin "${app_id}" 2>/dev/null || true)
        origin="${origin:-${remote}}"
        # Delegate the up-to-date check to flatpak's own resolver rather than comparing
        # raw commit hashes.  The installed object-store commit and remote-metadata commit
        # use different SHA representations and will never match even when the app is
        # current, causing an endless "update available" → no-op update loop.
        # --no-pull checks against the locally cached remote metadata (no download).
        update_check=$(flatpak update --no-pull -y "${app_id}" 2>&1 || true)
        if [[ "${update_check}" =~ ([Nn]othing[[:space:]]to[[:space:]]update|[Uu]p[[:space:]]to[[:space:]]date|[Nn]othing[[:space:]]to[[:space:]]do) ]]; then
            info "Flatpak ${app_id}: already up-to-date (${origin}) — skipping."
            return 0
        fi
        info "Flatpak ${app_id}: update available (${origin}) — updating."
        flatpak update -y "${app_id}" 2>/dev/null || \
            warn "Flatpak update of ${app_id} failed — will retry next run."
        return 0
    fi

    info "Flatpak ${app_id}: not installed — installing from ${remote}."
    if ! flatpak install -y "${remote}" "${app_id}" 2>/dev/null; then
        warn "Flatpak ${app_id} install failed."
        add_action_item "13" "MEDIUM" \
            "FLATPAK_INSTALL_FAILED_${app_id//[^a-zA-Z0-9]/_}" \
            "Flatpak ${app_id} could not be installed automatically — run: flatpak install ${remote} ${app_id}"
    fi
}

# ensure_command_dep() - Ensure command exists, attempting package install if missing.
# Usage: ensure_command_dep <command> <reason> <pkg1> [pkg2 ...]
ensure_command_dep() {
    local cmd="$1" reason="$2"
    shift 2
    cmd_exists "$cmd" && return 0

    warn "Missing dependency '$cmd' required for: $reason"
    if (( EUID != 0 )); then
        warn "Cannot auto-install '$cmd' without root privileges."
        return 1
    fi
    (( $# > 0 )) || return 1

    local pkg
    for pkg in "$@"; do
        info "Attempting to install '$pkg' for missing command '$cmd'..."
        install_dep_candidates "$pkg"
        unset "_CMD_CACHE[$cmd]" 2>/dev/null || true
        if cmd_exists "$cmd"; then
            ok "Dependency resolved: '$cmd'"
            return 0
        fi
    done

    warn "Dependency '$cmd' is still unavailable after install attempts."
    return 1
}

# download_file() - Download file from URL (with smart tool selection and error handling).
# Tries curl first (preferred), falls back to wget. Returns 0 on success, 1 on failure.
# Usage: download_file <url> <destination_path>
download_file() {
    local url="$1" dest="$2"
    local dest_dir="${dest%/*}"
    
    # Ensure destination directory exists before attempting download
    if [[ "$dest_dir" != "$dest" && ! -d "$dest_dir" ]]; then
        if ! install -d -m 700 "$dest_dir" 2>/dev/null; then
            err "Cannot create destination directory: $dest_dir"
            return 1
        fi
    fi
    
    if ! cmd_exists curl && ! cmd_exists wget; then
        ensure_command_dep curl "download operations" curl
        cmd_exists curl || ensure_command_dep wget "download operations fallback" wget
    fi
    if cmd_exists curl; then
        run "curl -fsSL '$url' -o '$dest' 2>/dev/null" && return 0
    fi
    if cmd_exists wget; then
        run "wget -qO '$dest' '$url' 2>/dev/null" && return 0
    fi
    err "Neither curl nor wget is available; cannot download $url"
    return 1
}

# user_home() - Retrieve home directory for specified local user (cached for this session).
# Caches results to avoid repeated /etc/passwd lookups.
# Usage: user_home <username>
declare -gA _USER_HOME_CACHE=()  # Session cache for user home dirs
user_home() {
    local user="$1"
    if [[ -v _USER_HOME_CACHE[$user] ]]; then
        echo "${_USER_HOME_CACHE[$user]}"
        return 0
    fi
    local entry home
    entry="$(getent passwd "$user" 2>/dev/null || true)"
    home="${entry#*:*:*:*:*:}"
    [[ "$home" == "$entry" ]] && home=""
    _USER_HOME_CACHE[$user]="$home"
    echo "$home"
}

# confirm() - Prompt user for yes/no confirmation (respects --yes flag).
# Returns 0 (success) for 'y'/'yes' response, 1 (failure) for 'n'/'no' or default.
# In --yes mode, automatically assumes affirmative response.
# Usage: confirm ["prompt text"]
confirm() {
    local prompt="${1:-Continue?}"
    if (( ASSUME_YES )); then
        info "Auto-yes: $prompt"
        return 0
    fi

    if (( GUI_MODE )); then
        case "$GUI_TOOL" in
            kdialog)
                kdialog --title "$SCRIPT_NAME" --yesno "$prompt"
                return $?
                ;;
            zenity)
                zenity --question --title="$SCRIPT_NAME" --text="$prompt" --width=480
                return $?
                ;;
        esac
    fi

    local reply
    read -r -p "$(printf '%s[??]%s  %s [y/N] ' "$C_YEL" "$C_RST" "$prompt")" reply
    [[ "$reply" =~ ^[Yy]([Ee][Ss])?$ ]]
}

# backup_file() - Create backup of file in designated backup directory.
# Creates directory structure if needed; uses mode 0700 for restricted access.
# All backups are organized by timestamp in /root/harden-backups-YYYYMMDD-HHMMSS/
# Usage: backup_file <file_path>
backup_file() {
    local f="$1"
    if [[ -f "$f" ]]; then
        if [[ ! -r "$f" ]]; then
            warn "Cannot read $f for backup (permission denied); backup skipped"
            return 0
        fi
        run "install -d -m 700 '$BACKUP_DIR'" || { warn "Failed to create backup directory"; return 1; }
        run "cp -a --parents '$f' '$BACKUP_DIR/'" || { warn "Failed to backup $f"; return 1; }
        info "Backed up $f → $BACKUP_DIR"
    fi
}

# in_list() - Check if needle is present in comma-separated list.
# Returns 0 (success) if found, 1 (failure) if not found.
# Used for --skip and --only section filtering logic.
# Usage: in_list <needle> <comma,separated,list>
in_list() {
    [[ -z "$2" ]] && return 1
    local IFS=','; for item in $2; do [[ "$item" == "$1" ]] && return 0; done
    return 1
}

# batch_sed() - Apply multiple sed patterns in a single pass (more efficient).
# Reduces I/O overhead by batching replacements on same file.
# Usage: batch_sed <file> <pattern1> <pattern2> ...
batch_sed() {
    local f="$1"; shift
    if (( DRY_RUN )); then
        info "Would apply sed patterns to $f"
        return 0
    fi
    # Build combined -e flags for all patterns at once
    local args=()
    for pattern in "$@"; do
        args+=(-e "$pattern")
    done
    if ! sed -i "${args[@]}" "$f" 2>/dev/null; then
        warn "sed failed on $f (file may be read-only or missing)"
        return 1
    fi
}

# cmd_exists() - Fast check if command exists in PATH (cached for this session).
# Uses have_cmd() with zero overhead after first check.
# Usage: cmd_exists <command_name>
declare -gA _CMD_CACHE=()  # Session cache for command existence
cmd_exists() {
    local cmd="$1"
    if [[ -v _CMD_CACHE[$cmd] ]]; then
        return "${_CMD_CACHE[$cmd]}"
    fi
    if have_cmd "$cmd"; then
        _CMD_CACHE[$cmd]=0
        return 0
    else
        _CMD_CACHE[$cmd]=1
        return 1
    fi
}

# pkg_cached() - Check if package is already installed (cached for session).
# Avoids repeated rpm -q calls for the same package.
# Usage: pkg_cached <package_name>
declare -gA _PKG_CACHE=()  # Session cache for package status
declare -gA _PKG_PENDING_CACHE=()  # rpm-ostree pending/staged layer packages (pre-loaded from live status + current-run requests)
pkg_cached() {
    local pkg="$1"
    if [[ -v _PKG_CACHE[$pkg] ]]; then
        return "${_PKG_CACHE[$pkg]}"
    fi
    if rpm -q "$pkg" >/dev/null 2>&1; then
        _PKG_CACHE[$pkg]=0
        return 0
    else
        _PKG_CACHE[$pkg]=1
        return 1
    fi
}

# detect_fedora_release_type() - Classify Fedora release family from os-release metadata.
detect_fedora_release_type() {
    local release_blob
    release_blob="${NAME:-} ${PRETTY_NAME:-} ${VARIANT:-} ${VARIANT_ID:-} ${CPE_NAME:-} ${PLATFORM_ID:-} ${ID_LIKE:-}"
    release_blob="${release_blob,,}"

    [[ "$release_blob" == *"workstation"* ]] && IS_WORKSTATION=1
    [[ "$release_blob" == *"server"* ]] && IS_SERVER=1
    [[ "$release_blob" == *"kinoite"* ]] && IS_KINOITE=1
    [[ "$release_blob" == *"silverblue"* ]] && IS_SILVERBLUE=1
    [[ "$release_blob" == *"iot"* ]] && IS_IOT=1
    [[ "$release_blob" == *"cloud"* ]] && IS_CLOUD=1
    [[ "$release_blob" == *"coreos"* ]] && IS_COREOS=1

    # Fedora Atomic desktops include Kinoite/Silverblue and the named Atomic editions.
    if (( IS_KINOITE || IS_SILVERBLUE )) \
       || [[ "$release_blob" == *"atomic"* && "$release_blob" == *"fedora"* ]]; then
        IS_ATOMIC_DESKTOP=1
    fi
}

# detect_desktop_envs() - Detect active/installed desktop environments for feature gating.
detect_desktop_envs() {
    local detected=()
    local xdg_blob="${XDG_CURRENT_DESKTOP:-}:${DESKTOP_SESSION:-}"
    xdg_blob="${xdg_blob,,}"

    # Running session hints.
    if [[ "$xdg_blob" == *"kde"* || "$xdg_blob" == *"plasma"* ]]; then
        HAS_KDE=1
        [[ ",${detected[*]}," == *",kde,"* ]] || detected+=("kde")
    fi
    if [[ "$xdg_blob" == *"gnome"* ]]; then
        HAS_GNOME=1
        [[ ",${detected[*]}," == *",gnome,"* ]] || detected+=("gnome")
    fi
    if [[ "$xdg_blob" == *"sway"* ]]; then
        [[ ",${detected[*]}," == *",sway,"* ]] || detected+=("sway")
    fi

    # Installed desktop/tooling hints.
    if cmd_exists kwriteconfig6 || cmd_exists kwriteconfig5 || pkg_cached plasma-workspace; then
        HAS_KDE=1
        [[ ",${detected[*]}," == *",kde,"* ]] || detected+=("kde")
    fi
    if cmd_exists gnome-shell || pkg_cached gnome-shell || pkg_cached gnome-session; then
        HAS_GNOME=1
        [[ ",${detected[*]}," == *",gnome,"* ]] || detected+=("gnome")
    fi
    if cmd_exists sway || pkg_cached sway; then
        [[ ",${detected[*]}," == *",sway,"* ]] || detected+=("sway")
    fi

    (( HAS_KDE || HAS_GNOME || ${#detected[@]} > 0 )) && HAS_DESKTOP=1
    DESKTOP_ENVS="$(IFS=,; echo "${detected[*]}")"
}

# section_compatible() - Check if a section is compatible with current system.
# Evaluates release type, desktop presence, and platform capabilities to auto-skip safely.
# Examples: Section 15 (KDE) skips if !HAS_KDE; Section 16 skips if !HAS_DESKTOP
# Returns 0 (compatible) or 1 (incompatible/should skip).
# Usage: section_compatible <section_number>
section_compatible() {
    local s="$1"
    case "$s" in
        15)
            # Section 15 requires KDE/Plasma to be installed and available.
            if (( ! HAS_KDE )); then
                info "Skipping section 15: KDE/Plasma tooling is not installed on this host."
                return 1
            fi
            ;;
        16)
            # Section 16 is desktop-focused and should run if any desktop environment is installed.
            if (( ! HAS_DESKTOP )); then
                info "Skipping section 16: no desktop environment detected on this host."
                return 1
            fi
            ;;
        8)
            # Section 8 can interfere with remote access if USB input devices are not whitelisted.
            if (( IS_SERVER )) && (( ! ASSUME_YES )); then
                warn "Section 8 (USBGuard) can disrupt remote-only server access if input devices are blocked."
            fi
            ;;
    esac
    return 0
}

# should_run() - Determine whether a section should execute based on user options.
# Checks --only, --skip, and system compatibility before allowing execution.
# Provides early exit for filtered or incompatible sections to reduce overhead.
# Returns 0 (should run) or 1 (should skip).
# Usage: should_run <section_number>
should_run() {
    local s="$1"
    # Check --only flag: if set, only run sections in the list.
    if [[ -n "$ONLY_LIST" ]]; then
        in_list "$s" "$ONLY_LIST" || return 1
    fi
    # Check --skip flag: skip sections in the list.
    if [[ -n "$SKIP_LIST" ]] && in_list "$s" "$SKIP_LIST"; then
        info "Skipping section $s (per --skip)"
        return 1
    fi
    # Check system compatibility: skip if section incompatible with this platform.
    section_compatible "$s" || return 1
    return 0
}

# analyze_error_log() - Parse error log and identify patterns for auto-remediation.
# Populates LAST_ERROR_COUNT and emits categorized findings.
# Usage: analyze_error_log
analyze_error_log() {
    init_log_target || return 1
    LAST_ERROR_COUNT=0
    
    if [[ ! -f "$ERROR_LOG" ]]; then
        info "No errors logged — script executed cleanly."
        return 0
    fi
    
    local error_count=0 line
    local permission_errors=0 package_errors=0 service_errors=0 connection_errors=0
    
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        (( error_count++ ))
        
        # Pattern matching for auto-remediation categories
        if [[ "$line" =~ "Permission denied" || "$line" =~ "not in sudoers" ]]; then
            (( permission_errors++ ))
        elif [[ "$line" =~ "No such file or directory" || "$line" =~ "package.*not found" ]]; then
            (( package_errors++ ))
        elif [[ "$line" =~ "service.*not available" || "$line" =~ "Unit.*not found" ]]; then
            (( service_errors++ ))
        elif [[ "$line" =~ "Connection refused" || "$line" =~ "Network.*unreachable" ]]; then
            (( connection_errors++ ))
        fi
    done < "$ERROR_LOG"
    
    LAST_ERROR_COUNT=$error_count
    if (( error_count == 0 )); then
        ok "Error analysis: No errors found."
        return 0
    fi
    
    warn "Error analysis: Found $error_count error(s)"
    (( permission_errors > 0 )) && warn "  ↳ Permission issues: $permission_errors"
    (( package_errors > 0 )) && warn "  ↳ Package/file issues: $package_errors"
    (( service_errors > 0 )) && warn "  ↳ Service issues: $service_errors"
    (( connection_errors > 0 )) && warn "  ↳ Connection issues: $connection_errors"
    
    return 0
}

# auto_remediate_errors() - Attempt to fix common errors identified in log analysis.
# Handles permission fixes, missing files, service issues, and network problems.
# Usage: auto_remediate_errors
auto_remediate_errors() {
    init_log_target || return 1
    
    [[ ! -f "$ERROR_LOG" ]] && return 0
    (( ++REMEDIATION_PASS ))
    
    if (( REMEDIATION_PASS > MAX_REMEDIATION_PASSES )); then
        warn "Reached maximum remediation attempts ($MAX_REMEDIATION_PASSES); stopping auto-remediation."
        return 1
    fi
    
    warn "Starting auto-remediation pass $REMEDIATION_PASS of $MAX_REMEDIATION_PASSES..."
    
    # Fix 1: Log file permissions
    if [[ -f "$LOG_FILE" ]]; then
        chmod 640 "$LOG_FILE" 2>/dev/null || true
        chmod 640 "$ERROR_LOG" 2>/dev/null || true
    fi
    
    # Fix 2: Cached package status might be stale after failures
    unset _PKG_CACHE _CMD_CACHE 2>/dev/null || true
    declare -gA _PKG_CACHE=()
    declare -gA _CMD_CACHE=()
    info "Cleared package/command caches for fresh validation"
    
    # Fix 3: Re-initialize ostree staged packages cache
    _OSTREE_STAGED_LOADED=0
    
    # Fix 4: Check for permission-related errors and attempt fixes
    if grep -q "Permission denied\|not in sudoers" "$ERROR_LOG" 2>/dev/null; then
        warn "Detected permission errors — verifying EUID and sudo context..."
        if (( EUID != 0 )); then
            err "Still running as non-root (EUID=$EUID) — cannot remediate."
            return 1
        fi
        info "Running as root — permission errors may have been transient"
    fi
    
    # Fix 5: Check for missing package manager states
    if grep -q "rpm -q.*not installed\|dnf.*not found" "$ERROR_LOG" 2>/dev/null; then
        warn "Detected package lookup errors — refreshing package lists..."
        run "dnf check-update -q || rpm-ostree status >/dev/null" || true
    fi
    
    ok "Auto-remediation pass $REMEDIATION_PASS complete"
    return 0
}

# validate_and_remediate_loop() - Run analysis and remediation until resolved or max attempts.
# This implements the recursive fix loop: analyze → remediate → validate → repeat.
# Usage: validate_and_remediate_loop
validate_and_remediate_loop() {
    info "Starting error validation and remediation loop..."
    REMEDIATION_PASS=0
    LAST_ERROR_COUNT=0
    
    while (( REMEDIATION_PASS < MAX_REMEDIATION_PASSES )); do
        analyze_error_log
        local error_count=$LAST_ERROR_COUNT
        
        if (( error_count == 0 )); then
            ok "✓ All errors resolved after $REMEDIATION_PASS pass(es)"
            return 0
        fi
        
        auto_remediate_errors || break
    done
    
    if (( LAST_ERROR_COUNT > 0 )); then
        warn "Could not fully auto-remediate errors after $MAX_REMEDIATION_PASSES pass(es)"
        warn "Review logs for manual remediation: $LOG_FILE and $ERROR_LOG"
        return 1
    fi
    return 0
}

# trap_cleanup() - Emergency cleanup handler for EXIT/ERR traps.
# Removes temporary files and performs resource cleanup on script failure.
# This prevents /tmp pollution and ensures graceful shutdown.
trap_cleanup() {
    local rc=$?
    gui_progress_close || true
    # Clean all registered temp files (registered via register_tmp())
    local _f
    for _f in "${TEMP_FILES[@]}"; do
        [[ -f "$_f" ]] && rm -f "$_f"
    done
    
    # Ensure logs remain accessible for post-script analysis
    if [[ -f "$LOG_FILE" ]]; then
        chmod 640 "$LOG_FILE" 2>/dev/null || true
    fi
    if [[ -f "$ERROR_LOG" ]]; then
        chmod 640 "$ERROR_LOG" 2>/dev/null || true
    fi
    
    return "$rc"
}

# trap_err() - Error handler for ERR trap.
# Captures exit code + command context, logs with full detail, then exits.
# Usage: Called automatically on error via trap.
trap_err() {
    local rc=$? line=${BASH_LINENO[0]:-?}
    local cmd_ctx="${BASH_COMMAND:-${LAST_RUN_CMD:-script execution}}"
    if (( EXPECTED_ABORT )); then
        exit "$rc"
    fi
    trap_cleanup || true
    capture_error_context "$line" "$cmd_ctx" "$rc" "$ERROR_CAPTURE_FILE" 2>/dev/null || true
    err "Aborted at line $line (exit $rc). See log: $LOG_FILE"
    warn "Error details saved to: $ERROR_LOG"
    gui_alert error "Hardening aborted at line $line (exit $rc).\n\nSee logs:\n$LOG_FILE\n$ERROR_LOG"
    exit "$rc"
}
# Enable error and exit traps to catch unexpected failures and clean resources.
trap trap_cleanup EXIT
trap trap_err ERR

# ---------- Report helpers --------------------------------------------------
# add_action_item() - Register a finding for the post-run actionable list.
# Format stored in ACTIONABLE_ITEMS: "S<num>|<priority>|<tag>|<description>"
# Usage: add_action_item <section_num> <priority: HIGH|MEDIUM|LOW> <tag> <desc>
add_action_item() {
    ACTIONABLE_ITEMS+=("S${1}|${2}|${3}|${4}")
}

# register_tmp() - Track a temp file path for guaranteed cleanup on EXIT.
# Usage: register_tmp <path>
register_tmp() { TEMP_FILES+=("$1"); }

# get_user_downloads_dir() - Resolve target user's XDG Downloads directory.
get_user_downloads_dir() {
    local user="${TARGET_USER:-${SUDO_USER:-}}"
    [[ -z "$user" || "$user" == "root" ]] && return 1
    local home; home="$(user_home "$user")"
    [[ -z "$home" ]] && return 1
    local dl
    dl="$(sudo -u "$user" xdg-user-dir DOWNLOAD 2>/dev/null || true)"
    [[ -z "$dl" ]] && dl="${home}/Downloads"
    printf '%s' "$dl"
}

# init_user_report_dirs() - Create Downloads/<project>/results and logs with correct ownership.
init_user_report_dirs() {
    local user="${TARGET_USER:-${SUDO_USER:-}}"
    USER_DOWNLOADS_DIR="$(get_user_downloads_dir 2>/dev/null || true)"
    if [[ -z "$USER_DOWNLOADS_DIR" ]]; then
        warn "No target user set — section reports will only appear in $LOG_FILE."
        return 0
    fi
    USER_PROJECT_DIR="${USER_DOWNLOADS_DIR}/${PROJECT_NAME}"
    USER_RESULTS_DIR="${USER_PROJECT_DIR}/results"
    USER_LOGS_DIR="${USER_PROJECT_DIR}/logs"
    if (( DRY_RUN )); then
        info "Would create: $USER_PROJECT_DIR"
        info "Would create: $USER_RESULTS_DIR"
        info "Would create: $USER_LOGS_DIR"
        return 0
    fi
    install -d -m 750 -o "$user" -g "$user" "$USER_PROJECT_DIR" 2>/dev/null \
        || { warn "Could not create $USER_PROJECT_DIR — reports will only be in $LOG_FILE."; return 0; }
    install -d -m 750 -o "$user" -g "$user" "$USER_RESULTS_DIR" 2>/dev/null \
        || { warn "Could not create $USER_RESULTS_DIR — reports will only be in $LOG_FILE."; return 0; }
    install -d -m 750 -o "$user" -g "$user" "$USER_LOGS_DIR" 2>/dev/null || true
    ok "Project export dir ready: $USER_PROJECT_DIR"
    ok "Report dir ready: $USER_RESULTS_DIR"
    ok "Log dir ready: $USER_LOGS_DIR"
}

# write_user_report() - Read stdin and write to a file in the user results directory.
# Usage: { echo content; } | write_user_report <filename>
write_user_report() {
    local filename="$1"
    if [[ -z "$USER_RESULTS_DIR" ]]; then cat >/dev/null; return 0; fi
    if (( DRY_RUN )); then
        info "Would write report: $USER_RESULTS_DIR/$filename"
        cat >/dev/null
        return 0
    fi
    local user="${TARGET_USER:-${SUDO_USER:-}}"
    local path="${USER_RESULTS_DIR}/${filename}"
    if ! cat > "$path" 2>/dev/null; then
        err "Failed to write report to $path (filesystem may be read-only or full)"
        return 1
    fi
    chown "${user}:${user}" "$path" 2>/dev/null || true
    chmod 640 "$path" 2>/dev/null || true
    ok "Report saved: $path"
}

# copy_to_user_results() - Copy a system-owned file into the user results directory.
# Usage: copy_to_user_results <source_path> [dest_filename]
copy_to_user_results() {
    local src="$1" dest_name="${2:-$(basename "$1")}"
    [[ -z "$USER_RESULTS_DIR" || ! -f "$src" ]] && return 0
    (( DRY_RUN )) && { info "Would copy $src -> $USER_RESULTS_DIR/$dest_name"; return 0; }
    local user="${TARGET_USER:-${SUDO_USER:-}}"
    cp -a "$src" "${USER_RESULTS_DIR}/${dest_name}" 2>/dev/null || true
    chown "${user}:${user}" "${USER_RESULTS_DIR}/${dest_name}" 2>/dev/null || true
    chmod 640 "${USER_RESULTS_DIR}/${dest_name}" 2>/dev/null || true
    ok "Copied $src -> $USER_RESULTS_DIR/$dest_name"
}

# copy_log_to_user() - Copy main and structured error logs to the user logs directory.
copy_log_to_user() {
    [[ -z "$USER_LOGS_DIR" || ! -f "$LOG_FILE" ]] && return 0
    (( DRY_RUN )) && { info "Would copy log -> $USER_LOGS_DIR/"; return 0; }
    local user="${TARGET_USER:-${SUDO_USER:-}}"
    local dest="${USER_LOGS_DIR}/$(basename "$LOG_FILE")"
    cp -a "$LOG_FILE" "$dest" 2>/dev/null || true
    chown "${user}:${user}" "$dest" 2>/dev/null || true
    chmod 640 "$dest" 2>/dev/null || true
    ok "Log copied: $dest"
    if [[ -n "$ERROR_LOG" && -f "$ERROR_LOG" ]]; then
        local err_dest="${USER_LOGS_DIR}/$(basename "$ERROR_LOG")"
        cp -a "$ERROR_LOG" "$err_dest" 2>/dev/null || true
        chown "${user}:${user}" "$err_dest" 2>/dev/null || true
        chmod 640 "$err_dest" 2>/dev/null || true
        ok "Error log copied: $err_dest"
    fi
}

# generate_audit_pdf() - Export a PDF audit report and importable TXT bundle.
# Usage: generate_audit_pdf [summary_txt_path]
generate_audit_pdf() {
    local summary_path="${1:-}"
    [[ -z "$USER_DOWNLOADS_DIR" ]] && { warn "No Downloads directory available for PDF audit export."; return 1; }

    local user="${TARGET_USER:-${SUDO_USER:-}}"
    local pdf_path="${USER_DOWNLOADS_DIR}/fedora-hardening-audit-${REPORT_DATE}.pdf"
    local bundle_path="${USER_DOWNLOADS_DIR}/fedora-hardening-audit-${REPORT_DATE}.txt"
    local txt_path="/tmp/fedora-hardening-audit-${REPORT_DATE}-$$.txt"
    local ps_path="/tmp/fedora-hardening-audit-${REPORT_DATE}-$$.ps"
    register_tmp "$txt_path"
    register_tmp "$ps_path"

    if (( DRY_RUN )); then
        info "Would generate audit PDF: $pdf_path"
        info "Would write audit import bundle: $bundle_path"
        return 0
    fi

    if [[ -n "$summary_path" && -f "$summary_path" ]]; then
        cp -f "$summary_path" "$txt_path" 2>/dev/null || true
    else
        {
            printf 'Fedora Hardening Audit Report\n'
            printf 'Generated: %s\n' "$RUN_STAMP_HUMAN"
            printf 'Host: %s\n' "$HOST_LABEL"
            printf 'Log file: %s\n\n' "$LOG_FILE"
            printf 'Actionable items: %d\n' "${#ACTIONABLE_ITEMS[@]}"
            for item in "${ACTIONABLE_ITEMS[@]}"; do
                local section priority tag desc
                IFS='|' read -r section priority tag desc <<<"$item"
                printf '  [%s][%s] %s\n' "$priority" "$section" "$desc"
            done
            printf '\nManual follow-up remains required. See reports/logs for full details.\n'
        } > "$txt_path"
    fi

    {
        printf '\n=== Importable Action Items ===\n'
        printf 'Re-import later with: sudo %s --import-audit %s\n\n' "$SCRIPT_NAME" "$pdf_path"
        for item in "${ACTIONABLE_ITEMS[@]}"; do
            printf 'ACTION_ITEM|%s\n' "$item"
        done
    } >> "$txt_path"

    {
        [[ -f "$txt_path" ]] && cat "$txt_path"
    } > "$bundle_path"
    chown "${user}:${user}" "$bundle_path" 2>/dev/null || true
    chmod 640 "$bundle_path" 2>/dev/null || true

    ensure_command_dep enscript "audit PDF generation" enscript
    ensure_command_dep ps2pdf "audit PDF generation" ghostscript
    if ! cmd_exists enscript || ! cmd_exists ps2pdf; then
        warn "PDF generation dependencies are unavailable; could not create $pdf_path"
        return 1
    fi

    if ! enscript -B -q -f Courier8 "$txt_path" -o "$ps_path" >/dev/null 2>&1; then
        warn "enscript failed while building the audit PDF source."
        return 1
    fi
    if ! ps2pdf "$ps_path" "$pdf_path" >/dev/null 2>&1; then
        warn "ps2pdf failed while writing the audit PDF."
        return 1
    fi

    chown "${user}:${user}" "$pdf_path" 2>/dev/null || true
    chmod 640 "$pdf_path" 2>/dev/null || true
    ok "Audit PDF saved: $pdf_path"
    ok "Audit import bundle saved: $bundle_path"
    return 0
}

# import_audit_items() - Load actionable items from a generated audit PDF or TXT bundle.
# Accepts either the PDF path or the companion TXT bundle path.
import_audit_items() {
    local input_path="$1"
    local source_path="$input_path"
    local extract_path="/tmp/fedora-hardening-audit-import-${REPORT_DATE}-$$.txt"
    register_tmp "$extract_path"

    if [[ ! -f "$input_path" ]]; then
        err "Audit import file not found: $input_path"
        return 1
    fi

    case "$input_path" in
        *.pdf)
            source_path="${input_path%.pdf}.txt"
            if [[ ! -f "$source_path" ]]; then
                ensure_command_dep pdftotext "audit import from PDF" poppler-utils
                if ! cmd_exists pdftotext; then
                    err "Cannot import audit PDF without companion TXT bundle or pdftotext."
                    return 1
                fi
                pdftotext "$input_path" "$extract_path" >/dev/null 2>&1 || {
                    err "Failed to extract text from audit PDF: $input_path"
                    return 1
                }
                source_path="$extract_path"
            fi
            ;;
    esac

    ACTIONABLE_ITEMS=()
    while IFS= read -r line; do
        [[ "$line" == ACTION_ITEM\|* ]] || continue
        ACTIONABLE_ITEMS+=("${line#ACTION_ITEM|}")
    done < "$source_path"

    if (( ${#ACTIONABLE_ITEMS[@]} == 0 )); then
        warn "No importable actionable items found in: $input_path"
        return 1
    fi
    ok "Imported ${#ACTIONABLE_ITEMS[@]} actionable item(s) from audit report."
    return 0
}

# select_actionable_items() - Split actionable items into selected and deferred groups.
# Accepts 'all', item numbers, item tags, or a comma-separated mix of numbers and tags.
select_actionable_items() {
    local selection="${1:-all}"
    
    # Validate selection input to prevent shell injection
    if [[ ! "$selection" =~ ^[a-zA-Z0-9,[:space:]]*$ ]]; then
        err "Invalid selection format: contains non-alphanumeric characters (only 0-9, a-z, A-Z, commas allowed)"
        return 1
    fi
    
    local token idx=1
    declare -A picks=()
    SELECTED_ACTIONABLE_ITEMS=()
    DEFERRED_ACTIONABLE_ITEMS=()

    selection="${selection// /}"
    if [[ -z "$selection" || "${selection,,}" == "all" ]]; then
        SELECTED_ACTIONABLE_ITEMS=("${ACTIONABLE_ITEMS[@]}")
        return 0
    fi

    IFS=',' read -r -a tokens <<< "$selection"
    for token in "${tokens[@]}"; do
        [[ -z "$token" ]] && continue
        if [[ "$token" =~ ^[0-9]+$ ]]; then
            picks["index:$token"]=1
        else
            picks["tag:${token^^}"]=1
        fi
    done

    for item in "${ACTIONABLE_ITEMS[@]}"; do
        local section priority tag desc
        IFS='|' read -r section priority tag desc <<<"$item"
        if [[ -n "${picks[index:$idx]:-}" || -n "${picks[tag:$tag]:-}" ]]; then
            SELECTED_ACTIONABLE_ITEMS+=("$item")
        else
            DEFERRED_ACTIONABLE_ITEMS+=("$item")
        fi
        ((idx++))
    done

    (( ${#SELECTED_ACTIONABLE_ITEMS[@]} > 0 ))
}

# handle_actionable_follow_up() - Gate implementation on approval and optional item selection.
# If declined, export a PDF audit report plus TXT import bundle; if approved,
# allow all or selected changes by item number and/or actionable tag.
handle_actionable_follow_up() {
    local summary_path="${1:-}"
    local selection="all"

    show_actionable_items
    (( ${#ACTIONABLE_ITEMS[@]} > 0 )) || return 0

    if ! confirm "Implement the recommended next steps from the final summary now?"; then
        info "User declined implementation of recommended changes."
        generate_audit_pdf "$summary_path" || true
        info "Actionable items remain recorded in: ${USER_RESULTS_DIR:-$LOG_FILE}"
        return 0
    fi

    if (( ${#ACTIONABLE_ITEMS[@]} > 1 )); then
        info "You can implement all items, or choose specific item numbers/tags from the actionable list."
        selection="$(prompt_input "Enter 'all' or comma-separated item numbers/tags to implement" "all")"
        if ! select_actionable_items "$selection"; then
            warn "Invalid actionable-item selection '$selection' — defaulting to all items."
            SELECTED_ACTIONABLE_ITEMS=("${ACTIONABLE_ITEMS[@]}")
            DEFERRED_ACTIONABLE_ITEMS=()
        fi
    else
        SELECTED_ACTIONABLE_ITEMS=("${ACTIONABLE_ITEMS[@]}")
        DEFERRED_ACTIONABLE_ITEMS=()
    fi

    ACTIONABLE_ITEMS=("${SELECTED_ACTIONABLE_ITEMS[@]}")
    remediation_loop
    if (( ${#DEFERRED_ACTIONABLE_ITEMS[@]} > 0 )); then
        info "${#DEFERRED_ACTIONABLE_ITEMS[@]} actionable item(s) were deferred by user choice."
        ACTIONABLE_ITEMS+=("${DEFERRED_ACTIONABLE_ITEMS[@]}")
    fi
    return 0
}

# ---------- Pre-flight Checks -----------------------------------------------
# Initialize script environment, detect system configuration, and validate prerequisites.
# Functions in this section handle argument parsing, system detection, and setup.

# usage() - Display script usage information from embedded documentation.
# Extracts comment header from the top-of-file documentation block.
# Used by --help flag to show syntax, options, and section descriptions.
# Usage: usage (called by --help or when argument parsing fails)
usage() {
    awk '
        NR == 1 { next }
        /^# =============================================================================$/ { sep++; next }
        sep == 1 { sub(/^# ?/, ""); print }
        sep >= 2 { exit }
    ' "$0"
}

# list_sections() - Display all available sections with descriptions and optimized execution order.
# Shows section numbers, names, and notes (e.g. "interactive", "manual").
# Also displays the computed optimal execution order based on dependencies.
# Used by --list flag to help users understand available options.
# Usage: list_sections (called by --list flag)
list_sections() {
    cat <<'EOF'
  2  System updates
  3  Automatic updates
  4  SELinux tools
  5  firewalld
  6  Secure Boot verify
  7  SSH hardening
  8  USBGuard
  9  PAM/password policy
 10  Kernel sysctl
 11  auditd
 12  rkhunter + AIDE
 13  Flatpak / Flathub
 14  DNS over TLS
 15  KDE settings
 16  Firefox Flatpak + arkenfox + extensions
 17  WireGuard
 18  Fail2Ban
 19  Service trim
 20  File permissions
 21  ClamAV
 22  OpenSCAP

 Optimized execution order (guide section numbers):
    2,3,6,13,4,5,7,9,10,11,14,18,15,16,17,21,22,12,19,20,8
EOF
}

parse_args() {
    # parse_args() - Parse command-line arguments and set global flags.
    # Recognized options: -u/--user, -y/--yes, -n/--dry-run, --gui, --gui-full,
    # --import-audit, --skip, --only, --list, -h/--help
    # Validates option syntax and applies settings globally for use throughout script.
    # Usage: parse_args "$@" (called in preflight)
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -u|--user)
                if [[ -z "${2:-}" ]]; then
                    err "Option --user requires a username argument"
                    usage; exit 2
                fi
                TARGET_USER="$2"; shift 2 ;;
            -y|--yes)       ASSUME_YES=1; shift ;;
            -n|--dry-run)   DRY_RUN=1; shift ;;
            --gui)          FORCE_GUI=1; shift ;;
            --gui-full)     FORCE_GUI_FULL=1; shift ;;
            --import-audit)
                if [[ -z "${2:-}" ]]; then
                    err "Option --import-audit requires a file path argument"
                    usage; exit 2
                fi
                IMPORT_AUDIT_PATH="$2"; shift 2 ;;
            --skip)
                if [[ -z "${2:-}" ]]; then
                    err "Option --skip requires a section list argument"
                    usage; exit 2
                fi
                SKIP_LIST="$2"; shift 2 ;;
            --only)
                if [[ -z "${2:-}" ]]; then
                    err "Option --only requires a section list argument"
                    usage; exit 2
                fi
                ONLY_LIST="$2"; shift 2 ;;
            --list)         list_sections; exit 0 ;;
            -h|--help)      usage; exit 0 ;;
            *) err "Unknown argument: $1"; usage; exit 2 ;;
        esac
    done
}

# preflight() - Initialize script environment, detect system configuration, and validate prerequisites.
# Runs pre-flight checks: validates root access, creates log/backup dirs, detects Fedora variant.
# Populates release/desktop detection flags for auto-gating features and dependency decisions.
# Sets FEDORA_MAJOR version for compatibility validation (expects 44+).
# Usage: preflight (called in main after parse_args)
preflight() {
    local privilege_source="direct root login/session"
    (( FORCE_GUI_FULL )) || draw_banner
    setup_ui_mode
    if (( EUID != 0 )); then
        err "This script must be run as root (use sudo)."
        PRECHECK_FAILED=1
        return 0
    fi
    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        privilege_source="sudo (invoked by ${SUDO_USER})"
    fi
    ok "Privilege check passed: running with administrator/root privileges via ${privilege_source}."

    mkdir -p "$LOG_DIR"
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE" 2>/dev/null || true
    LOG_READY=1

    # Distro check: Verify this is a Fedora system and detect variant
    # Sources /etc/os-release to extract distribution metadata
    if [[ ! -r /etc/os-release ]]; then
        err "Cannot read /etc/os-release — is this Fedora?"; exit 1
    fi
    . /etc/os-release
    if [[ "${ID:-}" == "fedora" ]]; then
        IS_FEDORA=1
    else
        warn "Distro ID is '${ID:-unknown}', not 'fedora'. Proceeding anyway."
    fi
    if [[ -e /run/ostree-booted ]]; then
        IS_OSTREE=1
    fi
    FEDORA_VARIANT="${VARIANT_ID:-${VARIANT:-unknown}}"
    detect_fedora_release_type
    detect_desktop_envs
    (( IS_KINOITE )) && HAS_KDE=1
    if [[ "${VERSION_ID:-}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        FEDORA_MAJOR="${VERSION_ID%%.*}"
    fi
    if (( FEDORA_MAJOR > 0 && FEDORA_MAJOR < 44 )); then
        warn "Fedora version is '${VERSION_ID:-unknown}' — guide targets Fedora 44+."
        confirm "Proceed on this older version?" || exit 0
    fi
    info "Host: $HOST_LABEL   Distro: ${PRETTY_NAME:-?}   Kernel: $KERNEL_LABEL"
    info "Variant: ${FEDORA_VARIANT}"
    info "Release flags: workstation=$IS_WORKSTATION server=$IS_SERVER iot=$IS_IOT cloud=$IS_CLOUD coreos=$IS_COREOS ostree=$IS_OSTREE atomic_desktop=$IS_ATOMIC_DESKTOP"
    if (( IS_OSTREE )); then
        info "Detected rpm-ostree (immutable) host. Using rpm-ostree for package/update actions."
    fi
    if (( IS_KINOITE )); then
        info "Detected Fedora Kinoite variant."
    fi
    if (( IS_SILVERBLUE )); then
        info "Detected Fedora Silverblue variant. KDE-only tweaks will be skipped where incompatible."
    fi
    if (( IS_WORKSTATION )); then
        info "Detected Fedora Workstation variant. Desktop-focused sections are enabled."
    fi
    if (( IS_SERVER )); then
        info "Detected Fedora Server release profile."
    fi
    if (( IS_IOT )); then
        info "Detected Fedora IoT release profile."
    fi
    if (( IS_CLOUD )); then
        info "Detected Fedora Cloud release profile."
    fi
    if (( IS_COREOS )); then
        info "Detected Fedora CoreOS release profile."
    fi
    info "Fedora major version detected: ${FEDORA_MAJOR}"
    if (( HAS_DESKTOP )); then
        info "Detected desktop environments: ${DESKTOP_ENVS:-unknown}"
    else
        warn "No desktop environment detected; desktop-focused sections may be skipped."
    fi
    if (( ! HAS_KDE )); then
        warn "KDE/Plasma tooling not detected; KDE-specific section will be skipped."
    fi
    info "Log file:    $LOG_FILE"
    info "Backup dir:  $BACKUP_DIR (created on first change)"
    (( DRY_RUN ))    && warn "DRY RUN mode — no changes will be applied."
    (( ASSUME_YES )) && warn "Auto-yes mode — no interactive confirmations."

    # Resolve target user if not given
    if [[ -z "$TARGET_USER" && -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
        TARGET_USER="$SUDO_USER"
        info "Target user inferred from sudo: $TARGET_USER"
    fi
    if [[ -z "$TARGET_USER" ]]; then
        if (( ASSUME_YES )); then
            warn "No target user set — sections that need one (7, 9c, 20) will skip user-specific tweaks."
        else
            TARGET_USER="$(prompt_input 'Enter the primary username to harden (blank to skip user-specific tweaks):')"
        fi
    fi
    if [[ -n "$TARGET_USER" ]] && ! id -u "$TARGET_USER" >/dev/null 2>&1; then
        warn "User '$TARGET_USER' does not exist — user-specific tweaks will skip."
        TARGET_USER=""
    fi
}

# ============================================================================
#  SECTION 2 — System updates
# ============================================================================
sec_02_updates() {
    should_run 2 || return 0
    section 2 "System updates"
    pkg_upgrade
    ok "System packages updated. A reboot is recommended when the script finishes."
}

# ============================================================================
#  SECTION 3 — dnf5-automatic (Fedora 41+)
# ============================================================================
sec_03_dnf_automatic() {
    should_run 3 || return 0
    section 3 "Automatic security updates"

    # Handle rpm-ostree (immutable) systems first
    if (( IS_OSTREE )); then
        local ro_conf="/etc/rpm-ostreed.conf"
        [[ ! -f "$ro_conf" ]] && { warn "$ro_conf not found; skipping config write."; return 0; }
        
        backup_file "$ro_conf"
        if (( ! DRY_RUN )); then
            # Update existing policy or add new [Daemon] section (batch single sed pass)
            if grep -qE '^\s*AutomaticUpdatePolicy\s*=' "$ro_conf"; then
                sed -i -E 's|^\s*AutomaticUpdatePolicy\s*=.*|AutomaticUpdatePolicy=stage|' "$ro_conf" 2>/dev/null || true
            elif grep -qE '^\[Daemon\]' "$ro_conf"; then
                sed -i '/^\[Daemon\]/a AutomaticUpdatePolicy=stage' "$ro_conf" 2>/dev/null || true
            else
                printf '\n[Daemon]\nAutomaticUpdatePolicy=stage\n' >> "$ro_conf" 2>/dev/null || true
            fi
            ok "Configured rpm-ostreed automatic update staging in $ro_conf"
        else
            info "Would set AutomaticUpdatePolicy=stage in $ro_conf"
        fi
        
        # Enable timer if available
        systemctl list-unit-files rpm-ostreed-automatic.timer >/dev/null 2>&1 && \
            run "systemctl enable --now rpm-ostreed-automatic.timer" || \
            warn "rpm-ostreed-automatic.timer not found; configure automatic updates manually."
        return 0
    fi

    # Handle mutable systems: detect dnf version, configure, enable
    local pkg timer conf
    pkg="dnf5-automatic"; timer="dnf5-automatic.timer"; conf="/etc/dnf/automatic5.conf"
    if ! cmd_exists dnf || ! dnf info dnf5-automatic &>/dev/null; then
        pkg="dnf-automatic"; timer="dnf-automatic.timer"; conf="/etc/dnf/automatic.conf"
        warn "dnf5-automatic not found in repos — falling back to dnf-automatic."
    fi

    pkg_install "$pkg"
    [[ -f "$conf" ]] || { warn "$conf not found after install; skipping config."; return 0; }
    
    backup_file "$conf"
    if (( ! DRY_RUN )); then
        # Batch sed patterns for single-pass efficiency
        batch_sed "$conf" \
            's|^\s*upgrade_type\s*=.*|upgrade_type = security|' \
            's|^\s*apply_updates\s*=.*|apply_updates = yes|' \
            's|^\s*reboot\s*=.*|reboot = when-needed|' \
            's|^\s*reboot_command\s*=.*|reboot_command = "shutdown -r +5 '\''Rebooting for security updates'\''"|'
        ok "Patched $conf (upgrade_type=security, apply_updates=yes, reboot=when-needed)"
    else
        info "Would patch $conf: upgrade_type=security, apply_updates=yes, reboot=when-needed"
    fi

    run "systemctl enable --now $timer"
}

# ============================================================================
#  SECTION 4 — SELinux
# ============================================================================
sec_04_selinux() {
    should_run 4 || return 0
    section 4 "SELinux (verify enforcing + install tools)"
    local mode; mode="$(getenforce 2>/dev/null || echo unknown)"
    info "Current SELinux mode: $mode"
    if [[ "$mode" != "Enforcing" ]]; then
        warn "SELinux is not enforcing — setting enforcing now and updating /etc/selinux/config"
        run "setenforce 1 || true"
        if [[ -f /etc/selinux/config ]]; then
            backup_file /etc/selinux/config
            if ! sed -i 's|^SELINUX=.*|SELINUX=enforcing|' /etc/selinux/config 2>/dev/null; then
            err "Failed to set SELINUX=enforcing in /etc/selinux/config"
            add_action_item 4 HIGH "SELINUX_CONFIG_UPDATE" "Manually set SELINUX=enforcing in /etc/selinux/config"
            return 1
        fi
        fi
    else
        ok "SELinux is enforcing."
    fi
    pkg_install setools-console setroubleshoot-server
    info "Use 'sudo ausearch -m avc -ts recent | audit2why' to diagnose denials."
}

# firewalld_ensure_service() - Register a custom firewalld service XML if not already known.
# Firewalld only ships built-in definitions for well-known services; KDE Connect and
# similar require a custom XML file before --add-service can reference them.
# Usage: firewalld_ensure_service <name> <short-desc> <port/proto> [<port/proto>...]
firewalld_ensure_service() {
    local svc_name="${1}"; shift
    local svc_short="${1}"; shift
    local svc_dir="/etc/firewalld/services"
    local svc_file="${svc_dir}/${svc_name}.xml"

    # Already known to firewalld — nothing to do.
    if firewall-cmd --get-services 2>/dev/null | grep -qw "${svc_name}"; then
        return 0
    fi

    if (( DRY_RUN )); then
        info "Would create firewalld service definition: ${svc_name}"
        return 0
    fi

    install -d -m 750 "${svc_dir}" 2>/dev/null || true
    {
        printf '<?xml version="1.0" encoding="utf-8"?>\n'
        printf '<service>\n'
        printf '  <short>%s</short>\n' "${svc_short}"
        local portproto port proto
        for portproto in "$@"; do
            port="${portproto%%/*}"; proto="${portproto##*/}"
            printf '  <port port="%s" protocol="%s"/>\n' "${port}" "${proto}"
        done
        printf '</service>\n'
    } > "${svc_file}"
    chmod 640 "${svc_file}" 2>/dev/null || true
    firewall-cmd --reload &>/dev/null || true
    info "Created firewalld service definition: ${svc_name}"
}

# firewalld_add_service() - Add a service to a firewalld zone (permanent), soft-failing on
# INVALID_SERVICE (exit 101) instead of aborting the script under set -e.
# Queues an action item for manual follow-up when the service is not recognised.
# Usage: firewalld_add_service <zone> <service>
firewalld_add_service() {
    local zone="${1}" svc="${2}"
    if (( DRY_RUN )); then
        info "Would run: firewall-cmd --zone=${zone} --add-service=${svc} --permanent"
        return 0
    fi
    log "[RUN]   firewall-cmd --zone=${zone} --add-service=${svc} --permanent"
    local out ec
    # Capture output and exit code without triggering set -e abort on failure
    out=$(firewall-cmd --zone="${zone}" --add-service="${svc}" --permanent 2>&1) || ec=$?
    ec=${ec:-0}
    if (( ec == 0 )); then
        ok "firewalld: added service '${svc}' to zone '${zone}'."
        return 0
    fi
    if (( ec == 101 )) || [[ "${out}" == *"INVALID_SERVICE"* ]]; then
        warn "firewalld: service '${svc}' not recognised — skipping. (${out})"
        add_action_item "5" "MEDIUM" "FW_INVALID_SVC_${svc^^}" \
            "firewalld service '${svc}' is not registered. Create /etc/firewalld/services/${svc}.xml then run: firewall-cmd --zone=${zone} --add-service=${svc} --permanent && firewall-cmd --reload"
        return 1
    fi
    err "firewall-cmd --add-service=${svc} failed (exit ${ec}): ${out}"
    return "${ec}"
}

# ============================================================================
#  SECTION 5 — firewalld
# ============================================================================
sec_05_firewalld() {
    should_run 5 || return 0
    section 5 "firewalld — drop-by-default with explicit allow-list"
    pkg_install firewalld
    run "systemctl enable --now firewalld"

    # Smart wait for firewalld readiness (max 10 seconds with exponential backoff)
    info "Waiting for firewalld to be ready..."
    local attempt=0 max_attempts=10
    while (( attempt < max_attempts )); do
        if firewall-cmd --state &>/dev/null; then
            ok "firewalld is ready"
            break
        fi
        (( attempt++ ))
        sleep $((attempt / 3 + 1))  # Exponential backoff: 1s, 1s, 2s, 2s...
    done
    (( attempt >= max_attempts )) && warn "firewalld failed to become ready; proceeding anyway"

    # Set default zone and configure services (batch permanent operations)
    info "Setting default zone to 'drop'..."
    run "firewall-cmd --set-default-zone=drop"

    local svc services_to_allow=()
    if confirm "Allow 'mdns' through the firewall?"; then
        services_to_allow+=("mdns")
    fi
    # kde-connect is KDE-specific and requires a custom service XML (not built-in to firewalld).
    if (( HAS_KDE )); then
        if confirm "Allow 'kde-connect' through the firewall?"; then
            firewalld_ensure_service "kde-connect" "KDE Connect" \
                "1714-1764/tcp" "1714-1764/udp"
            services_to_allow+=("kde-connect")
        fi
    fi

    if systemctl is-enabled --quiet sshd 2>/dev/null; then
        info "sshd is enabled — allowing SSH in firewall."
        services_to_allow+=("ssh")
    elif confirm "Allow SSH through the firewall (you'll harden sshd in section 7)?"; then
        services_to_allow+=("ssh")
    fi

    # Add each service with soft-fail guard (INVALID_SERVICE → warn + action item, not abort).
    for svc in "${services_to_allow[@]}"; do
        firewalld_add_service drop "$svc"
    done

    run "firewall-cmd --set-log-denied=all" || warn "firewall-cmd --set-log-denied failed"
    if ! run "firewall-cmd --reload"; then
        err "firewall-cmd --reload failed; firewall rules may not be active"
        add_action_item 5 HIGH "FIREWALL_RELOAD_FAILED" "Manually reload firewall: sudo firewall-cmd --reload"
    fi
    run "firewall-cmd --list-all"
    ok "firewalld configured."
}

# ============================================================================
#  SECTION 6 — Secure Boot verification
# ============================================================================
sec_06_secureboot() {
    should_run 6 || return 0
    section 6 "Secure Boot verification"
    if ! cmd_exists mokutil; then
        ensure_command_dep mokutil "Secure Boot verification" mokutil
    fi
    if cmd_exists mokutil; then
        local sb; sb="$(mokutil --sb-state 2>/dev/null || true)"
        info "$sb"
        if grep -qi "enabled" <<<"$sb"; then
            ok "Secure Boot is enabled."
        else
            warn "Secure Boot is NOT enabled. Enable it in UEFI firmware settings."
        fi
    else
        warn "mokutil is unavailable after dependency checks — cannot verify Secure Boot state."
    fi
    if (( GUI_FULL_MODE )); then
        gui_alert info "GRUB password setup (guide section 6b) is manual.\n\nRun: sudo grub2-mkpasswd-pbkdf2\nThen add password_pbkdf2 lines in /etc/grub.d/40_custom and regenerate grub.cfg."
    else
    cat <<'EOF'
NOTE on GRUB password (guide §6b):
  Setting a GRUB password requires interactive use of 'grub2-mkpasswd-pbkdf2'.
  This script does NOT automate it. To do it manually:
      sudo grub2-mkpasswd-pbkdf2
      # copy the hash into /etc/grub.d/40_custom as:
      #   set superusers="root"
      #   password_pbkdf2 root <HASH>
      sudo grub2-mkconfig -o /boot/efi/EFI/fedora/grub.cfg   # UEFI
      sudo grub2-mkconfig -o /boot/grub2/grub.cfg            # legacy BIOS
EOF
    fi
}

# ============================================================================
#  SECTION 7 — SSH hardening
# ============================================================================
sec_07_ssh() {
    should_run 7 || return 0
    section 7 "SSH hardening"
    if ! pkg_cached openssh-server; then
        warn "openssh-server is missing; attempting dependency install for section 7."
        pkg_install openssh-server || true
        pkg_cached openssh-server || { warn "openssh-server is still unavailable; skipping SSH hardening."; return 0; }
    fi

    if ! confirm "You are about to harden sshd (disables passwords, root login, limits users). Continue?"; then

        info "Skipped SSH hardening."
        return 0
    fi

    # Verify public key auth is working before disabling password auth
    if ! grep -q "^ssh-" ~/.ssh/authorized_keys 2>/dev/null; then
        warn "WARNING: No public SSH keys found in ~/.ssh/authorized_keys"
        warn "If you proceed with hardening, you will LOSE SSH access unless you have alternative access method."
        if ! confirm "Continue without verified public key? (Not recommended)"; then
            info "Skipped SSH hardening."
            return 0
        fi
        add_action_item 7 HIGH "SSH_NO_PUBLIC_KEY" "Install public SSH key to ~/.ssh/authorized_keys before testing remote login."
    fi
    local cfg="/etc/ssh/sshd_config"
    local drop="/etc/ssh/sshd_config.d/99-hardening.conf"
    backup_file "$cfg"

    # Validate TARGET_USER to prevent shell injection
    if [[ -n "$TARGET_USER" && ! "$TARGET_USER" =~ ^[a-zA-Z0-9._-]+$ ]]; then
        err "Invalid username: $TARGET_USER (must be alphanumeric, dots, dashes, underscores)"
        return 1
    fi

    local allow_users_line=""
    [[ -n "$TARGET_USER" ]] && allow_users_line="AllowUsers $TARGET_USER"

    if (( DRY_RUN )); then
        info "Would write hardened drop-in to $drop"
    else
        install -d -m 755 /etc/ssh/sshd_config.d 2>/dev/null || true
        if ! cat >"$drop" <<EOF
# Written by $SCRIPT_NAME on $RUN_STAMP_ISO
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 1
X11Forwarding no
AllowAgentForwarding no
${allow_users_line}
EOF
    then warn "Failed to write $drop (filesystem may be read-only or full)"; return 1; fi
        chmod 644 "$drop" 2>/dev/null || true
        ok "Wrote $drop"
    fi

    run "/usr/sbin/sshd -t || true"
    run "systemctl restart sshd"
    warn "IMPORTANT: Before closing this session, open a SECOND terminal and confirm"
    warn "you can still SSH in with your key. If not, you still have this session to fix it."
}

# ============================================================================
#  SECTION 8 — USBGuard
# ============================================================================
sec_08_usbguard() {
    should_run 8 || return 0
    section 8 "USBGuard — ⚠ BE CAREFUL ⚠"
    if (( GUI_FULL_MODE )); then
        gui_alert warning "USBGuard can block unapproved USB devices, including keyboard/mouse.\n\nBefore continuing, connect all required USB devices and ensure you have an alternate recovery path."
    else
    cat <<'EOF'
USBGuard will block every USB device that isn't in its policy file,
including your keyboard and mouse if they are USB. The policy is generated
from currently connected devices, so BEFORE continuing:

  1. Plug in every USB device you use (keyboard, mouse, webcam, YubiKey...)
  2. Have a way to reach the machine without USB input if possible (serial,
     SSH from another host, PS/2 keyboard, etc.) in case the policy misfires.

You can later manage devices with:
  sudo usbguard list-devices
  sudo usbguard allow-device <ID> [--permanent]
EOF
        fi
    if ! confirm "Install and enable USBGuard with the current devices whitelisted?"; then
        info "Skipped USBGuard."
        return 0
    fi

    pkg_install usbguard usbguard-tools
    if (( DRY_RUN )); then
        info "Would generate policy: usbguard generate-policy > /etc/usbguard/rules.conf"
    else
        umask 077
        local tmp_usbguard="/tmp/usbguard-rules-$$-$RANDOM-$SECONDS.conf"
        register_tmp "$tmp_usbguard"
        if ! usbguard generate-policy > "$tmp_usbguard" 2>/dev/null; then
            warn "usbguard generate-policy failed"; rm -f "$tmp_usbguard" 2>/dev/null || true; return 1
        fi
        if ! install -m 0600 -o root -g root "$tmp_usbguard" /etc/usbguard/rules.conf 2>/dev/null; then
            warn "Failed to install USBGuard rules (filesystem may be read-only)"; rm -f "$tmp_usbguard" 2>/dev/null || true; return 1
        fi
        rm -f "$tmp_usbguard" 2>/dev/null || true
        ok "Wrote /etc/usbguard/rules.conf (0600 root:root)"
    fi
    run "systemctl enable --now usbguard"

    if pkg_cached plasma-workspace; then
        if confirm "Install graphical USBGuard notifier (usbguard-notifier)?"; then
            pkg_install usbguard-notifier || true
        fi
    fi
}

# ============================================================================
#  SECTION 9 — Password & PAM policy
# ============================================================================
sec_09_pam() {
    should_run 9 || return 0
    section 9 "Password quality + account lockout + aging"

    # 9a pwquality — batched sed for efficiency
    local pq="/etc/security/pwquality.conf"
    backup_file "$pq"
    if (( ! DRY_RUN )); then
        batch_sed "$pq" \
          's|^\s*#?\s*minlen\s*=.*|minlen = 14|' \
          's|^\s*#?\s*ucredit\s*=.*|ucredit = -1|' \
          's|^\s*#?\s*lcredit\s*=.*|lcredit = -1|' \
          's|^\s*#?\s*dcredit\s*=.*|dcredit = -1|' \
          's|^\s*#?\s*ocredit\s*=.*|ocredit = -1|' \
          's|^\s*#?\s*minclass\s*=.*|minclass = 3|' \
          's|^\s*#?\s*dictcheck\s*=.*|dictcheck = 1|' \
          's|^\s*#?\s*usercheck\s*=.*|usercheck = 1|' \
          's|^\s*#?\s*retry\s*=.*|retry = 3|'
        ok "Applied pwquality policy in $pq"
    else
        info "Would set minlen=14, ucredit=-1, lcredit=-1, dcredit=-1, ocredit=-1, minclass=3, dictcheck=1, usercheck=1, retry=3"
    fi

    # 9b faillock
    local fl="/etc/security/faillock.conf"
    backup_file "$fl"
    if (( ! DRY_RUN )) && [[ -f "$fl" ]]; then
        batch_sed "$fl" \
          's|^\s*#?\s*deny\s*=.*|deny = 5|' \
          's|^\s*#?\s*unlock_time\s*=.*|unlock_time = 900|'
        grep -qE '^\s*even_deny_root' "$fl" || echo 'even_deny_root' >> "$fl"
        ok "Applied faillock policy in $fl"
    fi

    # 9c login.defs — batched sed
    local ld="/etc/login.defs"
    backup_file "$ld"
    if (( ! DRY_RUN )) && [[ -f "$ld" ]]; then
        batch_sed "$ld" \
          's|^\s*PASS_MAX_DAYS\s+.*|PASS_MAX_DAYS   90|' \
          's|^\s*PASS_MIN_DAYS\s+.*|PASS_MIN_DAYS   1|' \
          's|^\s*PASS_WARN_AGE\s+.*|PASS_WARN_AGE   14|'
        ok "Set PASS_MAX_DAYS=90, PASS_MIN_DAYS=1, PASS_WARN_AGE=14"
    fi
    if [[ -n "$TARGET_USER" ]]; then
        run "chage -M 90 -m 1 -W 14 '$TARGET_USER'"
        run "chage -l '$TARGET_USER'"
    else
        warn "No target user — skipping 'chage' password-aging apply."
    fi
}

# ============================================================================
#  SECTION 10 — Kernel sysctl
# ============================================================================
sec_10_sysctl() {
    should_run 10 || return 0
    section 10 "Kernel & network sysctl hardening"
    local f="/etc/sysctl.d/99-hardening.conf"
    if (( DRY_RUN )); then
        info "Would write $f with guide's full sysctl set"
    else
        if ! cat > "$f" <<'EOF'
# /etc/sysctl.d/99-hardening.conf
# Installed by fedora-harden.sh

# ── Network Hardening ──────────────────────────────────────────────────
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

net.ipv4.tcp_syncookies = 1

# Uncomment to fully disable IPv6:
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1

net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# ── Kernel Hardening ───────────────────────────────────────────────────
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.sysrq = 0

# NOTE: 'kernel.unprivileged_userns_clone' is an Ubuntu-specific knob
# and does not exist on the Fedora kernel. The Fedora equivalent is
# 'user.max_user_namespaces', but setting it to 0 breaks Flatpak,
# podman, browsers, and systemd user services — so it is left at the
# default intentionally. Uncomment only if you understand the impact.
# user.max_user_namespaces = 0

kernel.randomize_va_space = 2
kernel.pid_max = 65536

fs.suid_dumpable = 0
fs.protected_fifos = 2
fs.protected_regular = 2
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
EOF
        then err "Failed to write sysctl configuration"; return 1; fi
        chmod 644 "$f" 2>/dev/null || true
        ok "Wrote $f"
    fi
    run "sysctl --system"
    run "sysctl kernel.kptr_restrict"
}

# ============================================================================
#  SECTION 11 — auditd
# ============================================================================
sec_11_auditd() {
    should_run 11 || return 0
    section 11 "auditd rules"
    pkg_install audit audit-libs
    run "systemctl enable --now auditd"

    local rules="/etc/audit/rules.d/hardening.rules"
    if (( DRY_RUN )); then
        info "Would write $rules"
    else
        if ! cat > "$rules" <<'EOF'
-D
-b 8192
-f 1

# Identity / credential files
-w /etc/passwd    -p wa -k identity
-w /etc/group     -p wa -k identity
-w /etc/shadow    -p wa -k identity
-w /etc/sudoers   -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Login history
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# Privilege escalation
-w /usr/bin/sudo -p x -k sudo_usage
-w /usr/bin/su   -p x -k su_usage

# Daemon config
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/selinux/        -p wa -k selinux

# Scheduled tasks
-w /etc/cron.d/    -p wa -k cron
-w /etc/crontab    -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Kernel modules
-w /sbin/insmod   -p x -k modules
-w /sbin/rmmod    -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -k modules

# setuid/setgid execves that land as root
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid

# Uncomment to lock the ruleset at boot (requires reboot to change):
# -e 2
EOF
    then warn "Failed to write $rules (filesystem may be read-only)"; return 1; fi
        chmod 640 "$rules" 2>/dev/null || true
        ok "Wrote $rules"
    fi
    run "augenrules --load"
    run "systemctl restart auditd || service auditd restart"
}

# ============================================================================
#  SECTION 12 — rkhunter + AIDE
# ============================================================================
sec_12_ids() {
    should_run 12 || return 0
    section 12 "rkhunter + AIDE"

    pkg_install rkhunter aide

    # rkhunter: update signatures then run scan with output capture
    run "rkhunter --update || true"
    run "rkhunter --propupd"
    info "Running initial rkhunter scan (this takes a minute)..."
    local rk_tmp="/tmp/rkhunter-out-$$.tmp" rk_warn_count=0
    register_tmp "$rk_tmp"
    if (( ! DRY_RUN )); then
        log "[RUN]   rkhunter --check --sk --rwo"
        if (( GUI_FULL_MODE )); then
            rkhunter --check --sk --rwo >"$rk_tmp" 2>&1 || true
        else
            rkhunter --check --sk --rwo 2>&1 | tee "$rk_tmp" || true
        fi
        rk_warn_count="$(awk '/^\[ Warning \]/{count++} END{print count+0}' "$rk_tmp" 2>/dev/null || echo 0)"
    else
        run "rkhunter --check --sk --rwo || true"
    fi

    # Daily cron
    local cron_rk="/etc/cron.daily/rkhunter-scan"
    if (( ! DRY_RUN )); then
        if ! cat > "$cron_rk" <<'CRONEOF'
#!/bin/bash
/usr/bin/rkhunter --cronjob --update --quiet
CRONEOF
        then warn "Failed to write $cron_rk"; return 1; fi
        chmod 755 "$cron_rk" 2>/dev/null || true
        ok "Wrote $cron_rk"
    fi

    # AIDE: initialize database
    info "Initializing AIDE database (this can take several minutes)..."
    run "aide --init"
    if (( ! DRY_RUN )) && [[ -f /var/lib/aide/aide.db.new.gz ]]; then
        run "mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
    fi

    local cron_aide="/etc/cron.weekly/aide-check"
    if (( ! DRY_RUN )); then
        if ! cat > "$cron_aide" <<'CRONEOF'
#!/bin/bash
/usr/sbin/aide --check 2>&1 | logger -t aide
CRONEOF
        then warn "Failed to write $cron_aide"; return 1; fi
        chmod 755 "$cron_aide" 2>/dev/null || true
        ok "Wrote $cron_aide (results sent to journal via logger)"
    fi
    warn "Re-initialize AIDE after legitimate package updates: 'sudo aide --init && sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz'"

    # Write section report to user Downloads/<project>/results/
    if (( ! DRY_RUN )); then
        {
            printf '=== Section 12: rkhunter + AIDE Report ===\n'
            printf 'Generated: %s\n\n' "$RUN_STAMP_HUMAN"
            printf '--- rkhunter scan output (%d warning(s)) ---\n' "$rk_warn_count"
            [[ -f "$rk_tmp" ]] && cat "$rk_tmp" || printf '(capture unavailable)\n'
            printf '\n--- AIDE database status ---\n'
            if [[ -f /var/lib/aide/aide.db.gz ]]; then
                printf 'AIDE database: /var/lib/aide/aide.db.gz  [INITIALIZED]\n'
            else
                printf 'AIDE database: NOT FOUND — initialization may have failed\n'
            fi
            printf '\n--- Cron jobs installed ---\n'
            printf 'Daily rkhunter:  %s\n' "$cron_rk"
            printf 'Weekly AIDE:     %s\n' "$cron_aide"
        } | write_user_report "section-12-rkhunter-aide-${REPORT_DATE}.txt" || true
    fi

    # Populate actionable items based on findings
    if (( rk_warn_count > 0 )); then
        warn "rkhunter found $rk_warn_count warning(s) — review the section 12 report."
        add_action_item 12 HIGH "RK_WARNINGS" \
            "rkhunter found $rk_warn_count warning(s): investigate flagged files, then run: sudo rkhunter --propupd"
    else
        ok "rkhunter scan: no warnings detected."
    fi
    if (( ! DRY_RUN )) && [[ ! -f /var/lib/aide/aide.db.gz ]]; then
        add_action_item 12 HIGH "AIDE_DB_MISSING" \
            "AIDE database not initialized — run: sudo aide --init && sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
    fi
    add_action_item 12 LOW "AIDE_RECHECK" \
        "Re-initialize AIDE after any future package updates (command in section-12 report)."
}

# ============================================================================
#  SECTION 13 — Flatpak / Flathub
# ============================================================================
sec_13_flatpak() {
    should_run 13 || return 0
    section 13 "Flatpak + Flathub"
    if ! cmd_exists flatpak; then
        pkg_install flatpak
    else
        info "Flatpak already present."
    fi
    run "flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo"
    run "flatpak update -y || true"
    if confirm "Install Flatseal (graphical Flatpak permission manager)?"; then
        flatpak_install_or_update flathub com.github.tchx84.Flatseal
    fi
}

# ============================================================================
#  SECTION 14 — DNS over TLS
# ============================================================================
sec_14_dot() {
    should_run 14 || return 0
    section 14 "DNS over TLS via systemd-resolved"
    local cfg="/etc/systemd/resolved.conf"
    backup_file "$cfg"
    if (( ! DRY_RUN )); then
        # Write a drop-in instead of clobbering the main file.
        install -d -m 755 /etc/systemd/resolved.conf.d 2>/dev/null || true
        if ! cat >/etc/systemd/resolved.conf.d/99-hardening.conf <<'EOF'
[Resolve]
DNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net 1.1.1.1#cloudflare-dns.com
FallbackDNS=8.8.8.8#dns.google
DNSOverTLS=yes
DNSSEC=yes
EOF
        then err "Failed to write DNS-over-TLS configuration"; return 1; fi
        ok "Wrote /etc/systemd/resolved.conf.d/99-hardening.conf"
    fi
    run "systemctl restart systemd-resolved"
    run "resolvectl status | head -25 || true"
}

# ============================================================================
#  SECTION 15 — KDE CLI settings
# ============================================================================
sec_15_kde() {
    should_run 15 || return 0
    section 15 "KDE-specific CLI settings"
    if (( ! HAS_KDE )); then
        warn "Host variant does not appear KDE-based; skipping KDE-specific section."
        return 0
    fi

    # Detect which kwriteconfig is available (Plasma 6 uses kwriteconfig6)
    local KW=""
    for c in kwriteconfig6 kwriteconfig5; do
        if cmd_exists "$c"; then KW="$c"; break; fi
    done
    if [[ -z "$KW" ]]; then
        warn "Neither kwriteconfig6 nor kwriteconfig5 found — Plasma may not be installed. Skipping KDE tweaks."
        return 0
    fi
    info "Using $KW"

    if [[ -z "$TARGET_USER" ]]; then
        warn "No target user — cannot apply per-user KDE settings."
        return 0
    fi

    # Run as the user so the file is written into their ~/.config
    run "sudo -u '$TARGET_USER' '$KW' --file kscreenlockerrc --group Daemon --key Timeout 5"
    run "sudo -u '$TARGET_USER' '$KW' --file kscreenlockerrc --group Daemon --key Lock true"
    run "sudo -u '$TARGET_USER' '$KW' --file kscreenlockerrc --group Daemon --key LockGrace 0"
    run "sudo -u '$TARGET_USER' '$KW' --file kdeglobals --group RecentDocuments --key UseRecent false"

    # Per guide 15c — disable Bluetooth if user has no BT peripherals
    if confirm "Disable Bluetooth entirely (do this only if you use no BT peripherals)?"; then
        run "systemctl disable --now bluetooth || true"
        if [[ -f /etc/bluetooth/main.conf ]]; then
            backup_file /etc/bluetooth/main.conf
            run "sed -i 's|^#\?AutoEnable=.*|AutoEnable=false|' /etc/bluetooth/main.conf"
        fi
    fi
    info "GUI-only tweaks (KWallet master password, Privacy, Activity tracking) must be done in System Settings."
}

# ============================================================================
#  SECTION 16 — Firefox Flatpak + arkenfox + extensions
# ============================================================================
sec_16_firefox() {
    should_run 16 || return 0
    section 16 "Firefox hardening (Flatpak preferred + arkenfox + privacy extensions)"

    # Flatpak is preferred for Firefox due to stronger app sandboxing.
    if ! cmd_exists flatpak; then
        warn "flatpak is not available yet; attempting to install it now."
        pkg_install flatpak
        if (( IS_OSTREE )); then
            warn "On rpm-ostree, reboot is required before the newly layered flatpak command is usable."
            warn "Rerun section 16 after reboot."
            return 0
        fi
    fi

    # Keep native RPM Firefox if present, but prefer Flatpak as the managed baseline.
    if pkg_cached firefox; then
        info "Detected native RPM Firefox. Keeping it installed, but Flatpak Firefox remains the hardened preferred browser."
    fi

    run "flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo"
    flatpak_install_or_update flathub org.mozilla.firefox

    local ff_user="${TARGET_USER:-${SUDO_USER:-}}"
    if [[ -z "$ff_user" || "$ff_user" == "root" ]]; then
        warn "No non-root user available for profile hardening; installed Firefox Flatpak only."
        return 0
    fi
    if ! id -u "$ff_user" >/dev/null 2>&1; then
        warn "User '$ff_user' does not exist; skipping Firefox profile hardening."
        return 0
    fi

    local home ff_root profiles_ini profile_marker profile_path profile_dir
    home="$(user_home "$ff_user")"
    if [[ -z "$home" ]]; then
        warn "Could not resolve home directory for $ff_user; skipping Firefox profile hardening."
        return 0
    fi
    ff_root="$home/.var/app/org.mozilla.firefox/.mozilla/firefox"
    profiles_ini="$ff_root/profiles.ini"

    # Ensure profile scaffolding exists; if not, ask Firefox to create one.
    if [[ ! -f "$profiles_ini" ]]; then
        run "sudo -u '$ff_user' flatpak run --command=firefox org.mozilla.firefox -CreateProfile hardening-default || true"
    fi

    if [[ ! -f "$profiles_ini" ]]; then
        warn "Firefox profile metadata not found at $profiles_ini"
        warn "Launch Firefox once as '$ff_user' and rerun section 16 to apply arkenfox and extension policy."
        return 0
    fi

    profile_marker="$(awk -F= '
        /^\[Profile[0-9]+\]$/ {in_profile=1; path=""; def=0; rel=1; next}
        /^\[/ && $0 !~ /^\[Profile[0-9]+\]$/ {if (in_profile && def==1 && path!="") {print rel ":" path; exit} in_profile=0}
        in_profile && $1=="Path" {path=$2}
        in_profile && $1=="Default" {def=$2}
        in_profile && $1=="IsRelative" {rel=$2}
        END {if (in_profile && def==1 && path!="") print rel ":" path}
    ' "$profiles_ini")"

    if [[ -z "$profile_marker" ]]; then
        warn "Could not identify Firefox default profile from $profiles_ini; skipping arkenfox deployment."
    else
        if [[ "${profile_marker%%:*}" == "1" ]]; then
            profile_path="${profile_marker#*:}"
            profile_dir="$ff_root/$profile_path"
        else
            profile_dir="${profile_marker#*:}"
        fi

        if [[ -d "$profile_dir" ]]; then
            if (( DRY_RUN )); then
                info "Would install arkenfox user.js into $profile_dir/user.js"
            else
                local tmp_arken="/tmp/arkenfox-user-$$-$RANDOM-$SECONDS.js"
                register_tmp "$tmp_arken"
                if download_file "https://raw.githubusercontent.com/arkenfox/user.js/master/user.js" "$tmp_arken"; then
                    if ! install -m 0600 -o "$ff_user" -g "$ff_user" "$tmp_arken" "$profile_dir/user.js" 2>/dev/null; then
                        warn "Failed to install arkenfox user.js (filesystem may be read-only)"
                        rm -f "$tmp_arken" 2>/dev/null || true
                    else
                        rm -f "$tmp_arken" 2>/dev/null || true
                        ok "Installed arkenfox user.js into $profile_dir/user.js"
                    fi
                else
                    warn "arkenfox user.js download failed; Firefox profile will use defaults (no arkenfox hardening)"
                    rm -f "$tmp_arken"
                fi
            fi
        else
            warn "Resolved Firefox profile directory '$profile_dir' does not exist; skipping arkenfox deployment."
        fi
    fi

    # Install requested extensions via Firefox enterprise policy.
    local policy_dir policy_file
    policy_dir="$ff_root/distribution"
    policy_file="$policy_dir/policies.json"

    if (( DRY_RUN )); then
        info "Would write Firefox extension policy to $policy_file"
    else
        install -d -m 0700 -o "$ff_user" -g "$ff_user" "$policy_dir" 2>/dev/null || true
        local tmp_policy="/tmp/firefox-policies-$$-$RANDOM-$SECONDS.json"
        register_tmp "$tmp_policy"
        if ! cat > "$tmp_policy" <<'EOF'
{
  "policies": {
    "Extensions": {
      "Install": [
        "https://addons.mozilla.org/firefox/downloads/latest/ublock-origin/latest.xpi",
        "https://addons.mozilla.org/firefox/downloads/latest/privacy-badger17/latest.xpi",
        "https://addons.mozilla.org/firefox/downloads/latest/skip-redirect/latest.xpi",
        "https://addons.mozilla.org/firefox/downloads/latest/multi-account-containers/latest.xpi"
      ]
    },
    "ExtensionSettings": {
      "*": {
        "installation_mode": "allowed"
      }
    }
  }
}
EOF
        then warn "Failed to write Firefox policy JSON"; rm -f "$tmp_policy" 2>/dev/null || true; return 1; fi
        if ! install -m 0600 -o "$ff_user" -g "$ff_user" "$tmp_policy" "$policy_file" 2>/dev/null; then
            warn "Failed to install Firefox policy (filesystem may be read-only)"; rm -f "$tmp_policy" 2>/dev/null || true; return 1
        fi
        rm -f "$tmp_policy" 2>/dev/null || true
        ok "Installed Firefox extension policy at $policy_file"
    fi

    run "sudo -u '$ff_user' xdg-settings set default-web-browser org.mozilla.firefox.desktop || true"
    info "Firefox hardening complete for user '$ff_user' (Flatpak + arkenfox + uBlock Origin/Privacy Badger/Skip Redirect/Multi-Account Containers policy)."
    info "Restart Firefox to apply enterprise policy installs and arkenfox preferences."
}

# ============================================================================
#  SECTION 17 — WireGuard tools
# ============================================================================
sec_17_wireguard() {
    should_run 17 || return 0
    section 17 "WireGuard (tools only — tunnel config is manual)"
    pkg_install wireguard-tools
    info "Generate keys with:   wg genkey | tee privatekey | wg pubkey > publickey"
    info "Then craft /etc/wireguard/wg0.conf (chmod 600) with your peer details."
}

# ============================================================================
#  SECTION 18 — Fail2Ban
# ============================================================================
sec_18_fail2ban() {
    should_run 18 || return 0
    section 18 "Fail2Ban"
    pkg_install fail2ban
    local fb_dir="/etc/fail2ban"
    local jl="${fb_dir}/jail.local"

    if (( DRY_RUN )); then
        [[ -f "$jl" ]] && info "$jl already exists — would leave unchanged." \
                       || info "Would write $jl (not present yet)"
    else
        # Ensure configuration directory exists before writing jail.local.
        if ! run "install -d -m 0755 '$fb_dir'"; then
            warn "Could not create $fb_dir; skipping Fail2Ban configuration for now."
            add_action_item 18 HIGH "FAIL2BAN_DIR_CREATE_FAILED" \
                "Failed to create $fb_dir. Fix filesystem permissions and re-run section 18."
            return 0
        fi

        if [[ ! -f "$jl" ]]; then
            if ! cat > "$jl" <<'EOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5
backend  = systemd

[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
backend = systemd
EOF
            then
                warn "Could not write $jl; skipping Fail2Ban activation for now."
                add_action_item 18 HIGH "FAIL2BAN_JAIL_WRITE_FAILED" \
                    "Failed to write $jl. Fix filesystem/permissions and re-run section 18."
                return 0
            fi
            ok "Wrote $jl"
        else
            info "$jl already exists — leaving unchanged."
        fi

        # rpm-ostree hosts may have fail2ban staged but not active until reboot.
        if (( IS_OSTREE )) && ! systemctl list-unit-files 2>/dev/null | grep -q '^fail2ban\.service'; then
            warn "fail2ban is staged but not active yet on rpm-ostree. Reboot required before enabling service."
            add_action_item 18 HIGH "FAIL2BAN_PENDING_REBOOT" \
                "Reboot to activate staged fail2ban packages, then re-run section 18."
            return 0
        fi

        if ! run "systemctl enable --now fail2ban"; then
            warn "Unable to enable/start fail2ban right now."
            add_action_item 18 MEDIUM "FAIL2BAN_ENABLE_FAILED" \
                "Run: sudo systemctl enable --now fail2ban (after reboot on rpm-ostree hosts)."
            return 0
        fi
    fi

    # Post-enable status check and report
    if (( ! DRY_RUN )); then
        local f2b_active=0 f2b_status=""
        systemctl is-active --quiet fail2ban 2>/dev/null && f2b_active=1 || true
        if (( f2b_active )); then
            f2b_status="$(fail2ban-client status 2>&1 || true)"
            ok "fail2ban is active."
        else
            warn "fail2ban is not active after enable — see report."
            add_action_item 18 HIGH "FAIL2BAN_NOT_RUNNING" \
                "fail2ban service is not running — run: sudo systemctl restart fail2ban"
        fi
        {
            printf '=== Section 18: Fail2Ban Report ===\n'
            printf 'Generated: %s\n\n' "$RUN_STAMP_HUMAN"
            printf '--- Service status ---\n'
            systemctl status fail2ban --no-pager 2>&1 || true
            printf '\n--- Jail summary ---\n%s\n' "$f2b_status"
            printf '\n--- jail.local contents ---\n'
            [[ -f "$jl" ]] && cat "$jl" || printf '(not found)\n'
        } | write_user_report "section-18-fail2ban-${REPORT_DATE}.txt" || true
        if (( f2b_active )); then
            add_action_item 18 LOW "FAIL2BAN_REVIEW" \
                "Review fail2ban jail status and ban history: sudo fail2ban-client status sshd"
        fi
    fi
}

# ============================================================================
#  SECTION 19 — Disable unnecessary services (interactive)
# ============================================================================
sec_19_services() {
    should_run 19 || return 0
    section 19 "Disable unnecessary services (interactive)"
    local svc
    # Each entry: "service:description"
    local candidates=(
        "avahi-daemon:mDNS/Bonjour (local network discovery)"
        "cups:Local/network printing daemon"
        "cups-browsed:Auto-discovery of network printers"
        "bluetooth:Bluetooth stack"
        "ModemManager:Mobile broadband / 4G modem manager"
        "iscsi:iSCSI initiator (network block storage)"
        "iscsid:iSCSI daemon"
    )
    for entry in "${candidates[@]}"; do
        svc="${entry%%:*}"
        local desc="${entry#*:}"
        if systemctl is-enabled --quiet "$svc" 2>/dev/null || systemctl is-active --quiet "$svc" 2>/dev/null; then
            if confirm "Disable $svc ($desc)?"; then
                run "systemctl disable --now $svc || true"
            fi
        fi
    done
    info "Service security overview (higher = less sandboxed):"
    run "systemd-analyze security --no-pager | head -25 || true"
}

# ============================================================================
#  SECTION 20 — File permission hardening
# ============================================================================
sec_20_perms() {
    should_run 20 || return 0
    section 20 "File permission hardening"
    # Fedora defaults are already strict, but re-affirm.
    run "chmod 000 /etc/shadow"
    run "chmod 000 /etc/gshadow"
    run "chmod 644 /etc/passwd"
    run "chmod 644 /etc/group"
    run "chmod 1777 /tmp"

    if [[ -n "$TARGET_USER" ]]; then
        local home; home="$(user_home "$TARGET_USER")"
        if [[ -n "$home" && -d "$home" ]]; then
            run "chmod 700 '$home'"
        fi
    fi

    if (( IS_OSTREE )); then
        warn "Skipping /usr/bin compiler permission changes on immutable rpm-ostree systems."
    else
        if confirm "Restrict compiler toolchain (/usr/bin/gcc, g++, make) to mode 0750?"; then
            for bin in /usr/bin/gcc /usr/bin/g++ /usr/bin/make; do
                [[ -e "$bin" ]] && run "chmod 750 '$bin'"
            done
        fi
    fi

    info "Baseline of SUID files (saved for diffing later):"
    run "find / -xdev -perm /4000 -type f 2>/dev/null | sort > /root/suid-baseline-${RUN_DATE_YMD}.txt || true"
    info "Saved SUID baseline to /root/suid-baseline-*.txt"
}

# ============================================================================
#  SECTION 21 — ClamAV
# ============================================================================
sec_21_clamav() {
    should_run 21 || return 0
    section 21 "ClamAV antivirus"
    pkg_install clamav clamd clamav-update clamav-scanner-systemd
    info "Updating ClamAV signatures (freshclam)..."
    # freshclam can fail if the daemon already holds the lock; suppress for idempotency
    run "freshclam || true"
    run "systemctl enable --now clamav-freshclam || true"
    # The clamd@scan unit varies; try both
    run "systemctl enable --now clamd@scan || systemctl enable --now clamd@scan.service || true"

    # Post-enable status check and report
    if (( ! DRY_RUN )); then
        local freshclam_active=0 clamd_active=0
        if systemctl is-active --quiet clamav-freshclam 2>/dev/null; then
            freshclam_active=1
        fi
        if systemctl is-active --quiet clamd@scan 2>/dev/null || systemctl is-active --quiet clamd@scan.service 2>/dev/null; then
            clamd_active=1
        fi
        # Collect status output safely
        {
            echo "=== Section 21: ClamAV Report ==="
            echo "Generated: $RUN_STAMP_HUMAN"
            echo ""
            echo "--- clamav-freshclam status ---"
            systemctl status clamav-freshclam --no-pager 2>&1 || true
            echo ""
            echo "--- clamd@scan status ---"
            systemctl status clamd@scan --no-pager 2>&1 || systemctl status clamd@scan.service --no-pager 2>&1 || true
            echo ""
            echo "--- ClamAV version / DB ---"
            clamscan --version 2>&1 || true
            freshclam --version 2>&1 || true
        } | write_user_report "section-21-clamav-${REPORT_DATE}.txt" || true
        (( freshclam_active )) || add_action_item 21 MEDIUM "CLAMAV_FRESHCLAM_NOT_RUNNING" \
            "clamav-freshclam is not running — run: sudo systemctl start clamav-freshclam"
        (( clamd_active )) || add_action_item 21 MEDIUM "CLAMAV_CLAMD_NOT_RUNNING" \
            "clamd@scan is not running — run: sudo systemctl start clamd@scan"
        add_action_item 21 MEDIUM "CLAMAV_INITIAL_SCAN" \
            "Run initial ClamAV home-directory scan (handled automatically in remediation step)."
        add_action_item 21 LOW "CLAMAV_REVIEW" \
            "Review ClamAV status: $USER_RESULTS_DIR/section-21-clamav-${REPORT_DATE}.txt"
    fi
}

# ============================================================================
#  SECTION 22 — OpenSCAP
# ============================================================================
sec_22_openscap() {
    should_run 22 || return 0
    section 22 "OpenSCAP compliance scanner"
    pkg_install openscap-scanner scap-security-guide
    ensure_command_dep oscap "OpenSCAP compliance scan" openscap-scanner
    if ! cmd_exists oscap; then
        warn "oscap command is unavailable after dependency checks — skipping section 22."
        return 0
    fi
    local content="/usr/share/xml/scap/ssg/content/ssg-fedora-ds.xml"
    if [[ ! -f "$content" ]]; then
        warn "SSG content missing at expected path; retrying dependency install and alternate path lookup."
        pkg_install scap-security-guide
        if [[ ! -f "$content" ]]; then
            local alt_content=""
            local candidate
            for candidate in /usr/share/xml/scap/ssg/content/ssg-fedora*-ds.xml; do
                [[ -f "$candidate" ]] || continue
                alt_content="$candidate"
                break
            done
            if [[ -n "$alt_content" ]]; then
                content="$alt_content"
                info "Using alternate SSG content path: $content"
            else
                warn "No Fedora SSG datastream found; skipping OpenSCAP scan."
                return 0
            fi
        fi
    fi
    info "Available profiles:"
    run "oscap info '$content' | grep -E '^(Profile|Title)' | head -20 || true"
    if confirm "Run a baseline scan now (results in /root/scap-report.html)?"; then
        run "oscap xccdf eval \
            --profile xccdf_org.ssgproject.content_profile_standard \
            --results /root/scap-results.xml \
            --report  /root/scap-report.html \
            '$content' || true"
        ok "Report: /root/scap-report.html"
    fi

    # Copy results to user Downloads/<project>/results/ and generate text summary
    if (( ! DRY_RUN )); then
        copy_to_user_results /root/scap-report.html  "section-22-openscap-${REPORT_DATE}.html"
        copy_to_user_results /root/scap-results.xml  "section-22-openscap-results-${REPORT_DATE}.xml"
        local pass_count="?" fail_count="?" notchecked_count="?"
        if [[ -f /root/scap-results.xml ]]; then
            read -r pass_count fail_count notchecked_count < <(
                awk '
                    /result="pass"/ {pass++}
                    /result="fail"/ {fail++}
                    /result="notchecked"/ {notchecked++}
                    END {print pass+0, fail+0, notchecked+0}
                ' /root/scap-results.xml 2>/dev/null || printf '? ? ?\n'
            )
            info "OpenSCAP results — pass: $pass_count  fail: $fail_count  not-checked: $notchecked_count"
            {
                printf '=== Section 22: OpenSCAP Compliance Summary ===\n'
                printf 'Generated: %s\n\n' "$RUN_STAMP_HUMAN"
                printf 'Results XML:  /root/scap-results.xml\n'
                printf 'HTML report:  /root/scap-report.html\n\n'
                printf 'Pass:         %s\n' "$pass_count"
                printf 'Fail:         %s\n' "$fail_count"
                printf 'Not checked:  %s\n\n' "$notchecked_count"
                printf '--- Top 25 failing rules ---\n'
                awk -F'"' '/result="fail"/{for(i=1;i<NF;i++) if($i=="idref") print $(i+1)}' \
                  /root/scap-results.xml 2>/dev/null \
                  | head -25 \
                  || printf '(no failures found or XML parse error)\n'
            } | write_user_report "section-22-openscap-summary-${REPORT_DATE}.txt" || true
            local fail_n
            fail_n="${fail_count//[^0-9]/}"
            if [[ -n "$fail_n" ]] && (( fail_n > 0 )) 2>/dev/null; then
                add_action_item 22 HIGH "SCAP_FAILED_RULES" \
                    "OpenSCAP: $fail_count rule(s) failed — review $USER_RESULTS_DIR/section-22-openscap-${REPORT_DATE}.html"
            else
                ok "OpenSCAP scan: $pass_count passing, $fail_count failing."
            fi
        else
            add_action_item 22 MEDIUM "SCAP_NO_SCAN" \
                "OpenSCAP scan was skipped or results not found — rerun section 22 to generate compliance report."
        fi
    fi
}

# ---------- Actionable-items display + remediation --------------------------
# show_actionable_items() - Print the full prioritized actionable items list.
show_actionable_items() {
    if (( ${#ACTIONABLE_ITEMS[@]} == 0 )); then
        ok "No actionable items — sections 12/18/21/22 appear clean."
        return 0
    fi
    if (( ! GUI_FULL_MODE )); then
        printf '\n%s════════ Actionable Items (%d found) ════════%s\n' "$C_YEL" "${#ACTIONABLE_ITEMS[@]}" "$C_RST"
        local idx=1
        for item in "${ACTIONABLE_ITEMS[@]}"; do
            local section priority tag desc
            IFS='|' read -r section priority tag desc <<<"$item"
            case "$priority" in
                HIGH)   printf '%s  [%2d] [%s][%s] %s%s\n' "$C_RED" "$idx" "$priority" "$section" "$desc" "$C_RST" ;;
                MEDIUM) printf '%s  [%2d] [%s][%s] %s%s\n' "$C_YEL" "$idx" "$priority" "$section" "$desc" "$C_RST" ;;
                *)      printf '%s  [%2d] [%s][%s] %s%s\n' "$C_BLU" "$idx" "$priority" "$section" "$desc" "$C_RST" ;;
            esac
            ((idx++))
        done
        printf '%s════════════════════════════════════════════%s\n\n' "$C_YEL" "$C_RST"
    else
        local msg="Actionable Items (${#ACTIONABLE_ITEMS[@]}):"$'\n'
        for item in "${ACTIONABLE_ITEMS[@]}"; do
            local section priority tag desc
            IFS='|' read -r section priority tag desc <<<"$item"
            msg+="[${priority}][${section}] ${desc}"$'\n'
        done
        gui_alert warning "$msg"
    fi
}

# remediate_item() - Attempt automated fix for one actionable item identified by tag.
# Returns 0 if resolved, 1 if manual attention still required.
remediate_item() {
    local tag="$1"
    case "$tag" in
        FAIL2BAN_NOT_RUNNING)
            info "Attempting to restart fail2ban..."
            if systemctl restart fail2ban 2>/dev/null; then
                ok "fail2ban restarted successfully."
                return 0
            fi
            warn "fail2ban restart failed — check: journalctl -u fail2ban"
            return 1
            ;;
        CLAMAV_FRESHCLAM_NOT_RUNNING)
            info "Attempting to start clamav-freshclam..."
            if systemctl start clamav-freshclam 2>/dev/null; then
                ok "clamav-freshclam started."
                return 0
            fi
            warn "clamav-freshclam failed to start — check: journalctl -u clamav-freshclam"
            return 1
            ;;
        CLAMAV_CLAMD_NOT_RUNNING)
            info "Attempting to start clamd@scan..."
            if systemctl start clamd@scan 2>/dev/null || systemctl start clamd@scan.service 2>/dev/null; then
                ok "clamd@scan started."
                return 0
            fi
            warn "clamd@scan failed to start — check: journalctl -u clamd@scan"
            return 1
            ;;
        CLAMAV_FRESHCLAM_OUTDATED)
            info "Updating ClamAV virus definitions (freshclam)..."
            (( DRY_RUN )) && { info "Would run: freshclam"; return 1; }
            if freshclam 2>/dev/null; then
                ok "ClamAV definitions updated."
                return 0
            fi
            warn "freshclam failed — daemon may hold lock; retry after clamd starts."
            return 1
            ;;
        CLAMAV_INITIAL_SCAN)
            info "Running initial ClamAV scan of home directory (this may take several minutes)..."
            local scan_user="${TARGET_USER:-${SUDO_USER:-}}"
            local scan_home; scan_home="$(user_home "$scan_user" 2>/dev/null || echo "/root")"
            if (( DRY_RUN )); then
                info "Would run: clamscan -r --infected '$scan_home'"
                return 1
            fi
            local scan_tmp="/tmp/clamscan-out-$$.tmp"
            register_tmp "$scan_tmp"
            log "[RUN]   clamscan -r --infected $scan_home"
            if (( GUI_FULL_MODE )); then
                clamscan -r --infected "$scan_home" >"$scan_tmp" 2>&1 || true
            else
                clamscan -r --infected "$scan_home" 2>&1 | tee "$scan_tmp" || true
            fi
            local infected; infected="$(awk '/ FOUND$/{count++} END{print count+0}' "$scan_tmp" 2>/dev/null || echo 0)"
            {
                printf '=== ClamAV Initial Home Scan ===\nDate: %s\nTarget: %s\n\n' "$RUN_STAMP_HUMAN" "$scan_home"
                cat "$scan_tmp"
            } | write_user_report "section-21-clamav-initial-scan-${REPORT_DATE}.txt" || true
            if (( infected > 0 )); then
                warn "ClamAV found $infected infected file(s) — review the scan report."
                add_action_item 21 HIGH "CLAMAV_INFECTED" \
                    "ClamAV found $infected infected file(s) — manual quarantine/deletion required."
                return 1
            fi
            ok "ClamAV scan complete — no infected files found in $scan_home."
            return 0
            ;;
        AIDE_DB_MISSING)
            info "Attempting to initialize AIDE database..."
            (( DRY_RUN )) && { info "Would run: aide --init"; return 1; }
            if aide --init 2>/dev/null && \
               mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz 2>/dev/null; then
                ok "AIDE database initialized."
                return 0
            fi
            warn "AIDE initialization failed — run: sudo aide --init && sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
            return 1
            ;;
        SCAP_FAILED_RULES)
            info "OpenSCAP failures require manual review."
            info "  HTML report:  ${USER_RESULTS_DIR:+$USER_RESULTS_DIR/section-22-openscap-${REPORT_DATE}.html}"
            info "  Text summary: ${USER_RESULTS_DIR:+$USER_RESULTS_DIR/section-22-openscap-summary-${REPORT_DATE}.txt}"
            if [[ -f /root/scap-results.xml ]]; then
                info "  Top 10 failed rules:"
                awk -F'"' '/result="fail"/{for(i=1;i<NF;i++) if($i=="idref") print $(i+1)}' /root/scap-results.xml 2>/dev/null \
                    | head -10 \
                    | while IFS= read -r rule; do info "    • $rule"; done || true
            fi
            return 1
            ;;
        RK_WARNINGS)
            info "rkhunter warnings require manual investigation:"
            info "  Report: ${USER_RESULTS_DIR:+$USER_RESULTS_DIR/section-12-rkhunter-aide-${REPORT_DATE}.txt}"
            info "  After investigating, run: sudo rkhunter --propupd"
            return 1
            ;;
        AIDE_RECHECK|FAIL2BAN_REVIEW|CLAMAV_REVIEW|SCAP_NO_SCAN|CLAMAV_INFECTED)
            info "Item [${tag}] requires manual review — see reports in: ${USER_RESULTS_DIR:-$LOG_FILE}"
            return 1
            ;;
        *)
            info "No automated fix for tag '${tag}' — manual review required."
            return 1
            ;;
    esac
}

# remediation_loop() - Iteratively resolve all actionable items after summary approval.
remediation_loop() {
    (( ${#ACTIONABLE_ITEMS[@]} == 0 )) && return 0
    local round=1 max_rounds=5 prev_count=-1
    while (( ${#ACTIONABLE_ITEMS[@]} > 0 && round <= max_rounds )); do
        local current_count="${#ACTIONABLE_ITEMS[@]}"
        (( current_count == prev_count )) && break   # No progress — stop
        prev_count="$current_count"
        printf '\n'
        info "=== Remediation round $round of $max_rounds (${#ACTIONABLE_ITEMS[@]} item(s) remaining) ==="
        show_actionable_items
        local remaining_items=()
        for item in "${ACTIONABLE_ITEMS[@]}"; do
            local section priority tag desc
            IFS='|' read -r section priority tag desc <<<"$item"
            if remediate_item "$tag"; then
                REMEDIATED_ITEMS+=("$item")
                log "[REMEDIATED] [${section}][${tag}] $desc"
                ok "Resolved: [${section}] $desc"
            else
                remaining_items+=("$item")
            fi
        done
        if (( ${#remaining_items[@]} > 0 )); then
            ACTIONABLE_ITEMS=("${remaining_items[@]}")
        else
            ACTIONABLE_ITEMS=()
        fi
        (( ${#ACTIONABLE_ITEMS[@]} == 0 )) && { ok "All actionable items resolved in round $round."; break; }
        ((round++))
    done
    if (( ${#ACTIONABLE_ITEMS[@]} > 0 )); then
        warn "${#ACTIONABLE_ITEMS[@]} item(s) could not be auto-resolved and require manual action:"
        show_actionable_items
    fi
    if (( ${#REMEDIATED_ITEMS[@]} > 0 )); then
        ok "${#REMEDIATED_ITEMS[@]} item(s) were successfully remediated this session."
    fi
}

# ---------- Summary ---------------------------------------------------------
# final_summary() - Analyze section 12/18/21/22 findings, write all reports to
# user Downloads/<project>/results and Downloads/<project>/logs, display actionable list, and ask
# whether to implement recommended next steps. If declined, export a PDF audit
# report plus TXT import bundle into the user's Downloads directory instead of
# running remediation. If approved, the user can implement all or selected items.
final_summary() {
    local summary_file="harden-summary-${REPORT_DATE}.txt"
    local summary_path=""
    # Precompute platform label once — avoids two subshell spawns in report + terminal output.
    local _plat; (( IS_OSTREE )) && _plat="rpm-ostree (immutable)" || _plat="dnf (mutable)"

    # Write overall human-readable summary to Downloads/<project>/results/
    if [[ -n "$USER_RESULTS_DIR" ]]; then
        {
            printf '=== Fedora Hardening Run Summary ===\n'
            printf 'Generated:    %s\n' "$RUN_STAMP_HUMAN"
            printf 'Host:         %s\n' "$HOST_LABEL"
            printf 'Log file:     %s\n' "$LOG_FILE"
            printf 'Backups:      %s\n' "$BACKUP_DIR"
            printf 'Target user:  %s\n' "${TARGET_USER:-<none>}"
            printf 'Platform:     %s\n\n' "${_plat}"
            printf '=== Actionable Items (%d) ===\n' "${#ACTIONABLE_ITEMS[@]}"
            if (( ${#ACTIONABLE_ITEMS[@]} > 0 )); then
                local idx=1
                for item in "${ACTIONABLE_ITEMS[@]}"; do
                    local section priority tag desc
                    IFS='|' read -r section priority tag desc <<<"$item"
                    printf '  [%2d] [%s][%s] %s\n' "$idx" "$priority" "$section" "$desc"
                    ((idx++))
                done
            else
                printf '  None — sections 12/18/21/22 appear clean.\n'
            fi
            printf '\n=== Remediated Items (%d) ===\n' "${#REMEDIATED_ITEMS[@]}"
            if (( ${#REMEDIATED_ITEMS[@]} > 0 )); then
                for item in "${REMEDIATED_ITEMS[@]}"; do
                    local section priority tag desc
                    IFS='|' read -r section priority tag desc <<<"$item"
                    printf '  [RESOLVED][%s][%s] %s\n' "$priority" "$section" "$desc"
                done
            fi
            printf '\n=== Manual Follow-up Items ===\n'
            printf '  • LUKS full-disk encryption  — set during Fedora installation only.\n'
            printf '  • GRUB password (section 6b) — run: sudo grub2-mkpasswd-pbkdf2\n'
            printf '  • SSH keys                   — generate on CLIENT, then: ssh-copy-id user@host\n'
            printf '  • WireGuard tunnel           — configure /etc/wireguard/wg0.conf with peer keys.\n'
            printf '  • arkenfox overrides         — add exceptions in user-overrides.js as needed.\n'
            printf '  • KDE GUI-only settings      — KWallet master password, Privacy, Activity.\n'
            printf '  • AIDE re-init               — after any future package updates.\n'
            printf '  • REBOOT RECOMMENDED         — to apply kernel/sysctl/PAM/GRUB changes.\n'
            (( IS_OSTREE )) && printf '  • rpm-ostree REBOOT         — required for staged/layered package changes.\n'
            printf '\n=== Section Reports in Downloads/%s/results/ ===\n' "$PROJECT_NAME"
            for f in "$USER_RESULTS_DIR"/section-*.txt "$USER_RESULTS_DIR"/section-*.html; do
                [[ -f "$f" ]] && printf '  %s\n' "$(basename "$f")"
            done || true
        } | write_user_report "$summary_file" || true
        summary_path="${USER_RESULTS_DIR}/${summary_file}"
    fi

    # Copy the main harden log to Downloads/<project>/logs/
    copy_log_to_user

    # Display terminal summary
    if (( ! GUI_FULL_MODE )); then
        printf '\n%s════════════════════════ Summary ════════════════════════%s\n' "$C_GRN" "$C_RST"
        local reports_line="" ostree_line=""
        [[ -n "$USER_RESULTS_DIR" ]] && reports_line=" Reports:      $USER_RESULTS_DIR"
        (( IS_OSTREE )) && ostree_line=$'\n On rpm-ostree systems, reboot is also required to apply layered package changes and staged updates.'
        cat <<EOF
    Log file:     $LOG_FILE
    Backups:      $BACKUP_DIR  (empty if no changes needed)
    Target user:  ${TARGET_USER:-<none>}
    Platform:     ${_plat}
    $reports_line
    Manual follow-up items (from the guide, NOT automated by this script):
       • LUKS full-disk encryption — set during Fedora installation only.
       • GRUB password (§6b) — run 'sudo grub2-mkpasswd-pbkdf2' manually.
       • SSH keys — generate on your CLIENT machine and ssh-copy-id to this host.
       • WireGuard tunnel — edit /etc/wireguard/wg0.conf with your peer keys.
       • Review arkenfox defaults and add local exceptions in user-overrides.js as needed.
       • KDE GUI-only settings: KWallet master password, Privacy, Activity tracking.
       • Re-initialize AIDE database after any legitimate package upgrade.

    A REBOOT is recommended to pick up kernel, GRUB, sysctl, and PAM changes.$ostree_line
EOF
        printf '%s═════════════════════════════════════════════════════════%s\n' "$C_GRN" "$C_RST"
    else
        log "Summary: log=$LOG_FILE backups=$BACKUP_DIR target_user=${TARGET_USER:-<none>}"
        log "Summary: reboot recommended for kernel/GRUB/sysctl/PAM changes"
        (( IS_OSTREE )) && log "Summary: reboot required on rpm-ostree for staged/layered changes"
    fi

    gui_alert info "Fedora hardening finished.\n\nLog: $LOG_FILE\nBackups: $BACKUP_DIR${USER_RESULTS_DIR:+\nReports: $USER_RESULTS_DIR}"

    # Display the actionable items from sections 12/18/21/22 and handle approval/selection.
    handle_actionable_follow_up "$summary_path"

    # Re-write the summary with final state (after remediation updates ACTIONABLE/REMEDIATED lists)
    if [[ -n "$USER_RESULTS_DIR" ]] && (( ${#REMEDIATED_ITEMS[@]} > 0 )); then
        {
            printf '=== Fedora Hardening — Post-Remediation Summary Update ===\n'
            printf 'Generated: %s\n\n' "$RUN_STAMP_HUMAN"
            printf 'Remaining actionable items: %d\n' "${#ACTIONABLE_ITEMS[@]}"
            printf 'Remediated this session:    %d\n\n' "${#REMEDIATED_ITEMS[@]}"
            for item in "${REMEDIATED_ITEMS[@]}"; do
                local section priority tag desc
                IFS='|' read -r section priority tag desc <<<"$item"
                printf '  [RESOLVED][%s][%s] %s\n' "$priority" "$section" "$desc"
            done
            if (( ${#ACTIONABLE_ITEMS[@]} > 0 )); then
                printf '\nStill requires manual action:\n'
                for item in "${ACTIONABLE_ITEMS[@]}"; do
                    local section priority tag desc
                    IFS='|' read -r section priority tag desc <<<"$item"
                    printf '  [MANUAL][%s][%s] %s\n' "$priority" "$section" "$desc"
                done
            fi
        } | write_user_report "harden-remediation-update-${REPORT_DATE}.txt" || true
    fi
}

# ---------- Main ------------------------------------------------------------
main() {
    parse_args "$@"
    preflight
    if (( PRECHECK_FAILED )); then
        EXPECTED_ABORT=1
        exit 1
    fi
    init_user_report_dirs
    if [[ -n "$IMPORT_AUDIT_PATH" ]]; then
        import_audit_items "$IMPORT_AUDIT_PATH" || exit 1
        handle_actionable_follow_up ""
        exit 0
    fi
    calc_section_total
    gui_progress_start
    abort_if_cancelled

    # Execution order is optimized for dependency flow and operational safety.
    sec_02_updates
    sec_03_dnf_automatic
    sec_06_secureboot
    sec_13_flatpak
    sec_04_selinux
    sec_05_firewalld
    sec_07_ssh
    sec_09_pam
    sec_10_sysctl
    sec_11_auditd
    sec_14_dot
    sec_18_fail2ban
    sec_15_kde
    sec_16_firefox
    sec_17_wireguard
    sec_21_clamav
    sec_22_openscap
    sec_12_ids
    sec_19_services
    sec_20_perms
    sec_08_usbguard

    gui_progress_close
    final_summary
    
    # Execute error analysis and auto-remediation loop to resolve any issues detected
    info "Running error analysis and auto-remediation cycle..."
    validate_and_remediate_loop || warn "Some errors may require manual intervention — review logs"
    ok "Script execution complete. See logs for full details."
}

main "$@"
