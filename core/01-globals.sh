# shellcheck shell=bash
# ---------- Globals ---------------------------------------------------------
SCRIPT_NAME="$(basename "$0")"
# SCRIPT_DIR, the project directory, is set by fedora-harden.sh before this file loads.
PROJECT_NAME="$(basename "$SCRIPT_DIR")"
RUN_STAMP="$(date +%Y%m%d-%H%M%S)"
# Session IDs have one-second resolution. A run started in the same second as the
# previous one would share its backup directory and truncate its rollback journal,
# so wait for an unused second.
while [[ -e "/root/harden-backups-${RUN_STAMP}" || -e "/var/log/fedora-harden/harden-${RUN_STAMP}.log" ]]; do
	sleep 1
	RUN_STAMP="$(date +%Y%m%d-%H%M%S)"
done
RUN_DATE_YMD="${RUN_STAMP%%-*}"
RUN_STAMP_HUMAN="${RUN_STAMP/-/ }"
RUN_STAMP_ISO=""
HOST_LABEL=""
KERNEL_LABEL=""
LOG_DIR="/var/log/fedora-harden"
LOG_FILE="${LOG_DIR}/harden-${RUN_STAMP}.log"
BACKUP_DIR="/root/harden-backups-${RUN_STAMP}"
# On image-based systems these tools live in a box instead of the image (section 18).
TOOLS_BOX="fedora-harden-tools"
TOOLS_BOX_PKGS="openscap-scanner scap-security-guide setools-console buildah skopeo podman-compose"
# This release. The release workflow refuses a tag that doesn't match it.
FH_VERSION="1.1.0"

# ClamAV image for the scheduled scan on image-based systems (section 16). The
# signatures ship in the image; minor version pinned, patch releases follow.
CLAMAV_IMAGE="docker.io/clamav/clamav:1.5"

# arkenfox user.js release installed by section 14 (pinned + checksum-verified).
ARKENFOX_VERSION="144.0"
ARKENFOX_SHA256="e4ab33c6914899175cf7035e0e57a2d7f08ac887d8f957f1199e7e49bbe7e33e"

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

# ---------- Command-line option flags -----------------------------------------
TARGET_USER=""         # Target username for SSH/home-dir hardening (--user)
WG_CONFIG=""           # WireGuard config to install with kill switch (--wireguard-config)
PROFILE_ARG=""         # Use cases for section 19 (--profile everyday,gaming,creative,dev,laptop,private)
RESTORE_FILE=""        # Recovery file to replay (--restore FILE)
INCLUDE_SETUP=0        # --report also shows the recovery file's contents (--include-setup)
RECOVERY_BACKUP_ARG="" # Copy the recovery file into the home backups: yes|no (--recovery-backup on|off)
BACKUP_TARGET=""       # Second drive for home copies on systems without Btrfs (--backup-target)
ROUTINE_HELPER="/usr/local/libexec/fedora-harden-routine"
ROUTINE_ACTIVE=0 # Section 19 ran: record the managed state for the drift check
ASSUME_YES=0     # Non-interactive mode (--yes)
DRY_RUN=0        # Print what would run without making changes (--dry-run)
SKIP_LIST=""     # Comma-separated section numbers to skip (--skip)
ONLY_LIST=""     # Comma-separated sections to run exclusively (--only)
REPORT_MODE=0    # Write an HTML report of the last session (--report)
REPORT_FILE=""   # Where to write it (--report FILE)
REPORT_FULL=0    # Keep host, user names, home paths and addresses in it (--full)
RESUME_MODE=0    # Review the last session's open follow-ups (--resume)
SCORE_MODE=0     # Print the protection scorecard and exit (--score)
SCORE_JSON=0     # With --score: print it as JSON (--json)
SCORE_FD=1       # Where the JSON goes (main points it at the real stdout)
FORCE_GUI=0      # Run in one window (--gui)

# Add the kernel boot hardening options without asking (--kernel-hardening)
KERNEL_HARDENING=0

# ---------- GUI mode state ------------------------------------------------
AIDE_BASELINE_PENDING=0 # Section 24 asks for the AIDE baseline; it is recorded last
GUI_FULL_MODE=0         # Set to 1 while the --gui window is open
GUI_CANCEL_REQUESTED=0  # Set to 1 when the user stops the run from the window

# ---------- Execution state flags -------------------------------------------
LOG_READY=0       # Set to 1 after log file initialized
PRECHECK_FAILED=0 # Set to 1 if preflight checks fail
EXPECTED_ABORT=0  # Set to 1 if clean exit expected (--list, --rollback)

# ---------- Platform/variant detection flags --------------------------------
IS_OSTREE=0            # 1 on image-based systems (set by the platform file)
ETC_BASELINE_PENDING=0 # Section 24 (image-based): record the /etc baseline after the last section
HAS_KDE=0              # Set to 1 if KDE Plasma session detected
HAS_GNOME=0            # Set to 1 if GNOME session detected
HAS_SWAY=0             # Set to 1 if Sway/wlroots compositor detected
HAS_HYPRLAND=0         # Set to 1 if Hyprland compositor detected
HAS_I3=0               # Set to 1 if i3 window manager detected
HAS_XFCE=0             # Set to 1 if XFCE desktop detected
HAS_CINNAMON=0         # Set to 1 if Cinnamon desktop detected
HAS_MATE=0             # Set to 1 if MATE desktop detected
HAS_BUDGIE=0           # Set to 1 if Budgie desktop detected
HAS_LXQT=0             # Set to 1 if LXQt desktop detected
HAS_DESKTOP=0          # Set to 1 if any desktop environment detected
DESKTOP_ENVS=""        # Comma-separated list of detected desktop environments
UI_SECTION_DONE=0      # Count of completed sections for progress tracking
CURRENT_SECTION=0      # Section number currently executing (for action items)
UI_SECTION_TOTAL=23    # Total hardening sections to execute

# Error tracking & remediation infrastructure
ERROR_CAPTURE_FILE=""        # Temp file for capturing command stderr
declare -gi ERR_COUNT=0      # Steps that reported an error this run
declare -gA TOUCHED_UNITS=() # Units this run enabled/started/restarted (diagnosis)
LOG_JOURNAL=0                # 1 = messages go to the system journal
LOG_WHERE=""                 # Where to read this run's log (journalctl command or file)
# Prevents infinite loops; persistent errors typically need manual intervention
LAST_RUN_CMD="" # Last command dispatched via run()

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
declare -ga TEMP_FILES=() # All temp paths to auto-clean on EXIT

# ---------- Rollback & session-tracking globals ------------------------------
FH_STATE="/var/lib/fedora-harden" # Root-only state of this script (not in its folder)

ROLLBACK_JOURNAL=""              # Path to per-run change journal inside BACKUP_DIR
SESSION_DIR="$FH_STATE/sessions" # Session and rollback reports (root-only)
SESSION_REPORT_FILE=""           # Path to current session's report in SESSION_DIR
SESSION_STATUS="running"         # Updated to 'completed' or 'aborted' on exit
SESSION_REPORT_WRITTEN=0         # Guards against double-write on abort path
ROLLBACK_SESSION_ID=""           # Session ID to roll back (set by --rollback)
LIST_SESSIONS_MODE=0             # Set by --list-sessions

# Colors (disabled if not a tty)
if [[ -t 1 ]]; then
	C_RED=$'\033[0;31m'
	C_GRN=$'\033[0;32m'
	C_YEL=$'\033[0;33m'
	C_BLU=$'\033[0;34m'
	C_CYN=$'\033[0;36m'
	C_BLD=$'\033[1m'
	C_RST=$'\033[0m'
else
	C_RED=""
	C_GRN=""
	C_YEL=""
	C_BLU=""
	C_CYN=""
	C_BLD=""
	C_RST=""
fi

# Host and date in the banner make long runs easier to track at a glance.
draw_banner() {
	printf '\n%s╔══════════════════════════════════════════════════════════════╗%s\n' "$C_CYN" "$C_RST"
	printf '%s║%s Fedora Hardening Orchestrator                              %s║%s\n' "$C_CYN" "$C_BLD" "$C_CYN" "$C_RST"
	local who
	who="${SUDO_USER:-${USER:-root}}"
	printf '%s║%s %s@%s  %s                                        %s║%s\n' \
		"$C_CYN" "$C_RST" "$who" "$HOST_LABEL" "$RUN_STAMP_HUMAN" "$C_CYN" "$C_RST"
	printf '%s╚══════════════════════════════════════════════════════════════╝%s\n' "$C_CYN" "$C_RST"
}

# Usage: progress_bar <current> <total> [width]
progress_bar() {
	local current="$1" total="$2" width="${3:-28}"
	((total <= 0)) && total=1
	((current < 0)) && current=0
	((current > total)) && current=total
	local filled=$((current * width / total))
	local empty=$((width - filled))
	printf '['
	printf '%*s' "$filled" '' | tr ' ' '#'
	printf '%*s' "$empty" '' | tr ' ' '-'
	printf ']'
}
