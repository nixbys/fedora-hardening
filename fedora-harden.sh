#!/usr/bin/env bash
# =============================================================================
#  Fedora 44+ Security Hardening Script (multi-release + multi-desktop aware)
#  Based on: Fedora44-KDE-Security-Hardening-Guide.md (April 2026)
#  Aligned with privacyguides.org and inteltechniques.com recommendations
#  Efficiency-tuned and low-I/O focused (v2.6 - June 2026)
#
#  FEATURES:
#    • 23 hardening sections (plus subsection 14b) with automatic
#      release/profile detection
#    • Dual-mode support: mutable (dnf) and immutable (rpm-ostree) systems
#    • Fedora release detection: Workstation, Server, IoT, Cloud, CoreOS,
#      Kinoite, Silverblue, Onyx, Sericea, Lazurite, Vauxite, Bazzite, Aurora,
#      and all Atomic desktop variants
#    • Full desktop environment support: KDE Plasma, GNOME, Budgie, Cinnamon,
#      MATE, XFCE, LXQt, Sway, Hyprland, i3 — with per-DE privacy/screen-lock
#      settings configured from the CLI
#    • Firefox Flatpak hardening with arkenfox + 3 security extensions (uBlock, LocalCDN, Containers)
#    • VPN detection (WireGuard, NetworkManager, Mullvad, ProtonVPN) with
#      recommendations when absent (Mullvad/ProtonVPN/IVPN per privacyguides.org)
#    • Firmware and CPU microcode updates via fwupd (privacyguides.org)
#    • NetworkManager MAC address randomization (privacyguides.org network privacy)
#    • IPv6 privacy extensions (RFC 4941 temporary addresses)
#    • Rootless Podman + Toolbox containerized-mindset setup (image policy, seccomp,
#      no-new-privileges, subuid/subgid, unqualified-registry block)
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
#    • Full rollback support: per-session change journal + --rollback to undo any run
#    • Full-reset failsafe: --rollback all reverses every session from the very first run
#    • Pre-journal session support: raw file restore for runs predating the journal feature
#    • Session reports: written to ./sessions/ on every exit (success or abort)
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
#        --list-sessions    List all past hardening sessions with their status
#        --rollback [id|all] Roll back changes from the last session (or session <id>)
#                           Use 'all' to perform a full-reset rollback of every session
#                           from the very first run (failsafe complete reversal).
#                           Sessions without a journal have backed-up files restored;
#                           use --list-sessions first to view available session IDs.
#    -h, --help             Show this help and exit
#
#  SECTIONS (execution order optimized for dependency flow):
#     2  System updates (dnf upgrade + fwupd firmware/microcode install
#        + optional hardware security key support: YubiKey/FIDO2/PIV/pam-u2f)
#     3  Automatic updates (dnf5-automatic or rpm-ostreed)
#     4  SELinux verification + tools
#     5  firewalld hardening (drop-default policy)
#     6  Secure Boot verification (GRUB password is manual — printed as a note)
#     7  SSH hardening (key-based auth, hardened cipher suite)
#     8  USBGuard (interactive — can lock out input devices if misconfigured)
#     9  Password & PAM policy (pwquality, faillock, account aging)
#    10  Kernel sysctl hardening (network, VM, filesystem, IPv6 privacy extensions)
#    11  auditd rules (identity, privilege escalation, module tracking,
#        time/network-config/mount/delete syscall coverage)
#    12  rkhunter + AIDE (rootkit detection + file integrity monitoring)
#    13  Flatpak / Flathub (app sandboxing foundation) + optional Firejail
#    14  DNS over TLS (systemd-resolved with Quad9 + Cloudflare)
#   14b  NetworkManager MAC address randomization (network-layer privacy)
#    15  Desktop environment settings — auto-dispatches by detected DE:
#            KDE Plasma (kwriteconfig6/5: screen lock, recent-docs, BT)
#            GNOME/Onyx (gsettings: lock, location, privacy, mic)
#            Budgie     (gsettings GNOME backend)
#            Cinnamon   (org.cinnamon.desktop.screensaver + GNOME privacy)
#            MATE       (org.mate.screensaver + power-manager)
#            XFCE/Vauxite (xfconf-query: screensaver, power manager)
#            Sway/Sericea (swaylock.conf + swayidle.conf)
#            Hyprland   (hypridle.conf)
#            i3         (xss-lock + i3lock drop-in via config.d/)
#            LXQt/Lazurite (lxqt-screensaver.conf + lxqt-powermanagement.conf)
#    16  Firefox Flatpak + arkenfox + extensions (uBlock Origin, LocalCDN,
#        Multi-Account Containers) + VPN detection + recommendations
#    17  WireGuard tool install (tunnel config is manual; autostart guidance)
#    18  Fail2Ban (intrusion detection + auto-ban)
#    19  Disable unnecessary services (avahi, cups, bluetooth, modemmanager)
#    20  File permission hardening (shadow files, /tmp, compiler access,
#        umask 077, core dump limits, hostname privacy check)
#    21  ClamAV install + freshclam + on-access scanning for /home
#    22  OpenSCAP scanner install + initial scan (compliance framework)
#    23  Container security — rootless Podman + Toolbox (containerized-mindset setup:
#        image policy hardening, no-new-privileges, seccomp, subuid/subgid,
#        unqualified-registry block, optional buildah/skopeo/podman-compose)
#
#  SECTIONS NOT AUTOMATED (by design):
#     1  LUKS — must be chosen during Anaconda install
#    6b  GRUB password — requires interactive grub2-mkpasswd-pbkdf2
#    15  KDE GUI-only screens (Privacy, KWallet master password, Activity tracking)
#    15  GNOME GUI-only screens (Online Accounts, Sharing, Bluetooth)
#    15  Sway compositor: add 'exec swayidle -w' to sway config (action item)
#    15  Hyprland: add 'exec-once = hypridle' to hyprland.conf (action item)
#    15  i3: add lock keybind (action item)
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
#    ✓ Fedora Silverblue (immutable, rpm-ostree + GNOME)
#    ✓ Fedora Onyx (immutable, rpm-ostree + GNOME Atomic)
#    ✓ Fedora Sericea (immutable, rpm-ostree + Sway Atomic)
#    ✓ Fedora Lazurite (immutable, rpm-ostree + LXQt Atomic)
#    ✓ Fedora Vauxite (immutable, rpm-ostree + XFCE Atomic)
#    ✓ Bazzite (gaming remix, rpm-ostree + KDE or GNOME)
#    ✓ Aurora / Universal Blue (rpm-ostree + KDE)
#    ✓ Fedora XFCE Spin (mutable, dnf + XFCE)
#    ✓ Fedora LXQt Spin (mutable, dnf + LXQt)
#    ✓ Fedora Cinnamon Spin (mutable, dnf + Cinnamon)
#    ✓ Fedora MATE-Compiz Spin (mutable, dnf + MATE)
#    ✓ Fedora Budgie Spin (mutable, dnf + Budgie)
#    Auto-detection: Reads /etc/os-release metadata + /run/ostree-booted
#    Desktop detection: XDG_CURRENT_DESKTOP + installed tooling/packages
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

# ---------- Command-line option flags -----------------------------------------
TARGET_USER=""       # Target username for SSH/home-dir hardening (--user)
ASSUME_YES=0         # Non-interactive mode (--yes)
DRY_RUN=0            # Print what would run without making changes (--dry-run)
SKIP_LIST=""         # Comma-separated section numbers to skip (--skip)
ONLY_LIST=""         # Comma-separated sections to run exclusively (--only)
IMPORT_AUDIT_PATH="" # Path to audit PDF/TXT to import (--import-audit)
FORCE_GUI=0          # Request graphical prompts (--gui)
FORCE_GUI_FULL=0     # Full GUI frontend with progress (--gui-full)

# ---------- GUI mode state ------------------------------------------------
GUI_MODE=0              # Set to 1 if kdialog/zenity available and enabled
GUI_FULL_MODE=0         # Set to 1 if --gui-full requested and display available
GUI_TOOL=""             # Selected dialog tool: "kdialog" or "zenity"
GUI_PROGRESS_REF=""     # D-Bus reference for kdialog progress tracking
QDBUS_CMD=""            # qdbus binary name (qdbus-qt6 / qdbus-qt5 / qdbus)
GUI_PROGRESS_PIPE_FD="" # File descriptor for GUI progress updates
GUI_PROGRESS_PID=""     # PID of running GUI progress process
GUI_LAST_STATUS=""      # Last status message sent to GUI
GUI_CANCEL_REQUESTED=0  # Set to 1 if user cancels via GUI

# ---------- Execution state flags -------------------------------------------
LOG_READY=0       # Set to 1 after log file initialized
PRECHECK_FAILED=0 # Set to 1 if preflight checks fail
EXPECTED_ABORT=0  # Set to 1 if clean exit expected (--list, --rollback)

# ---------- Platform/variant detection flags --------------------------------
IS_OSTREE=0              # Set to 1 if system uses immutable rpm-ostree
IS_KINOITE=0             # Set to 1 if Fedora Kinoite (immutable + KDE)
IS_SILVERBLUE=0          # Set to 1 if Fedora Silverblue (immutable + GNOME)
IS_ONYX=0                # Set to 1 if Fedora Onyx (immutable + GNOME, Atomic)
IS_SERICEA=0             # Set to 1 if Fedora Sericea (immutable + Sway, Atomic)
IS_LAZURITE=0            # Set to 1 if Fedora Lazurite (immutable + LXQt, Atomic)
IS_VAUXITE=0             # Set to 1 if Fedora Vauxite (immutable + XFCE, Atomic)
IS_BAZZITE=0             # Set to 1 if Bazzite (gaming remix, KDE or GNOME)
IS_AURORA=0              # Set to 1 if Aurora (Universal Blue KDE remix)
IS_SERVER=0              # Set to 1 if Fedora Server
IS_WORKSTATION=0         # Set to 1 if Fedora Workstation
IS_IOT=0                 # Set to 1 if Fedora IoT (immutable)
IS_CLOUD=0               # Set to 1 if Fedora Cloud
IS_COREOS=0              # Set to 1 if Fedora CoreOS (immutable)
IS_ATOMIC_DESKTOP=0      # Set to 1 if Atomic Desktop variant
IS_GAMING_SPIN=0         # Set to 1 if gaming-oriented spin (Bazzite, etc.)
IS_FEDORA=0              # Set to 1 if any Fedora detected
HAS_KDE=0                # Set to 1 if KDE Plasma session detected
HAS_GNOME=0              # Set to 1 if GNOME session detected
HAS_SWAY=0               # Set to 1 if Sway/wlroots compositor detected
HAS_HYPRLAND=0           # Set to 1 if Hyprland compositor detected
HAS_I3=0                 # Set to 1 if i3 window manager detected
HAS_XFCE=0               # Set to 1 if XFCE desktop detected
HAS_CINNAMON=0           # Set to 1 if Cinnamon desktop detected
HAS_MATE=0               # Set to 1 if MATE desktop detected
HAS_BUDGIE=0             # Set to 1 if Budgie desktop detected
HAS_LXQT=0               # Set to 1 if LXQt desktop detected
HAS_DESKTOP=0            # Set to 1 if any desktop environment detected
DESKTOP_ENVS=""          # Comma-separated list of detected desktop environments
FEDORA_VARIANT="unknown" # Human-readable Fedora variant name
FEDORA_MAJOR=0           # Fedora major version number
UI_SECTION_DONE=0        # Count of completed sections for progress tracking
UI_SECTION_TOTAL=23      # Total hardening sections to execute

# Error tracking & remediation infrastructure
ERROR_LOG=""                         # Structured error log file path
ERROR_CAPTURE_FILE=""                # Temp file for capturing command stderr
declare -ga ERROR_DETAILS=()         # Array: "line|cmd|exit_code|stderr|timestamp"
declare -gi LAST_ERROR_COUNT=0       # Track errors for remediation loop
declare -gi REMEDIATION_PASS=0       # Current pass through remediation
declare -gi MAX_REMEDIATION_PASSES=3 # Max auto-remediation attempts
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
ROLLBACK_JOURNAL=""                  # Path to per-run change journal inside BACKUP_DIR
SESSION_DIR="${SCRIPT_DIR}/sessions" # Project-relative sessions report directory
SESSION_REPORT_FILE=""               # Path to current session's report in SESSION_DIR
SESSION_STATUS="running"             # Updated to 'completed' or 'aborted' on exit
SESSION_REPORT_WRITTEN=0             # Guards against double-write on abort path
ROLLBACK_SESSION_ID=""               # Session ID to roll back (set by --rollback)
LIST_SESSIONS_MODE=0                 # Set by --list-sessions

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

# setup_ui_mode() - Configure GUI prompt mode if requested and available.
# Prefers kdialog on KDE systems, then zenity, otherwise falls back to TTY prompts.
setup_ui_mode() {
	local has_display=0
	local prefers_kde=0
	[[ -n "${DISPLAY:-}" || -n "${WAYLAND_DISPLAY:-}" ]] && has_display=1
	[[ "${XDG_CURRENT_DESKTOP:-}${DESKTOP_SESSION:-}" =~ ([Kk][Dd][Ee]|[Pp]lasma) ]] && prefers_kde=1

	# If GUI mode is requested, try to satisfy missing GUI dialog dependencies.
	if ((has_display && (FORCE_GUI || FORCE_GUI_FULL))); then
		if ((prefers_kde)); then
			cmd_exists kdialog || ensure_command_dep kdialog "GUI dialog mode" kdialog
		fi
		if ! cmd_exists kdialog; then
			cmd_exists zenity || ensure_command_dep zenity "GUI dialog fallback" zenity
		fi
	fi

	if ((has_display)) && cmd_exists kdialog; then
		GUI_TOOL="kdialog"
	elif ((has_display)) && cmd_exists zenity; then
		GUI_TOOL="zenity"
	fi

	if ((FORCE_GUI)); then
		if [[ -n "$GUI_TOOL" ]]; then
			GUI_MODE=1
			info "GUI mode enabled using $GUI_TOOL dialogs."
		else
			GUI_MODE=0
			warn "--gui requested, but no supported GUI dialog tool was found. Falling back to terminal prompts."
			warn "Install 'kdialog' (KDE) or 'zenity' (GTK) to use GUI prompts."
		fi
	fi

	if ((FORCE_GUI_FULL)); then
		FORCE_GUI=1
		if [[ -n "$GUI_TOOL" ]]; then
			if [[ "$GUI_TOOL" == "kdialog" ]]; then
				# Fedora 44+ ships qdbus-qt6; older releases use qdbus-qt5 or qdbus.
				# Install the package if needed, then probe all known binary names.
				if ! cmd_exists qdbus-qt6 && ! cmd_exists qdbus-qt5 && ! cmd_exists qdbus; then
					install_dep_candidates qt6-qttools qt5-qttools 2>/dev/null || true
				fi
				if cmd_exists qdbus-qt6; then
					QDBUS_CMD="qdbus-qt6"
				elif cmd_exists qdbus-qt5; then
					QDBUS_CMD="qdbus-qt5"
				elif cmd_exists qdbus; then
					QDBUS_CMD="qdbus"
				else
					QDBUS_CMD=""
					warn "qdbus not found; kdialog progress updates will be limited."
				fi
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
	local planned=(2 3 6 13 4 5 7 9 10 11 14 18 15 16 17 21 22 23 12 19 20 8)
	local s n=0
	for s in "${planned[@]}"; do
		[[ -n "$ONLY_LIST" ]] && ! in_list "$s" "$ONLY_LIST" && continue
		[[ -n "$SKIP_LIST" ]] && in_list "$s" "$SKIP_LIST" && continue
		((++n))
	done
	((n > 0)) && UI_SECTION_TOTAL="$n" || UI_SECTION_TOTAL="${#planned[@]}"
	UI_SECTION_DONE=0
}

# gui_alert() - Show concise GUI notifications for summary and fatal errors.
# Usage: gui_alert <info|warning|error> <message>
gui_alert() {
	local level="$1" message="$2"
	((GUI_MODE)) || return 0
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

	if ((GUI_MODE)); then
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
	((GUI_FULL_MODE)) || return 0

	case "$GUI_TOOL" in
	kdialog)
		if [[ -n "${QDBUS_CMD:-}" ]]; then
			GUI_PROGRESS_REF="$(kdialog --title "$SCRIPT_NAME" --progressbar "Initializing hardening..." "$UI_SECTION_TOTAL")"
			if [[ -n "$GUI_PROGRESS_REF" ]]; then
				"$QDBUS_CMD" "$GUI_PROGRESS_REF" showCancelButton true >/dev/null 2>&1 || true
				"$QDBUS_CMD" "$GUI_PROGRESS_REF" setLabelText "Preparing section execution..." >/dev/null 2>&1 || true
				"$QDBUS_CMD" "$GUI_PROGRESS_REF" Set "" value 0 >/dev/null 2>&1 || true
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
	((GUI_FULL_MODE)) || return 0
	((total <= 0)) && total=1
	((current < 0)) && current=0
	((current > total)) && current=total
	local pct=$((current * 100 / total))
	GUI_LAST_STATUS="$message"

	case "$GUI_TOOL" in
	kdialog)
		[[ -n "$GUI_PROGRESS_REF" ]] || return 0
		if [[ -n "${QDBUS_CMD:-}" ]] && [[ "$(${QDBUS_CMD} "$GUI_PROGRESS_REF" wasCancelled 2>/dev/null || echo false)" == "true" ]]; then
			GUI_CANCEL_REQUESTED=1
			return 0
		fi
		"${QDBUS_CMD:-qdbus}" "$GUI_PROGRESS_REF" Set "" value "$current" >/dev/null 2>&1 || true
		"${QDBUS_CMD:-qdbus}" "$GUI_PROGRESS_REF" setLabelText "$message" >/dev/null 2>&1 || true
		;;
	zenity)
		[[ -n "$GUI_PROGRESS_PIPE_FD" ]] || return 0
		if ! printf '%s\n# %s\n' "$pct" "$message" 1>&"$GUI_PROGRESS_PIPE_FD" 2>/dev/null; then
			GUI_CANCEL_REQUESTED=1
		fi
		;;
	esac
}

# gui_progress_close() - Gracefully close full-GUI progress resources.
gui_progress_close() {
	((GUI_FULL_MODE)) || return 0

	case "$GUI_TOOL" in
	kdialog)
		if [[ -n "$GUI_PROGRESS_REF" ]]; then
			"${QDBUS_CMD:-qdbus}" "$GUI_PROGRESS_REF" close >/dev/null 2>&1 || true
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
	((GUI_FULL_MODE)) || return 0

	case "$level" in
	info | ok)
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
	((GUI_FULL_MODE)) || return 1
	((GUI_CANCEL_REQUESTED)) && return 0

	case "$GUI_TOOL" in
	kdialog)
		if [[ -n "${QDBUS_CMD:-}" ]] && [[ -n "$GUI_PROGRESS_REF" ]] && [[ "$(${QDBUS_CMD} "$GUI_PROGRESS_REF" wasCancelled 2>/dev/null || echo false)" == "true" ]]; then
			GUI_CANCEL_REQUESTED=1
			return 0
		fi
		;;
	esac
	return 1
}

# abort_if_cancelled() - Gracefully terminate when user cancels from GUI frontend.
# Includes the last status message in the error for context when available.
abort_if_cancelled() {
	if gui_check_cancel; then
		local ctx="${GUI_LAST_STATUS:+ (last: $GUI_LAST_STATUS)}"
		err "Execution cancelled by user from GUI frontend.${ctx}"
		exit 130
	fi
}

# ---------- Logging helpers -------------------------------------------------
# init_log_target() - Ensure log destination exists, with /tmp fallback when needed.
init_log_target() {
	((LOG_READY)) && return 0

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
	if ((LOG_READY)); then
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
	printf '%s %s\n' "$ts" "$*" >>"$LOG_FILE" 2>/dev/null || true
}

# info() - Write informational message to stdout and log (blue color).
# Used for status updates and intermediate steps.
# Usage: info "message text"
info() {
	((!GUI_FULL_MODE)) && printf '%s[INFO]%s  %s\n' "$C_BLU" "$C_RST" "$*"
	log "[INFO]  $*"
	gui_status_event info "$*"
}

# ok() - Write success message to stdout and log (green color).
# Indicates successful completion of a task or verification.
# Usage: ok "message text"
ok() {
	((!GUI_FULL_MODE)) && printf '%s[ OK ]%s  %s\n' "$C_GRN" "$C_RST" "$*"
	log "[OK]    $*"
	gui_status_event ok "$*"
}

# warn() - Write warning message to stdout and log (yellow color).
# Alerts about non-critical issues, skipped steps, or prerequisites.
# Usage: warn "message text"
warn() {
	((!GUI_FULL_MODE)) && printf '%s[WARN]%s  %s\n' "$C_YEL" "$C_RST" "$*"
	log "[WARN]  $*"
	gui_status_event warning "$*"
}

# err() - Write error message to stderr and log (red color).
# Indicates a problem that may prevent further execution.
# Usage: err "message text"
err() {
	((!GUI_FULL_MODE)) && printf '%s[FAIL]%s  %s\n' "$C_RED" "$C_RST" "$*" >&2
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
		stderr_content="${stderr_content//\"/\\\"}"   # Escape quotes
		stderr_content="${stderr_content//$'\n'/ | }" # Replace newlines with |
	else
		stderr_content="(no stderr captured)"
	fi

	# Store as: "line|cmd|exit_code|stderr|timestamp"
	ERROR_DETAILS+=("${line}|${cmd}|${ec}|${stderr_content}|${ts}")

	# Write to structured error log
	{
		printf '{"timestamp":"%s","line":%d,"exit_code":%d,"command":"%s","stderr":"%s"}\n' \
			"$ts" "$line" "$ec" "${cmd//\"/\\\"}" "$stderr_content"
	} >>"$ERROR_LOG" 2>/dev/null || true

	log "[DEBUG] Error at line $line: cmd='$cmd' exit=$ec"
}

# section() - Print formatted section header with visual divider and log entry.
# Displays section number and title with colored borders for visual clarity.
# All section headers are logged for audit trail with timestamps.
# Usage: section <number> <title...>
section() {
	abort_if_cancelled
	local n="$1"
	shift
	((++UI_SECTION_DONE))
	local pct=$((UI_SECTION_DONE * 100 / UI_SECTION_TOTAL))
	local pb
	pb="$(progress_bar "$UI_SECTION_DONE" "$UI_SECTION_TOTAL" 28)"
	if ((!GUI_FULL_MODE)); then
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
	if ((DRY_RUN)); then
		((!GUI_FULL_MODE)) && printf '%s[DRY ]%s  %s\n' "$C_YEL" "$C_RST" "$*"
		((GUI_FULL_MODE)) && gui_status_event info "DRY RUN: $*"
		log "[DRY]   $*"
		return 0
	fi
	log "[RUN]   $*"
	local rc=0
	if ((GUI_FULL_MODE)); then
		: >"$ERROR_CAPTURE_FILE" 2>/dev/null || true
		# shellcheck disable=SC2294
		eval "$@" >>"$LOG_FILE" 2>>"$ERROR_CAPTURE_FILE" || rc=$?
	else
		# Capture stderr for error analysis
		: >"$ERROR_CAPTURE_FILE" 2>/dev/null || true
		# shellcheck disable=SC2294
		eval "$@" 2>>"$ERROR_CAPTURE_FILE" || rc=$?
	fi
	# Log stderr if command failed (applies to GUI and non-GUI modes).
	if ((rc != 0)) && [[ -f "$ERROR_CAPTURE_FILE" && -s "$ERROR_CAPTURE_FILE" ]]; then
		log "[STDERR] $*"
		local line
		while IFS= read -r line; do
			log "[STDERR]   $line"
		done <"$ERROR_CAPTURE_FILE"
		capture_error_context "${BASH_LINENO[0]}" "$*" "$rc" "$ERROR_CAPTURE_FILE"
	fi
	# Record service enable/disable transitions for rollback journal.
	if ((rc == 0)); then
		local _cmd_str="$*"
		if [[ "$_cmd_str" =~ ^[[:space:]]*systemctl[[:space:]]+(enable|disable)[[:space:]] ]]; then
			local _sctl_op="${BASH_REMATCH[1]}"
			local _sctl_rest="${_cmd_str#*systemctl }"
			_sctl_rest="${_sctl_rest#enable }"
			_sctl_rest="${_sctl_rest#disable }"
			_sctl_rest="${_sctl_rest#--now }"
			local _sctl_unit="${_sctl_rest%% *}"
			_sctl_unit="${_sctl_unit%%||*}"
			_sctl_unit="${_sctl_unit%%&*}"
			[[ -n "$_sctl_unit" && "$_sctl_unit" != '--'* ]] &&
				record_change "SERVICE_${_sctl_op^^}" "$_sctl_unit"
		fi
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
# Upgrade failures are treated as warnings, not fatal errors — transient repo
# conflicts or network issues must not abort the remaining hardening sections.
pkg_upgrade() {
	local rc=0
	if ((IS_OSTREE)); then
		run "rpm-ostree upgrade" || rc=$?
		if ((rc != 0)); then
			warn "rpm-ostree upgrade failed (exit $rc) — likely a transient upstream repo conflict."
			warn "Re-run 'sudo rpm-ostree upgrade' manually once the conflict is resolved."
			warn "Continuing with remaining hardening sections."
		else
			warn "rpm-ostree upgrades are staged and applied on reboot. Reboot when this script completes."
		fi
	else
		run "dnf upgrade --refresh -y" || rc=$?
		if ((rc != 0)); then
			warn "dnf upgrade failed (exit $rc) — check repo availability and re-run manually."
			warn "Continuing with remaining hardening sections."
		fi
	fi
	return 0
}

# _load_ostree_staged_packages() - Populate _PKG_PENDING_CACHE from the live rpm-ostree
# staged/pending layer (runs once per script execution).  Prevents "Package X is already
# requested" errors when pkg_install is called after a prior run that layered packages
# but the system has not yet been rebooted.
_OSTREE_STAGED_LOADED=0
_load_ostree_staged_packages() {
	((_OSTREE_STAGED_LOADED)) && return 0
	((IS_OSTREE)) || return 0
	_OSTREE_STAGED_LOADED=1
	local pkg
	# Parse LayeredPackages tokens in one awk pass to avoid extra sed/tr/grep forks.
	while IFS= read -r pkg; do
		[[ -n "$pkg" ]] && _PKG_PENDING_CACHE[$pkg]=1
	done < <(
		local out rc=0
		out=$(rpm-ostree status 2>&1) || rc=$?
		if ((rc != 0)); then
			warn "Failed to query rpm-ostree staged packages"
			return 1
		fi
		# Use a here-string to avoid a fork for the echo process.
		awk '
            /LayeredPackages:/ {
                sub(/.*LayeredPackages:[[:space:]]*/, "", $0)
                for (i=1; i<=NF; i++) {
                    if ($i !~ /^\(/) print $i
                }
            }
        ' <<<"$out"
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
	((${#pkgs[@]} == 0)) && return 0

	# On rpm-ostree, pre-load staged packages so we don't re-request them.
	((IS_OSTREE)) && _load_ostree_staged_packages

	# Filter already-cached/installed packages from install list (caching optimization)
	for pkg in "${pkgs[@]}"; do
		# On rpm-ostree, skip packages already queued (this run or a prior pending layer).
		if ((IS_OSTREE)) && [[ "${_PKG_PENDING_CACHE[$pkg]:-0}" -eq 1 ]]; then
			info "Package '${pkg}' already in rpm-ostree pending layer — skipping."
			continue
		fi
		pkg_cached "$pkg" || needed+=("$pkg")
	done

	((${#needed[@]} == 0)) && {
		info "All packages already installed (cached)."
		return 0
	}

	if ((DRY_RUN)); then
		if ((IS_OSTREE)); then
			info "Would run: rpm-ostree install ${needed[*]}"
		else
			info "Would run: dnf install -y ${needed[*]}"
		fi
		return 0
	fi

	if ((IS_OSTREE)); then
		local out rc
		log "[RUN]   rpm-ostree install ${needed[*]}"
		# Capture output and exit code without triggering set -e abort on failure
		out="$(rpm-ostree install "${needed[@]}" 2>&1)" || rc=$?
		rc=${rc:-0}
		[[ -n "${out}" ]] && printf '%s\n' "$out" >>"$LOG_FILE"

		if ((rc != 0)); then
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
		record_change PKG_INSTALL "${needed[*]}"
		warn "Layered packages are applied on reboot. Reboot when this script completes."
	else
		run "dnf install -y ${needed[*]}"
		# Keep package cache coherent after successful mutable-system installs.
		for pkg in "${needed[@]}"; do
			_PKG_CACHE[$pkg]=0
		done
		record_change PKG_INSTALL "${needed[*]}"
		# New binaries may now exist; refresh command cache.
		unset _CMD_CACHE
		declare -gA _CMD_CACHE=()
	fi
}

# install_dep_candidates() - Best-effort install of dependency package candidates.
# Attempts each package and continues even if one candidate fails.
install_dep_candidates() {
	local pkg attempted=0
	((DRY_RUN)) && {
		info "Would install dependency package(s): $*"
		return 0
	}
	for pkg in "$@"; do
		[[ -z "$pkg" ]] && continue
		attempted=1
		pkg_install "$pkg" || true
	done
	((attempted)) && return 0
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

	if ((DRY_RUN)); then
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
		flatpak update -y "${app_id}" 2>/dev/null ||
			warn "Flatpak update of ${app_id} failed — will retry next run."
		return 0
	fi

	info "Flatpak ${app_id}: not installed — installing from ${remote}."
	if ! flatpak install -y "${remote}" "${app_id}" 2>/dev/null; then
		warn "Flatpak ${app_id} install failed."
		add_action_item "13" "MEDIUM" \
			"FLATPAK_INSTALL_FAILED_${app_id//[^a-zA-Z0-9]/_}" \
			"Flatpak ${app_id} could not be installed automatically — run: flatpak install ${remote} ${app_id}"
	else
		record_change FLATPAK_INSTALL "$app_id"
	fi
}

# ensure_command_dep() - Ensure command exists, attempting package install if missing.
# Usage: ensure_command_dep <command> <reason> <pkg1> [pkg2 ...]
ensure_command_dep() {
	local cmd="$1" reason="$2"
	shift 2
	cmd_exists "$cmd" && return 0

	warn "Missing dependency '$cmd' required for: $reason"
	if ((EUID != 0)); then
		warn "Cannot auto-install '$cmd' without root privileges."
		return 1
	fi
	(($# > 0)) || return 1

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
		ensure_command_dep curl "download operations" curl || true
		cmd_exists curl || ensure_command_dep wget "download operations fallback" wget || true
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
declare -gA _USER_HOME_CACHE=() # Session cache for user home dirs
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
	if ((ASSUME_YES)); then
		info "Auto-yes: $prompt"
		return 0
	fi

	if ((GUI_MODE)); then
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
		run "install -d -m 700 '$BACKUP_DIR'" || {
			warn "Failed to create backup directory"
			return 1
		}
		run "cp -a --parents '$f' '$BACKUP_DIR/'" || {
			warn "Failed to backup $f"
			return 1
		}
		record_change FILE_BACKUP "$f"
		info "Backed up $f → $BACKUP_DIR"
	fi
}

# in_list() - Check if needle is present in comma-separated list.
# Returns 0 (success) if found, 1 (failure) if not found.
# Used for --skip and --only section filtering logic.
# Usage: in_list <needle> <comma,separated,list>
in_list() {
	[[ -z "$2" ]] && return 1
	local IFS=','
	for item in $2; do [[ "$item" == "$1" ]] && return 0; done
	return 1
}

# batch_sed() - Apply multiple sed patterns in a single pass (more efficient).
# Reduces I/O overhead by batching replacements on same file.
# Usage: batch_sed <file> <pattern1> <pattern2> ...
batch_sed() {
	local f="$1"
	shift
	if ((DRY_RUN)); then
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
declare -gA _CMD_CACHE=() # Session cache for command existence
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
declare -gA _PKG_CACHE=()         # Session cache for package status
declare -gA _PKG_PENDING_CACHE=() # rpm-ostree pending/staged layer packages (pre-loaded from live status + current-run requests)
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
# Handles all official Fedora variants, Atomic Desktop spins, and community remixes
# (Bazzite, Aurora, Universal Blue). Sets IS_* flags for downstream feature-gating.
detect_fedora_release_type() {
	local release_blob
	release_blob="${NAME:-} ${PRETTY_NAME:-} ${VARIANT:-} ${VARIANT_ID:-} ${CPE_NAME:-} ${PLATFORM_ID:-} ${ID_LIKE:-}"
	release_blob="${release_blob,,}"

	# Official Fedora variants
	[[ "$release_blob" == *"workstation"* ]] && IS_WORKSTATION=1
	[[ "$release_blob" == *"server"* ]] && IS_SERVER=1
	[[ "$release_blob" == *"kinoite"* ]] && IS_KINOITE=1
	[[ "$release_blob" == *"silverblue"* ]] && IS_SILVERBLUE=1
	[[ "$release_blob" == *"onyx"* ]] && IS_ONYX=1
	[[ "$release_blob" == *"sericea"* ]] && IS_SERICEA=1
	[[ "$release_blob" == *"lazurite"* ]] && IS_LAZURITE=1
	[[ "$release_blob" == *"vauxite"* ]] && IS_VAUXITE=1
	[[ "$release_blob" == *"iot"* ]] && IS_IOT=1
	[[ "$release_blob" == *"cloud"* ]] && IS_CLOUD=1
	[[ "$release_blob" == *"coreos"* ]] && IS_COREOS=1

	# Universal Blue / community remixes
	if [[ "$release_blob" == *"bazzite"* ]]; then
		IS_BAZZITE=1
		IS_GAMING_SPIN=1
	fi
	if [[ "$release_blob" == *"aurora"* && "$release_blob" == *"universal blue"* ]] ||
		[[ "${ID:-}" == "aurora" ]] || [[ "${VARIANT_ID:-}" == "aurora" ]]; then
		IS_AURORA=1
	fi
	# Generic Universal Blue detection (bluefin, aurora, etc. share a common base)
	if [[ "${ID_LIKE:-}" == *"fedora"* ]] &&
		[[ "$release_blob" == *"universal blue"* || "$release_blob" == *"bluefin"* ||
			"$release_blob" == *"aurora"* ]]; then
		IS_AURORA=1
	fi

	# Fedora Atomic desktops: Kinoite, Silverblue, Onyx, Sericea, Lazurite, Vauxite,
	# and any other Fedora Atomic variant
	if ((IS_KINOITE || IS_SILVERBLUE || IS_ONYX || IS_SERICEA || IS_LAZURITE || IS_VAUXITE)) ||
		((IS_BAZZITE || IS_AURORA)) ||
		[[ "$release_blob" == *"atomic"* && "$release_blob" == *"fedora"* ]]; then
		IS_ATOMIC_DESKTOP=1
	fi
}

# detect_desktop_envs() - Detect active/installed desktop environments for feature gating.
# Covers KDE, GNOME, Sway, Hyprland, i3, XFCE, Cinnamon, MATE, Budgie, LXQt.
# Uses both running-session hints (XDG_CURRENT_DESKTOP) and installed-package hints.
detect_desktop_envs() {
	local detected=()
	local xdg_blob="${XDG_CURRENT_DESKTOP:-}:${DESKTOP_SESSION:-}"
	xdg_blob="${xdg_blob,,}"

	# ── Running session hints ────────────────────────────────────────────────
	if [[ "$xdg_blob" == *"kde"* || "$xdg_blob" == *"plasma"* ]]; then
		HAS_KDE=1
		[[ ",${detected[*]}," == *",kde,"* ]] || detected+=("kde")
	fi
	if [[ "$xdg_blob" == *"gnome"* ]]; then
		HAS_GNOME=1
		[[ ",${detected[*]}," == *",gnome,"* ]] || detected+=("gnome")
	fi
	if [[ "$xdg_blob" == *"budgie"* ]]; then
		HAS_BUDGIE=1
		[[ ",${detected[*]}," == *",budgie,"* ]] || detected+=("budgie")
	fi
	if [[ "$xdg_blob" == *"cinnamon"* ]]; then
		HAS_CINNAMON=1
		[[ ",${detected[*]}," == *",cinnamon,"* ]] || detected+=("cinnamon")
	fi
	if [[ "$xdg_blob" == *"mate"* ]]; then
		HAS_MATE=1
		[[ ",${detected[*]}," == *",mate,"* ]] || detected+=("mate")
	fi
	if [[ "$xdg_blob" == *"xfce"* ]]; then
		HAS_XFCE=1
		[[ ",${detected[*]}," == *",xfce,"* ]] || detected+=("xfce")
	fi
	if [[ "$xdg_blob" == *"lxqt"* ]]; then
		HAS_LXQT=1
		[[ ",${detected[*]}," == *",lxqt,"* ]] || detected+=("lxqt")
	fi
	if [[ "$xdg_blob" == *"sway"* ]]; then
		HAS_SWAY=1
		[[ ",${detected[*]}," == *",sway,"* ]] || detected+=("sway")
	fi
	if [[ "$xdg_blob" == *"hyprland"* ]]; then
		HAS_HYPRLAND=1
		[[ ",${detected[*]}," == *",hyprland,"* ]] || detected+=("hyprland")
	fi
	if [[ "$xdg_blob" == *"i3"* ]]; then
		HAS_I3=1
		[[ ",${detected[*]}," == *",i3,"* ]] || detected+=("i3")
	fi

	# ── Installed-package / command hints ────────────────────────────────────
	if cmd_exists kwriteconfig6 || cmd_exists kwriteconfig5 || pkg_cached plasma-workspace; then
		HAS_KDE=1
		[[ ",${detected[*]}," == *",kde,"* ]] || detected+=("kde")
	fi
	if cmd_exists gnome-shell || pkg_cached gnome-shell || pkg_cached gnome-session; then
		HAS_GNOME=1
		[[ ",${detected[*]}," == *",gnome,"* ]] || detected+=("gnome")
	fi
	if pkg_cached budgie-desktop || pkg_cached budgie-desktop-view; then
		HAS_BUDGIE=1
		[[ ",${detected[*]}," == *",budgie,"* ]] || detected+=("budgie")
	fi
	if cmd_exists cinnamon || pkg_cached cinnamon; then
		HAS_CINNAMON=1
		[[ ",${detected[*]}," == *",cinnamon,"* ]] || detected+=("cinnamon")
	fi
	if cmd_exists mate-session || pkg_cached mate-session-manager; then
		HAS_MATE=1
		[[ ",${detected[*]}," == *",mate,"* ]] || detected+=("mate")
	fi
	if cmd_exists xfce4-session || pkg_cached xfce4-session; then
		HAS_XFCE=1
		[[ ",${detected[*]}," == *",xfce,"* ]] || detected+=("xfce")
	fi
	if cmd_exists startlxqt || pkg_cached lxqt-session; then
		HAS_LXQT=1
		[[ ",${detected[*]}," == *",lxqt,"* ]] || detected+=("lxqt")
	fi
	if cmd_exists sway || pkg_cached sway; then
		HAS_SWAY=1
		[[ ",${detected[*]}," == *",sway,"* ]] || detected+=("sway")
	fi
	if cmd_exists Hyprland || cmd_exists hyprland || pkg_cached hyprland; then
		HAS_HYPRLAND=1
		[[ ",${detected[*]}," == *",hyprland,"* ]] || detected+=("hyprland")
	fi
	if cmd_exists i3 || pkg_cached i3; then
		HAS_I3=1
		[[ ",${detected[*]}," == *",i3,"* ]] || detected+=("i3")
	fi

	# Sericea and Lazurite Atomic spins imply their respective DEs
	((IS_SERICEA)) && {
		HAS_SWAY=1
		[[ ",${detected[*]}," == *",sway,"* ]] || detected+=("sway")
	}
	((IS_LAZURITE)) && {
		HAS_LXQT=1
		[[ ",${detected[*]}," == *",lxqt,"* ]] || detected+=("lxqt")
	}
	((IS_VAUXITE)) && {
		HAS_XFCE=1
		[[ ",${detected[*]}," == *",xfce,"* ]] || detected+=("xfce")
	}
	# Onyx is GNOME Atomic; Kinoite/Aurora are KDE
	((IS_ONYX)) && {
		HAS_GNOME=1
		[[ ",${detected[*]}," == *",gnome,"* ]] || detected+=("gnome")
	}
	((IS_AURORA)) && {
		HAS_KDE=1
		[[ ",${detected[*]}," == *",kde,"* ]] || detected+=("kde")
	}
	# Bazzite ships both KDE and GNOME editions — honour running session above; default to KDE
	if ((IS_BAZZITE)) && ((!HAS_KDE && !HAS_GNOME)); then
		HAS_KDE=1
		[[ ",${detected[*]}," == *",kde,"* ]] || detected+=("kde")
	fi

	((${#detected[@]} > 0)) && HAS_DESKTOP=1
	local IFS=','
	DESKTOP_ENVS="${detected[*]:-}"
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
		# Section 15 requires at least one desktop environment to be installed.
		if ((!HAS_DESKTOP)); then
			info "Skipping section 15: no desktop environment detected on this host."
			return 1
		fi
		;;
	16)
		# Section 16 is desktop-focused and should run if any desktop environment is installed.
		if ((!HAS_DESKTOP)); then
			info "Skipping section 16: no desktop environment detected on this host."
			return 1
		fi
		;;
	8)
		# Section 8 can interfere with remote access if USB input devices are not whitelisted.
		if ((IS_SERVER)) && ((!ASSUME_YES)); then
			warn "Section 8 (USBGuard) can disrupt remote-only server access if input devices are blocked."
		fi
		# Sway/Hyprland/i3 users: input-device whitelists in compositors must allow USB keyboards/mice.
		if ((HAS_SWAY || HAS_HYPRLAND || HAS_I3)) && ((!ASSUME_YES)); then
			warn "Section 8 (USBGuard): tiling WM users should whitelist USB input devices in their compositor config."
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
		((error_count++))

		# Pattern matching for auto-remediation categories
		if [[ "$line" =~ Permission\ denied || "$line" =~ not\ in\ sudoers ]]; then
			((permission_errors++))
		elif [[ "$line" =~ No\ such\ file\ or\ directory || "$line" =~ package.*not\ found ]]; then
			((package_errors++))
		elif [[ "$line" =~ service.*not\ available || "$line" =~ Unit.*not\ found ]]; then
			((service_errors++))
		elif [[ "$line" =~ Connection\ refused || "$line" =~ Network.*unreachable ]]; then
			((connection_errors++))
		fi
	done <"$ERROR_LOG"

	LAST_ERROR_COUNT=$error_count
	if ((error_count == 0)); then
		ok "Error analysis: No errors found."
		return 0
	fi

	warn "Error analysis: Found $error_count error(s)"
	((permission_errors > 0)) && warn "  ↳ Permission issues: $permission_errors"
	((package_errors > 0)) && warn "  ↳ Package/file issues: $package_errors"
	((service_errors > 0)) && warn "  ↳ Service issues: $service_errors"
	((connection_errors > 0)) && warn "  ↳ Connection issues: $connection_errors"

	return 0
}

# auto_remediate_errors() - Attempt to fix common errors identified in log analysis.
# Handles permission fixes, missing files, service issues, and network problems.
# Usage: auto_remediate_errors
auto_remediate_errors() {
	init_log_target || return 1

	[[ ! -f "$ERROR_LOG" ]] && return 0
	((++REMEDIATION_PASS))

	if ((REMEDIATION_PASS > MAX_REMEDIATION_PASSES)); then
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
		if ((EUID != 0)); then
			err "Still running as non-root (EUID=$EUID) — cannot remediate."
			return 1
		fi
		info "Running as root — permission errors may have been transient"
	fi

	# Fix 5: Check for missing package manager states (Fedora-specific checks)
	if ((IS_FEDORA)) && grep -q "rpm -q.*not installed\|dnf.*not found" "$ERROR_LOG" 2>/dev/null; then
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

	while ((REMEDIATION_PASS < MAX_REMEDIATION_PASSES)); do
		analyze_error_log
		local error_count=$LAST_ERROR_COUNT

		if ((error_count == 0)); then
			ok "✓ All errors resolved after $REMEDIATION_PASS pass(es)"
			return 0
		fi

		auto_remediate_errors || break
	done

	if ((LAST_ERROR_COUNT > 0)); then
		warn "Could not fully auto-remediate errors after $MAX_REMEDIATION_PASSES pass(es)"
		warn "Review logs for manual remediation: $LOG_FILE and $ERROR_LOG"
		return 1
	fi
	return 0
}

# trap_cleanup() - Emergency cleanup handler for EXIT/ERR traps.
# Removes temporary files and performs resource cleanup on script failure.
# Also writes the session report to sessions/ on every exit (normal or abort).
trap_cleanup() {
	local rc=$?
	gui_progress_close || true
	# Clean all registered temp files (registered via register_tmp())
	local _f
	for _f in "${TEMP_FILES[@]}"; do
		[[ -f "$_f" ]] && rm -f "$_f"
	done

	# Finalize the session report on every exit path.
	write_session_report || true

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
	if ((EXPECTED_ABORT)); then
		exit "$rc"
	fi
	SESSION_STATUS="aborted"
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

# ---------- Rollback journal helpers ----------------------------------------

# record_change() - Append one change entry to the rollback journal.
# Format written: "TIMESTAMP|CHANGE_TYPE|DETAIL"
# Types: FILE_BACKUP, PKG_INSTALL, FLATPAK_INSTALL, SERVICE_ENABLE, SERVICE_DISABLE
# No-ops in --dry-run mode or when journal is not yet initialized.
# Usage: record_change <type> <detail>
record_change() {
	[[ -z "$ROLLBACK_JOURNAL" ]] && return 0
	((DRY_RUN)) && return 0
	local ts
	printf -v ts '%(%F %T)T' -1 2>/dev/null || ts="$(date '+%F %T')"
	printf '%s|%s|%s\n' "$ts" "$1" "$2" >>"$ROLLBACK_JOURNAL" 2>/dev/null || true
}

# init_rollback_journal() - Create BACKUP_DIR and the per-session change journal.
# Called during preflight after log initialization.
# Usage: init_rollback_journal
init_rollback_journal() {
	((DRY_RUN)) && return 0
	install -d -m 700 "$BACKUP_DIR" 2>/dev/null || true
	ROLLBACK_JOURNAL="${BACKUP_DIR}/.rollback-journal"
	{
		printf '# Fedora Hardening Rollback Journal\n'
		printf '# Session:  %s\n' "$RUN_STAMP"
		printf '# Host:     %s\n' "$HOST_LABEL"
		printf '# Started:  %s\n' "$RUN_STAMP_ISO"
		printf '# Format:   TIMESTAMP|CHANGE_TYPE|DETAIL\n'
		printf '#\n'
	} >"$ROLLBACK_JOURNAL" 2>/dev/null || ROLLBACK_JOURNAL=""
	[[ -n "$ROLLBACK_JOURNAL" ]] && chmod 600 "$ROLLBACK_JOURNAL" 2>/dev/null || true
}

# init_session_dir() - Create ./sessions/ and write the session header stub.
# The stub is overwritten with full content by write_session_report() on exit.
# Usage: init_session_dir
init_session_dir() {
	if ! install -d -m 755 "$SESSION_DIR" 2>/dev/null; then
		warn "Could not create sessions directory: $SESSION_DIR — session reports disabled."
		SESSION_DIR=""
		return 0
	fi
	SESSION_REPORT_FILE="${SESSION_DIR}/session-${RUN_STAMP}.txt"
	{
		printf '=== Fedora Hardening Session Report ===\n'
		printf 'Session:   %s\n' "$RUN_STAMP"
		printf 'Status:    running\n'
		printf 'Host:      %s\n' "$HOST_LABEL"
		printf 'Started:   %s\n' "$RUN_STAMP_ISO"
		printf 'Log:       %s\n' "$LOG_FILE"
		printf 'Backups:   %s\n' "$BACKUP_DIR"
		printf '\n(Script still running — full report written on exit)\n'
	} >"$SESSION_REPORT_FILE" 2>/dev/null || SESSION_REPORT_FILE=""
}

# write_session_report() - Finalize and persist the session report to sessions/.
# Called automatically from trap_cleanup on both clean exit and abort.
# Idempotent: skips if already written (SESSION_REPORT_WRITTEN guard).
# Usage: write_session_report
write_session_report() {
	((SESSION_REPORT_WRITTEN)) && return 0
	SESSION_REPORT_WRITTEN=1
	[[ -z "$SESSION_REPORT_FILE" ]] && return 0

	local plat
	((IS_OSTREE)) && plat="rpm-ostree (immutable)" || plat="dnf (mutable)"

	local change_count=0 file_backups=0 pkg_installs=0
	local svc_enables=0 svc_disables=0 flatpak_installs=0

	if [[ -n "$ROLLBACK_JOURNAL" && -f "$ROLLBACK_JOURNAL" ]]; then
		while IFS='|' read -r _ts ctype _detail; do
			[[ "$_ts" == '#'* || -z "${ctype:-}" ]] && continue
			((change_count++))
			case "$ctype" in
			FILE_BACKUP) ((file_backups++)) ;;
			PKG_INSTALL) ((pkg_installs++)) ;;
			SERVICE_ENABLE) ((svc_enables++)) ;;
			SERVICE_DISABLE) ((svc_disables++)) ;;
			FLATPAK_INSTALL) ((flatpak_installs++)) ;;
			esac
		done <"$ROLLBACK_JOURNAL"
	fi

	{
		printf '=== Fedora Hardening Session Report ===\n'
		printf 'Session:   %s\n' "$RUN_STAMP"
		printf 'Status:    %s\n' "$SESSION_STATUS"
		printf 'Host:      %s\n' "$HOST_LABEL"
		printf 'Kernel:    %s\n' "$KERNEL_LABEL"
		printf 'Platform:  %s\n' "$plat"
		printf 'Started:   %s\n' "$RUN_STAMP_ISO"
		printf 'Log:       %s\n' "$LOG_FILE"
		printf 'Backups:   %s\n' "$BACKUP_DIR"
		printf '\n'
		printf '=== Change Summary (%d total) ===\n' "$change_count"
		printf '  File backups created:    %d\n' "$file_backups"
		printf '  Packages installed:      %d\n' "$pkg_installs"
		printf '  Services enabled:        %d\n' "$svc_enables"
		printf '  Services disabled:       %d\n' "$svc_disables"
		printf '  Flatpak apps installed:  %d\n' "$flatpak_installs"
		printf '\n'
		printf '=== Detailed Changes ===\n'
		if ((DRY_RUN)); then
			printf '  No changes recorded (dry-run mode).\n'
		elif [[ -n "$ROLLBACK_JOURNAL" && -f "$ROLLBACK_JOURNAL" && "$change_count" -gt 0 ]]; then
			while IFS='|' read -r _ts ctype detail; do
				[[ "$_ts" == '#'* || -z "${ctype:-}" ]] && continue
				printf '  [%s] %-18s %s\n' "$_ts" "$ctype" "$detail"
			done <"$ROLLBACK_JOURNAL"
		else
			printf '  No changes were applied this session.\n'
		fi
		printf '\n'
		printf '=== Actionable Items (%d) ===\n' "${#ACTIONABLE_ITEMS[@]}"
		if ((${#ACTIONABLE_ITEMS[@]} > 0)); then
			local idx=1
			for item in "${ACTIONABLE_ITEMS[@]}"; do
				local section priority tag desc
				IFS='|' read -r section priority tag desc <<<"$item"
				printf '  [%2d] [%s][%s] %s\n' "$idx" "$priority" "$section" "$desc"
				((idx++))
			done
		else
			printf '  None.\n'
		fi
		printf '\n'
		printf '=== Remediated Items (%d) ===\n' "${#REMEDIATED_ITEMS[@]}"
		if ((${#REMEDIATED_ITEMS[@]} > 0)); then
			for item in "${REMEDIATED_ITEMS[@]}"; do
				local section priority tag desc
				IFS='|' read -r section priority tag desc <<<"$item"
				printf '  [RESOLVED][%s][%s] %s\n' "$priority" "$section" "$desc"
			done
		else
			printf '  None.\n'
		fi
		printf '\n'
		if [[ "$SESSION_STATUS" == "aborted" ]]; then
			printf '=== Abort Information ===\n'
			printf '  The script was aborted before completing all sections.\n'
			printf '  Some changes may have been applied; see detailed changes above.\n'
			printf '  Error log: %s\n\n' "$ERROR_LOG"
		fi
		printf '=== Rollback Instructions ===\n'
		if ((change_count > 0)); then
			printf '  To undo all changes from this session:\n'
			printf '    sudo %s --rollback %s\n\n' "$SCRIPT_NAME" "$RUN_STAMP"
			printf '  To undo ALL changes from every session (full reset):\n'
			printf '    sudo %s --rollback all\n\n' "$SCRIPT_NAME"
			printf '  Manual restore of config files from:\n'
			printf '    %s\n' "$BACKUP_DIR"
		elif ((DRY_RUN)); then
			printf '  No changes were made (dry-run mode) — nothing to roll back.\n'
		else
			printf '  No changes were recorded — nothing to roll back.\n'
		fi
	} >"$SESSION_REPORT_FILE" 2>/dev/null || true
	chmod 644 "$SESSION_REPORT_FILE" 2>/dev/null || true
	log "[SESSION] Session report written: $SESSION_REPORT_FILE"
}

# ---------- Rollback session helpers ----------------------------------------

# find_session_backup_dir() - Locate BACKUP_DIR for a given session ID (RUN_STAMP format).
# Prints the directory path on success; returns 1 if not found.
# Usage: find_session_backup_dir <stamp>
find_session_backup_dir() {
	local stamp="$1"
	local dir="/root/harden-backups-${stamp}"
	if [[ -d "$dir" ]]; then
		printf '%s' "$dir"
		return 0
	fi
	return 1
}

# list_sessions_cmd() - Display all past sessions from the sessions/ directory.
# Also surfaces backup directories that have no matching session report (pre-feature runs).
# Usage: list_sessions_cmd
list_sessions_cmd() {
	printf '\n%s════════ Past Hardening Sessions ════════%s\n' "$C_CYN" "$C_RST"

	local found=0
	local -A seen_stamps=() # track stamps that have session reports

	if [[ -d "$SESSION_DIR" ]]; then
		for f in "$SESSION_DIR"/session-*.txt; do
			[[ -f "$f" ]] || continue
			((found++))
			# Single awk pass extracts both Session and Status fields to avoid reading the file twice.
			local session_id status _awk_out
			_awk_out="$(awk '/^Session:/{sid=$2} /^Status:/{sts=$2} END{print (sid?sid:"unknown"), (sts?sts:"unknown")}' "$f" 2>/dev/null || true)"
			session_id="${_awk_out%% *}"
			status="${_awk_out##* }"
			[[ -z "$session_id" ]] && session_id="unknown"
			[[ -z "$status" ]] && status="unknown"
			seen_stamps["$session_id"]=1
			case "$status" in
			completed) printf '  %s[✓]%s %s  (completed)\n' "$C_GRN" "$C_RST" "$session_id" ;;
			aborted) printf '  %s[✗]%s %s  (aborted)\n' "$C_RED" "$C_RST" "$session_id" ;;
			running) printf '  %s[~]%s %s  (interrupted)\n' "$C_YEL" "$C_RST" "$session_id" ;;
			*) printf '       %s  (%s)\n' "$session_id" "$status" ;;
			esac
			printf '       Report: %s\n' "$f"
		done
	fi

	# Show backup dirs that have no session report (pre-session-feature runs)
	for d in /root/harden-backups-*/; do
		[[ -d "$d" ]] || continue
		local stamp="${d%/}"
		stamp="${stamp##*/harden-backups-}"
		[[ -n "${seen_stamps[$stamp]:-}" ]] && continue
		((found++))
		local journal_note="no journal"
		[[ -f "${d}.rollback-journal" ]] && journal_note="journal present"
		printf '  %s[?]%s %s  (no session report — %s)\n' "$C_YEL" "$C_RST" "$stamp" "$journal_note"
		printf '       Backup dir: %s\n' "$d"
	done

	if ((found == 0)); then
		printf '  No sessions found.\n'
	fi
	printf '%s═════════════════════════════════════════%s\n\n' "$C_CYN" "$C_RST"
	printf 'To roll back a single session:  sudo %s --rollback <session-id>\n' "$SCRIPT_NAME"
	printf 'To roll back ALL sessions:      sudo %s --rollback all\n\n' "$SCRIPT_NAME"
}

# _apply_rollback_journal() - Process journal entries in reverse, applying rollback actions.
# Shared helper used by rollback_session() and rollback_all_sessions().
# Modifies globals: _RBJ_RESTORED, _RBJ_ERRORS (caller must initialize).
# Arguments: <journal_file> <backup_dir> <rb_report>
_apply_rollback_journal() {
	local journal_file="$1" backup_dir="$2" rb_report="$3"

	_rjl() { [[ -n "$rb_report" ]] && printf '%s\n' "$*" >>"$rb_report" 2>/dev/null || true; }

	local -a journal_lines=()
	while IFS= read -r jline; do
		[[ "$jline" == '#'* || -z "$jline" ]] && continue
		journal_lines+=("$jline")
	done <"$journal_file"

	local i n=${#journal_lines[@]}
	for ((i = n - 1; i >= 0; i--)); do
		local ts ctype detail
		IFS='|' read -r ts ctype detail <<<"${journal_lines[$i]}"
		[[ -z "${ctype:-}" ]] && continue

		case "$ctype" in
		FILE_BACKUP)
			local restored_path="/${detail#/}"
			local backup_copy="${backup_dir}${detail}"
			if [[ -f "$backup_copy" ]]; then
				if ((DRY_RUN)); then
					info "Would restore: $restored_path"
				elif cp -a "$backup_copy" "$restored_path" 2>/dev/null; then
					ok "Restored: $restored_path"
					_rjl "  [OK]   RESTORE  $restored_path"
					((_RBJ_RESTORED++))
				else
					warn "Failed to restore: $restored_path"
					_rjl "  [FAIL] RESTORE  $restored_path"
					((_RBJ_ERRORS++))
				fi
			else
				warn "Backup copy not found: $backup_copy — skipping restore of $detail"
				_rjl "  [SKIP] RESTORE  $detail (backup copy missing)"
			fi
			;;

		PKG_INSTALL)
			if ((IS_OSTREE)); then
				if ((DRY_RUN)); then
					info "Would run: rpm-ostree uninstall $detail"
				elif run "rpm-ostree uninstall $detail" 2>/dev/null; then
					ok "rpm-ostree uninstall queued: $detail (reboot required)"
					_rjl "  [OK]   RPM_OSTREE_UNINSTALL  $detail"
					((_RBJ_RESTORED++))
				else
					warn "rpm-ostree uninstall failed for: $detail (may not have been layered)"
					_rjl "  [WARN] RPM_OSTREE_UNINSTALL  $detail"
					((_RBJ_ERRORS++))
				fi
			else
				if ((DRY_RUN)); then
					info "Would run: dnf remove -y $detail"
				elif run "dnf remove -y $detail" 2>/dev/null; then
					ok "Packages removed: $detail"
					_rjl "  [OK]   PKG_REMOVE  $detail"
					((_RBJ_RESTORED++))
				else
					warn "dnf remove failed for: $detail (may have been pre-existing)"
					_rjl "  [WARN] PKG_REMOVE  $detail"
					((_RBJ_ERRORS++))
				fi
			fi
			;;

		SERVICE_ENABLE)
			if ((DRY_RUN)); then
				info "Would run: systemctl disable $detail"
			elif systemctl disable "$detail" 2>/dev/null; then
				ok "Service disabled: $detail"
				_rjl "  [OK]   SERVICE_DISABLE  $detail"
				((_RBJ_RESTORED++))
			else
				warn "Could not disable service: $detail"
				_rjl "  [WARN] SERVICE_DISABLE  $detail"
				((_RBJ_ERRORS++))
			fi
			;;

		SERVICE_DISABLE)
			if ((DRY_RUN)); then
				info "Would run: systemctl enable $detail"
			elif systemctl enable "$detail" 2>/dev/null; then
				ok "Service re-enabled: $detail"
				_rjl "  [OK]   SERVICE_ENABLE  $detail"
				((_RBJ_RESTORED++))
			else
				warn "Could not re-enable service: $detail"
				_rjl "  [WARN] SERVICE_ENABLE  $detail"
				((_RBJ_ERRORS++))
			fi
			;;

		FLATPAK_INSTALL)
			if ((DRY_RUN)); then
				info "Would run: flatpak uninstall -y $detail"
			elif have_cmd flatpak && flatpak uninstall -y "$detail" 2>/dev/null; then
				ok "Flatpak removed: $detail"
				_rjl "  [OK]   FLATPAK_REMOVE  $detail"
				((_RBJ_RESTORED++))
			else
				warn "Flatpak uninstall failed for: $detail"
				_rjl "  [WARN] FLATPAK_REMOVE  $detail"
				((_RBJ_ERRORS++))
			fi
			;;

		*)
			warn "Unknown journal entry type '$ctype' — skipping"
			_rjl "  [SKIP] UNKNOWN  $ctype: $detail"
			;;
		esac
	done
}

# _restore_backup_dir_files() - Restore all backed-up files from a directory with no journal.
# Used for pre-journal runs where only file backups are available.
# Modifies globals: _RBJ_RESTORED, _RBJ_ERRORS.
# Arguments: <backup_dir> <rb_report>
_restore_backup_dir_files() {
	local backup_dir="$1" rb_report="$2"

	_rbfl() { [[ -n "$rb_report" ]] && printf '%s\n' "$*" >>"$rb_report" 2>/dev/null || true; }

	local found_any=0
	while IFS= read -r bfile; do
		found_any=1
		local rel="${bfile#"${backup_dir}"}"
		local restored_path="/${rel#/}"
		if ((DRY_RUN)); then
			info "Would restore: $restored_path"
		elif cp -a "$bfile" "$restored_path" 2>/dev/null; then
			ok "Restored: $restored_path"
			_rbfl "  [OK]   RESTORE  $restored_path"
			((_RBJ_RESTORED++))
		else
			warn "Failed to restore: $restored_path"
			_rbfl "  [FAIL] RESTORE  $restored_path"
			((_RBJ_ERRORS++))
		fi
	done < <(find "$backup_dir" -type f ! -name '.rollback-journal' 2>/dev/null | sort)

	if ((!found_any)); then
		warn "No backup files found in: $backup_dir"
		_rbfl "  [INFO] No files found in backup dir: $backup_dir"
	fi
}

# rollback_session() - Reverse all changes recorded in a single session rollback journal.
# Restores backed-up config files, removes installed packages, reverses service
# enables/disables, and removes Flatpak installs. Generates a rollback report in
# the sessions/ directory.
# Usage: rollback_session <session-id|last>
rollback_session() {
	local session_id="${1:-last}"
	local backup_dir journal_file

	# Resolve 'last' to the most recent known session stamp
	if [[ "$session_id" == "last" ]]; then
		local latest=""
		if [[ -d "$SESSION_DIR" ]]; then
			for f in "$SESSION_DIR"/session-*.txt; do
				[[ -f "$f" ]] || continue
				local stamp
				stamp="$(basename "$f" .txt)"
				stamp="${stamp#session-}"
				[[ -z "$latest" || "$stamp" > "$latest" ]] && latest="$stamp"
			done
		fi
		if [[ -z "$latest" ]]; then
			for d in /root/harden-backups-*/; do
				[[ -d "$d" ]] || continue
				local stamp
				stamp="${d%/}"
				stamp="${stamp##*/harden-backups-}"
				[[ -z "$latest" || "$stamp" > "$latest" ]] && latest="$stamp"
			done
		fi
		if [[ -z "$latest" ]]; then
			err "No previous sessions found to roll back."
			return 1
		fi
		session_id="$latest"
		info "Most recent session found: $session_id"
	fi

	backup_dir="$(find_session_backup_dir "$session_id")" || {
		err "Backup directory not found for session: $session_id"
		err "Expected location: /root/harden-backups-${session_id}"
		return 1
	}

	journal_file="${backup_dir}/.rollback-journal"
	local has_journal=1
	if [[ ! -f "$journal_file" ]]; then
		has_journal=0
		warn "No rollback journal found in: $backup_dir"
		warn "This appears to be a pre-journal run — backed-up files will be restored."
		warn "Package installs and service state changes cannot be automatically reversed."
	fi

	info "Session:     $session_id"
	info "Backup dir:  $backup_dir"
	if ((has_journal)); then
		info "Journal:     $journal_file"
	else
		info "Journal:     (none)"
	fi

	if ! confirm "Proceed with rollback of session ${session_id}?"; then
		info "Rollback cancelled."
		return 0
	fi

	local rb_stamp
	printf -v rb_stamp '%(%Y%m%d-%H%M%S)T' -1 2>/dev/null || rb_stamp="$(date +%Y%m%d-%H%M%S)"
	local rb_report=""
	if [[ -d "$SESSION_DIR" ]]; then
		rb_report="${SESSION_DIR}/rollback-${session_id}-at-${rb_stamp}.txt"
	fi

	_RBJ_RESTORED=0
	_RBJ_ERRORS=0

	if [[ -n "$rb_report" ]]; then
		{
			printf '=== Fedora Hardening Rollback Report ===\n'
			printf 'Rolling back session:  %s\n' "$session_id"
			printf 'Rollback started:      %s\n' "$(date '+%F %T')"
			printf 'Host:                  %s\n' "$HOST_LABEL"
			printf 'Backup dir:            %s\n' "$backup_dir"
			if ((has_journal)); then
				printf 'Journal:               %s\n' "$journal_file"
			else
				printf 'Journal:               NONE (pre-journal run — file restore only)\n'
				printf '\nNOTE: Package installs and service state changes from this session\n'
				printf '      cannot be automatically reversed. Review manually.\n'
			fi
			printf '\n=== Rollback Actions ===\n'
		} >"$rb_report" 2>/dev/null || rb_report=""
	fi

	if ((has_journal)); then
		_apply_rollback_journal "$journal_file" "$backup_dir" "$rb_report"
	else
		_restore_backup_dir_files "$backup_dir" "$rb_report"
	fi

	if [[ -n "$rb_report" ]]; then
		{
			printf '\n=== Rollback Summary ===\n'
			printf 'Session rolled back:  %s\n' "$session_id"
			printf 'Changes reverted:     %d\n' "$_RBJ_RESTORED"
			printf 'Errors/warnings:      %d\n' "$_RBJ_ERRORS"
			printf 'Completed:            %s\n' "$(date '+%F %T')"
			((IS_OSTREE)) && printf '\nNOTE: rpm-ostree uninstalls require a reboot to take effect.\n'
			printf '\nA reboot is recommended to ensure all rollback changes are applied.\n'
		} >>"$rb_report" 2>/dev/null || true
		chmod 644 "$rb_report" 2>/dev/null || true
		ok "Rollback report saved: $rb_report"
	fi

	if ((_RBJ_ERRORS > 0)); then
		warn "Rollback completed with $_RBJ_ERRORS warning(s) — manual review may be needed."
	else
		ok "Rollback complete: $_RBJ_RESTORED change(s) reversed for session $session_id."
	fi
	((IS_OSTREE)) && warn "A reboot is required for rpm-ostree changes to take effect."
	info "A system reboot is recommended to finalize all rollback changes."
	return 0
}

# rollback_all_sessions() - Reverse ALL changes from every hardening session, newest first.
# Processes sessions in reverse chronological order so the most recent changes are undone
# first, guaranteeing a safe and consistent state across multiple runs (including aborted
# sessions). Sessions without a rollback journal (pre-journal runs) have their backed-up
# config files restored; package/service state cannot be inferred and is logged as unknown.
# A combined rollback report AND a dedicated log file are written to sessions/.
# Usage: rollback_all_sessions
rollback_all_sessions() {
	printf '\n%s╔══════════════════════════════════════════════╗%s\n' "$C_RED" "$C_RST"
	printf '%s║   FULL SYSTEM ROLLBACK — ALL SESSIONS        ║%s\n' "$C_RED" "$C_RST"
	printf '%s╚══════════════════════════════════════════════╝%s\n\n' "$C_RED" "$C_RST"
	warn "This will attempt to reverse ALL changes from ALL hardening sessions."
	warn "File restores, package removals, and service state reversals will be applied."
	printf '\n'

	# 1. Discover all backup directories
	local -a all_stamps=()
	for d in /root/harden-backups-*/; do
		[[ -d "$d" ]] || continue
		local stamp="${d%/}"
		stamp="${stamp##*/harden-backups-}"
		all_stamps+=("$stamp")
	done

	if [[ ${#all_stamps[@]} -eq 0 ]]; then
		err "No hardening backup directories found under /root/harden-backups-*."
		warn "If the script was run before backup support existed, no automatic rollback is possible."
		warn "Check /root/ manually for any files that may have been modified."
		return 1
	fi

	# Sort stamps lexicographically — YYYYMMDD-HHMMSS sorts correctly as strings
	local -a sorted_stamps=()
	while IFS= read -r s; do sorted_stamps+=("$s"); done \
		< <(printf '%s\n' "${all_stamps[@]}" | sort)

	local total_sessions=${#sorted_stamps[@]}
	info "Found $total_sessions session(s) to roll back (will process newest first):"
	local i
	for ((i = total_sessions - 1; i >= 0; i--)); do
		local s="${sorted_stamps[$i]}"
		if [[ -f "/root/harden-backups-${s}/.rollback-journal" ]]; then
			printf '  %s[journal]%s  %s\n' "$C_GRN" "$C_RST" "$s"
		else
			printf '  %s[no journal — file restore only]%s  %s\n' "$C_YEL" "$C_RST" "$s"
		fi
	done
	printf '\n'

	if ! confirm "Proceed with FULL rollback of all $total_sessions session(s)?"; then
		info "Full rollback cancelled."
		return 0
	fi

	# 2. Set up combined report and log files
	local rb_stamp
	printf -v rb_stamp '%(%Y%m%d-%H%M%S)T' -1 2>/dev/null || rb_stamp="$(date +%Y%m%d-%H%M%S)"

	# Ensure sessions dir exists — it may not if this is a pre-session-feature environment
	if [[ -z "$SESSION_DIR" ]] || ! install -d -m 755 "$SESSION_DIR" 2>/dev/null; then
		SESSION_DIR="/tmp"
		warn "sessions/ directory unavailable; writing report to /tmp/"
	fi

	local rb_report="${SESSION_DIR}/rollback-full-at-${rb_stamp}.txt"
	local rb_log="${SESSION_DIR}/rollback-full-at-${rb_stamp}.log"

	_frblog() {
		local msg="$*"
		printf '[%s] %s\n' "$(date '+%F %T')" "$msg" >>"$rb_log" 2>/dev/null || true
		log "[FULL-ROLLBACK] $msg"
	}

	{
		printf '=== Fedora Hardening — Full System Rollback Report ===\n'
		printf 'Started:        %s\n' "$(date '+%F %T')"
		printf 'Host:           %s\n' "$HOST_LABEL"
		printf 'Sessions found: %d\n' "$total_sessions"
		printf 'Processing:     newest-first (reverse chronological)\n'
		printf '\n'
		printf 'Sessions discovered:\n'
		for ((i = total_sessions - 1; i >= 0; i--)); do
			local s="${sorted_stamps[$i]}"
			if [[ -f "/root/harden-backups-${s}/.rollback-journal" ]]; then
				printf '  %s  [journal present]\n' "$s"
			else
				printf '  %s  [no journal — file restore only]\n' "$s"
			fi
		done
		printf '\n'
		printf 'NOTE: Sessions without a rollback journal (runs predating this feature)\n'
		printf '      will have their backed-up config files restored. Package installs\n'
		printf '      and service state changes from those sessions cannot be automatically\n'
		printf '      reversed and must be reviewed manually.\n'
		printf '\n'
	} >"$rb_report" 2>/dev/null || {
		warn "Could not create rollback report file."
		rb_report=""
	}
	: >"$rb_log" 2>/dev/null || true

	_frblog "Full rollback started. Sessions (${total_sessions}): ${sorted_stamps[*]}"

	# 3. Process sessions newest-first
	local total_restored=0 total_errors=0 sessions_ok=0 sessions_skipped=0
	for ((i = total_sessions - 1; i >= 0; i--)); do
		local s="${sorted_stamps[$i]}"
		local bdir="/root/harden-backups-${s}"
		local jfile="${bdir}/.rollback-journal"

		{
			printf '\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
			printf 'Session:    %s\n' "$s"
			printf 'Backup dir: %s\n' "$bdir"
		} >>"$rb_report" 2>/dev/null || true

		_frblog "Processing session $s"

		if [[ ! -d "$bdir" ]]; then
			warn "Backup directory missing for session $s — skipping."
			printf '  [SKIP] Backup directory not found.\n' >>"$rb_report" 2>/dev/null || true
			_frblog "Session $s skipped: backup dir missing"
			((sessions_skipped++))
			continue
		fi

		_RBJ_RESTORED=0
		_RBJ_ERRORS=0

		if [[ -f "$jfile" ]]; then
			printf 'Journal:    %s\n\nRollback actions:\n' "$jfile" >>"$rb_report" 2>/dev/null || true
			_frblog "Session $s: processing journal"
			_apply_rollback_journal "$jfile" "$bdir" "$rb_report"
		else
			{
				printf 'Journal:    NONE (pre-journal run — restoring files only)\n\n'
				printf 'NOTE: Package installs and service state changes from this session\n'
				printf '      cannot be automatically reversed. Review manually.\n\n'
				printf 'Rollback actions:\n'
			} >>"$rb_report" 2>/dev/null || true
			warn "Session $s: no journal — restoring backed-up files only."
			_frblog "Session $s: no journal found; attempting raw file restore"
			_restore_backup_dir_files "$bdir" "$rb_report"
		fi

		printf '\n  Session result: restored=%d  errors/warnings=%d\n' \
			"$_RBJ_RESTORED" "$_RBJ_ERRORS" >>"$rb_report" 2>/dev/null || true
		_frblog "Session $s done: restored=$_RBJ_RESTORED errors=$_RBJ_ERRORS"

		((total_restored += _RBJ_RESTORED))
		((total_errors += _RBJ_ERRORS))
		((sessions_ok++))
	done

	# 4. Write combined summary to report and log
	{
		printf '\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
		printf '=== Full Rollback Summary ===\n'
		printf 'Sessions found:     %d\n' "$total_sessions"
		printf 'Sessions processed: %d\n' "$sessions_ok"
		printf 'Sessions skipped:   %d\n' "$sessions_skipped"
		printf 'Changes reverted:   %d\n' "$total_restored"
		printf 'Errors/warnings:    %d\n' "$total_errors"
		printf 'Completed:          %s\n' "$(date '+%F %T')"
		printf 'Log file:           %s\n' "$rb_log"
		((IS_OSTREE)) && printf '\nNOTE: rpm-ostree uninstalls require a reboot to take effect.\n'
		printf '\nA reboot is strongly recommended to finalize all rollback changes.\n'
	} >>"$rb_report" 2>/dev/null || true
	chmod 644 "$rb_report" 2>/dev/null || true
	chmod 644 "$rb_log" 2>/dev/null || true

	_frblog "Full rollback complete. Processed=$sessions_ok Skipped=$sessions_skipped Restored=$total_restored Errors=$total_errors"

	printf '\n'
	ok "Full rollback report: $rb_report"
	ok "Full rollback log:    $rb_log"
	if ((total_errors > 0)); then
		warn "Full rollback completed with $total_errors warning(s) — manual review may be needed."
	else
		ok "Full rollback complete: $total_restored change(s) reversed across $sessions_ok session(s)."
	fi
	((IS_OSTREE)) && warn "A reboot is required for rpm-ostree changes to take effect."
	info "A system reboot is strongly recommended to finalize all rollback changes."
	return 0
}
# get_user_downloads_dir() - Resolve the XDG Downloads directory for the target user.
# Uses xdg-user-dir if available; falls back to ~/Downloads.
# Returns 1 (prints nothing) when no valid non-root target user is configured.
# Usage: get_user_downloads_dir
get_user_downloads_dir() {
	local user="${TARGET_USER:-${SUDO_USER:-}}"
	[[ -z "$user" || "$user" == "root" ]] && return 1
	local home
	home="$(user_home "$user")"
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
	if ((DRY_RUN)); then
		info "Would create: $USER_PROJECT_DIR"
		info "Would create: $USER_RESULTS_DIR"
		info "Would create: $USER_LOGS_DIR"
		return 0
	fi
	install -d -m 750 -o "$user" -g "$user" "$USER_PROJECT_DIR" 2>/dev/null ||
		{
			warn "Could not create $USER_PROJECT_DIR — reports will only be in $LOG_FILE."
			return 0
		}
	install -d -m 750 -o "$user" -g "$user" "$USER_RESULTS_DIR" 2>/dev/null ||
		{
			warn "Could not create $USER_RESULTS_DIR — reports will only be in $LOG_FILE."
			return 0
		}
	install -d -m 750 -o "$user" -g "$user" "$USER_LOGS_DIR" 2>/dev/null || true
	ok "Project export dir ready: $USER_PROJECT_DIR"
	ok "Report dir ready: $USER_RESULTS_DIR"
	ok "Log dir ready: $USER_LOGS_DIR"
}

# write_user_report() - Read stdin and write to a file in the user results directory.
# Usage: { echo content; } | write_user_report <filename>
write_user_report() {
	local filename="$1"
	if [[ -z "$USER_RESULTS_DIR" ]]; then
		cat >/dev/null
		return 0
	fi
	if ((DRY_RUN)); then
		info "Would write report: $USER_RESULTS_DIR/$filename"
		cat >/dev/null
		return 0
	fi
	local user="${TARGET_USER:-${SUDO_USER:-}}"
	local path="${USER_RESULTS_DIR}/${filename}"
	if ! cat >"$path" 2>/dev/null; then
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
	((DRY_RUN)) && {
		info "Would copy $src -> $USER_RESULTS_DIR/$dest_name"
		return 0
	}
	local user="${TARGET_USER:-${SUDO_USER:-}}"
	cp -a "$src" "${USER_RESULTS_DIR}/${dest_name}" 2>/dev/null || true
	chown "${user}:${user}" "${USER_RESULTS_DIR}/${dest_name}" 2>/dev/null || true
	chmod 640 "${USER_RESULTS_DIR}/${dest_name}" 2>/dev/null || true
	ok "Copied $src -> $USER_RESULTS_DIR/$dest_name"
}

# copy_log_to_user() - Copy main and structured error logs to the user logs directory.
copy_log_to_user() {
	[[ -z "$USER_LOGS_DIR" || ! -f "$LOG_FILE" ]] && return 0
	((DRY_RUN)) && {
		info "Would copy log -> $USER_LOGS_DIR/"
		return 0
	}
	local user="${TARGET_USER:-${SUDO_USER:-}}"
	local dest
	dest="${USER_LOGS_DIR}/$(basename "$LOG_FILE")"
	cp -a "$LOG_FILE" "$dest" 2>/dev/null || true
	chown "${user}:${user}" "$dest" 2>/dev/null || true
	chmod 640 "$dest" 2>/dev/null || true
	ok "Log copied: $dest"
	if [[ -n "$ERROR_LOG" && -f "$ERROR_LOG" ]]; then
		local err_dest
		err_dest="${USER_LOGS_DIR}/$(basename "$ERROR_LOG")"
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
	[[ -z "$USER_DOWNLOADS_DIR" ]] && {
		warn "No Downloads directory available for PDF audit export."
		return 1
	}

	local user="${TARGET_USER:-${SUDO_USER:-}}"
	local pdf_path="${USER_DOWNLOADS_DIR}/fedora-hardening-audit-${REPORT_DATE}.pdf"
	local bundle_path="${USER_DOWNLOADS_DIR}/fedora-hardening-audit-${REPORT_DATE}.txt"
	local txt_path="/tmp/fedora-hardening-audit-${REPORT_DATE}-$$.txt"
	local ps_path="/tmp/fedora-hardening-audit-${REPORT_DATE}-$$.ps"
	register_tmp "$txt_path"
	register_tmp "$ps_path"

	if ((DRY_RUN)); then
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
		} >"$txt_path"
	fi

	{
		printf '\n=== Importable Action Items ===\n'
		printf 'Re-import later with: sudo %s --import-audit %s\n\n' "$SCRIPT_NAME" "$pdf_path"
		for item in "${ACTIONABLE_ITEMS[@]}"; do
			printf 'ACTION_ITEM|%s\n' "$item"
		done
	} >>"$txt_path"

	{
		[[ -f "$txt_path" ]] && cat "$txt_path"
	} >"$bundle_path"
	chown "${user}:${user}" "$bundle_path" 2>/dev/null || true
	chmod 640 "$bundle_path" 2>/dev/null || true

	ensure_command_dep enscript "audit PDF generation" enscript || true
	ensure_command_dep ps2pdf "audit PDF generation" ghostscript || true
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
			ensure_command_dep pdftotext "audit import from PDF" poppler-utils || true
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
	done <"$source_path"

	if ((${#ACTIONABLE_ITEMS[@]} == 0)); then
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

	IFS=',' read -r -a tokens <<<"$selection"
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
		if [[ -v "picks[index:${idx}]" || -v "picks[tag:${tag}]" ]]; then
			SELECTED_ACTIONABLE_ITEMS+=("$item")
		else
			DEFERRED_ACTIONABLE_ITEMS+=("$item")
		fi
		((idx++))
	done

	((${#SELECTED_ACTIONABLE_ITEMS[@]} > 0))
}

# handle_actionable_follow_up() - Gate implementation on approval and optional item selection.
# If declined, export a PDF audit report plus TXT import bundle; if approved,
# allow all or selected changes by item number and/or actionable tag.
handle_actionable_follow_up() {
	local summary_path="${1:-}"
	local selection="all"

	show_actionable_items
	((${#ACTIONABLE_ITEMS[@]} > 0)) || return 0

	if ! confirm "Implement the recommended next steps from the final summary now?"; then
		info "User declined implementation of recommended changes."
		generate_audit_pdf "$summary_path" || true
		info "Actionable items remain recorded in: ${USER_RESULTS_DIR:-$LOG_FILE}"
		return 0
	fi

	if ((${#ACTIONABLE_ITEMS[@]} > 1)); then
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
	if ((${#DEFERRED_ACTIONABLE_ITEMS[@]} > 0)); then
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
  2  System updates (incl. fwupd firmware/microcode + hardware key support)
  3  Automatic updates
  4  SELinux tools
  5  firewalld
  6  Secure Boot verify
  7  SSH hardening
  8  USBGuard
  9  PAM/password policy
 10  Kernel sysctl (incl. IPv6 privacy extensions)
 11  auditd (incl. time/network/mount/delete rules)
 12  rkhunter + AIDE
 13  Flatpak / Flathub (incl. optional Firejail)
 14  DNS over TLS (14b: NetworkManager MAC address randomization)
 15  Desktop environment settings (auto-dispatches by detected DE):
       KDE Plasma  — kwriteconfig6/5: screen lock, recent-docs, BT opt-out
       GNOME/Onyx  — gsettings: lock, location off, privacy, mic off
       Budgie      — gsettings (GNOME backend): same privacy stack
       Cinnamon    — org.cinnamon.desktop.screensaver + GNOME privacy schemas
       MATE        — org.mate.screensaver + org.mate.power-manager
       XFCE/Vauxite— xfconf-query: screensaver + power manager idle
       Sway/Sericea— writes swaylock.conf + swayidle.conf
       Hyprland    — writes hypridle.conf (lock 5 min, suspend 10 min)
       i3          — xss-lock + i3lock drop-in via config.d/
       LXQt/Lazurite — lxqt-screensaver.conf + lxqt-powermanagement.conf
 16  Firefox Flatpak + arkenfox + extensions (uBlock, LocalCDN, Containers) + VPN check
 17  WireGuard
 18  Fail2Ban
 19  Service trim
 20  File permissions (incl. umask 077, core dump limits, hostname privacy)
 21  ClamAV (incl. on-access scanning for /home)
 22  OpenSCAP
 23  Container security (Podman + Toolbox / containerized-mindset setup)

 Optimized execution order (guide section numbers):
    2,3,6,13,4,5,7,9,10,11,14,18,15,16,17,21,22,23,12,19,20,8

 DE detection (section 15 auto-dispatches — all detected DEs are hardened):
    Running session: XDG_CURRENT_DESKTOP / DESKTOP_SESSION
    Installed tools: kwriteconfig, gnome-shell, cinnamon, mate-session,
                     xfce4-session, startlxqt, sway, Hyprland, i3, budgie-desktop
    Spin → DE:  Kinoite/Aurora→KDE  Silverblue/Onyx→GNOME  Sericea→Sway
                Lazurite→LXQt  Vauxite→XFCE  Bazzite→KDE or GNOME

 Supported Fedora variants (auto-detected):
    Workstation, Server, IoT, Cloud, CoreOS
    Kinoite (KDE), Silverblue (GNOME), Onyx (GNOME Atomic)
    Sericea (Sway Atomic), Lazurite (LXQt Atomic), Vauxite (XFCE Atomic)
    Bazzite (gaming), Aurora / Universal Blue (KDE)
    XFCE/LXQt/Cinnamon/MATE/Budgie spins (mutable)
EOF
}

# parse_args() - Parse command-line arguments and set global flags.
# Recognized options: -u/--user, -y/--yes, -n/--dry-run, --gui, --gui-full,
# --import-audit, --skip, --only, --list, -h/--help
# Validates option syntax and applies settings globally for use throughout script.
# Usage: parse_args "$@" (called in main before preflight)
parse_args() {
	while [[ $# -gt 0 ]]; do
		case "$1" in
		-u | --user)
			if [[ -z "${2:-}" ]]; then
				err "Option --user requires a username argument"
				usage
				exit 2
			fi
			TARGET_USER="$2"
			shift 2
			;;
		-y | --yes)
			ASSUME_YES=1
			shift
			;;
		-n | --dry-run)
			DRY_RUN=1
			shift
			;;
		--gui)
			FORCE_GUI=1
			shift
			;;
		--gui-full)
			FORCE_GUI_FULL=1
			shift
			;;
		--import-audit)
			if [[ -z "${2:-}" ]]; then
				err "Option --import-audit requires a file path argument"
				usage
				exit 2
			fi
			IMPORT_AUDIT_PATH="$2"
			shift 2
			;;
		--skip)
			if [[ -z "${2:-}" ]]; then
				err "Option --skip requires a section list argument"
				usage
				exit 2
			fi
			SKIP_LIST="$2"
			shift 2
			;;
		--only)
			if [[ -z "${2:-}" ]]; then
				err "Option --only requires a section list argument"
				usage
				exit 2
			fi
			ONLY_LIST="$2"
			shift 2
			;;
		--list)
			list_sections
			exit 0
			;;
		--list-sessions)
			LIST_SESSIONS_MODE=1
			shift
			;;
		--rollback)
			if [[ -n "${2:-}" && "${2:-}" != -* ]]; then
				ROLLBACK_SESSION_ID="$2"
				shift 2
			else
				ROLLBACK_SESSION_ID="last"
				shift
			fi
			;;
		-h | --help)
			usage
			exit 0
			;;
		*)
			err "Unknown argument: $1"
			usage
			exit 2
			;;
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
	((FORCE_GUI_FULL)) || draw_banner
	setup_ui_mode
	if ((EUID != 0)); then
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
		err "Cannot read /etc/os-release — is this Fedora?"
		exit 1
	fi
	# shellcheck source=/dev/null
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
	((IS_KINOITE)) && HAS_KDE=1
	if [[ "${VERSION_ID:-}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
		FEDORA_MAJOR="${VERSION_ID%%.*}"
	fi
	if ((FEDORA_MAJOR > 0 && FEDORA_MAJOR < 44)); then
		warn "Fedora version is '${VERSION_ID:-unknown}' — guide targets Fedora 44+."
		confirm "Proceed on this older version?" || exit 0
	fi
	info "Host: $HOST_LABEL   Distro: ${PRETTY_NAME:-?}   Kernel: $KERNEL_LABEL"
	info "Variant: ${FEDORA_VARIANT}"
	info "Release flags: workstation=$IS_WORKSTATION server=$IS_SERVER iot=$IS_IOT cloud=$IS_CLOUD coreos=$IS_COREOS ostree=$IS_OSTREE atomic_desktop=$IS_ATOMIC_DESKTOP"
	if ((IS_OSTREE)); then
		info "Detected rpm-ostree (immutable) host. Using rpm-ostree for package/update actions."
	fi
	if ((IS_KINOITE)); then
		info "Detected Fedora Kinoite variant."
	fi
	if ((IS_SILVERBLUE)); then
		info "Detected Fedora Silverblue variant. KDE-only tweaks will be skipped where incompatible."
	fi
	if ((IS_WORKSTATION)); then
		info "Detected Fedora Workstation variant. Desktop-focused sections are enabled."
	fi
	if ((IS_SERVER)); then
		info "Detected Fedora Server release profile."
	fi
	if ((IS_IOT)); then
		info "Detected Fedora IoT release profile."
	fi
	if ((IS_CLOUD)); then
		info "Detected Fedora Cloud release profile."
	fi
	if ((IS_COREOS)); then
		info "Detected Fedora CoreOS release profile."
	fi
	info "Fedora major version detected: ${FEDORA_MAJOR}"
	if ((HAS_DESKTOP)); then
		info "Detected desktop environments: ${DESKTOP_ENVS:-unknown}"
	else
		warn "No desktop environment detected; desktop-focused sections may be skipped."
	fi
	info "Log file:    $LOG_FILE"
	info "Backup dir:  $BACKUP_DIR (created on first change)"
	init_rollback_journal
	init_session_dir
	((DRY_RUN)) && warn "DRY RUN mode — no changes will be applied."
	((ASSUME_YES)) && warn "Auto-yes mode — no interactive confirmations."

	# Resolve target user if not given
	if [[ -z "$TARGET_USER" && -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
		TARGET_USER="$SUDO_USER"
		info "Target user inferred from sudo: $TARGET_USER"
	fi
	if [[ -z "$TARGET_USER" ]]; then
		if ((ASSUME_YES)); then
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
# sec_02_updates() - Perform full system package updates plus firmware/microcode
# Runs dnf upgrade (or rpm-ostree update on immutable systems). Also installs fwupd
# for firmware updates (privacyguides.org) and ensures CPU microcode is current
# (Intel: microcode_ctl; AMD: linux-firmware) to patch Spectre/Meltdown and similar.
# Optionally installs hardware security key support (YubiKey/FIDO2/PIV: pcsc-lite,
# opensc, libfido2, yubico-piv-tool, yubikey-manager, pam-u2f) and reminds the user
# to have the key plugged in before section 8 (USBGuard) runs.
# Recommends reboot after completion.
sec_02_updates() {
	should_run 2 || return 0
	section 2 "System updates"
	pkg_upgrade
	ok "System packages updated. A reboot is recommended when the script finishes."

	# Install fwupd for firmware updates and check for available updates (privacyguides.org)
	if ! cmd_exists fwupdmgr; then
		pkg_install fwupd
		unset '_CMD_CACHE[fwupdmgr]' # Invalidate stale cache after install
	fi
	if cmd_exists fwupdmgr; then
		info "Refreshing fwupd metadata and checking for firmware updates..."
		run "fwupdmgr refresh --force || true"
		run "fwupdmgr get-updates || true"
		info "Apply firmware updates with: sudo fwupdmgr update"
	fi

	# Ensure CPU microcode is installed (privacyguides.org — patches Spectre/Meltdown/etc.)
	local cpu_vendor
	cpu_vendor="$(awk -F: '/^vendor_id/{print $2; exit}' /proc/cpuinfo 2>/dev/null | tr -d ' ')"
	case "${cpu_vendor:-}" in
	GenuineIntel)
		pkg_cached microcode_ctl || pkg_install microcode_ctl
		ok "Intel microcode package ensured."
		;;
	AuthenticAMD)
		pkg_cached linux-firmware || pkg_install linux-firmware
		ok "AMD microcode (linux-firmware) ensured."
		;;
	*)
		info "CPU vendor not Intel/AMD ('${cpu_vendor:-unknown}') — skipping microcode install."
		;;
	esac

	# ── Hardware security key support (YubiKey, FIDO2, PIV smart cards) ──────
	# Ask if the user owns a hardware security key. If yes, install support packages
	# and remind them to have the key physically accessible during section 8 (USBGuard),
	# since USBGuard will prompt to allow or block every new USB device — a key that
	# is unplugged at that point would need to be explicitly allowed afterwards.
	if confirm "Do you use a hardware security key (YubiKey, FIDO2 token, PIV smart card)?"; then
		info "Installing hardware security key support packages..."
		pkg_install pcsc-lite pcsc-lite-libs opensc libfido2 yubico-piv-tool yubikey-manager
		run "systemctl enable --now pcscd.socket || true"
		ok "Hardware key support packages installed and pcscd.socket enabled."
		if confirm "Install pam_u2f for PAM/sudo authentication via FIDO2/U2F key?"; then
			pkg_install pam-u2f
			info "pam_u2f installed — configure /etc/pam.d/ manually to add the U2F factor."
			info "  Reference: https://developers.yubico.com/pam-u2f/"
			add_action_item 2 MEDIUM "HWKEY_PAM_U2F" \
				"pam-u2f was installed. Configure PAM (/etc/pam.d/sudo, /etc/pam.d/system-auth) to require your hardware key for authentication. See: https://developers.yubico.com/pam-u2f/"
		fi
		printf '\n%s╔══════════════════════════════════════════════════════════════╗%s\n' "$C_YEL" "$C_RST"
		printf '%s║  ⚠  HARDWARE KEY REMINDER — READ BEFORE SECTION 8            ║%s\n' "$C_YEL" "$C_RST"
		printf '%s║                                                              ║%s\n' "$C_YEL" "$C_RST"
		printf '%s║  Section 8 (USBGuard) will prompt you to ALLOW or BLOCK      ║%s\n' "$C_YEL" "$C_RST"
		printf '%s║  every USB device it sees at configuration time.             ║%s\n' "$C_YEL" "$C_RST"
		printf '%s║                                                              ║%s\n' "$C_YEL" "$C_RST"
		printf '%s║  • Plug in your hardware key BEFORE section 8 runs so it     ║%s\n' "$C_YEL" "$C_RST"
		printf '%s║    gets added to the allowlist automatically.                ║%s\n' "$C_YEL" "$C_RST"
		printf '%s║  • If you miss it, run afterwards:                           ║%s\n' "$C_YEL" "$C_RST"
		printf '%s║     sudo usbguard generate-policy >> /etc/usbguard/rules.conf║%s\n' "$C_YEL" "$C_RST"
		printf '%s║    or use the USBGuard GUI / CLI to allow the device.        ║%s\n' "$C_YEL" "$C_RST"
		printf '%s╚══════════════════════════════════════════════════════════════╝%s\n\n' "$C_YEL" "$C_RST"
		add_action_item 2 HIGH "HWKEY_USBGUARD_READY" \
			"Hardware security key detected: ensure it is plugged in BEFORE section 8 (USBGuard) runs so it is added to the allowlist. If missed, run: sudo usbguard generate-policy >> /etc/usbguard/rules.conf"
	fi
}

# ============================================================================
#  SECTION 3 — dnf5-automatic (Fedora 41+)
# ============================================================================
# sec_03_dnf_automatic() - Configure automatic security updates + countme opt-out
# Sets up dnf5-automatic for mutable systems or rpm-ostreed policy for immutable
# systems to apply security patches automatically. On rpm-ostree, stages updates.
# Sub-section 3b disables the Fedora system-counting mechanism: sets countme=false
# in /etc/dnf/dnf.conf on mutable systems, or masks rpm-ostree-countme.timer on
# immutable ones — per privacyguides.org recommendation.
sec_03_dnf_automatic() {
	should_run 3 || return 0
	section 3 "Automatic security updates"

	# Handle rpm-ostree (immutable) systems first
	if ((IS_OSTREE)); then
		local ro_conf="/etc/rpm-ostreed.conf"
		[[ ! -f "$ro_conf" ]] && {
			warn "$ro_conf not found; skipping config write."
			return 0
		}

		backup_file "$ro_conf"
		if ((!DRY_RUN)); then
			# Update existing policy or add new [Daemon] section (batch single sed pass)
			if grep -qE '^\s*AutomaticUpdatePolicy\s*=' "$ro_conf"; then
				sed -i -E 's|^\s*AutomaticUpdatePolicy\s*=.*|AutomaticUpdatePolicy=stage|' "$ro_conf" 2>/dev/null || true
			elif grep -qE '^\[Daemon\]' "$ro_conf"; then
				sed -i '/^\[Daemon\]/a AutomaticUpdatePolicy=stage' "$ro_conf" 2>/dev/null || true
			else
				printf '\n[Daemon]\nAutomaticUpdatePolicy=stage\n' >>"$ro_conf" 2>/dev/null || true
			fi
			ok "Configured rpm-ostreed automatic update staging in $ro_conf"
		else
			info "Would set AutomaticUpdatePolicy=stage in $ro_conf"
		fi

		# Enable timer if available
		if systemctl list-unit-files rpm-ostreed-automatic.timer >/dev/null 2>&1; then
			run "systemctl enable --now rpm-ostreed-automatic.timer"
		else
			warn "rpm-ostreed-automatic.timer not found; configure automatic updates manually."
		fi
		return 0
	fi

	# Handle mutable systems: detect dnf version, configure, enable
	local pkg timer conf
	pkg="dnf5-automatic"
	timer="dnf5-automatic.timer"
	conf="/etc/dnf/automatic.conf"
	if ! cmd_exists dnf || ! dnf info dnf5-automatic &>/dev/null; then
		pkg="dnf-automatic"
		timer="dnf-automatic.timer"
		conf="/etc/dnf/automatic.conf"
		warn "dnf5-automatic not found in repos — falling back to dnf-automatic."
	fi

	pkg_install "$pkg"
	[[ -f "$conf" ]] || {
		warn "$conf not found after install; skipping config."
		return 0
	}

	backup_file "$conf"
	if ((!DRY_RUN)); then
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

	# 3b — DNF countme=false (privacyguides.org: opt out of Fedora system counting)
	# The Fedora Project uses a 'countme' variable to count unique systems accessing
	# its mirrors. privacyguides.org explicitly recommends opting out. On rpm-ostree
	# the equivalent is masking the rpm-ostree-countme timer.
	local dnf_conf="/etc/dnf/dnf.conf"
	if ((IS_OSTREE)); then
		if ((!DRY_RUN)); then
			if systemctl mask rpm-ostree-countme.timer 2>/dev/null; then
				ok "Masked rpm-ostree-countme.timer (privacyguides.org: opt out of system counting)"
			else
				info "rpm-ostree-countme.timer not found or already masked — skipping."
			fi
		else
			info "Would mask rpm-ostree-countme.timer"
		fi
	elif [[ -f "$dnf_conf" ]]; then
		if ((!DRY_RUN)); then
			if grep -qE '^\s*countme\s*=' "$dnf_conf" 2>/dev/null; then
				sed -i 's|^\s*countme\s*=.*|countme=false|' "$dnf_conf" 2>/dev/null || true
			else
				echo 'countme=false' >>"$dnf_conf" 2>/dev/null || true
			fi
			ok "Set countme=false in $dnf_conf (privacyguides.org: opt out of system counting)"
		else
			info "Would set countme=false in $dnf_conf"
		fi
	else
		info "$dnf_conf not found — skipping countme opt-out."
	fi
}

# ============================================================================
#  SECTION 4 — SELinux
# ============================================================================
# sec_04_selinux() - Verify SELinux is enforcing and install tools
# Confirms SELinux is in enforcing mode; installs debugging and management tools
# (policycoreutils, selinux-policy-devel). Logs policy violations.
sec_04_selinux() {
	should_run 4 || return 0
	section 4 "SELinux (verify enforcing + install tools)"
	local mode
	mode="$(getenforce 2>/dev/null || echo unknown)"
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
	local svc_name="${1}"
	shift
	local svc_short="${1}"
	shift
	local svc_dir="/etc/firewalld/services"
	local svc_file="${svc_dir}/${svc_name}.xml"

	# Already known to firewalld — nothing to do.
	if firewall-cmd --get-services 2>/dev/null | grep -qw "${svc_name}"; then
		return 0
	fi

	if ((DRY_RUN)); then
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
			port="${portproto%%/*}"
			proto="${portproto##*/}"
			printf '  <port port="%s" protocol="%s"/>\n' "${port}" "${proto}"
		done
		printf '</service>\n'
	} >"${svc_file}"
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
	if ((DRY_RUN)); then
		info "Would run: firewall-cmd --zone=${zone} --add-service=${svc} --permanent"
		return 0
	fi
	log "[RUN]   firewall-cmd --zone=${zone} --add-service=${svc} --permanent"
	local out ec
	# Capture output and exit code without triggering set -e abort on failure
	out=$(firewall-cmd --zone="${zone}" --add-service="${svc}" --permanent 2>&1) || ec=$?
	ec=${ec:-0}
	if ((ec == 0)); then
		ok "firewalld: added service '${svc}' to zone '${zone}'."
		return 0
	fi
	if ((ec == 101)) || [[ "${out}" == *"INVALID_SERVICE"* ]]; then
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
# sec_05_firewalld() - Harden firewalld with drop-default policy
# Sets default policy to DROP, allows minimal services, enables logging
sec_05_firewalld() {
	should_run 5 || return 0
	section 5 "firewalld — drop-by-default with explicit allow-list"
	pkg_install firewalld
	run "systemctl enable --now firewalld"

	# Smart wait for firewalld readiness (max 10 seconds with exponential backoff)
	info "Waiting for firewalld to be ready..."
	local attempt=0 max_attempts=10
	while ((attempt < max_attempts)); do
		if firewall-cmd --state &>/dev/null; then
			ok "firewalld is ready"
			break
		fi
		((attempt++))
		sleep $((attempt / 3 + 1)) # Exponential backoff: 1s, 1s, 2s, 2s...
	done
	((attempt >= max_attempts)) && warn "firewalld failed to become ready; proceeding anyway"

	# Set default zone and configure services (batch permanent operations)
	info "Setting default zone to 'drop'..."
	run "firewall-cmd --set-default-zone=drop"

	local svc services_to_allow=()
	if confirm "Allow 'mdns' through the firewall?"; then
		services_to_allow+=("mdns")
	fi
	# kde-connect is KDE-specific and requires a custom service XML (not built-in to firewalld).
	# firewalld_ensure_service queries firewall-cmd --get-services internally, so no pre-caching needed.
	if ((HAS_KDE)); then
		if confirm "Allow 'kde-connect' through the firewall?"; then
			firewalld_ensure_service "kde-connect" "KDE Connect" \
				"1714-1764/tcp" "1714-1764/udp"
			services_to_allow+=("kde-connect")
		fi
	fi

	# Bazzite/gaming spins: offer Steam Remote Play and game streaming ports
	if ((IS_GAMING_SPIN)); then
		if confirm "Gaming spin detected (Bazzite). Allow Steam Remote Play + game-streaming ports?"; then
			firewalld_ensure_service "steam-remote-play" "Steam Remote Play" \
				"27031/tcp" "27036/tcp" "27031/udp" "27032/udp" "27033/udp" "27034/udp" "27035/udp" "27036/udp"
			services_to_allow+=("steam-remote-play")
			add_action_item 5 LOW "GAMING_FIREWALL_REVIEW" \
				"Bazzite/gaming spin: review firewall zone after game installs (Steam, Heroic, etc. may request additional ports)."
		else
			info "Skipping Steam Remote Play ports — add manually if needed."
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
# sec_06_secureboot() - Verify Secure Boot is enabled
# Confirms UEFI Secure Boot is active. GRUB password is manual task.
sec_06_secureboot() {
	should_run 6 || return 0
	section 6 "Secure Boot verification"
	if ! cmd_exists mokutil; then
		ensure_command_dep mokutil "Secure Boot verification" mokutil || true
	fi
	if cmd_exists mokutil; then
		local sb
		sb="$(mokutil --sb-state 2>/dev/null || true)"
		info "$sb"
		if grep -qi "enabled" <<<"$sb"; then
			ok "Secure Boot is enabled."
		else
			warn "Secure Boot is NOT enabled. Enable it in UEFI firmware settings."
		fi
	else
		warn "mokutil is unavailable after dependency checks — cannot verify Secure Boot state."
	fi
	if ((GUI_FULL_MODE)); then
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
# sec_07_ssh() - Configure SSH for key-based auth with hardened ciphers
# Disables password auth, enables key-based auth, applies strong cipher suite.
sec_07_ssh() {
	should_run 7 || return 0
	section 7 "SSH hardening"
	if ! pkg_cached openssh-server; then
		warn "openssh-server is missing; attempting dependency install for section 7."
		pkg_install openssh-server || true
		pkg_cached openssh-server || {
			warn "openssh-server is still unavailable; skipping SSH hardening."
			return 0
		}
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

	if ((DRY_RUN)); then
		info "Would write hardened drop-in to $drop"
	else
		install -d -m 755 /etc/ssh/sshd_config.d 2>/dev/null || true
		if ! cat >"$drop" <<EOF; then
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
			warn "Failed to write $drop (filesystem may be read-only or full)"
			return 1
		fi
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
# sec_08_usbguard() - Install and configure USBGuard
# Configures device control policy; note: can lock out input devices if misconfigured.
sec_08_usbguard() {
	should_run 8 || return 0
	section 8 "USBGuard — ⚠ BE CAREFUL ⚠"
	if ((GUI_FULL_MODE)); then
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
	if ((DRY_RUN)); then
		info "Would generate policy: usbguard generate-policy > /etc/usbguard/rules.conf"
	else
		umask 077
		local tmp_usbguard="/tmp/usbguard-rules-$$-$RANDOM-$SECONDS.conf"
		register_tmp "$tmp_usbguard"
		if ! usbguard generate-policy >"$tmp_usbguard" 2>/dev/null; then
			warn "usbguard generate-policy failed"
			rm -f "$tmp_usbguard" 2>/dev/null || true
			return 1
		fi
		if ! install -m 0600 -o root -g root "$tmp_usbguard" /etc/usbguard/rules.conf 2>/dev/null; then
			warn "Failed to install USBGuard rules (filesystem may be read-only)"
			rm -f "$tmp_usbguard" 2>/dev/null || true
			return 1
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
# sec_09_pam() - Configure PAM policy
# Sets password quality, account lockout, aging rules via pwquality and faillock.
sec_09_pam() {
	should_run 9 || return 0
	section 9 "Password quality + account lockout + aging"

	# 9a pwquality — batched sed for efficiency
	local pq="/etc/security/pwquality.conf"
	backup_file "$pq"
	if ((!DRY_RUN)); then
		batch_sed "$pq" \
			's|^\s*#?\s*minlen\s*=.*|minlen = 14|' \
			's|^\s*#?\s*ucredit\s*=.*|ucredit = -1|' \
			's|^\s*#?\s*lcredit\s*=.*|lcredit = -1|' \
			's|^\s*#?\s*dcredit\s*=.*|dcredit = -1|' \
			's|^\s*#?\s*ocredit\s*=.*|ocredit = -1|' \
			's|^\s*#?\s*minclass\s*=.*|minclass = 3|' \
			's|^\s*#?\s*dictcheck\s*=.*|dictcheck = 1|' \
			's|^\s*#?\s*usercheck\s*=.*|usercheck = 1|' \
			's|^\s*#?\s*gecoscheck\s*=.*|gecoscheck = 1|' \
			's|^\s*#?\s*retry\s*=.*|retry = 3|'
		# Ensure gecoscheck and badwords are present (may not be in all pwquality.conf versions)
		grep -qE '^\s*gecoscheck\s*=' "$pq" || echo 'gecoscheck = 1' >>"$pq"
		grep -qE '^\s*badwords\s*=' "$pq" || echo 'badwords = admin root password' >>"$pq"
		ok "Applied pwquality policy in $pq"
	else
		info "Would set minlen=14, ucredit=-1, lcredit=-1, dcredit=-1, ocredit=-1, minclass=3, dictcheck=1, usercheck=1, retry=3"
	fi

	# 9b faillock
	local fl="/etc/security/faillock.conf"
	backup_file "$fl"
	if ((!DRY_RUN)) && [[ -f "$fl" ]]; then
		batch_sed "$fl" \
			's|^\s*#?\s*deny\s*=.*|deny = 5|' \
			's|^\s*#?\s*unlock_time\s*=.*|unlock_time = 900|'
		grep -qE '^\s*even_deny_root' "$fl" || echo 'even_deny_root' >>"$fl"
		ok "Applied faillock policy in $fl"
	fi

	# 9c login.defs — batched sed
	local ld="/etc/login.defs"
	backup_file "$ld"
	if ((!DRY_RUN)) && [[ -f "$ld" ]]; then
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
# sec_10_sysctl() - Apply kernel sysctl hardening
# Hardens network, VM, filesystem, memory protections via kernel parameters.
# Covers: network spoofing/ICMP/redirect/forwarding mitigations, ASLR (randomize_va_space +
# mmap_rnd_bits), BPF JIT hardening, kexec disable, ptrace restriction, sysrq disable,
# TCP timestamp privacy, IPv6 privacy extensions, and core dump suppression.
# Based on Madaidan's Linux Hardening Guide (linked by privacyguides.org).
sec_10_sysctl() {
	should_run 10 || return 0
	section 10 "Kernel & network sysctl hardening"
	local f="/etc/sysctl.d/99-hardening.conf"
	if ((DRY_RUN)); then
		info "Would write $f with guide's full sysctl set"
	else
		if ! cat >"$f" <<'EOF'; then
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
net.ipv6.conf.default.accept_redirects = 0

net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1

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

# Prevent kexec — stops loading a new kernel without a full reboot, which
# blocks a major attack vector for persistent compromise (Madaidan / privacyguides.org)
kernel.kexec_load_disabled = 1

# Harden BPF JIT and restrict unprivileged BPF — limits exploitation of BPF
# subsystem vulnerabilities (Madaidan Linux Hardening Guide, linked by privacyguides.org)
net.core.bpf_jit_harden = 2
kernel.unprivileged_bpf_disabled = 1

# NOTE: 'kernel.unprivileged_userns_clone' is an Ubuntu-specific knob
# and does not exist on the Fedora kernel. The Fedora equivalent is
# 'user.max_user_namespaces', but setting it to 0 breaks Flatpak,
# podman, browsers, and systemd user services — so it is left at the
# default intentionally. Uncomment only if you understand the impact.
# user.max_user_namespaces = 0

kernel.randomize_va_space = 2

# Increase ASLR entropy on 64-bit systems for stronger randomization
# (Madaidan Linux Hardening Guide; these are the maximum safe values on x86_64)
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16

kernel.pid_max = 65536

fs.suid_dumpable = 0
fs.protected_fifos = 2
fs.protected_regular = 2
fs.protected_symlinks = 1
fs.protected_hardlinks = 1

# ── IPv6 Privacy Extensions ───────────────────────────────────────────
# Randomize temporary IPv6 source addresses (privacyguides.org)
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2

# ── Network Privacy ───────────────────────────────────────────────────
# Disable TCP timestamps to reduce remote clock-skew fingerprinting
net.ipv4.tcp_timestamps = 0

# ── Core Dump Suppression ─────────────────────────────────────────────
# Route core dumps to /bin/false so they are silently discarded
kernel.core_pattern = |/bin/false
EOF
			err "Failed to write sysctl configuration"
			return 1
		fi
		chmod 644 "$f" 2>/dev/null || true
		ok "Wrote $f"
	fi
	run "sysctl --system"
	run "sysctl kernel.kptr_restrict"
}

# ============================================================================
#  SECTION 11 — auditd
# ============================================================================
# sec_11_auditd() - Configure auditd audit rules
# Tracks identity changes, privilege escalation, kernel module loading, time
# changes, network configuration edits, filesystem mounts, and file deletions
# per inteltechniques.com recommendations. Covers NIST/CIS baseline events.
sec_11_auditd() {
	should_run 11 || return 0
	section 11 "auditd rules"
	pkg_install audit audit-libs
	run "systemctl enable --now auditd"

	local rules="/etc/audit/rules.d/hardening.rules"
	if ((DRY_RUN)); then
		info "Would write $rules"
	else
		if ! cat >"$rules" <<'EOF'; then
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

# System time changes (inteltechniques.com)
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time_change
-w /etc/localtime -p wa -k time_change

# Network configuration changes (inteltechniques.com)
-a always,exit -F arch=b64 -S sethostname,setdomainname -k network_config
-w /etc/hosts        -p wa -k network_config
-w /etc/network/     -p wa -k network_config
-w /etc/sysconfig/network -p wa -k network_config

# File system mounts (inteltechniques.com)
-a always,exit -F arch=b64 -S mount -k mounts

# File deletion by users (inteltechniques.com)
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete

# Uncomment to lock the ruleset at boot (requires reboot to change):
# -e 2
EOF
			warn "Failed to write $rules (filesystem may be read-only)"
			return 1
		fi
		chmod 640 "$rules" 2>/dev/null || true
		ok "Wrote $rules"
	fi
	local augen_rc=0
	run "augenrules --load" || augen_rc=$?
	if ((augen_rc != 0)); then
		warn "augenrules --load failed (exit $augen_rc) — check $rules for syntax errors."
		warn "Audit rules written but not loaded. Re-run 'sudo augenrules --load' after fixing."
	fi
	run "systemctl restart auditd || service auditd restart"
}

# ============================================================================
#  SECTION 12 — rkhunter + AIDE
# ============================================================================
# sec_12_ids() - Install intrusion and file integrity detection
# Installs rkhunter for rootkit detection and AIDE for file integrity monitoring.
sec_12_ids() {
	should_run 12 || return 0
	section 12 "rkhunter + AIDE"

	pkg_install rkhunter aide

	local rk_tmp="/tmp/rkhunter-out-$$.tmp" rk_warn_count=0 cron_rk="/etc/cron.daily/rkhunter-scan"
	register_tmp "$rk_tmp"

	if cmd_exists rkhunter; then
		# rkhunter: update signatures then run scan with output capture
		run "rkhunter --update || true"
		run "rkhunter --propupd"
		info "Running initial rkhunter scan (this takes a minute)..."
		if ((!DRY_RUN)); then
			log "[RUN]   rkhunter --check --sk --rwo"
			if ((GUI_FULL_MODE)); then
				rkhunter --check --sk --rwo >"$rk_tmp" 2>&1 || true
			else
				rkhunter --check --sk --rwo 2>&1 | tee "$rk_tmp" || true
			fi
			rk_warn_count="$(awk '/^\[ Warning \]/{count++} END{print count+0}' "$rk_tmp" 2>/dev/null || echo 0)"
		else
			run "rkhunter --check --sk --rwo || true"
		fi

		# Daily cron
		if ((!DRY_RUN)); then
			if ! cat >"$cron_rk" <<'CRONEOF'; then
#!/bin/bash
/usr/bin/rkhunter --cronjob --update --quiet
CRONEOF
				warn "Failed to write $cron_rk"
			else
				chmod 755 "$cron_rk" 2>/dev/null || true
				ok "Wrote $cron_rk"
			fi
		fi
	else
		warn "rkhunter not yet active (staged for next boot on rpm-ostree) — skipping scan; cron will run after reboot."
		add_action_item 12 MEDIUM "RK_REBOOT_REQUIRED" \
			"rkhunter staged but not active — reboot then run: sudo rkhunter --propupd && sudo rkhunter --check --sk --rwo"
	fi

	# AIDE: initialize database
	local cron_aide="/etc/cron.weekly/aide-check"
	if cmd_exists aide; then
		info "Initializing AIDE database (this can take several minutes)..."
		run "aide --init"
		if ((!DRY_RUN)) && [[ -f /var/lib/aide/aide.db.new.gz ]]; then
			run "mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
		fi
	else
		warn "aide not yet active (staged for next boot on rpm-ostree) — skipping database init."
		add_action_item 12 MEDIUM "AIDE_REBOOT_REQUIRED" \
			"aide staged but not active — reboot then run: sudo aide --init && sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
	fi

	if cmd_exists aide && ((!DRY_RUN)); then
		if ! cat >"$cron_aide" <<'CRONEOF'; then
#!/bin/bash
/usr/sbin/aide --check 2>&1 | logger -t aide
CRONEOF
			warn "Failed to write $cron_aide"
		else
			chmod 755 "$cron_aide" 2>/dev/null || true
			ok "Wrote $cron_aide (results sent to journal via logger)"
		fi
		warn "Re-initialize AIDE after legitimate package updates: 'sudo aide --init && sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz'"
	fi

	# Write section report to user Downloads/<project>/results/
	if ((!DRY_RUN)); then
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
	if ((rk_warn_count > 0)); then
		warn "rkhunter found $rk_warn_count warning(s) — review the section 12 report."
		add_action_item 12 HIGH "RK_WARNINGS" \
			"rkhunter found $rk_warn_count warning(s): investigate flagged files, then run: sudo rkhunter --propupd"
	else
		ok "rkhunter scan: no warnings detected."
	fi
	if ((!DRY_RUN)) && [[ ! -f /var/lib/aide/aide.db.gz ]]; then
		add_action_item 12 HIGH "AIDE_DB_MISSING" \
			"AIDE database not initialized — run: sudo aide --init && sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
	fi
	add_action_item 12 LOW "AIDE_RECHECK" \
		"Re-initialize AIDE after any future package updates (command in section-12 report)."
}

# ============================================================================
#  SECTION 13 — Flatpak / Flathub
# ============================================================================
# sec_13_flatpak() - Configure Flatpak for app sandboxing
# Installs Flatpak, adds Flathub, and offers Flatseal for permission management.
# Optionally installs Firejail for sandboxing non-Flatpak applications
# (inteltechniques.com recommendation); runs firecfg for desktop integration.
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

	# Optional: Firejail for sandboxing non-Flatpak apps (inteltechniques.com recommendation)
	if confirm "Install Firejail (sandbox non-Flatpak applications)?"; then
		pkg_install firejail
		unset '_CMD_CACHE[firecfg]' # Invalidate stale cache after install
		if cmd_exists firecfg; then
			info "Running firecfg to create desktop integration symlinks..."
			run "firecfg || true"
			ok "Firejail installed. Run 'firecfg --list' to see sandboxed apps."
		fi
	fi

	# Remind user to review Flatpak app permissions with Flatseal after install.
	# privacyguides.org notes Flatpak allows unsafe defaults — Flatseal lets you
	# restrict per-app access to filesystem, network, portals, etc.
	add_action_item 13 MEDIUM "FLATPAK_PERMISSIONS" \
		"Review Flatpak app permissions with Flatseal (com.github.tchx84.Flatseal). Apps may have overly broad filesystem/network access by default — restrict each app to only what it needs."
}

# ============================================================================
#  SECTION 14 — DNS over TLS
# ============================================================================
# sec_14_dot() - Configure DNS over TLS (DoT) + NetworkManager MAC randomization
# Sets systemd-resolved to use Quad9 and Cloudflare DNS with TLS encryption and
# DNSSEC validation. Also writes a NetworkManager drop-in (14b) to randomize MAC
# addresses for Wi-Fi scans and connections, and for Ethernet — per
# privacyguides.org network-layer privacy guidance.
# Alternative no-log DoT provider (not configured automatically but recommended by
# privacyguides.org): Mullvad DNS — 194.242.2.2 / dns.mullvad.net — operates under
# Sweden's strong privacy laws, enforces no-logging, and supports DoT + DoH.
sec_14_dot() {
	should_run 14 || return 0
	section 14 "DNS over TLS via systemd-resolved"
	local dropin_dir="/etc/systemd/resolved.conf.d"
	local dropin="${dropin_dir}/99-hardening.conf"
	# Back up the drop-in if it already exists (not the base file, which we don't touch)
	[[ -f "$dropin" ]] && backup_file "$dropin"
	if ((!DRY_RUN)); then
		install -d -m 755 "$dropin_dir" 2>/dev/null || true
		if ! cat >"$dropin" <<'EOF'; then
[Resolve]
DNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net 1.1.1.1#cloudflare-dns.com
FallbackDNS=149.112.112.112#dns.quad9.net
DNSOverTLS=yes
DNSSEC=yes
EOF
			err "Failed to write DNS-over-TLS configuration"
			return 1
		fi
		ok "Wrote $dropin"
		info "DNS-over-TLS: Quad9 (primary, malware-blocking) + Cloudflare (fallback)"
		info "Alternative no-log options per privacyguides.org:"
		info "  • Mullvad DNS  — 194.242.2.2 / dns.mullvad.net  (Sweden, no-log, DoT+DoH)"
		info "  • AdGuard DNS  — 94.140.14.14 / dns.adguard-dns.com (anonymized, DoT+DoH+DoQ)"
	fi
	run "systemctl restart systemd-resolved"
	run "resolvectl status | head -25 || true"

	# 14b — NetworkManager MAC address randomization (privacyguides.org network privacy)
	info "Configuring NetworkManager MAC address randomization..."
	local nm_mac="/etc/NetworkManager/conf.d/99-mac-randomize.conf"
	if ((DRY_RUN)); then
		info "Would write $nm_mac (Wi-Fi and Ethernet MAC randomization)"
	else
		install -d -m 755 /etc/NetworkManager/conf.d 2>/dev/null || true
		if ! cat >"$nm_mac" <<'EOF'; then
[device]
wifi.scan-rand-mac-address=yes

[connection]
ethernet.cloned-mac-address=random
wifi.cloned-mac-address=random
EOF
			warn "Failed to write $nm_mac"
		else
			chmod 644 "$nm_mac" 2>/dev/null || true
			ok "Wrote $nm_mac (MAC address randomization enabled)"
			run "systemctl restart NetworkManager || true"
		fi
	fi
}

# ============================================================================
#  SECTION 15 — Desktop environment privacy & screen-lock settings
# ============================================================================
# sec_15_desktop() - Apply security and privacy settings for every detected DE.
#
# Single entry-point that auto-dispatches to per-DE sub-handlers based on the
# HAS_* flags set by detect_desktop_envs(). Multiple DEs can be active at once
# (e.g. GNOME + KDE on a multi-seat box); all detected ones are hardened.
#
# DE coverage (each block runs only if the corresponding HAS_* flag is set):
#   KDE Plasma    — kwriteconfig6/5: screen lock, recent-docs off, BT opt-out
#   GNOME/Onyx    — gsettings: screen lock, location off, privacy, mic off
#   Budgie        — gsettings (GNOME backend): same privacy stack as GNOME
#   Cinnamon      — gsettings: org.cinnamon.desktop.screensaver + GNOME privacy
#   MATE          — gsettings: org.mate.screensaver + power-manager
#   XFCE/Vauxite  — xfconf-query: screensaver lock + power manager idle
#   Sway/Sericea  — writes ~/.config/swaylock/config + ~/.config/swayidle/config
#   Hyprland      — writes ~/.config/hypr/hypridle.conf
#   i3            — xss-lock + i3lock drop-in in ~/.config/i3/config.d/
#   LXQt/Lazurite — writes lxqt-screensaver.conf + lxqt-powermanagement.conf
#
# Spin → DE mapping (inferred by detect_fedora_release_type + detect_desktop_envs):
#   Kinoite/Aurora/Bazzite-KDE → KDE
#   Silverblue/Onyx/Bazzite-GNOME → GNOME
#   Sericea → Sway    |  Lazurite → LXQt    |  Vauxite → XFCE
#   XFCE/LXQt/Cinnamon/MATE/Budgie spins → respective DE
sec_15_desktop() {
	should_run 15 || return 0
	section 15 "Desktop environment settings (all detected DEs)"

	if ((!HAS_DESKTOP)); then
		info "No desktop environment detected — skipping section 15."
		return 0
	fi

	if [[ -z "$TARGET_USER" ]]; then
		warn "No target user — cannot apply per-user DE settings."
		return 0
	fi

	local user_home applied_des=()
	user_home="$(eval echo "~${TARGET_USER}")"

	info "Detected desktop(s): ${DESKTOP_ENVS:-unknown}  (spin: ${FEDORA_VARIANT})"

	# ── KDE Plasma ────────────────────────────────────────────────────────────
	if ((HAS_KDE)); then
		info "--- KDE Plasma settings ---"
		local KW=""
		for c in kwriteconfig6 kwriteconfig5; do
			cmd_exists "$c" && KW="$c" && break
		done
		if [[ -z "$KW" ]]; then
			warn "kwriteconfig6/5 not found — KDE may not be fully installed; skipping KDE tweaks."
			add_action_item 15 MEDIUM "KDE_KWRITECONFIG_MISSING" \
				"kwriteconfig6/5 not found. After installing plasma-desktop, rerun: sudo ./fedora-harden.sh --only 15"
		else
			info "Using $KW for KDE settings"
			run "sudo -u '$TARGET_USER' '$KW' --file kscreenlockerrc --group Daemon --key Timeout 5"
			run "sudo -u '$TARGET_USER' '$KW' --file kscreenlockerrc --group Daemon --key Lock true"
			run "sudo -u '$TARGET_USER' '$KW' --file kscreenlockerrc --group Daemon --key LockGrace 0"
			run "sudo -u '$TARGET_USER' '$KW' --file kdeglobals --group RecentDocuments --key UseRecent false"
			if confirm "Disable Bluetooth entirely (only if you use no BT peripherals)?"; then
				run "systemctl disable --now bluetooth || true"
				if [[ -f /etc/bluetooth/main.conf ]]; then
					backup_file /etc/bluetooth/main.conf
					run "sed -i 's|^#\?AutoEnable=.*|AutoEnable=false|' /etc/bluetooth/main.conf"
				fi
			fi
			ok "KDE: screen lock, recent-docs disabled."
			info "KDE GUI-only: KWallet master password, Privacy tab, Activity tracking → System Settings."
			applied_des+=("KDE")
		fi
	fi

	# ── GNOME (Silverblue, Onyx, Workstation GNOME) ──────────────────────────
	if ((HAS_GNOME)); then
		info "--- GNOME settings ---"
		if ((!DRY_RUN)); then
			log "[RUN]   sudo -u '$TARGET_USER' gsettings batch (GNOME privacy)"
			sudo -u "$TARGET_USER" bash -c '
				gsettings set org.gnome.desktop.session idle-delay 300
				gsettings set org.gnome.desktop.screensaver lock-enabled true
				gsettings set org.gnome.desktop.screensaver lock-delay 0
				gsettings set org.gnome.system.location enabled false
				gsettings set org.gnome.desktop.privacy remove-old-temp-files true
				gsettings set org.gnome.desktop.privacy remove-old-trash-files true
				gsettings set org.gnome.desktop.privacy old-files-age 7
				gsettings set org.gnome.desktop.privacy send-software-usage-stats false
				gsettings set org.gnome.desktop.privacy report-technical-problems false
				gsettings set org.gnome.desktop.privacy remember-recent-files false
				gsettings set org.gnome.desktop.privacy disable-microphone true
			' 2>/dev/null || true
		else
			info "Would apply GNOME gsettings: screen lock, location off, privacy, mic off"
		fi
		ok "GNOME: screen lock, location off, privacy, mic off."
		info "GNOME GUI-only: Online Accounts, Sharing, Bluetooth → GNOME Settings."
		applied_des+=("GNOME")
	fi

	# ── Budgie (GNOME gsettings backend) ─────────────────────────────────────
	if ((HAS_BUDGIE)); then
		info "--- Budgie settings ---"
		if ((!DRY_RUN)); then
			log "[RUN]   sudo -u '$TARGET_USER' gsettings batch (Budgie/GNOME privacy)"
			sudo -u "$TARGET_USER" bash -c '
				gsettings set org.gnome.desktop.session idle-delay 300
				gsettings set org.gnome.desktop.screensaver lock-enabled true
				gsettings set org.gnome.desktop.screensaver lock-delay 0
				gsettings set org.gnome.system.location enabled false
				gsettings set org.gnome.desktop.privacy remember-recent-files false
				gsettings set org.gnome.desktop.privacy remove-old-temp-files true
				gsettings set org.gnome.desktop.privacy remove-old-trash-files true
				gsettings set org.gnome.desktop.privacy old-files-age 7
				gsettings set org.gnome.desktop.privacy send-software-usage-stats false
				gsettings set org.gnome.desktop.privacy disable-microphone true
			' 2>/dev/null || true
		else
			info "Would apply Budgie gsettings: screen lock, location off, privacy, mic off"
		fi
		ok "Budgie: screen lock, privacy applied."
		applied_des+=("Budgie")
	fi

	# ── Cinnamon ──────────────────────────────────────────────────────────────
	if ((HAS_CINNAMON)); then
		info "--- Cinnamon settings ---"
		if ((!DRY_RUN)); then
			log "[RUN]   sudo -u '$TARGET_USER' gsettings batch (Cinnamon privacy)"
			sudo -u "$TARGET_USER" bash -c '
				gsettings set org.cinnamon.desktop.screensaver lock-enabled true
				gsettings set org.cinnamon.desktop.screensaver lock-delay 0
				gsettings set org.cinnamon.desktop.session idle-delay 300 2>/dev/null || true
				gsettings set org.gnome.desktop.privacy remember-recent-files false 2>/dev/null || true
				gsettings set org.gnome.desktop.privacy remove-old-temp-files true 2>/dev/null || true
				gsettings set org.gnome.desktop.privacy remove-old-trash-files true 2>/dev/null || true
				gsettings set org.gnome.desktop.privacy old-files-age 7 2>/dev/null || true
				gsettings set org.gnome.system.location enabled false 2>/dev/null || true
			' 2>/dev/null || true
		else
			info "Would apply Cinnamon gsettings: screen lock, privacy, location off"
		fi
		ok "Cinnamon: screen lock, privacy applied."
		applied_des+=("Cinnamon")
	fi

	# ── MATE ──────────────────────────────────────────────────────────────────
	if ((HAS_MATE)); then
		info "--- MATE settings ---"
		if ((!DRY_RUN)); then
			log "[RUN]   sudo -u '$TARGET_USER' gsettings batch (MATE privacy)"
			sudo -u "$TARGET_USER" bash -c '
				gsettings set org.mate.screensaver lock-enabled true 2>/dev/null || true
				gsettings set org.mate.screensaver idle-activation-enabled true 2>/dev/null || true
				gsettings set org.mate.screensaver idle-delay 5 2>/dev/null || true
				gsettings set org.mate.power-manager sleep-display-ac 300 2>/dev/null || true
				gsettings set org.gnome.desktop.privacy remember-recent-files false 2>/dev/null || true
				gsettings set org.gnome.system.location enabled false 2>/dev/null || true
			' 2>/dev/null || true
		else
			info "Would apply MATE gsettings: screensaver lock, idle timeout, privacy"
		fi
		ok "MATE: screensaver lock, power-manager idle applied."
		applied_des+=("MATE")
	fi

	# ── XFCE (XFCE Spin + Vauxite Atomic) ────────────────────────────────────
	if ((HAS_XFCE)); then
		info "--- XFCE settings ---"
		if ! cmd_exists xfconf-query; then
			warn "xfconf-query not found — cannot configure XFCE settings."
			add_action_item 15 MEDIUM "XFCE_SCREENSAVER_MANUAL" \
				"Manually enable screensaver lock in XFCE Settings → Screensaver (lock after 5 min idle)"
		else
			if ((!DRY_RUN)); then
				log "[RUN]   sudo -u '$TARGET_USER' xfconf-query batch (XFCE screensaver/power)"
				sudo -u "$TARGET_USER" xfconf-query -c xfce4-screensaver -p /saver/enabled -s true 2>/dev/null || true
				sudo -u "$TARGET_USER" xfconf-query -c xfce4-screensaver -p /lock/enabled -s true 2>/dev/null || true
				sudo -u "$TARGET_USER" xfconf-query -c xfce4-screensaver -p /saver/idle-activation/enabled -s true 2>/dev/null || true
				sudo -u "$TARGET_USER" xfconf-query -c xfce4-screensaver -p /saver/idle-activation/delay -s 5 2>/dev/null || true
				sudo -u "$TARGET_USER" xfconf-query -c xfce4-power-manager -p /xfce4-power-manager/blank-on-ac -s 5 2>/dev/null || true
				sudo -u "$TARGET_USER" xfconf-query -c xfce4-power-manager -p /xfce4-power-manager/blank-on-battery -s 3 2>/dev/null || true
				sudo -u "$TARGET_USER" xfconf-query -c xfce4-session -p /general/SaveOnExit -s false 2>/dev/null || true
			else
				info "Would apply xfconf-query: screensaver lock, power manager idle, session save off"
			fi
			ok "XFCE: screensaver lock, power manager idle applied."
			info "XFCE GUI-only: File Manager → Preferences → Privacy (clear recent files on exit)."
		fi
		applied_des+=("XFCE")
	fi

	# ── Sway / wlroots (Sericea Atomic + any Sway session) ───────────────────
	if ((HAS_SWAY)); then
		info "--- Sway/wlroots settings ---"
		cmd_exists swaylock || {
			pkg_install swaylock || true
			unset '_CMD_CACHE[swaylock]'
		}
		cmd_exists swayidle || {
			pkg_install swayidle || true
			unset '_CMD_CACHE[swayidle]'
		}

		local swaylock_cfg="${user_home}/.config/swaylock/config"
		local swayidle_cfg="${user_home}/.config/swayidle/config"

		if ((!DRY_RUN)); then
			run "mkdir -p '${user_home}/.config/swaylock' '${user_home}/.config/swayidle'"
			if [[ ! -f "$swaylock_cfg" ]]; then
				cat >"$swaylock_cfg" <<'SWAYEOF'
# swaylock - privacy-hardened config (fedora-harden.sh)
color=000000
ignore-empty-password
show-failed-attempts
daemonize
SWAYEOF
				run "chown '${TARGET_USER}:${TARGET_USER}' '${swaylock_cfg}'"
				ok "Wrote $swaylock_cfg"
			else
				info "swaylock config already exists — leaving intact."
			fi
			if [[ ! -f "$swayidle_cfg" ]]; then
				cat >"$swayidle_cfg" <<'SWAYEOF'
# swayidle - auto-lock/suspend config (fedora-harden.sh)
timeout 300 'swaylock -f'
timeout 600 'systemctl suspend'
before-sleep 'swaylock -f'
SWAYEOF
				run "chown '${TARGET_USER}:${TARGET_USER}' '${swayidle_cfg}'"
				ok "Wrote $swayidle_cfg"
			else
				info "swayidle config already exists — leaving intact."
			fi
		else
			info "Would write swaylock.conf (black, immediate lock) + swayidle (lock 5 min, suspend 10 min)"
		fi
		add_action_item 15 MEDIUM "SWAY_AUTOSTART_SWAYIDLE" \
			"Add 'exec swayidle -w' to ~/.config/sway/config to autostart idle/lock daemon on login."
		applied_des+=("Sway")
	fi

	# ── Hyprland ──────────────────────────────────────────────────────────────
	if ((HAS_HYPRLAND)); then
		info "--- Hyprland settings ---"
		cmd_exists hypridle || {
			pkg_install hypridle 2>/dev/null || true
			unset '_CMD_CACHE[hypridle]'
		}
		cmd_exists hyprlock || {
			pkg_install hyprlock 2>/dev/null || true
			unset '_CMD_CACHE[hyprlock]'
		}

		local hypridle_cfg="${user_home}/.config/hypr/hypridle.conf"
		if ((!DRY_RUN)); then
			run "mkdir -p '${user_home}/.config/hypr'"
			if [[ ! -f "$hypridle_cfg" ]]; then
				cat >"$hypridle_cfg" <<'HYPREOF'
# hypridle - auto-lock config (fedora-harden.sh)
general {
    lock_cmd = pidof hyprlock || hyprlock
    before_sleep_cmd = loginctl lock-session
}

listener {
    timeout = 300
    on-timeout = loginctl lock-session
}

listener {
    timeout = 600
    on-timeout = systemctl suspend
}
HYPREOF
				run "chown '${TARGET_USER}:${TARGET_USER}' '${hypridle_cfg}'"
				ok "Wrote $hypridle_cfg"
			else
				info "hypridle config already exists — leaving intact."
			fi
		else
			info "Would write hypridle.conf (lock 5 min, suspend 10 min)"
		fi
		add_action_item 15 MEDIUM "HYPRLAND_AUTOSTART_HYPRIDLE" \
			"Add 'exec-once = hypridle' to ~/.config/hypr/hyprland.conf to autostart the idle daemon."
		applied_des+=("Hyprland")
	fi

	# ── i3 ────────────────────────────────────────────────────────────────────
	if ((HAS_I3)); then
		info "--- i3 settings ---"
		cmd_exists xss-lock || {
			pkg_install xss-lock 2>/dev/null || true
			unset '_CMD_CACHE[xss-lock]'
		}
		cmd_exists i3lock || {
			pkg_install i3lock 2>/dev/null || true
			unset '_CMD_CACHE[i3lock]'
		}

		local i3_cfg="${user_home}/.config/i3/config"
		local i3_cfg_d="${user_home}/.config/i3/config.d"
		local i3_lock_frag="${i3_cfg_d}/99-autolock.conf"

		if ((!DRY_RUN)); then
			run "mkdir -p '${i3_cfg_d}'"
			if [[ ! -f "$i3_lock_frag" ]]; then
				cat >"$i3_lock_frag" <<'I3EOF'
# i3 auto-lock via xss-lock + i3lock (fedora-harden.sh)
exec --no-startup-id xss-lock --transfer-sleep-lock -- i3lock --nofork --color=000000
exec --no-startup-id xautolock -time 5 -locker 'i3lock --color=000000'
I3EOF
				run "chown '${TARGET_USER}:${TARGET_USER}' '${i3_lock_frag}'"
				ok "Wrote $i3_lock_frag"
			else
				info "i3 autolock fragment already exists — leaving intact."
			fi
			if [[ -f "$i3_cfg" ]] && ! grep -q "config.d" "$i3_cfg" 2>/dev/null; then
				printf '\n# Auto-included by fedora-harden.sh\ninclude %s/*.conf\n' "${i3_cfg_d}" >>"$i3_cfg" || true
			fi
		else
			info "Would write i3 autolock drop-in (xss-lock + i3lock) in ${i3_cfg_d}/"
		fi
		add_action_item 15 MEDIUM "I3_LOCK_KEYBIND" \
			"Add a manual lock keybind: bindsym \$mod+l exec i3lock --color=000000"
		applied_des+=("i3")
	fi

	# ── LXQt (LXQt Spin + Lazurite Atomic) ───────────────────────────────────
	if ((HAS_LXQT)); then
		info "--- LXQt settings ---"
		local ss_cfg="${user_home}/.config/lxqt/lxqt-screensaver.conf"
		local pm_cfg="${user_home}/.config/lxqt/lxqt-powermanagement.conf"

		if ((!DRY_RUN)); then
			run "mkdir -p '${user_home}/.config/lxqt'"
			if [[ ! -f "$ss_cfg" ]]; then
				printf '[General]\nlockAfterEnable=true\nlockAfterTimeout=300\nscreensaverTimeout=300\n' >"$ss_cfg"
				run "chown '${TARGET_USER}:${TARGET_USER}' '${ss_cfg}'"
				ok "Wrote LXQt screensaver config"
			else
				backup_file "$ss_cfg"
				sed -i \
					-e 's|^lockAfterEnable=.*|lockAfterEnable=true|' \
					-e 's|^lockAfterTimeout=.*|lockAfterTimeout=300|' \
					-e 's|^screensaverTimeout=.*|screensaverTimeout=300|' \
					"$ss_cfg" || true
				ok "Patched LXQt screensaver config"
			fi
			if [[ ! -f "$pm_cfg" ]]; then
				printf '[General]\nenableIdleSuspend=true\nidleSuspendTimeout=600\n' >"$pm_cfg"
				run "chown '${TARGET_USER}:${TARGET_USER}' '${pm_cfg}'"
				ok "Wrote LXQt power management config"
			fi
		else
			info "Would write LXQt screensaver (lock 5 min) + power management (suspend 10 min) configs"
		fi
		info "LXQt GUI-only: verify in LXQt Settings → Screensaver / Power Management."
		applied_des+=("LXQt")
	fi

	# ── Summary ───────────────────────────────────────────────────────────────
	if ((${#applied_des[@]} > 0)); then
		ok "Section 15 complete. Hardened: ${applied_des[*]}"
	else
		warn "Section 15: desktop detected but no DE-specific settings could be applied."
	fi
}
# ============================================================================
# sec_16_firefox() - Harden Firefox Flatpak with arkenfox + extensions + telemetry opt-out + VPN check
# Installs Firefox Flatpak with arkenfox profiles and security extensions (uBlock Origin,
# LocalCDN, Multi-Account Containers). Enterprise policy also disables Firefox telemetry,
# studies, and Pocket. Also detects active VPN and recommends one if absent.
sec_16_firefox() {
	should_run 16 || return 0
	section 16 "Firefox hardening (Flatpak preferred + arkenfox + privacy extensions)"

	# Flatpak is preferred for Firefox due to stronger app sandboxing.
	if ! cmd_exists flatpak; then
		warn "flatpak is not available yet; attempting to install it now."
		pkg_install flatpak
		if ((IS_OSTREE)); then
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
			if ((DRY_RUN)); then
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

	if ((DRY_RUN)); then
		info "Would write Firefox extension policy to $policy_file"
	else
		install -d -m 0700 -o "$ff_user" -g "$ff_user" "$policy_dir" 2>/dev/null || true
		local tmp_policy="/tmp/firefox-policies-$$-$RANDOM-$SECONDS.json"
		register_tmp "$tmp_policy"
		if ! cat >"$tmp_policy" <<'EOF'; then
{
  "policies": {
    "DisableTelemetry": true,
    "DisableFirefoxStudies": true,
    "DisablePocket": true,
    "OverrideFirstRunPage": "",
    "OverridePostUpdatePage": "",
    "Extensions": {
      "Install": [
        "https://addons.mozilla.org/firefox/downloads/latest/ublock-origin/latest.xpi",
        "https://addons.mozilla.org/firefox/downloads/latest/localcdn-fork-of-decentraleyes/latest.xpi",
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
			warn "Failed to write Firefox policy JSON"
			rm -f "$tmp_policy" 2>/dev/null || true
			return 1
		fi
		if ! install -m 0600 -o "$ff_user" -g "$ff_user" "$tmp_policy" "$policy_file" 2>/dev/null; then
			warn "Failed to install Firefox policy (filesystem may be read-only)"
			rm -f "$tmp_policy" 2>/dev/null || true
			return 1
		fi
		rm -f "$tmp_policy" 2>/dev/null || true
		ok "Installed Firefox extension policy at $policy_file"
	fi

	run "sudo -u '$ff_user' xdg-settings set default-web-browser org.mozilla.firefox.desktop || true"
	info "Firefox hardening complete for user '$ff_user' (Flatpak + arkenfox + uBlock Origin/LocalCDN/Multi-Account Containers policy + telemetry disabled)."
	info "Restart Firefox to apply enterprise policy installs and arkenfox preferences."

	# --- 16b: VPN detection and recommendation ---------------------------------
	info "Checking for an active VPN connection (system or browser)..."
	local vpn_found=0 vpn_source=""

	# Check for WireGuard interfaces
	if ip link show 2>/dev/null | grep -qE '^[0-9]+: wg[0-9]+'; then
		vpn_found=1 vpn_source="WireGuard interface"
	fi

	# Check active NetworkManager VPN connections
	if ! ((vpn_found)) && cmd_exists nmcli; then
		if nmcli connection show --active 2>/dev/null | grep -qi 'vpn'; then
			vpn_found=1 vpn_source="NetworkManager VPN"
		fi
	fi

	# Check running VPN daemon processes
	local _vp
	for _vp in openvpn mullvad protonvpn; do
		if ! ((vpn_found)) && pgrep -x "$_vp" >/dev/null 2>&1; then
			vpn_found=1 vpn_source="$_vp process"
		fi
	done

	# Check Mullvad CLI status if available
	if ! ((vpn_found)) && cmd_exists mullvad; then
		local _ms
		_ms="$(mullvad status 2>/dev/null || true)"
		if [[ "$_ms" == *"Connected"* ]]; then
			vpn_found=1 vpn_source="Mullvad VPN"
		fi
	fi

	# Check Firefox profile extensions directory for known VPN extension patterns
	if ! ((vpn_found)) && [[ -d "$ff_root" ]]; then
		if find "$ff_root" -maxdepth 5 \( -iname '*vpn*' -o -iname '*mullvad*' -o -iname '*proton*' -o -iname '*ivpn*' \) 2>/dev/null | grep -q .; then
			vpn_found=1 vpn_source="browser VPN extension"
		fi
	fi

	if ((vpn_found)); then
		ok "VPN detected ($vpn_source) — no action needed."
	else
		warn "No active VPN detected on this system or in Firefox."
		if ((!GUI_FULL_MODE)); then
			cat <<'VPNEOF'

  ╔══════════════════════════════════════════════════════════════════════╗
  ║  VPN Recommendations (privacyguides.org + inteltechniques.com)      ║
  ╚══════════════════════════════════════════════════════════════════════╝

  All three options below are audited, open-source, no-logs VPNs. They
  support WireGuard and accept anonymous payment methods (cash / Monero).
  Section 17 installs wireguard-tools for use with any of these providers.

  1. Mullvad VPN — https://mullvad.net
     • No account e-mail needed; each account is a random 16-digit number
     • Accepts cash, Monero, and other crypto; no payment record tied to identity
     • Audited no-logs policy; open-source Linux app + browser extension
     • Top pick by privacyguides.org AND Michael Bazzell (inteltechniques.com)
     • Install:  flatpak install flathub net.mullvad.MullvadVpn
       or download the native app:  https://mullvad.net/en/download/linux

  2. ProtonVPN — https://protonvpn.com
     • Based in Switzerland; independently audited no-logs; open-source apps
     • Free tier available; strong integration with Proton Mail/Drive ecosystem
     • Supports WireGuard, OpenVPN, and Stealth protocol (censorship bypass)
     • Recommended by privacyguides.org
     • Install:  flatpak install flathub com.protonvpn.desktop
       or see:   https://protonvpn.com/support/linux-vpn-setup/

  3. IVPN — https://ivpn.net
     • No e-mail or personal info required to create an account
     • Accepts cash and Monero; audited no-logs; multi-hop routing available
     • Supports WireGuard + OpenVPN; includes ad/tracker blocking (AntiTracker)
     • Recommended by privacyguides.org AND Michael Bazzell (inteltechniques.com)
     • Install:  https://ivpn.net/apps-linux/

  Quick WireGuard config (after choosing a provider):
    sudo dnf install wireguard-tools       # section 17 handles this
    # download provider WireGuard config, then:
    sudo install -m 600 <provider>.conf /etc/wireguard/wg0.conf
    sudo wg-quick up wg0
    sudo systemctl enable wg-quick@wg0    # autostart on boot

VPNEOF
		else
			gui_alert warning "No VPN detected.\n\nRecommended VPNs (privacyguides.org + inteltechniques.com):\n• Mullvad VPN — mullvad.net (flatpak install flathub net.mullvad.MullvadVpn)\n• ProtonVPN — protonvpn.com (flatpak install flathub com.protonvpn.desktop)\n• IVPN — ivpn.net"
		fi
		add_action_item 16 MEDIUM "NO_VPN_DETECTED" \
			"No VPN detected — install Mullvad (recommended), ProtonVPN, or IVPN. See section 16b output and section 17 for WireGuard setup."
	fi
}

# ============================================================================
#  SECTION 17 — WireGuard
# ============================================================================
# sec_17_wireguard() - Install WireGuard tools and print quick-start guide
# Installs wireguard-tools (wg, wg-quick). Tunnel configuration is intentionally
# left manual since it requires provider-specific keys and endpoints. Prints a
# concise setup guide covering key generation, config install (chmod 600),
# wg-quick bring-up, and systemd autostart (wg-quick@wg0). Adds an action item
# reminding the user to complete tunnel configuration.
sec_17_wireguard() {
	should_run 17 || return 0
	section 17 "WireGuard (tools only — tunnel config is manual)"
	pkg_install wireguard-tools
	info "WireGuard tools installed. Quick-start guide:"
	info "  1. Generate keys:      wg genkey | tee private.key | wg pubkey > public.key"
	info "  2. Install config:     sudo install -m 600 <provider>.conf /etc/wireguard/wg0.conf"
	info "  3. Bring up tunnel:    sudo wg-quick up wg0"
	info "  4. Autostart on boot:  sudo systemctl enable wg-quick@wg0"
	info "  5. Verify IP:          curl -s https://am.i.mullvad.net/json || curl ifconfig.me"
	info "Most providers (Mullvad, ProtonVPN, IVPN) offer downloadable WireGuard configs."
	add_action_item 17 MEDIUM "WIREGUARD_TUNNEL_CONFIG" \
		"Configure WireGuard tunnel: install provider config to /etc/wireguard/wg0.conf (chmod 600) then run: sudo systemctl enable --now wg-quick@wg0"
}

# ============================================================================
#  SECTION 18 — Fail2Ban
# ============================================================================
# sec_18_fail2ban() - Install and configure Fail2Ban IDS
# Installs Fail2Ban for intrusion detection and auto-banning of brute-force attempts.
sec_18_fail2ban() {
	should_run 18 || return 0
	section 18 "Fail2Ban"
	pkg_install fail2ban
	local fb_dir="/etc/fail2ban"
	local jl="${fb_dir}/jail.local"

	if ((DRY_RUN)); then
		if [[ -f "$jl" ]]; then
			info "$jl already exists — would leave unchanged."
		else
			info "Would write $jl (not present yet)"
		fi
	else
		# Ensure configuration directory exists before writing jail.local.
		if ! run "install -d -m 0755 '$fb_dir'"; then
			warn "Could not create $fb_dir; skipping Fail2Ban configuration for now."
			add_action_item 18 HIGH "FAIL2BAN_DIR_CREATE_FAILED" \
				"Failed to create $fb_dir. Fix filesystem permissions and re-run section 18."
			return 0
		fi

		if [[ ! -f "$jl" ]]; then
			if ! cat >"$jl" <<'EOF'; then
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
		if ((IS_OSTREE)) && ! systemctl list-unit-files 2>/dev/null | grep -q '^fail2ban\.service'; then
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
	if ((!DRY_RUN)); then
		local f2b_active=0 f2b_status=""
		systemctl is-active --quiet fail2ban 2>/dev/null && f2b_active=1 || true
		if ((f2b_active)); then
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
		if ((f2b_active)); then
			add_action_item 18 LOW "FAIL2BAN_REVIEW" \
				"Review fail2ban jail status and ban history: sudo fail2ban-client status sshd"
		fi
	fi
}

# ============================================================================
#  SECTION 19 — Disable unnecessary services (interactive)
# ============================================================================
# sec_19_services() - Disable unnecessary services
# Disables avahi, cups, bluetooth, modemmanager and similar auto-start services.
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
		"nfs-server:NFS server (network file sharing)"
		"rpcbind:RPC portmapper (required by NFS)"
		"telnet.socket:Telnet socket (unencrypted remote shell)"
		"rsh.socket:RSH socket (unencrypted remote shell)"
		"rlogin.socket:RLogin socket (unencrypted remote login)"
	)

	# On tiling/minimal WMs (Sway, Hyprland, i3), bluetooth is typically unwanted —
	# note it for the user but the interactive prompt already handles it.
	if ((HAS_SWAY || HAS_HYPRLAND || HAS_I3)); then
		info "Tiling WM detected: consider disabling bluetooth unless you use BT peripherals."
	fi
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
# sec_20_perms() - Harden file permissions, umask, core dumps, hostname & username privacy
# Tightens permissions on shadow files, /tmp, and compiler access (20a). Sets umask 077
# for restrictive default file creation (20b). Disables core dumps via limits.d (20c).
# Checks hostname for identity leakage (20d) and flags non-generic usernames (20e) per
# privacyguides.org and inteltechniques.com recommendations.
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
		local home
		home="$(user_home "$TARGET_USER")"
		if [[ -n "$home" && -d "$home" ]]; then
			run "chmod 700 '$home'"
		fi
	fi

	if ((IS_OSTREE)); then
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

	# 20b — umask 077 (inteltechniques.com: restrict new file visibility)
	local umask_f="/etc/profile.d/99-umask.sh"
	if ((DRY_RUN)); then
		info "Would write $umask_f (umask 077)"
	elif [[ ! -f "$umask_f" ]]; then
		if ! cat >"$umask_f" <<'EOF'; then
# Set restrictive default umask so new files are not world/group readable
umask 077
EOF
			warn "Failed to write $umask_f"
		else
			chmod 644 "$umask_f" 2>/dev/null || true
			ok "Wrote $umask_f (umask 077 — new files private by default)"
		fi
	else
		info "$umask_f already exists — leaving unchanged."
	fi

	# 20c — Core dump suppression via limits.d (privacyguides.org)
	local coredump_f="/etc/security/limits.d/99-coredump.conf"
	if ((DRY_RUN)); then
		info "Would write $coredump_f (disable core dumps)"
	elif [[ ! -f "$coredump_f" ]]; then
		if ! cat >"$coredump_f" <<'EOF'; then
* soft core 0
* hard core 0
EOF
			warn "Failed to write $coredump_f"
		else
			chmod 644 "$coredump_f" 2>/dev/null || true
			ok "Wrote $coredump_f (core dumps disabled via PAM limits)"
		fi
	else
		info "$coredump_f already exists — leaving unchanged."
	fi

	# 20d — hostname privacy check (inteltechniques.com: non-identifying hostname)
	local current_hostname
	current_hostname="$(hostname -s 2>/dev/null || true)"
	local real_name="${TARGET_USER:-$(logname 2>/dev/null || true)}"
	if [[ -n "$current_hostname" && -n "$real_name" ]]; then
		if grep -qi "$real_name" <<<"$current_hostname" 2>/dev/null; then
			warn "Hostname '$current_hostname' appears to contain your username — consider a non-identifying hostname."
			add_action_item 20 MEDIUM "HOSTNAME_PRIVACY" \
				"Hostname '$current_hostname' may leak identity — change with: sudo hostnamectl set-hostname <generic-name>"
		fi
	fi

	# 20e — username privacy check (privacyguides.org: use generic username, not real name)
	# privacyguides.org recommends: "Consider using generic terms like 'user' rather than
	# your actual name" to limit the amount of personal data exposed by the OS.
	local cur_user="${TARGET_USER:-$(logname 2>/dev/null || true)}"
	if [[ -n "$cur_user" ]]; then
		# Flag if username is a simple word (all letters) and not already a generic term
		case "$cur_user" in
		root | user | admin | nobody | guest | fedora | linux) ;;
		*)
			info "Current username: '$cur_user' — privacyguides.org recommends a generic username" \
				"(e.g., 'user') rather than a real name to limit OS-level personal-data exposure."
			add_action_item 20 LOW "USERNAME_PRIVACY" \
				"Consider a non-identifying system username instead of '$cur_user' (privacyguides.org recommendation)"
			;;
		esac
	fi
}

# ============================================================================
#  SECTION 21 — ClamAV
# ============================================================================
# sec_21_clamav() - Install ClamAV antivirus with on-access scanning
# Installs ClamAV engine, clamd daemon, and freshclam for signature updates.
# Enables clamav-freshclam for automatic daily database updates and clamd@scan
# for real-time scanning. Configures on-access scanning for /home directories
# in /etc/clamd.d/scan.conf per inteltechniques.com recommendation.
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

	# Configure on-access scanning for home directories (inteltechniques.com)
	local clamd_conf="/etc/clamd.d/scan.conf"
	if [[ -f "$clamd_conf" ]]; then
		if ((!DRY_RUN)); then
			backup_file "$clamd_conf"
			# Enable on-access scanning if not already configured
			if ! grep -q "^OnAccessIncludePath" "$clamd_conf" 2>/dev/null; then
				if {
					echo ""
					echo "# On-access scanning — monitor home directories (inteltechniques.com)"
					echo "OnAccessIncludePath /home"
					echo "OnAccessExcludeRootUID yes"
					echo "OnAccessPrevention no"
				} >>"$clamd_conf" 2>/dev/null; then
					ok "Configured ClamAV on-access scanning for /home in $clamd_conf"
				else
					warn "Failed to update $clamd_conf for on-access scanning"
				fi
			else
				info "ClamAV on-access scanning already configured in $clamd_conf"
			fi
		else
			info "Would configure ClamAV on-access scanning (OnAccessIncludePath /home) in $clamd_conf"
		fi
	else
		info "ClamAV clamd config not found at $clamd_conf — on-access config skipped."
		add_action_item 21 LOW "CLAMAV_ONACCESS_CONFIG" \
			"Manually configure on-access scanning: add 'OnAccessIncludePath /home' to your clamd config (/etc/clamd.d/scan.conf)"
	fi

	# Post-enable status check and report
	if ((!DRY_RUN)); then
		local freshclam_active=0 clamd_active=0
		if systemctl is-active --quiet clamav-freshclam 2>/dev/null; then
			freshclam_active=1
		fi
		if systemctl is-active --quiet clamd@scan 2>/dev/null || systemctl is-active --quiet clamd@scan.service 2>/dev/null; then
			clamd_active=1
		fi
		# Collect status output safely
		{
			printf '=== Section 21: ClamAV Report ===\n'
			printf 'Generated: %s\n\n' "$RUN_STAMP_HUMAN"
			printf '--- clamav-freshclam status ---\n'
			systemctl status clamav-freshclam --no-pager 2>&1 || true
			printf '\n--- clamd@scan status ---\n'
			systemctl status clamd@scan --no-pager 2>&1 || systemctl status clamd@scan.service --no-pager 2>&1 || true
			printf '\n--- ClamAV version / DB ---\n'
			clamscan --version 2>&1 || true
			freshclam --version 2>&1 || true
		} | write_user_report "section-21-clamav-${REPORT_DATE}.txt" || true
		((freshclam_active)) || add_action_item 21 MEDIUM "CLAMAV_FRESHCLAM_NOT_RUNNING" \
			"clamav-freshclam is not running — run: sudo systemctl start clamav-freshclam"
		((clamd_active)) || add_action_item 21 MEDIUM "CLAMAV_CLAMD_NOT_RUNNING" \
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
# sec_22_openscap() - Install and run OpenSCAP compliance scanner
# Installs OpenSCAP framework and runs initial compliance scan against security baseline.
sec_22_openscap() {
	should_run 22 || return 0
	section 22 "OpenSCAP compliance scanner"
	pkg_install openscap-scanner scap-security-guide
	# On rpm-ostree, packages are staged — oscap may not be available until reboot.
	# Use cmd_exists check only; do not hard-fail if missing.
	ensure_command_dep oscap "OpenSCAP compliance scan" openscap-scanner || true
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
	if ((!DRY_RUN)); then
		copy_to_user_results /root/scap-report.html "section-22-openscap-${REPORT_DATE}.html"
		copy_to_user_results /root/scap-results.xml "section-22-openscap-results-${REPORT_DATE}.xml"
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
					/root/scap-results.xml 2>/dev/null |
					head -25 ||
					printf '(no failures found or XML parse error)\n'
			} | write_user_report "section-22-openscap-summary-${REPORT_DATE}.txt" || true
			local fail_n
			fail_n="${fail_count//[^0-9]/}"
			if [[ -n "$fail_n" ]] && ((fail_n > 0)) 2>/dev/null; then
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

# ============================================================================
#  SECTION 23 — Container Security (Podman + Toolbox)
# ============================================================================
# sec_23_containers() - Rootless Podman + Toolbox containerized-mindset hardening.
# Establishes a "containerized mindset" security posture where:
#   • System-level administration runs natively (this script, system tools)
#   • Development, daily work, and untrusted software run inside containers
# Hardens image policy, runtime defaults, and registry resolution to reduce
# the attack surface of containerised workloads.
sec_23_containers() {
	should_run 23 || return 0
	section 23 "Container security (Podman + Toolbox — containerized mindset)"

	pkg_install podman toolbox
	ensure_command_dep podman "rootless container engine" podman || true
	if ! cmd_exists podman; then
		warn "podman not available after install attempt — skipping section 23."
		return 0
	fi

	if confirm "Install buildah (OCI image builder) and skopeo (image inspection/transfer)?"; then
		pkg_install buildah skopeo
	fi

	if confirm "Install podman-compose (docker-compose compatibility layer)?"; then
		pkg_install podman-compose
	fi

	# ── Rootless Podman: subuid/subgid ───────────────────────────────────────
	local run_user="${TARGET_USER:-${SUDO_USER:-}}"
	if [[ -n "$run_user" && "$run_user" != "root" ]]; then
		if ! grep -q "^${run_user}:" /etc/subuid 2>/dev/null; then
			info "Adding subuid range for rootless Podman (user: $run_user)..."
			if ((!DRY_RUN)); then
				usermod --add-subuids 100000-165535 "$run_user" 2>/dev/null ||
					printf '%s:100000:65536\n' "$run_user" >>/etc/subuid
			else
				info "[DRY] Would add subuid 100000-165535 for $run_user"
			fi
		else
			ok "subuid entry already present for $run_user."
		fi
		if ! grep -q "^${run_user}:" /etc/subgid 2>/dev/null; then
			info "Adding subgid range for rootless Podman (user: $run_user)..."
			if ((!DRY_RUN)); then
				usermod --add-subgids 100000-165535 "$run_user" 2>/dev/null ||
					printf '%s:100000:65536\n' "$run_user" >>/etc/subgid
			else
				info "[DRY] Would add subgid 100000-165535 for $run_user"
			fi
		else
			ok "subgid entry already present for $run_user."
		fi

		# ── User-level containers.conf with secure runtime defaults ──────────
		local user_home cont_conf_dir cont_conf
		user_home="$(user_home "$run_user")"
		cont_conf_dir="${user_home}/.config/containers"
		cont_conf="${cont_conf_dir}/containers.conf"
		if [[ -n "$user_home" ]]; then
			if ((!DRY_RUN)); then
				install -d -m 700 "$cont_conf_dir" 2>/dev/null || true
				if [[ ! -f "$cont_conf" ]]; then
					cat >"$cont_conf" <<'EOF'
# Rootless Podman hardening defaults — written by fedora-harden.sh
[containers]
# Block privilege escalation inside containers
no_new_privileges = true

# Enforce kernel syscall allowlist (system default seccomp profile)
seccomp_profile = "/usr/share/containers/seccomp.json"

# Minimal capability set — grant only what is explicitly required per workload
default_capabilities = [
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "FSETID",
    "KILL",
    "NET_BIND_SERVICE",
    "SETFCAP",
    "SETGID",
    "SETPCAP",
    "SETUID",
    "SYS_CHROOT",
]

[engine]
# crun is the default OCI runtime on Fedora; preferred over runc for performance + security
# runtime = "crun"
EOF
					run "chown '${run_user}:${run_user}' '${cont_conf}'"
					ok "Wrote rootless containers.conf for $run_user (no-new-privileges + seccomp defaults)."
				else
					ok "containers.conf already exists for $run_user — not overwriting."
				fi
			else
				info "[DRY] Would write ${cont_conf} with no-new-privileges + seccomp + minimal caps."
			fi
		fi
	fi

	# ── System image policy: reject pulls from unregistered registries ────────
	# Default Fedora policy is 'insecureAcceptAnything' for all registries.
	# Hardened policy sets default to 'reject' and explicitly allows trusted sources.
	local policy_file="/etc/containers/policy.json"
	if [[ -f "$policy_file" ]]; then
		local current_policy
		current_policy="$(cat "$policy_file" 2>/dev/null || true)"
		if [[ "$current_policy" == *'"insecureAcceptAnything"'* &&
			"$current_policy" != *'"type": "reject"'* ]]; then
			if confirm "Harden container image policy to reject unknown registries? (Permits fedora, quay.io, docker.io; blocks all others)"; then
				backup_file "$policy_file"
				if ((!DRY_RUN)); then
					cat >"$policy_file" <<'EOF'
{
    "default": [{"type": "reject"}],
    "transports": {
        "containers-storage": {
            "": [{"type": "insecureAcceptAnything"}]
        },
        "docker": {
            "registry.fedoraproject.org": [{"type": "insecureAcceptAnything"}],
            "registry.centos.org":        [{"type": "insecureAcceptAnything"}],
            "registry.access.redhat.com": [{"type": "insecureAcceptAnything"}],
            "quay.io":                    [{"type": "insecureAcceptAnything"}],
            "docker.io":                  [{"type": "insecureAcceptAnything"}]
        },
        "docker-daemon": {
            "": [{"type": "insecureAcceptAnything"}]
        }
    }
}
EOF
					ok "Image policy hardened — pulls from unlisted registries will be rejected."
				else
					info "[DRY] Would write restricted image policy to $policy_file"
				fi
			else
				add_action_item 23 LOW "CONTAINER_POLICY_PERMISSIVE" \
					"Container image policy allows pulls from any registry (insecureAcceptAnything). Consider restricting to trusted sources in /etc/containers/policy.json."
			fi
		else
			ok "Container image policy already restricts unknown registries."
		fi
	else
		warn "Container image policy file not found at $policy_file — skipping policy hardening."
	fi

	# ── Block unqualified image names resolving silently to docker.io ─────────
	# Without this, 'podman pull nginx' silently resolves to docker.io/library/nginx.
	# Requiring fully-qualified names (registry/org/image:tag) prevents supply-chain
	# confusion and makes registry provenance explicit.
	local reg_conf_d="/etc/containers/registries.conf.d"
	local reg_conf="${reg_conf_d}/99-hardening.conf"
	if [[ ! -f "$reg_conf" ]]; then
		if ((!DRY_RUN)); then
			install -d -m 755 "$reg_conf_d" 2>/dev/null || true
			cat >"$reg_conf" <<'EOF'
# Require fully-qualified image names — written by fedora-harden.sh
# An empty list prevents silent docker.io resolution for unqualified names.
# Always use full names: docker.io/library/nginx, quay.io/fedora/fedora, etc.
unqualified-search-registries = []
EOF
			ok "Blocked unqualified image name resolution — explicit registry required for all pulls."
		else
			info "[DRY] Would write ${reg_conf} disabling unqualified registry search."
		fi
	else
		ok "Registry conf.d override already present at $reg_conf."
	fi

	# ── Toolbox availability check ────────────────────────────────────────────
	if ! cmd_exists toolbox; then
		warn "toolbox command not found after install. On rpm-ostree systems a reboot may be required."
		if ((IS_OSTREE)); then
			info "After reboot, run: toolbox create && toolbox enter"
		fi
	else
		ok "Toolbox is available — run 'toolbox create && toolbox enter' to start a containerized workspace."
	fi

	# ── Immutable-system guidance ─────────────────────────────────────────────
	if ((IS_OSTREE)); then
		info "Immutable system detected: Toolbox/Distrobox containers are the recommended"
		info "  way to install developer packages without mutating the read-only host OS."
		info "  Example: toolbox create --image registry.fedoraproject.org/fedora-toolbox:$(rpm -E %fedora 2>/dev/null || echo 42)"
	fi

	# ── Post-run guidance action items ────────────────────────────────────────
	add_action_item 23 MEDIUM "CONTAINER_WORKFLOW" \
		"Adopt a containerized mindset: use 'toolbox create && toolbox enter' for development, IDEs, compilers, and scripts (isolated from host). For services: 'podman run --read-only --security-opt no-new-privileges:true --cap-drop ALL --cap-add <only_what_is_needed>'."
	add_action_item 23 LOW "CONTAINER_NETWORK_AUDIT" \
		"Review Podman network isolation: run 'podman network ls' and use 'podman network create --internal' for workloads that must not reach the internet. Verify inter-container traffic is explicitly controlled."

	ok "Section 23 complete — rootless Podman hardened, image policy set, Toolbox ready."
}

# ---------- Actionable-items display + remediation --------------------------
# show_actionable_items() - Print the full prioritized actionable items list.
show_actionable_items() {
	if ((${#ACTIONABLE_ITEMS[@]} == 0)); then
		ok "No actionable items — sections 12/18/21/22/23 appear clean."
		return 0
	fi
	if ((!GUI_FULL_MODE)); then
		printf '\n%s════════ Actionable Items (%d found) ════════%s\n' "$C_YEL" "${#ACTIONABLE_ITEMS[@]}" "$C_RST"
		local idx=1
		for item in "${ACTIONABLE_ITEMS[@]}"; do
			local section priority tag desc
			IFS='|' read -r section priority tag desc <<<"$item"
			case "$priority" in
			HIGH) printf '%s  [%2d] [%s][%s] %s%s\n' "$C_RED" "$idx" "$priority" "$section" "$desc" "$C_RST" ;;
			MEDIUM) printf '%s  [%2d] [%s][%s] %s%s\n' "$C_YEL" "$idx" "$priority" "$section" "$desc" "$C_RST" ;;
			*) printf '%s  [%2d] [%s][%s] %s%s\n' "$C_BLU" "$idx" "$priority" "$section" "$desc" "$C_RST" ;;
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
		((DRY_RUN)) && {
			info "Would run: freshclam"
			return 1
		}
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
		local scan_home
		scan_home="$(user_home "$scan_user" 2>/dev/null || echo "/root")"
		if ((DRY_RUN)); then
			info "Would run: clamscan -r --infected '$scan_home'"
			return 1
		fi
		local scan_tmp="/tmp/clamscan-out-$$.tmp"
		register_tmp "$scan_tmp"
		log "[RUN]   clamscan -r --infected $scan_home"
		if ((GUI_FULL_MODE)); then
			clamscan -r --infected "$scan_home" >"$scan_tmp" 2>&1 || true
		else
			clamscan -r --infected "$scan_home" 2>&1 | tee "$scan_tmp" || true
		fi
		local infected
		infected="$(awk '/ FOUND$/{count++} END{print count+0}' "$scan_tmp" 2>/dev/null || echo 0)"
		{
			printf '=== ClamAV Initial Home Scan ===\nDate: %s\nTarget: %s\n\n' "$RUN_STAMP_HUMAN" "$scan_home"
			cat "$scan_tmp"
		} | write_user_report "section-21-clamav-initial-scan-${REPORT_DATE}.txt" || true
		if ((infected > 0)); then
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
		((DRY_RUN)) && {
			info "Would run: aide --init"
			return 1
		}
		if aide --init 2>/dev/null &&
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
			awk -F'"' '/result="fail"/{for(i=1;i<NF;i++) if($i=="idref") print $(i+1)}' /root/scap-results.xml 2>/dev/null |
				head -10 |
				while IFS= read -r rule; do info "    • $rule"; done || true
		fi
		return 1
		;;
	RK_WARNINGS)
		info "rkhunter warnings require manual investigation:"
		info "  Report: ${USER_RESULTS_DIR:+$USER_RESULTS_DIR/section-12-rkhunter-aide-${REPORT_DATE}.txt}"
		info "  After investigating, run: sudo rkhunter --propupd"
		return 1
		;;
	AIDE_RECHECK | FAIL2BAN_REVIEW | CLAMAV_REVIEW | SCAP_NO_SCAN | CLAMAV_INFECTED)
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
	((${#ACTIONABLE_ITEMS[@]} == 0)) && return 0
	local round=1 max_rounds=5 prev_count=-1
	while ((${#ACTIONABLE_ITEMS[@]} > 0 && round <= max_rounds)); do
		local current_count="${#ACTIONABLE_ITEMS[@]}"
		((current_count == prev_count)) && break # No progress — stop
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
		if ((${#remaining_items[@]} > 0)); then
			ACTIONABLE_ITEMS=("${remaining_items[@]}")
		else
			ACTIONABLE_ITEMS=()
		fi
		((${#ACTIONABLE_ITEMS[@]} == 0)) && {
			ok "All actionable items resolved in round $round."
			break
		}
		((round++))
	done
	if ((${#ACTIONABLE_ITEMS[@]} > 0)); then
		warn "${#ACTIONABLE_ITEMS[@]} item(s) could not be auto-resolved and require manual action:"
		show_actionable_items
	fi
	if ((${#REMEDIATED_ITEMS[@]} > 0)); then
		ok "${#REMEDIATED_ITEMS[@]} item(s) were successfully remediated this session."
	fi
}

# ---------- Summary ---------------------------------------------------------
# final_summary() - Analyze section 12/18/21/22/23 findings, write all reports to
# user Downloads/<project>/results and Downloads/<project>/logs, display actionable list, and ask
# whether to implement recommended next steps. If declined, export a PDF audit
# report plus TXT import bundle into the user's Downloads directory instead of
# running remediation. If approved, the user can implement all or selected items.
final_summary() {
	local summary_file="harden-summary-${REPORT_DATE}.txt"
	local summary_path=""
	# Precompute platform label once — avoids two subshell spawns in report + terminal output.
	local _plat
	((IS_OSTREE)) && _plat="rpm-ostree (immutable)" || _plat="dnf (mutable)"

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
			if ((${#ACTIONABLE_ITEMS[@]} > 0)); then
				local idx=1
				for item in "${ACTIONABLE_ITEMS[@]}"; do
					local section priority tag desc
					IFS='|' read -r section priority tag desc <<<"$item"
					printf '  [%2d] [%s][%s] %s\n' "$idx" "$priority" "$section" "$desc"
					((idx++))
				done
			else
				printf '  None — sections 12/18/21/22/23 appear clean.\n'
			fi
			printf '\n=== Remediated Items (%d) ===\n' "${#REMEDIATED_ITEMS[@]}"
			if ((${#REMEDIATED_ITEMS[@]} > 0)); then
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
			printf '  • VPN                        — if not detected in section 16b: install Mullvad, ProtonVPN, or IVPN.\n'
			printf '  • WireGuard tunnel           — configure /etc/wireguard/wg0.conf with peer keys.\n'
			printf '  • arkenfox overrides         — add exceptions in user-overrides.js as needed.\n'
			printf '  • KDE GUI-only settings      — KWallet master password, Privacy, Activity.\n'
			printf '  • AIDE re-init               — after any future package updates.\n'
			printf '  • REBOOT RECOMMENDED         — to apply kernel/sysctl/PAM/GRUB changes.\n'
			((IS_OSTREE)) && printf '  • rpm-ostree REBOOT         — required for staged/layered package changes.\n'
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
	if ((!GUI_FULL_MODE)); then
		printf '\n%s════════════════════════ Summary ════════════════════════%s\n' "$C_GRN" "$C_RST"
		local reports_line="" ostree_line=""
		[[ -n "$USER_RESULTS_DIR" ]] && reports_line=" Reports:      $USER_RESULTS_DIR"
		((IS_OSTREE)) && ostree_line=$'\n On rpm-ostree systems, reboot is also required to apply layered package changes and staged updates.'
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
       • VPN — if not detected in §16b: install Mullvad, ProtonVPN, or IVPN.
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
		((IS_OSTREE)) && log "Summary: reboot required on rpm-ostree for staged/layered changes"
	fi

	gui_alert info "Fedora hardening finished.\n\nLog: $LOG_FILE\nBackups: $BACKUP_DIR${USER_RESULTS_DIR:+\nReports: $USER_RESULTS_DIR}"

	# Display the actionable items from sections 12/18/21/22/23 and handle approval/selection.
	handle_actionable_follow_up "$summary_path"

	# Re-write the summary with final state (after remediation updates ACTIONABLE/REMEDIATED lists)
	if [[ -n "$USER_RESULTS_DIR" ]] && ((${#REMEDIATED_ITEMS[@]} > 0)); then
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
			if ((${#ACTIONABLE_ITEMS[@]} > 0)); then
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
# main() - Master orchestrator for fedora-harden script execution
# Manages command-line argument parsing, permission verification, session tracking,
# and execution of all 23 hardening sections in dependency-optimized order.
# Includes error analysis, auto-remediation, and structured session reporting.
# Exit codes: 0 = success, 1 = preflight failed, catch-all for other errors
main() {
	parse_args "$@"

	# --list-sessions: show past sessions without running a full preflight
	if ((LIST_SESSIONS_MODE)); then
		((FORCE_GUI_FULL)) || draw_banner
		list_sessions_cmd
		EXPECTED_ABORT=1
		exit 0
	fi

	preflight
	if ((PRECHECK_FAILED)); then
		EXPECTED_ABORT=1
		exit 1
	fi

	# --rollback: undo a previous session (requires root + IS_OSTREE detection from preflight)
	if [[ -n "$ROLLBACK_SESSION_ID" ]]; then
		SESSION_REPORT_FILE="" # Rollback produces its own report; skip session stub
		if [[ "$ROLLBACK_SESSION_ID" == "all" ]]; then
			rollback_all_sessions
		else
			rollback_session "$ROLLBACK_SESSION_ID"
		fi
		EXPECTED_ABORT=1
		exit 0
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
	sec_15_desktop
	sec_16_firefox
	sec_17_wireguard
	sec_21_clamav
	sec_22_openscap
	sec_23_containers
	sec_12_ids
	sec_19_services
	sec_20_perms
	sec_08_usbguard

	gui_progress_close
	final_summary

	# Execute error analysis and auto-remediation loop to resolve any issues detected
	info "Running error analysis and auto-remediation cycle..."
	validate_and_remediate_loop || warn "Some errors may require manual intervention — review logs"

	SESSION_STATUS="completed"
	ok "Script execution complete. See logs for full details."
	[[ -n "$SESSION_REPORT_FILE" ]] && ok "Session report: $SESSION_REPORT_FILE"
}

main "$@"
