# shellcheck shell=bash
# ---------- Pre-flight Checks -----------------------------------------------
# Initialize script environment, detect system configuration, and validate prerequisites.
# Functions in this section handle argument parsing, system detection, and setup.

# --help: the header comment of fedora-harden.sh, between its first two separator lines.
usage() {
	awk '
        NR == 1 { next }
        /^# =============================================================================$/ { sep++; next }
        sep == 1 { sub(/^# ?/, ""); print }
        sep >= 2 { exit }
    ' "$0"
}

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
		--backup-target)
			if [[ -z "${2:-}" || ! -d "$2" ]]; then
				err "--backup-target needs an existing directory (on a second drive)."
				exit 2
			fi
			BACKUP_TARGET="$(realpath -- "$2")"
			shift 2
			;;
		--profile)
			if [[ ! "${2:-}" =~ ^(everyday|gaming|creative|dev|laptop|private)(,(everyday|gaming|creative|dev|laptop|private))*$ ]]; then
				err "--profile expects a comma-separated list with no spaces: everyday,gaming,creative,dev,laptop,private"
				exit 2
			fi
			PROFILE_ARG="$2"
			shift 2
			;;
		--wireguard-config)
			if [[ -z "${2:-}" ]]; then
				err "Option --wireguard-config requires a file argument"
				usage
				exit 2
			fi
			if [[ ! -r "$2" ]]; then
				err "--wireguard-config: cannot read '$2'."
				exit 2
			fi
			WG_CONFIG="$(realpath -- "$2")"
			shift 2
			;;
		-n | --dry-run)
			DRY_RUN=1
			shift
			;;
		--gui)
			FORCE_GUI=1
			shift
			;;
		--report)
			REPORT_MODE=1
			if [[ -n "${2:-}" && "${2:-}" != -* ]]; then
				REPORT_FILE="$2"
				shift 2
			else
				shift
			fi
			;;
		--full)
			REPORT_FULL=1
			shift
			;;
		--resume)
			RESUME_MODE=1
			shift
			;;
		--score)
			SCORE_MODE=1
			shift
			;;
		--kernel-hardening)
			KERNEL_HARDENING=1
			shift
			;;
		--restore)
			if [[ -z "${2:-}" ]]; then
				err "Option --restore requires a recovery file"
				exit 2
			fi
			RESTORE_FILE="$2"
			shift 2
			;;
		--include-setup)
			INCLUDE_SETUP=1
			shift
			;;
		--recovery-backup)
			case "${2:-}" in
			on) RECOVERY_BACKUP_ARG=yes ;;
			off) RECOVERY_BACKUP_ARG=no ;;
			*)
				err "--recovery-backup expects on or off"
				exit 2
				;;
			esac
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
		-V | --version)
			echo "fedora-harden.sh $FH_VERSION"
			exit 0
			;;
		*)
			err "Unknown argument: $1"
			usage
			exit 2
			;;
		esac
	done
	[[ -n "$ONLY_LIST" ]] && validate_section_list --only "$ONLY_LIST"
	[[ -n "$SKIP_LIST" ]] && validate_section_list --skip "$SKIP_LIST"
	if [[ -n "$TARGET_USER" ]] && ! getent passwd "$TARGET_USER" >/dev/null 2>&1; then
		err "--user: there is no account named '$TARGET_USER'."
		exit 2
	fi
	return 0
}

# Exit 2 unless <list> is comma-separated section numbers this script runs (a typo
# would otherwise silently run nothing, or everything).
# Usage: validate_section_list <option> <list>
validate_section_list() {
	local opt="$1" list="$2" item known=" ${SECTIONS[*]} " # joined before IFS changes
	if [[ ! "$list" =~ ^[1-9][0-9]*(,[1-9][0-9]*)*$ ]]; then
		err "$opt expects section numbers separated by commas (e.g. 5,7,10), not '$list'. See --list."
		exit 2
	fi
	local IFS=','
	for item in $list; do
		if [[ "$known" != *" $item "* ]]; then
			err "$opt: there is no section $item. See --list for the sections."
			exit 2
		fi
	done
}

# Refuse to start while another run is changing the system: two runs would
# interleave edits and journal entries. A PID file (not an inherited flock) so
# helpers that outlive the run, like the GUI window, cannot hold it; a lock left by
# a killed run is taken over.
RUN_LOCK=""
acquire_run_lock() {
	local lock=/run/fedora-harden.pid other
	if ! (set -o noclobber && echo "$$" >"$lock") 2>/dev/null; then
		other="$(cat "$lock" 2>/dev/null || true)"
		if [[ "$other" =~ ^[0-9]+$ ]] && ((other != $$)) && kill -0 "$other" 2>/dev/null &&
			grep -qa fedora-harden "/proc/$other/cmdline" 2>/dev/null; then
			err "Another fedora-harden run is already in progress (PID $other). Wait for it to finish, then try again."
			return 1
		fi
		echo "$$" 2>/dev/null >"$lock" || true # stale lock from a run that was killed
	fi
	RUN_LOCK="$lock"
}
release_run_lock() {
	[[ -n "$RUN_LOCK" && "$(cat "$RUN_LOCK" 2>/dev/null)" == "$$" ]] && rm -f "$RUN_LOCK"
	RUN_LOCK=""
}

# Root check, run lock, log, release and desktop detection (Fedora 44+), backups.
preflight() {
	local privilege_source="direct root login/session"
	((FORCE_GUI)) || draw_banner
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
	if ! acquire_run_lock; then
		PRECHECK_FAILED=1
		return 0
	fi

	init_log_target || true

	# Distribution and variant detection (the family's platform file).
	platform_detect
	if ((HAS_DESKTOP)); then
		info "Detected desktop environments: ${DESKTOP_ENVS:-unknown}"
	else
		warn "No desktop environment detected; desktop-focused sections may be skipped."
	fi
	info "Log:         $LOG_WHERE"
	info "Backup dir:  $BACKUP_DIR"
	# Without a writable journal nothing this run changes could be rolled back.
	if ((! REPORT_MODE && ! SCORE_MODE)) && ! init_rollback_journal; then # --report/--score only read
		err "Cannot write the backup folder $BACKUP_DIR (read-only, full, or missing — on image-based systems /root is /var/roothome). Nothing was changed."
		PRECHECK_FAILED=1
		return 0
	fi
	((SCORE_MODE)) || init_session_dir
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
