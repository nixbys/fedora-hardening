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

list_sections() {
	cat <<'EOF'
   1  System updates (incl. fwupd firmware/microcode + hardware key support)
   2  Automatic updates
   3  Secure Boot verify
   4  Flatpak / Flathub, global Flatpak restrictions, mat2 (Firejail opt-in)
   5  SELinux tools
   6  firewalld
   7  SSH hardening
   8  PAM/password policy (incl. sudo use_pty)
   9  Kernel sysctl (incl. IPv6 privacy extensions, io_uring for root only)
  10  auditd (incl. time/network/mount rules, deletes under /etc)
  11  DNS over TLS (11b: NetworkManager MAC address randomization)
  12  Fail2Ban
  13  Desktop environment settings (auto-dispatches by detected DE):
       KDE Plasma  — kwriteconfig6/5: screen lock, recent-docs, BT opt-out
       GNOME/Onyx  — gsettings: lock, location off, privacy (mic off if asked)
       Budgie      — gsettings (GNOME backend): same privacy stack
       Cinnamon    — org.cinnamon.desktop.screensaver + GNOME privacy schemas
       MATE        — org.mate.screensaver + org.mate.power-manager
       XFCE/Vauxite— xfconf-query: screensaver + power manager idle
       Sway/Sericea— writes swaylock.conf + swayidle.conf
       Hyprland    — writes hypridle.conf (lock 5 min, suspend 10 min)
       i3          — xss-lock + i3lock drop-in via config.d/
       LXQt/Lazurite — lxqt-screensaver.conf + lxqt-powermanagement.conf
  14  Browsers: Firefox + arkenfox, Brave/Chromium/Chrome policies, VPN check, Tor/Mullvad Browser (opt-in)
  15  WireGuard tunnel with kill switch (--wireguard-config FILE)
  16  ClamAV (weekly scan of /home, on-access opt-in; image-based: container scan)
  17  OpenSCAP (image-based: from a container)
  18  Container security (Podman + toolbox/distrobox / containerized-mindset setup)
  19  Your routine: upkeep, health and drift checks for your use cases (--profile)
  20  Home snapshots (Btrfs) or incremental copies, as often as the machine is used
  21  Service trim
  22  File permissions (incl. umask 077 for users, core dump limits, hostname privacy)
  23  USBGuard
  24  AIDE file integrity (image-based: image signature + /etc change report)

 Execution order: 1 to 24. The numbers follow the dependency flow.

 DE detection (section 13 auto-dispatches — all detected DEs are hardened):
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

	# Distro check: Verify this is a Fedora system and detect variant
	# Sources /etc/os-release to extract distribution metadata
	if [[ ! -r /etc/os-release ]]; then
		err "Cannot read /etc/os-release — is this Fedora?"
		exit 1
	fi
	# shellcheck source=/dev/null
	. /etc/os-release
	[[ "${ID:-}" == "fedora" ]] || warn "Distro ID is '${ID:-unknown}', not 'fedora'. Proceeding anyway."
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
