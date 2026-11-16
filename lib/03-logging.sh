# shellcheck shell=bash
# ---------- Logging helpers -------------------------------------------------
# init_log_target() - Choose where this run logs. On a normal system that is the
# journal (journalctl -t fedora-harden FH_SESSION=<session>): rotation, size limits
# and access control come with it. Without journald (minimal containers) the same
# lines go to a file under /var/log/fedora-harden, or /tmp as a last resort.
init_log_target() {
	((LOG_READY)) && return 0
	if [[ -S /run/systemd/journal/socket ]] && have_cmd logger &&
		printf 'MESSAGE=fedora-harden session %s started\nPRIORITY=6\nSYSLOG_IDENTIFIER=fedora-harden\nFH_SESSION=%s\n' \
			"$RUN_STAMP" "$RUN_STAMP" | logger --journald 2>/dev/null; then
		LOG_JOURNAL=1
		LOG_WHERE="journalctl -t fedora-harden FH_SESSION=$RUN_STAMP"
	else
		local d="${LOG_FILE%/*}"
		if ! { mkdir -p "$d" 2>/dev/null && : 2>/dev/null >>"$LOG_FILE"; }; then
			LOG_FILE="/tmp/${SCRIPT_NAME%.*}-${RUN_STAMP}.log"
			: 2>/dev/null >>"$LOG_FILE" || return 1
		fi
		chmod 600 "$LOG_FILE" 2>/dev/null || true
		LOG_WHERE="$LOG_FILE"
	fi
	LOG_READY=1
	# stderr of commands run through run(), shown when a step fails
	ERROR_CAPTURE_FILE="/tmp/fedora-harden-stderr-$$.tmp"
	register_tmp "$ERROR_CAPTURE_FILE"
	return 0
}

# log() - Record a message: in the journal with the session and section as fields,
# or in the log file. Priority follows the message type.
# Usage: log "message text"
log() {
	init_log_target || return 0
	local msg="${*//$'\n'/ }" prio=6
	case "$msg" in
	"[WARN]"*) prio=4 ;;
	"[ERROR]"*) prio=3 ;;
	"[OK]"*) prio=5 ;;
	esac
	if ((LOG_JOURNAL)); then
		printf 'MESSAGE=%s\nPRIORITY=%s\nSYSLOG_IDENTIFIER=fedora-harden\nFH_SESSION=%s\nFH_SECTION=%s\n' \
			"$msg" "$prio" "$RUN_STAMP" "${CURRENT_SECTION:-0}" | logger --journald 2>/dev/null || true
		return 0
	fi
	local ts
	printf -v ts '%(%F %T)T' -1 2>/dev/null || ts="$(date '+%F %T')"
	printf '%s %s\n' "$ts" "$msg" 2>/dev/null >>"$LOG_FILE" || true
}

# log_stream() - Log every line read from stdin (command output).
log_stream() {
	local line
	while IFS= read -r line || [[ -n "$line" ]]; do
		log "  | $line"
		gui_send LOG out "$line"
	done
}

# info() - Write informational message to stdout and log (blue color).
# Used for status updates and intermediate steps.
# Usage: info "message text"
info() {
	((! GUI_FULL_MODE)) && printf '%s[INFO]%s  %s\n' "$C_BLU" "$C_RST" "$*"
	log "[INFO]  $*"
	gui_send LOG info "$*"
}

# ok() - Write success message to stdout and log (green color).
# Indicates successful completion of a task or verification.
# Usage: ok "message text"
ok() {
	((! GUI_FULL_MODE)) && printf '%s[ OK ]%s  %s\n' "$C_GRN" "$C_RST" "$*"
	log "[OK]    $*"
	gui_send LOG ok "$*"
}

# warn() - Write warning message to stdout and log (yellow color).
# Alerts about non-critical issues, skipped steps, or prerequisites.
# Usage: warn "message text"
warn() {
	((! GUI_FULL_MODE)) && printf '%s[WARN]%s  %s\n' "$C_YEL" "$C_RST" "$*"
	log "[WARN]  $*"
	gui_send LOG warn "$*"
}

# err() - Write error message to stderr and log (red color).
# Indicates a problem that may prevent further execution.
# Usage: err "message text"
err() {
	((++ERR_COUNT))
	((! GUI_FULL_MODE)) && printf '%s[FAIL]%s  %s\n' "$C_RED" "$C_RST" "$*" >&2
	log "[ERROR] $*"
	gui_send LOG error "$*"
}

# capture_error_context() - Log detailed error information including command, exit code, and stderr.
# Stores structured error data for later analysis and automatic remediation.
# Called by trap_err and soft-fail handlers to capture full error context.
# Usage: capture_error_context <line> <cmd> <exit_code> [stderr_file]
capture_error_context() {
	local line="$1" cmd="$2" ec="$3" stderr_file="${4:-}" detail=""
	[[ -n "$stderr_file" && -s "$stderr_file" ]] && detail="$(tail -n 5 "$stderr_file" | tr '\n' ' ')"
	log "[ERROR] line $line: '$cmd' exited $ec${detail:+ — $detail}"
}

# section() - Print formatted section header with visual divider and log entry.
# Displays section number and title with colored borders for visual clarity.
# All section headers are logged for audit trail with timestamps.
# Usage: section <number> <title...>
section() {
	abort_if_cancelled
	local n="$1"
	shift
	CURRENT_SECTION="$n"
	((++UI_SECTION_DONE))
	local pct=$((UI_SECTION_DONE * 100 / UI_SECTION_TOTAL))
	local pb
	pb="$(progress_bar "$UI_SECTION_DONE" "$UI_SECTION_TOTAL" 28)"
	if ((! GUI_FULL_MODE)); then
		printf '\n%s══════════════════════════════════════════════════════════════%s\n' "$C_CYN" "$C_RST"
		printf '%s Section %s: %s%s\n' "$C_BLD" "$n" "$*" "$C_RST"
		printf '%s Progress:%s %s %d/%d (%d%%)\n' "$C_BLU" "$C_RST" "$pb" "$UI_SECTION_DONE" "$UI_SECTION_TOTAL" "$pct"
		printf '%s══════════════════════════════════════════════════════════════%s\n' "$C_CYN" "$C_RST"
	fi
	gui_send SECTION "$n" "$*"
	log "==== Section $n: $* ===="
}

# run() - Execute shell command or simulate execution in --dry-run mode.
# In dry-run mode, logs the command for preview without executing it.
# All commands are logged to audit file regardless of execution.
# Captures stderr from failed commands so a failure can say why.
# Usage: run "command" "with" "args"
run() {
	abort_if_cancelled
	LAST_RUN_CMD="$*"
	if ((DRY_RUN)); then
		((! GUI_FULL_MODE)) && printf '%s[DRY ]%s  %s\n' "$C_YEL" "$C_RST" "$*"
		gui_send LOG dry "$*"
		log "[DRY]   $*"
		return 0
	fi
	log "[RUN]   $*"
	gui_send LOG run "$*"
	_track_units "$*"
	local rc=0
	if ((GUI_FULL_MODE)); then
		: >"$ERROR_CAPTURE_FILE" 2>/dev/null || true
		# shellcheck disable=SC2294
		eval "$@" > >(log_stream) 2>>"$ERROR_CAPTURE_FILE" || rc=$?
	else
		# Capture stderr so a failure can say why
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
# dnf_repos_ready() - Check once that the repositories answer (bounded time). An
# unreachable repository that drops packets makes every dnf call wait out its
# timeouts and retries; without this check one such repository stalled a run for
# well over half an hour. When it fails, package work is skipped with one follow-up.
_DNF_REPOS_CHECKED=0
_DNF_REPOS_OK=1
dnf_repos_ready() {
	((DRY_RUN)) && return 0
	if ((! _DNF_REPOS_CHECKED)); then
		_DNF_REPOS_CHECKED=1
		info "Checking that the package repositories answer (dnf makecache)..."
		if ! timeout "${DNF_CHECK_TIMEOUT:-600}" dnf makecache -q >/dev/null 2>"${ERROR_CAPTURE_FILE:-/dev/null}"; then
			_DNF_REPOS_OK=0
			warn "The package repositories did not answer — package installs and upgrades are skipped this run."
			add_action_item 0 HIGH "PKG_REPOS_UNREACHABLE" \
				"The package repositories could not be reached (network, proxy or a broken .repo file in /etc/yum.repos.d — see 'sudo dnf makecache'). Fix that, then re-run the script; sections that need packages will complete."
		fi
	fi
	((_DNF_REPOS_OK))
}

pkg_upgrade() {
	local rc=0
	if ((IS_OSTREE)); then
		run "rpm-ostree upgrade" || rc=$?
		if ((rc != 0)); then
			local stderr_content=""
			[[ -f "$ERROR_CAPTURE_FILE" ]] && stderr_content=$(<"$ERROR_CAPTURE_FILE")
			if [[ "$stderr_content" =~ depsolve|conflicting[[:space:]]requests|cannot[[:space:]]install[[:space:]]both ]]; then
				warn "rpm-ostree upgrade failed due to a package resolution conflict; continuing without staging an upgrade."
			else
				warn "rpm-ostree upgrade failed (exit $rc); continuing without staging an upgrade."
			fi
			warn "Continuing with remaining hardening sections."
		else
			warn "rpm-ostree upgrades are staged and applied on reboot. Reboot when this script completes."
		fi
	else
		dnf_repos_ready || return 0
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
		# Logging must never abort the run (set -e), even if the log is unwritable.
		[[ -n "${out}" ]] && printf '%s\n' "$out" | log_stream

		if ((rc != 0)); then
			# Idempotent rpm-ostree no-op cases should not abort under strict mode.
			if [[ "$out" =~ already[[:space:]]requested|already[[:space:]]provided|No[[:space:]]packages[[:space:]]in[[:space:]]transaction|is[[:space:]]already[[:space:]]provided ]]; then
				warn "rpm-ostree reports package(s) already queued/provided; treating as up-to-date."
			else
				# As with dnf: a package that cannot be layered (not in the image's
				# repositories — Bazzite ships without Fedora's — or no network) must
				# not abort the remaining sections; callers check for what they need.
				capture_error_context "${BASH_LINENO[0]:-?}" "rpm-ostree install ${needed[*]}" "$rc" "/dev/null" || true
				local reason
				reason="$(grep -m1 -iE 'error|not found' <<<"$out" || true)"
				warn "rpm-ostree could not layer: ${needed[*]}${reason:+ — $reason}"
				add_action_item "${CURRENT_SECTION:-0}" MEDIUM "PKG_INSTALL_FAILED_${needed[0]//[^a-zA-Z0-9]/_}" \
					"Package layering failed${reason:+ ($reason)}: sudo rpm-ostree install ${needed[*]} — if the image does not carry the package, use a Flatpak or a toolbox/distrobox instead."
				return 0
			fi
		fi

		# Mark requested packages as pending to avoid redundant layering attempts this run.
		for pkg in "${needed[@]}"; do
			_PKG_PENDING_CACHE[$pkg]=1
		done
		record_change PKG_INSTALL "${needed[*]}"
		warn "Layered packages are applied on reboot. Reboot when this script completes."
	else
		if ! dnf_repos_ready; then
			warn "Skipping install of ${needed[*]} (repositories unreachable)."
			return 0
		fi
		# Record every package the transaction adds (dependencies and weak
		# dependencies included), so --rollback removes exactly what came in.
		local pkgs_before=""
		((DRY_RUN)) || pkgs_before="$(rpm -qa --qf '%{NAME}.%{ARCH}\n' 2>/dev/null | sort -u)"
		if ! run "dnf install -y ${needed[*]}"; then
			# A missing/renamed package must not abort every remaining section; the
			# callers check for the commands they need and skip what is unavailable.
			warn "dnf install failed for: ${needed[*]}"
			add_action_item "${CURRENT_SECTION:-0}" MEDIUM "PKG_INSTALL_FAILED_${needed[0]//[^a-zA-Z0-9]/_}" \
				"Package install failed: sudo dnf install -y ${needed[*]}"
			return 0
		fi
		# Keep package cache coherent after successful mutable-system installs.
		for pkg in "${needed[@]}"; do
			_PKG_CACHE[$pkg]=0
		done
		local added=""
		if [[ -n "$pkgs_before" ]]; then
			added="$(comm -13 <(printf '%s\n' "$pkgs_before") <(rpm -qa --qf '%{NAME}.%{ARCH}\n' 2>/dev/null | sort -u) | tr '\n' ' ')"
		fi
		added="${added% }"
		record_change PKG_INSTALL "${added:-${needed[*]}}"
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
	if ! timeout 1800 flatpak install -y "${remote}" "${app_id}" 2>/dev/null; then
		warn "Flatpak ${app_id} install failed."
		add_action_item "4" "MEDIUM" \
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
		run "curl -fsSL --connect-timeout 20 --max-time 600 '$url' -o '$dest' 2>/dev/null" && return 0
	fi
	if cmd_exists wget; then
		run "wget -q --timeout=20 --tries=3 -O '$dest' '$url' 2>/dev/null" && return 0
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
	home="$(cut -d: -f6 <<<"$entry")"
	_USER_HOME_CACHE[$user]="$home"
	echo "$home"
}

# image_box_tool() - The pet-container tool to use on this system: distrobox on
# Universal Blue images (they ship distrobox, not toolbox), toolbox elsewhere.
image_box_tool() {
	if [[ -r /usr/share/ublue-os/image-info.json ]] && cmd_exists distrobox; then
		echo distrobox
	elif cmd_exists toolbox || ! cmd_exists distrobox; then
		echo toolbox
	else
		echo distrobox
	fi
}

# write_new_file() - Write stdin to <path> with <mode>, journaling it for --rollback.
# Usage: write_new_file <path> <mode> <<'EOF' ... EOF
write_new_file() {
	local f="$1" mode="$2"
	if ((DRY_RUN)); then
		info "Would write $f"
		cat >/dev/null
		return 0
	fi
	backup_file "$f" || return 1
	install -d -m 755 "$(dirname "$f")" 2>/dev/null || true
	if ! cat 2>/dev/null >"$f"; then
		warn "Failed to write $f"
		return 1
	fi
	chmod "$mode" "$f" 2>/dev/null || true
}

# enable_timer() - daemon-reload and enable a timer, journaling the enable symlink
# so --rollback removes it together with the unit files.
enable_timer() {
	local timer="$1"
	backup_file "/etc/systemd/system/timers.target.wants/$timer" || return 1
	run "systemctl daemon-reload" || true
	run "systemctl enable --now $timer"
}

# confirm() - Prompt user for yes/no confirmation (respects --yes flag).
# Returns 0 (success) for 'y'/'yes' response, 1 (failure) for 'n'/'no' or default.
# In --yes mode the answer is the default: yes, unless the caller passes "no" for
# an option that current guidance does not recommend enabling automatically.
# Usage: confirm ["prompt text"] [yes|no]
# Every answer is remembered for the recovery file; with --restore, a question
# answered before gets the same answer again.
confirm() {
	local _q="${1:-Continue?}" _k
	_k="$(_answer_key "$_q")"
	if [[ -n "${RESTORE_ANSWERS[$_k]:-}" ]]; then
		info "Answer from the recovery file ($_q): ${RESTORE_ANSWERS[$_k]}"
		ANSWERS["$_k"]="${RESTORE_ANSWERS[$_k]}"
		ANSWER_TEXT["$_k"]="$_q"
		[[ "${RESTORE_ANSWERS[$_k]}" == yes ]]
		return
	fi
	if _confirm_ask "$@"; then
		ANSWERS["$_k"]=yes
		ANSWER_TEXT["$_k"]="$_q"
		return 0
	fi
	ANSWERS["$_k"]=no
	ANSWER_TEXT["$_k"]="$_q"
	return 1
}

# _confirm_ask - The question itself (--yes default, the window, or the terminal).
_confirm_ask() {
	local prompt="${1:-Continue?}" default="${2:-yes}"
	if ((ASSUME_YES)); then
		if [[ "$default" == no ]]; then
			info "Auto-no (opt-in only): $prompt"
			return 1
		fi
		info "Auto-yes: $prompt"
		return 0
	fi

	if ((GUI_FULL_MODE)); then
		local answer=""
		if gui_ask confirm "$default" "$prompt" answer; then
			[[ "$answer" == yes ]]
			return
		fi
		# No answer: the user stopped the run (or closed the window).
		abort_if_cancelled
		return 1
	fi

	local reply
	read -r -p "$(printf '%s[??]%s  %s [y/N] ' "$C_YEL" "$C_RST" "$prompt")" reply
	[[ "$reply" =~ ^[Yy]([Ee][Ss])?$ ]]
}

# backup_file() - Create backup of file in designated backup directory.
# Creates directory structure if needed; uses mode 0700 for restricted access.
# All backups are organized by timestamp in /root/harden-backups-YYYYMMDD-HHMMSS/
# If the file does not exist yet, journal FILE_CREATE instead so that --rollback
# removes the file this run is about to create.
# Usage: backup_file <file_path>
backup_file() {
	local f="$1" dir what
	# Never change what cannot be written or rolled back. Returning 1 makes the caller
	# skip the change (sections: `backup_file X || return 0`); the run goes on.
	if ((! DRY_RUN)); then
		dir="$(dirname -- "$f")"
		if [[ -e "$f" && ! -w "$f" ]] || [[ ! -e "$f" && -d "$dir" && ! -w "$dir" ]]; then
			warn "Leaving $f unchanged: it is not writable (read-only filesystem or immutable file)."
			add_action_item "${CURRENT_SECTION:-0}" MEDIUM "NOT_WRITABLE_${f//[^a-zA-Z0-9]/_}" \
				"Section ${CURRENT_SECTION:-?} stopped at $f, which is not writable (read-only filesystem or 'chattr +i'). Make it writable, then re-run: sudo ./fedora-harden.sh --only ${CURRENT_SECTION:-N}"
			return 1
		fi
	fi
	if [[ ! -e "$f" ]]; then
		record_change FILE_CREATE "$f"
		return 0
	fi
	[[ -f "$f" ]] || return 0
	what=""
	if [[ ! -r "$f" ]]; then
		what="it cannot be read"
	elif ! run "install -d -m 700 '$BACKUP_DIR'"; then
		what="the backup folder $BACKUP_DIR cannot be created"
	elif ! run "cp -a --parents '$f' '$BACKUP_DIR/'"; then
		what="the copy to $BACKUP_DIR failed (disk full?)"
	fi
	if [[ -n "$what" ]]; then
		warn "Leaving $f unchanged: could not back it up ($what)."
		add_action_item "${CURRENT_SECTION:-0}" HIGH "BACKUP_FAILED_${f//[^a-zA-Z0-9]/_}" \
			"Section ${CURRENT_SECTION:-?} stopped because $f could not be backed up ($what). Free space under /root, then re-run: sudo ./fedora-harden.sh --only ${CURRENT_SECTION:-N}"
		return 1
	fi
	record_change FILE_BACKUP "$f"
	info "Backed up $f → $BACKUP_DIR"
}

# tool_dir_begin / tool_dir_end <dir> - Tools such as firewall-cmd and augenrules
# rewrite files themselves. Back up every file under <dir> before they run, and
# journal the files they create, so --rollback restores the directory exactly.
declare -gA _TOOL_DIR_BEFORE=()
tool_dir_begin() {
	local dir="$1" f
	((DRY_RUN)) && return 0
	[[ -d "$dir" ]] || return 0
	_TOOL_DIR_BEFORE[$dir]="$(find "$dir" -xdev -type f 2>/dev/null | sort)"
	while IFS= read -r f; do
		[[ -n "$f" ]] || continue
		backup_file "$f" || return 1
	done <<<"${_TOOL_DIR_BEFORE[$dir]}"
}
tool_dir_end() {
	local dir="$1" f
	((DRY_RUN)) && return 0
	[[ -d "$dir" ]] || return 0
	while IFS= read -r f; do
		[[ -n "$f" ]] || continue
		grep -qxF -- "$f" <<<"${_TOOL_DIR_BEFORE[$dir]:-}" || record_change FILE_CREATE "$f"
	done < <(find "$dir" -xdev -type f 2>/dev/null | sort)
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
# Patterns are POSIX *extended* regular expressions (sed -E), so #? and \s+ work.
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
	if ! sed -E -i "${args[@]}" "$f" 2>/dev/null; then
		warn "sed failed on $f (file may be read-only or missing)"
		return 1
	fi
}

# set_conf_key() - Set "key<sep>value" in a config file: replaces the first active or
# commented-out occurrence of the key, or appends it when absent. Idempotent.
# <sep> is " = " for key=value files, or whitespace (e.g. "   ") for login.defs.
# Usage: set_conf_key <file> <key> <value> [sep]
set_conf_key() {
	local f="$1" key="$2" value="$3" sep="${4:- = }" line new
	line="${key}${sep}${value}"
	if ((DRY_RUN)); then
		info "Would set '${line}' in $f"
		return 0
	fi
	[[ -f "$f" ]] || {
		warn "$f not found — cannot set $key"
		return 1
	}
	# Set the first active occurrence and drop later duplicates (one effective value);
	# otherwise uncomment the first commented default; otherwise append. awk avoids sed
	# delimiter/quoting pitfalls, and writing back with printf keeps the file's inode,
	# owner, mode and SELinux label.
	if ! new="$(awk -v k="$key" -v l="$line" '
		BEGIN { act = "^[ \t]*" k "([ \t]|=)"; com = "^[ \t]*#[ \t]*" k "([ \t]|=)" }
		{ lines[NR] = $0; if ($0 ~ act) has_act = 1; else if (!first_com && $0 ~ com) first_com = NR }
		END {
			for (i = 1; i <= NR; i++) {
				if (has_act && lines[i] ~ act) { if (!done) print l; done = 1 }
				else if (!has_act && i == first_com) print l
				else print lines[i]
			}
			if (!has_act && !first_com) print l
		}' "$f")"; then
		warn "Could not parse $f to set $key"
		return 1
	fi
	if ! printf '%s\n' "$new" 2>/dev/null >"$f"; then
		warn "Could not write $key to $f"
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
	# Several names the script uses are only *provided* by another package on
	# Fedora 44/45 (clamav-update → clamav-freshclam, wget → wget2-wget,
	# dnf-automatic → dnf5-plugin-automatic). `rpm -q <name>` misses those, which
	# made every run re-attempt the install; --whatprovides resolves them.
	if rpm -q "$pkg" >/dev/null 2>&1 || rpm -q --whatprovides "$pkg" >/dev/null 2>&1; then
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
	if ((IS_BAZZITE)) && ((! HAS_KDE && ! HAS_GNOME)); then
		HAS_KDE=1
		[[ ",${detected[*]}," == *",kde,"* ]] || detected+=("kde")
	fi

	((${#detected[@]} > 0)) && HAS_DESKTOP=1
	local IFS=','
	DESKTOP_ENVS="${detected[*]:-}"
}

# section_compatible() - Check if a section is compatible with current system.
# Evaluates release type, desktop presence, and platform capabilities to auto-skip safely.
# Examples: Section 13 (KDE) skips if !HAS_KDE; Section 14 skips if !HAS_DESKTOP
# Returns 0 (compatible) or 1 (incompatible/should skip).
# Usage: section_compatible <section_number>
section_compatible() {
	local s="$1"
	case "$s" in
	13)
		# Section 13 requires at least one desktop environment to be installed.
		if ((! HAS_DESKTOP)); then
			info "Skipping section 13: no desktop environment detected on this host."
			return 1
		fi
		;;
	14)
		# Section 14 is desktop-focused and should run if any desktop environment is installed.
		if ((! HAS_DESKTOP)); then
			info "Skipping section 14: no desktop environment detected on this host."
			return 1
		fi
		;;
	23)
		# Section 23 can interfere with remote access if USB input devices are not whitelisted.
		if ((IS_SERVER)) && ((! ASSUME_YES)); then
			warn "Section 23 (USBGuard) can disrupt remote-only server access if input devices are blocked."
		fi
		# Sway/Hyprland/i3 users: input-device whitelists in compositors must allow USB keyboards/mice.
		if ((HAS_SWAY || HAS_HYPRLAND || HAS_I3)) && ((! ASSUME_YES)); then
			warn "Section 23 (USBGuard): tiling WM users should whitelist USB input devices in their compositor config."
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

# _track_units <command> - Remember the units a command enables, starts or restarts,
# so diagnose_failures only reports services this run touched.
_track_units() {
	[[ "$1" =~ systemctl[[:space:]]+(--[a-z-]+[[:space:]]+)*(enable|start|restart|reload|reload-or-restart|try-restart)[[:space:]]+(.*) ]] || return 0
	local w
	local -a words
	read -ra words <<<"${BASH_REMATCH[3]}"
	for w in "${words[@]}"; do
		case "$w" in
		"||" | "&&" | ";" | "|" | ">"* | "2>"*) break ;;
		-*) continue ;;
		esac
		w="${w//\'/}"
		[[ "$w" == *.* ]] || w="$w.service"
		TOUCHED_UNITS["$w"]=1
	done
}

# diagnose_failures() - After the sections: which services this run touched have
# failed, and why, in their own words (their journal). Each becomes a follow-up.
diagnose_failures() {
	((DRY_RUN)) && return 0
	local u reason n=0
	for u in "${!TOUCHED_UNITS[@]}"; do
		systemctl is-failed --quiet "$u" 2>/dev/null || continue
		((++n))
		reason="$(journalctl -u "$u" -b -p warning -n 3 --no-pager -o cat 2>/dev/null | tr '\n' ' ')"
		warn "$u failed${reason:+: $reason}"
		add_action_item 0 HIGH "UNIT_FAILED_${u//[^a-zA-Z0-9]/_}" \
			"$u failed${reason:+ ($reason)}. Full log: journalctl -u $u -b"
	done
	((n)) || ok "Every service this run enabled or restarted is running."
	if ((ERR_COUNT)); then
		if ((LOG_JOURNAL)); then
			warn "$ERR_COUNT step(s) reported errors: $LOG_WHERE -p err"
		else
			warn "$ERR_COUNT step(s) reported errors: grep ERROR $LOG_WHERE"
		fi
	fi
}

# trap_cleanup() - Emergency cleanup handler for EXIT/ERR traps.
# Removes temporary files and performs resource cleanup on script failure.
# Also writes the session report to sessions/ on every exit (normal or abort).
trap_cleanup() {
	local rc=$?
	[[ "$BASHPID" == "$$" ]] || return "$rc" # subshells never clean up for the run
	gui_finish "$rc"
	release_run_lock
	# Clean all registered temp files (registered via register_tmp())
	local _f
	for _f in "${TEMP_FILES[@]}"; do
		[[ -f "$_f" ]] && rm -f "$_f"
	done

	# Finalize the session report on every exit path.
	write_session_report || true

	# Ensure logs remain accessible for post-script analysis
	return "$rc"
}

# trap_err() - Error handler for ERR trap.
# Captures exit code + command context, logs with full detail, then exits.
# Usage: Called automatically on error via trap.
trap_err() {
	local rc=$? line=${BASH_LINENO[0]:-?}
	# With set -E this trap also fires in subshells and command substitutions when a
	# command fails there. Cleanup belongs to the main script only: a subshell
	# running it removed the run lock and temp files while the run went on.
	[[ "$BASHPID" == "$$" ]] || return "$rc"
	local cmd_ctx="${BASH_COMMAND:-${LAST_RUN_CMD:-script execution}}"
	if ((EXPECTED_ABORT)); then
		exit "$rc"
	fi
	SESSION_STATUS="aborted"
	capture_error_context "$line" "$cmd_ctx" "$rc" "$ERROR_CAPTURE_FILE" 2>/dev/null || true
	err "Aborted at line $line (exit $rc). Log: ${LOG_WHERE:-$LOG_FILE}"
	trap_cleanup || true
	exit "$rc"
}
# Enable error and exit traps to catch unexpected failures and clean resources.
trap trap_cleanup EXIT
trap trap_err ERR
