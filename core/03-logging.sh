# shellcheck shell=bash
# ---------- Logging helpers -------------------------------------------------
# Choose where this run logs. On a normal system that is the journal (journalctl -t
# fedora-harden FH_SESSION=<session>): rotation, size limits and access control
# come with it. Without journald (minimal containers) the same lines go to a file
# under /var/log/fedora-harden, or /tmp as a last resort.
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

# Record a message: in the journal with the session and section as fields,
# or in the log file. Priority follows the message type.
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

# Log every line read from stdin (command output).
log_stream() {
	local line
	while IFS= read -r line || [[ -n "$line" ]]; do
		log "  | $line"
		gui_send LOG out "$line"
	done
}

# Status lines: printed in colour (err to stderr), logged and sent to the window.
info() {
	((! GUI_FULL_MODE)) && printf '%s[INFO]%s  %s\n' "$C_BLU" "$C_RST" "$*"
	log "[INFO]  $*"
	gui_send LOG info "$*"
}

ok() {
	((! GUI_FULL_MODE)) && printf '%s[ OK ]%s  %s\n' "$C_GRN" "$C_RST" "$*"
	log "[OK]    $*"
	gui_send LOG ok "$*"
}

warn() {
	((! GUI_FULL_MODE)) && printf '%s[WARN]%s  %s\n' "$C_YEL" "$C_RST" "$*"
	log "[WARN]  $*"
	gui_send LOG warn "$*"
}

err() {
	((++ERR_COUNT))
	((! GUI_FULL_MODE)) && printf '%s[FAIL]%s  %s\n' "$C_RED" "$C_RST" "$*" >&2
	log "[ERROR] $*"
	gui_send LOG error "$*"
}

# Log a failed command with its exit code and the tail of its stderr.
# Usage: capture_error_context <where> <cmd> <exit_code> [stderr_file]
capture_error_context() {
	local where="$1" cmd="$2" ec="$3" stderr_file="${4:-}" detail=""
	[[ -n "$stderr_file" && -s "$stderr_file" ]] && detail="$(tail -n 5 "$stderr_file" | tr '\n' ' ')"
	log "[ERROR] $where: '$cmd' exited $ec${detail:+ — $detail}"
}

# source_line <file> <line> - "fedora/sections/05-selinux.sh line 42": a location in the
# script's own files, relative to the project directory.
source_line() {
	printf '%s line %s' "${1#"$SCRIPT_DIR"/}" "$2"
}

# Section header: printed with the progress bar, sent to the window, logged.
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

# Run a command line (eval'd), or only log it under --dry-run. Stderr is captured so
# a failure can say why.
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
		capture_error_context "$(source_line "${BASH_SOURCE[1]:-$0}" "${BASH_LINENO[0]}")" "$*" "$rc" "$ERROR_CAPTURE_FILE"
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

have_cmd() {
	command -v "$1" >/dev/null 2>&1
}

# Best effort: tries each package and goes on when one fails.
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

# Install, or update when an update is available; never aborts the script (a failure
# becomes a follow-up). Up-to-date detection uses `flatpak update --no-pull` (locally
# cached metadata, no network) instead of comparing commit hashes: `flatpak info
# --show-commit` and `flatpak remote-info --show-commit` use different representations
# that never match, which caused a no-op update on every run.
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

# Install a package providing <command> when it is missing.
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

# curl, falling back to wget. Usage: download_file <url> <destination>
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

# Home directory of a local user, cached for the run.
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

# Write stdin to <path> with <mode>, journaling it for --rollback.
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

# Run daemon-reload and enable a timer, journaling the enable symlink so --rollback
# removes it together with the unit files.
enable_timer() {
	local timer="$1"
	backup_file "/etc/systemd/system/timers.target.wants/$timer" || return 1
	run "systemctl daemon-reload" || true
	run "systemctl enable --now $timer"
}

# Yes/no question; returns 0 for yes. In --yes mode the answer is the default: yes,
# unless the caller passes "no" for an option that current guidance does not recommend
# enabling automatically. Every answer is remembered for the recovery file; with
# --restore, a question answered before gets the same answer again.
# Usage: confirm ["prompt text"] [yes|no]
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

# Copy a file into this session's backup directory (/root/harden-backups-<session>,
# mode 0700) before it changes. A file that does not exist yet is journaled as
# FILE_CREATE instead, so --rollback removes the file this run creates.
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

# Usage: in_list <needle> <comma,separated,list>
in_list() {
	[[ -z "$2" ]] && return 1
	local IFS=','
	for item in $2; do [[ "$item" == "$1" ]] && return 0; done
	return 1
}

# Apply several sed expressions to a file in one pass. Patterns are POSIX *extended*
# regular expressions (sed -E), so #? and \s+ work.
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

# Set "key<sep>value" in a config file: replaces the first active or commented-out
# occurrence of the key, or appends it when absent. Idempotent. <sep> is " = " for
# key=value files, or whitespace (e.g. "   ") for login.defs.
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

# have_cmd, cached for the run.
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

# --only, --skip and section_compatible decide. Usage: should_run <section_number>
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

# After the sections: which services this run touched have failed, and why, in
# their own words (their journal). Each becomes a follow-up.
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

# EXIT trap: remove temp files and write the session report (normal exit or abort).
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

trap_err() {
	# The failing command is at line BASH_LINENO[0] of file BASH_SOURCE[1].
	local rc=$? line=${BASH_LINENO[0]:-?} file=${BASH_SOURCE[1]:-$0}
	file="${file#"$SCRIPT_DIR"/}"
	# With set -E this trap also fires in subshells and command substitutions when a
	# command fails there. Cleanup belongs to the main script only: a subshell
	# running it removed the run lock and temp files while the run went on.
	[[ "$BASHPID" == "$$" ]] || return "$rc"
	local cmd_ctx="${BASH_COMMAND:-${LAST_RUN_CMD:-script execution}}"
	if ((EXPECTED_ABORT)); then
		exit "$rc"
	fi
	SESSION_STATUS="aborted"
	capture_error_context "$file line $line" "$cmd_ctx" "$rc" "$ERROR_CAPTURE_FILE" 2>/dev/null || true
	err "Aborted at line $line of $file (exit $rc). Log: ${LOG_WHERE:-$LOG_FILE}"
	trap_cleanup || true
	exit "$rc"
}
# Enable error and exit traps to catch unexpected failures and clean resources.
trap trap_cleanup EXIT
trap trap_err ERR
