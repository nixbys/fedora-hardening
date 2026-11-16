# shellcheck shell=bash
# ---------- GUI (--gui): one window for the whole run -----------------------
# A GTK4/libadwaita app (Python, libexec/fedora-harden-gui.py) shows the run in one
# window: the sections with their status, a progress bar with elapsed and remaining
# time, a live activity log with filters and search, questions answered inline,
# notices, and the summary with follow-up items at the end. GTK4, libadwaita and
# their Python bindings ship with Fedora Workstation and every Atomic desktop;
# elsewhere --gui installs them. The script and the window talk over a pipe, one
# tab-separated event per line (the protocol is described at the top of the app).
# The window stays open after the script exits so the summary can be read.
GUI_DIR=""     # Private directory for the app (root-only)
GUI_APP_PID="" # PID of the window process
GUI_TX_FD=""   # Script → window events
GUI_RX_FD=""   # Window → script answers and stop requests
GUI_ENDED=0    # END was sent
declare -gA GUI_SECTION_TITLES=()

# /run/fedora-harden/gui (root-only tmpfs, cleared at reboot), falling back to a
# private /tmp directory.
gui_dir() {
	local dir="/run/fedora-harden/gui"
	if ! install -d -m 700 "$dir" 2>/dev/null; then
		dir="$(mktemp -d "/tmp/fedora-harden-gui.XXXXXX" 2>/dev/null)" || return 1
	fi
	GUI_DIR="$dir"
}

# True when python3 can load GTK4 and libadwaita.
gui_deps_ok() {
	have_cmd python3 && python3 -c 'import gi; gi.require_version("Gtk", "4.0"); gi.require_version("Adw", "1"); from gi.repository import Adw, Gtk' >/dev/null 2>&1
}

# With --gui and a display, open the window; otherwise stay in the terminal. On a
# package-based system the GTK4 Python stack is installed if missing; on an Atomic
# system it is part of the image (nothing is layered for the GUI).
setup_ui_mode() {
	((FORCE_GUI)) || return 0
	if [[ -z "${DISPLAY:-}" && -z "${WAYLAND_DISPLAY:-}" ]]; then
		warn "--gui needs a graphical session (no DISPLAY or WAYLAND_DISPLAY) — using the terminal."
		return 0
	fi
	if ! gui_deps_ok && ((! IS_OSTREE)) && ((EUID == 0)); then
		install_dep_candidates python3-gobject 2>/dev/null || true
		install_dep_candidates gobject-introspection 2>/dev/null || true
		install_dep_candidates gtk4 2>/dev/null || true
		install_dep_candidates libadwaita 2>/dev/null || true
	fi
	if ! gui_deps_ok; then
		warn "--gui needs python3-gobject, gtk4 and libadwaita — using the terminal."
		return 0
	fi
	gui_dir || {
		warn "--gui could not create its private directory — using the terminal."
		return 0
	}
	local app="$GUI_DIR/fedora-harden-gui.py"
	install -m 600 "$SCRIPT_DIR/libexec/fedora-harden-gui.py" "$app"

	# Root often has no UTF-8 locale (sudo -i, pkexec); the window text needs one.
	local -a env_add=(PYTHONDONTWRITEBYTECODE=1)
	[[ "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" =~ [Uu][Tt][Ff]-?8 ]] || env_add+=(LC_ALL=C.UTF-8)
	# Writing to the window after it closed must not kill the script (SIGPIPE).
	trap '' PIPE
	coproc GUI_APP { exec env "${env_add[@]}" python3 "$app" 2>>"$GUI_DIR/window.log"; }
	GUI_APP_PID="${GUI_APP_PID:-}"
	# Plain descriptors (not the coproc's) so subshells such as log_stream can use them.
	exec {GUI_TX_FD}>&"${GUI_APP[1]}" {GUI_RX_FD}<&"${GUI_APP[0]}"
	local ready=""
	read -r -t 30 -u "$GUI_RX_FD" ready 2>/dev/null || true
	if [[ "$ready" != READY ]]; then
		[[ -n "$GUI_APP_PID" ]] && kill "$GUI_APP_PID" 2>/dev/null
		exec {GUI_TX_FD}>&- {GUI_RX_FD}<&-
		GUI_TX_FD="" GUI_RX_FD="" GUI_APP_PID=""
		trap - PIPE
		warn "The --gui window did not open (see $GUI_DIR/window.log) — using the terminal."
		return 0
	fi
	GUI_FULL_MODE=1
	printf '%s[INFO]%s  Running in the "Fedora Hardening" window. Closing it asks before stopping.\n' "$C_BLU" "$C_RST"
	local mode="Applying changes"
	((DRY_RUN)) && mode="Dry run — nothing is changed"
	gui_send MODE "$mode"
}

# Send one event to the window: gui_send <KIND> [field...]
# Fields are escaped (backslash, tab, newline) so every event is one line.
gui_send() {
	[[ -n "$GUI_TX_FD" ]] || return 0
	local out="$1" f
	shift
	for f in "$@"; do
		f="${f//\\/\\\\}"
		f="${f//$'\t'/\\t}"
		out+=$'\t'"${f//$'\n'/\\n}"
	done
	printf '%s\n' "$out" 1>&"$GUI_TX_FD" 2>/dev/null || true
	return 0
}

# Messages written for the terminal use a literal "\n" for line breaks.
gui_text() {
	printf '%s' "${1//\\n/$'\n'}"
}

# Count the sections this run will execute (--only/--skip applied) and, with
# --gui, show them in the window in execution order.
calc_section_total() {
	local s n=0 num title
	if ((GUI_FULL_MODE)); then
		while read -r num title; do
			[[ "$num" =~ ^[0-9]+$ ]] && GUI_SECTION_TITLES[$num]="${title%:}"
		done < <(list_sections | sed '/^$/q')
	fi
	for s in "${SECTIONS[@]}"; do
		[[ -n "$ONLY_LIST" ]] && ! in_list "$s" "$ONLY_LIST" && continue
		[[ -n "$SKIP_LIST" ]] && in_list "$s" "$SKIP_LIST" && continue
		((++n))
		gui_send PLAN "$s" "${GUI_SECTION_TITLES[$s]:-Section $s}"
	done
	((n > 0)) && UI_SECTION_TOTAL="$n" || UI_SECTION_TOTAL="${#SECTIONS[@]}"
	UI_SECTION_DONE=0
}

# Something the user should read: a notice in the window (it stays until
# dismissed). Usage: gui_alert <info|warning|error> <message>
gui_alert() {
	((GUI_FULL_MODE)) || return 0
	gui_send NOTICE "$1" "$(gui_text "$2")"
}

# Show the follow-up items (open ones by priority, then the ones resolved this
# run) on the window's summary page.
gui_send_items() {
	((GUI_FULL_MODE)) || return 0
	local item section priority tag desc
	gui_send ITEMS
	for item in "${ACTIONABLE_ITEMS[@]}"; do
		IFS='|' read -r section priority tag desc <<<"$item"
		gui_send ITEM "$priority" "$section" "$desc"
	done
	for item in "${REMEDIATED_ITEMS[@]}"; do
		IFS='|' read -r section priority tag desc <<<"$item"
		gui_send ITEM DONE "$section" "$desc"
	done
}

# Switch the window to its summary page: gui_final_summary <headline> <details>
gui_final_summary() {
	((GUI_FULL_MODE)) || return 0
	gui_send SUMMARY "$1" "$(gui_text "$2")"
	gui_send_items
}

# Tell the window the run is over (once; called from the EXIT trap). The window
# stays open for reading; the script does not wait for it.
gui_finish() {
	local rc="$1" msg
	((GUI_FULL_MODE && ! GUI_ENDED)) || return 0
	GUI_ENDED=1
	case "$rc" in
	0) msg="Finished. A reboot is recommended to apply kernel, sysctl and PAM changes." ;;
	130) msg="Stopped at your request. Undo changes with: sudo $SCRIPT_NAME --rollback" ;;
	*) msg="Stopped by an error (exit $rc). Log: ${LOG_WHERE:-$LOG_FILE}" ;;
	esac
	gui_send_items
	gui_send END "$rc" "$msg"
	exec {GUI_TX_FD}>&- {GUI_RX_FD}<&- 2>/dev/null
	GUI_TX_FD="" GUI_RX_FD=""
	[[ -n "$GUI_APP_PID" ]] && disown "$GUI_APP_PID" 2>/dev/null
	trap - PIPE
	return 0
}

# The window went away mid-run: the user closed it (it asks first) or it crashed.
# Either way the run stops instead of going on unseen.
gui_lost() {
	GUI_CANCEL_REQUESTED=1
	[[ -n "$GUI_DIR" ]] && : >"$GUI_DIR/cancelled" 2>/dev/null
	return 0
}

# Read one line from the window into the named variable; on EOF (window gone) mark
# the run as cancelled. Usage: gui_read_line <var> [timeout]
gui_read_line() {
	local -n _line="$1"
	local -a t=()
	[[ -n "${2:-}" ]] && t=(-t "$2")
	if ! IFS= read -r "${t[@]}" -u "$GUI_RX_FD" _line 2>/dev/null; then
		gui_lost
		return 1
	fi
	[[ "$_line" == CANCEL ]] && gui_lost
	return 0
}

# Ask in the window and wait for the answer.
# Usage: gui_ask <confirm|input> <default> <text> <result-var>
# Returns 1 when there is no answer (window gone or the user stopped the run).
gui_ask() {
	local -n _answer="$4"
	[[ -n "$GUI_RX_FD" ]] && ((! GUI_CANCEL_REQUESTED)) || return 1
	# The id must be unique in subshells too (prompt_input runs inside $(...)).
	local id="$BASHPID-$RANDOM" line
	gui_send ASK "$id" "$1" "$2" "$(gui_text "$3")"
	while gui_read_line line; do
		[[ "$line" == CANCEL ]] && return 1
		if [[ "$line" == ANSWER$'\t'"$id"$'\t'* ]]; then
			line="${line#ANSWER$'\t'"$id"$'\t'}"
			line="${line//\\n/$'\n'}"
			line="${line//\\t/$'\t'}"
			_answer="${line//\\\\/\\}"
			return 0
		fi
	done
	return 1
}

# True once the user stopped the run (Stop button, or closing the window and
# confirming) or the window went away.
gui_check_cancel() {
	((GUI_FULL_MODE)) || return 1
	((GUI_CANCEL_REQUESTED)) && return 0
	[[ -n "$GUI_DIR" && -e "$GUI_DIR/cancelled" ]] && GUI_CANCEL_REQUESTED=1 && return 0
	local line
	while [[ -n "$GUI_RX_FD" ]] && read -r -t 0 -u "$GUI_RX_FD" 2>/dev/null; do
		gui_read_line line 1 || break
	done
	((GUI_CANCEL_REQUESTED)) && return 0
	if [[ -n "$GUI_APP_PID" ]] && ! kill -0 "$GUI_APP_PID" 2>/dev/null; then
		gui_lost
		return 0
	fi
	return 1
}

abort_if_cancelled() {
	if gui_check_cancel; then
		err "Execution cancelled by user from the window."
		exit 130
	fi
}

# Free-form input, in the window or the terminal: prompt_input <prompt> [default]
prompt_input() {
	local prompt="$1" default_value="${2:-}" value=""

	# --yes: take the default without prompting (consistent with confirm()).
	if ((ASSUME_YES)); then
		# stdout is the return value here (callers use $(...)), so log instead of info().
		log "[INFO]  Auto-yes: $prompt → ${default_value:-<empty>}"
		printf '%s' "$default_value"
		return 0
	fi

	if ((GUI_FULL_MODE)); then
		# No answer means the run was stopped: return nothing; the next step exits.
		gui_ask input "$default_value" "$prompt" value || value=""
		printf '%s' "$value"
		return 0
	fi
	read -r -p "$(printf '%s[??]%s  %s ' "$C_YEL" "$C_RST" "$prompt")" value || true

	printf '%s' "$value"
}
