# shellcheck shell=bash
# ---------- Rollback journal helpers ----------------------------------------

# Append "TIMESTAMP|TYPE|DETAIL" to the rollback journal (types such as FILE_BACKUP,
# PKG_INSTALL, FLATPAK_INSTALL, SERVICE_ENABLE, SERVICE_DISABLE). No-op under
# --dry-run or before the journal exists. Usage: record_change <type> <detail>
record_change() {
	[[ -z "$ROLLBACK_JOURNAL" ]] && return 0
	((DRY_RUN)) && return 0
	local ts
	printf -v ts '%(%F %T)T' -1 2>/dev/null || ts="$(date '+%F %T')"
	printf '%s|%s|%s\n' "$ts" "$1" "$2" 2>/dev/null >>"$ROLLBACK_JOURNAL" || true
}

# BACKUP_DIR and the session's change journal (preflight, after the log).
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
	} 2>/dev/null >"$ROLLBACK_JOURNAL" || {
		ROLLBACK_JOURNAL=""
		return 1
	}
	chmod 600 "$ROLLBACK_JOURNAL" 2>/dev/null || true
}

# Root-only sessions directory and the session report stub; write_session_report
# replaces the stub on exit.
init_session_dir() {
	if ! install -d -m 700 "$SESSION_DIR" 2>/dev/null; then
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
		printf 'Log:       %s\n' "$LOG_WHERE"
		printf 'Backups:   %s\n' "$BACKUP_DIR"
		printf '\n(Script still running — full report written on exit)\n'
	} >"$SESSION_REPORT_FILE" 2>/dev/null || SESSION_REPORT_FILE=""
}

# Called from trap_cleanup on every exit; writes once (SESSION_REPORT_WRITTEN).
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
			((++change_count))
			case "$ctype" in
			FILE_BACKUP) ((++file_backups)) ;;
			PKG_INSTALL) ((++pkg_installs)) ;;
			SERVICE_ENABLE) ((++svc_enables)) ;;
			SERVICE_DISABLE) ((++svc_disables)) ;;
			FLATPAK_INSTALL) ((++flatpak_installs)) ;;
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
		printf 'Log:       %s\n' "$LOG_WHERE"
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
				((++idx))
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
			printf '  Errors: %s -p err\n\n' "$LOG_WHERE"
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
	chmod 600 "$SESSION_REPORT_FILE" 2>/dev/null || true
	log "[SESSION] Session report written: $SESSION_REPORT_FILE"
}
