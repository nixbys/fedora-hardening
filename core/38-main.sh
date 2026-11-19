# shellcheck shell=bash
# ---------- Main ------------------------------------------------------------
# Exit codes: 0 success, 1 preflight failed; anything else is an abort.
main() {
	parse_args "$@"
	# --score --json: everything except the JSON goes to stderr, so stdout parses.
	if ((SCORE_JSON)); then
		exec {SCORE_FD}>&1 1>&2
	fi
	[[ -n "$RESTORE_FILE" ]] && load_recovery_file "$RESTORE_FILE"

	# --list-sessions: show past sessions without running a full preflight
	if ((LIST_SESSIONS_MODE)); then
		((FORCE_GUI)) || draw_banner
		list_sessions_cmd
		EXPECTED_ABORT=1
		exit 0
	fi

	preflight
	if ((PRECHECK_FAILED)); then
		EXPECTED_ABORT=1
		exit 1
	fi

	# --rollback: undo a previous session (requires root and the platform detection from preflight)
	if [[ -n "$ROLLBACK_SESSION_ID" ]]; then
		SESSION_REPORT_FILE="" # Rollback produces its own report; skip session stub
		local rb_rc=0
		if [[ "$ROLLBACK_SESSION_ID" == "all" ]]; then
			rollback_all_sessions || rb_rc=$?
		else
			rollback_session "$ROLLBACK_SESSION_ID" || rb_rc=$?
		fi
		EXPECTED_ABORT=1
		exit "$rb_rc"
	fi

	# --score: read-only, no session, no report folders
	if ((SCORE_MODE)); then
		SESSION_REPORT_FILE=""
		show_protection_scorecard
		EXPECTED_ABORT=1
		exit 0
	fi

	init_user_report_dirs
	if ((REPORT_MODE)); then
		local rp_rc=0
		write_html_report "$REPORT_FILE" || rp_rc=$?
		EXPECTED_ABORT=1
		exit "$rp_rc"
	fi
	if ((RESUME_MODE)); then
		local rs_rc=0
		resume_followups || rs_rc=$?
		EXPECTED_ABORT=1
		exit "$rs_rc"
	fi
	calc_section_total
	abort_if_cancelled
	safety_point

	# The family's sections, in their order (the platform file).
	platform_run_sections

	diagnose_failures
	final_summary
	show_protection_scorecard
	write_recovery_file
	# Last to write (the platform file): integrity baselines include everything this
	# run wrote, the recovery file and any follow-ups applied included, so the first
	# checks start clean. Follow-ups are saved after them so a late item is kept.
	platform_after_run
	save_followups

	SESSION_STATUS="completed"
	ok "Script execution complete. See logs for full details."
	if [[ -n "$SESSION_REPORT_FILE" ]]; then
		ok "Session report: $SESSION_REPORT_FILE"
	fi
}
