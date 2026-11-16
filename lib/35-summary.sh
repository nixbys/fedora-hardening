# shellcheck shell=bash
# ---------- Summary ---------------------------------------------------------
# save_followups() - Keep this run's open follow-ups with its backups, so --resume
# and --report can show them later.
save_followups() {
	((DRY_RUN)) && return 0
	[[ -d "$BACKUP_DIR" ]] || return 0
	# The file also marks a completed hardening run (report and rollback runs have none).
	if ((${#ACTIONABLE_ITEMS[@]})); then
		printf '%s\n' "${ACTIONABLE_ITEMS[@]}" 2>/dev/null >"$BACKUP_DIR/.followups" || return 0
	else
		: 2>/dev/null >"$BACKUP_DIR/.followups" || return 0
	fi
	chmod 600 "$BACKUP_DIR/.followups" 2>/dev/null || true
}

# last_session_dir() - Backup folder of the most recent earlier hardening run (the
# ones with a .followups file; --report, --resume and --rollback runs do not count).
last_session_dir() {
	local d latest=""
	for d in /root/harden-backups-*/; do
		[[ -f "${d}.followups" ]] || continue
		[[ "$d" == "/root/harden-backups-${RUN_STAMP}/" ]] && continue
		[[ -z "$latest" || "$d" > "$latest" ]] && latest="$d"
	done
	[[ -n "$latest" ]] || return 1
	echo "${latest%/}"
}

# resume_followups() - Show the last session's open follow-ups and offer the fixes
# again; what stays open is saved back to that session.
resume_followups() {
	local dir
	if ! dir="$(last_session_dir)" || [[ ! -s "$dir/.followups" ]]; then
		info "No open follow-ups from an earlier run."
		return 0
	fi
	mapfile -t ACTIONABLE_ITEMS < <(grep -v '^$' "$dir/.followups")
	info "Open follow-ups from session ${dir##*/harden-backups-}:"
	handle_actionable_follow_up ""
	if ((! DRY_RUN)); then
		if ((${#ACTIONABLE_ITEMS[@]})); then
			printf '%s\n' "${ACTIONABLE_ITEMS[@]}" 2>/dev/null >"$dir/.followups" || true
		else
			: 2>/dev/null >"$dir/.followups" || true
		fi
	fi
}

# _html() - Escape text for HTML.
_html() {
	local t="${1//&/&amp;}"
	t="${t//</&lt;}"
	printf '%s' "${t//>/&gt;}"
}

# report_redact - Filter stdin for a report meant to be shared: the host name, local
# user names, home paths, IPv4/IPv6 and MAC addresses become placeholders.
report_redact() {
	local -a expr=() u
	local esc
	# Home paths first (they contain the user name), then names, then addresses.
	expr+=(-e 's#/(var/)?home/[^/[:space:]<"]+#/home/\&lt;user\&gt;#g')
	while IFS=: read -r u _ uid _ _ home _; do
		((uid >= 1000 && uid < 60000)) || [[ "$u" == "${SUDO_USER:-}" || "$u" == "${TARGET_USER:-}" ]] || continue
		((${#u} >= 3)) || continue
		esc="$(printf '%s' "$u" | sed 's/[][\.*^$/+?(){}|]/\\&/g')"
		expr+=(-e "s/\\b${esc}\\b/\\&lt;user\\&gt;/g")
	done </etc/passwd
	if [[ -n "$HOST_LABEL" && "$HOST_LABEL" != unknown ]]; then
		esc="$(printf '%s' "$HOST_LABEL" | sed 's/[][\.*^$/+?(){}|]/\\&/g')"
		expr+=(-e "s/\\b${esc}\\b/\\&lt;host\\&gt;/g")
	fi
	expr+=(-e 's/\b([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?\b/\&lt;address\&gt;/g'
		-e 's/\b([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b/\&lt;address\&gt;/g'
		-e 's/(\b[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4})*)?::[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4})*\b/\&lt;address\&gt;/g'
		-e 's/\b[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){7}\b/\&lt;address\&gt;/g')
	sed -E "${expr[@]}"
}

# write_html_report [file] - One self-contained page about the last session: what it
# changed, what is still open, the warnings it logged, and (when tests/verify-host.sh
# is next to the script) whether the hardening is in effect right now.
write_html_report() {
	local out="$1" dir session line
	if ! dir="$(last_session_dir)"; then
		err "No hardening session found to report on."
		return 1
	fi
	session="${dir##*/harden-backups-}"
	[[ -n "$out" ]] || out="${USER_PROJECT_DIR:-/root}/fedora-harden-report-${session}.html"
	if ((DRY_RUN)); then
		info "Would write the report for session $session to $out"
		return 0
	fi
	local verify="$SCRIPT_DIR/tests/verify-host.sh" raw
	raw="$(mktemp)" || return 1
	register_tmp "$raw"
	protection_scorecard
	{
		printf '<!doctype html><meta charset="utf-8"><title>fedora-harden report %s</title>\n' "$session"
		printf '<style>body{font:15px/1.5 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;color:#1d2320;background:#fbfbf9}h1,h2{font-weight:600}pre{background:#eef1ee;padding:.75rem;overflow-x:auto;white-space:pre-wrap}td{padding:.2rem .6rem;vertical-align:top;border-bottom:1px solid #dde2dd}</style>\n'
		printf '<h1>fedora-harden report</h1><p>Host <b>%s</b> · session <b>%s</b> · written %s</p>\n' \
			"$(_html "$HOST_LABEL")" "$session" "$(date '+%F %T')"
		printf '<h2>Changes</h2><table>\n'
		if [[ -f "$dir/.rollback-journal" ]]; then
			while IFS='|' read -r _ ctype detail; do
				[[ -z "$ctype" || "$ctype" == '#'* ]] && continue
				printf '<tr><td>%s</td><td>%s</td></tr>\n' "$(_html "$ctype")" "$(_html "$detail")"
			done < <(grep -v '^#' "$dir/.rollback-journal")
		fi
		printf '</table><p>Undo: <code>sudo %s --rollback %s</code></p>\n' "$SCRIPT_NAME" "$session"
		printf '<h2>Open follow-ups</h2><table>\n'
		if [[ -s "$dir/.followups" ]]; then
			while IFS='|' read -r sec prio _ desc; do
				printf '<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n' "$(_html "$prio")" "$(_html "$sec")" "$(_html "$desc")"
			done <"$dir/.followups"
		else
			printf '<tr><td>None.</td></tr>\n'
		fi
		printf '</table>\n'
		_report_recovery
		printf '<h2>Warnings and errors logged</h2><pre>\n'
		if ((LOG_JOURNAL)); then
			journalctl -t fedora-harden "FH_SESSION=$session" -p warning -o short-iso --no-pager 2>/dev/null |
				while IFS= read -r line; do
					_html "$line"
					printf '\n'
				done
		elif [[ -f "$LOG_DIR/harden-${session}.log" ]]; then
			grep -E '\[(WARN|ERROR)\]' "$LOG_DIR/harden-${session}.log" | while IFS= read -r line; do
				_html "$line"
				printf '\n'
			done
		fi
		printf '</pre>\n<h2>Protection now</h2><table>\n'
		local row state label detail fix
		for row in "${SCORE_ROWS[@]}"; do
			IFS='|' read -r state label detail fix <<<"$row"
			case "$state" in ok) state="Protected" ;; no) state="Not protected" ;; info) state="Advice" ;; *) state="Not applicable" ;; esac
			printf '<tr><td>%s</td><td>%s</td><td>%s%s</td></tr>\n' "$(_html "$state")" "$(_html "$label")" \
				"$(_html "$detail")" "${fix:+<br>Fix: $(_html "$fix")}"
		done
		printf '</table>\n<h2>In effect now</h2>\n'
		if [[ -x "$verify" ]]; then
			printf '<pre>\n'
			"$verify" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | while IFS= read -r line; do
				_html "$line"
				printf '\n'
			done
			printf '</pre>\n'
		else
			printf '<p>Live checks need tests/verify-host.sh next to the script.</p>\n'
		fi
		((REPORT_FULL)) || printf '<p><small>Host name, user names, home paths and addresses are replaced with placeholders; <code>--report --full</code> keeps them.</small></p>\n'
	} 2>/dev/null >"$raw"
	if ((REPORT_FULL)); then
		cat "$raw" 2>/dev/null >"$out"
	else
		report_redact <"$raw" 2>/dev/null >"$out"
	fi || {
		err "Could not write $out"
		return 1
	}
	local user="${TARGET_USER:-${SUDO_USER:-}}"
	[[ -n "$user" && "$user" != root ]] && chown "$user:" "$out" 2>/dev/null
	chmod 640 "$out" 2>/dev/null || true
	ok "Report: $out"
}

# final_summary() - Analyze section 12/16/17/18/24 findings, write all reports to
# user Downloads/<project>/results and Downloads/<project>/logs, display actionable list, and ask
# whether to implement recommended next steps. If declined, they are kept for --resume
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
			printf 'Log:          %s\n' "$LOG_WHERE"
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
					((++idx))
				done
			else
				printf '  None — sections 12/16/17/18/24 appear clean.\n'
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
			printf '  • GRUB password (section 3b) — run: sudo grub2-mkpasswd-pbkdf2\n'
			printf '  • SSH keys                   — generate on CLIENT, then: ssh-copy-id user@host\n'
			printf '  • VPN                        — if not detected in section 14b: install Mullvad, ProtonVPN, or IVPN.\n'
			printf '  • WireGuard tunnel           — re-run with --only 15 --wireguard-config <provider.conf>.\n'
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
	if ((! GUI_FULL_MODE)); then
		printf '\n%s════════════════════════ Summary ════════════════════════%s\n' "$C_GRN" "$C_RST"
		local reports_line="" ostree_line=""
		[[ -n "$USER_RESULTS_DIR" ]] && reports_line=" Reports:      $USER_RESULTS_DIR"
		((IS_OSTREE)) && ostree_line=$'\n On rpm-ostree systems, reboot is also required to apply layered package changes and staged updates.'
		cat <<EOF
    Log:          $LOG_WHERE
    Backups:      $BACKUP_DIR  (empty if no changes needed)
    Target user:  ${TARGET_USER:-<none>}
    Platform:     ${_plat}
    $reports_line
    Manual follow-up items (from the guide, NOT automated by this script):
       • LUKS full-disk encryption — set during Fedora installation only.
       • GRUB password (§3b) — run 'sudo grub2-mkpasswd-pbkdf2' manually.
       • SSH keys — generate on your CLIENT machine and ssh-copy-id to this host.
       • VPN — if not detected in §14b: install Mullvad, ProtonVPN, or IVPN.
       • WireGuard tunnel — re-run with: --only 15 --wireguard-config <provider.conf> (kill switch included).
       • Review arkenfox defaults and add local exceptions in user-overrides.js as needed.
       • KDE GUI-only settings: KWallet master password, Privacy, Activity tracking.
       • Re-initialize AIDE database after any legitimate package upgrade.

    A REBOOT is recommended to pick up kernel, GRUB, sysctl, and PAM changes.$ostree_line
EOF
		printf '%s═════════════════════════════════════════════════════════%s\n' "$C_GRN" "$C_RST"
	else
		log "Summary: log=$LOG_WHERE backups=$BACKUP_DIR target_user=${TARGET_USER:-<none>}"
		log "Summary: reboot recommended for kernel/GRUB/sysctl/PAM changes"
		((IS_OSTREE)) && log "Summary: reboot required on rpm-ostree for staged/layered changes"
	fi

	local gui_headline="Fedora hardening finished."
	((DRY_RUN)) && gui_headline="Dry run finished — no changes were made."
	local gui_items="${#ACTIONABLE_ITEMS[@]} item(s) need follow-up (listed below)."
	((${#ACTIONABLE_ITEMS[@]} == 0)) && gui_items="No follow-up items."
	gui_final_summary "$gui_headline" "${gui_items}\nA reboot is recommended.\n\nLog: $LOG_WHERE\nBackups: $BACKUP_DIR${USER_RESULTS_DIR:+\nReports: $USER_RESULTS_DIR}"

	# Display the actionable items from sections 12/16/17/18/24 and handle approval/selection.
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
