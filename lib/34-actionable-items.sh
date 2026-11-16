# shellcheck shell=bash
# ---------- Actionable-items display + remediation --------------------------
# show_actionable_items() - Print the full prioritized actionable items list.
show_actionable_items() {
	if ((${#ACTIONABLE_ITEMS[@]} == 0)); then
		ok "No actionable items — sections 12/16/17/18/24 appear clean."
		return 0
	fi
	if ((! GUI_FULL_MODE)); then
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
			((++idx))
		done
		printf '%s════════════════════════════════════════════%s\n\n' "$C_YEL" "$C_RST"
	else
		gui_send_items
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
		cmd_exists clamscan || {
			warn "clamscan is not installed — skipping the initial scan."
			return 1
		}
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
			clamscan -r --infected "$scan_home" 2>&1 | tee "$scan_tmp" | log_stream || true
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
			add_action_item 16 HIGH "CLAMAV_INFECTED" \
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
	AIDE_RECHECK | FAIL2BAN_REVIEW | CLAMAV_REVIEW | SCAP_NO_SCAN | CLAMAV_INFECTED)
		info "Item [${tag}] requires manual review — see reports in: ${USER_RESULTS_DIR:-$LOG_WHERE}"
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
		((++round))
	done
	if ((${#ACTIONABLE_ITEMS[@]} > 0)); then
		warn "${#ACTIONABLE_ITEMS[@]} item(s) could not be auto-resolved and require manual action:"
		show_actionable_items
	fi
	if ((${#REMEDIATED_ITEMS[@]} > 0)); then
		ok "${#REMEDIATED_ITEMS[@]} item(s) were successfully remediated this session."
	fi
}
