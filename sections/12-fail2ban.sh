# shellcheck shell=bash
# ============================================================================
#  SECTION 12 — Fail2Ban
# ============================================================================
# sec_12_fail2ban() - Install and configure Fail2Ban IDS
# Installs Fail2Ban for intrusion detection and auto-banning of brute-force attempts.
sec_12_fail2ban() {
	should_run 12 || return 0
	section 12 "Fail2Ban"
	# Fail2Ban slows password guessing against a reachable SSH server; with sshd off
	# it would only be one more daemon.
	if ! systemctl is-enabled --quiet sshd 2>/dev/null && ! systemctl is-active --quiet sshd 2>/dev/null; then
		info "sshd is not enabled — Fail2Ban not needed (section 12 skipped)."
		return 0
	fi
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
			add_action_item 12 HIGH "FAIL2BAN_DIR_CREATE_FAILED" \
				"Failed to create $fb_dir. Fix filesystem permissions and re-run section 12."
			return 0
		fi

		if [[ ! -f "$jl" ]]; then
			backup_file "$jl" || return 0
			if ! cat 2>/dev/null >"$jl" <<'EOF'
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
			then
				warn "Could not write $jl; skipping Fail2Ban activation for now."
				add_action_item 12 HIGH "FAIL2BAN_JAIL_WRITE_FAILED" \
					"Failed to write $jl. Fix filesystem/permissions and re-run section 12."
				return 0
			fi
			ok "Wrote $jl"
		else
			info "$jl already exists — leaving unchanged."
		fi

		# rpm-ostree hosts may have fail2ban staged but not active until reboot.
		if ((IS_OSTREE)) && ! systemctl list-unit-files 2>/dev/null | grep -q '^fail2ban\.service'; then
			warn "fail2ban is staged but not active yet on rpm-ostree. Reboot required before enabling service."
			add_action_item 12 HIGH "FAIL2BAN_PENDING_REBOOT" \
				"Reboot to activate staged fail2ban packages, then re-run section 12."
			return 0
		fi

		if ! run "systemctl enable --now fail2ban"; then
			warn "Unable to enable/start fail2ban right now."
			add_action_item 12 MEDIUM "FAIL2BAN_ENABLE_FAILED" \
				"Run: sudo systemctl enable --now fail2ban (after reboot on rpm-ostree hosts)."
			return 0
		fi
	fi

	# Post-enable status check and report
	if ((! DRY_RUN)); then
		local f2b_active=0 f2b_status=""
		systemctl is-active --quiet fail2ban 2>/dev/null && f2b_active=1 || true
		if ((f2b_active)); then
			f2b_status="$(fail2ban-client status 2>&1 || true)"
			ok "fail2ban is active."
		else
			warn "fail2ban is not active after enable — see report."
			add_action_item 12 HIGH "FAIL2BAN_NOT_RUNNING" \
				"fail2ban service is not running — run: sudo systemctl restart fail2ban"
		fi
		{
			printf '=== Section 12: Fail2Ban Report ===\n'
			printf 'Generated: %s\n\n' "$RUN_STAMP_HUMAN"
			printf -- '--- Service status ---\n'
			systemctl status fail2ban --no-pager 2>&1 || true
			printf '\n--- Jail summary ---\n%s\n' "$f2b_status"
			printf '\n--- jail.local contents ---\n'
			[[ -f "$jl" ]] && cat "$jl" || printf '(not found)\n'
		} | write_user_report "section-18-fail2ban-${REPORT_DATE}.txt" || true
		if ((f2b_active)); then
			add_action_item 12 LOW "FAIL2BAN_REVIEW" \
				"Review fail2ban jail status and ban history: sudo fail2ban-client status sshd"
		fi
	fi
}
