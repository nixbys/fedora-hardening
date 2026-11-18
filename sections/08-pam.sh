# shellcheck shell=bash
# ============================================================================
#  SECTION 8 — Password & PAM policy
# ============================================================================
# Password quality (pwquality), lockout (faillock) and password aging.
sec_08_pam() {
	should_run 8 || return 0
	section 8 "Password quality + account lockout"

	# 8a pwquality, per NIST SP 800-63B: length matters, composition rules and forced
	# periodic changes do not (they lead to predictable passwords). Credits and
	# minclass are set to 0 so an older run's composition rules are lifted too.
	local pq="/etc/security/pwquality.conf" kv
	local -a pq_settings=(minlen=15 ucredit=0 lcredit=0 dcredit=0 ocredit=0 minclass=0
		dictcheck=1 usercheck=1 gecoscheck=1 retry=3 "badwords=admin root password")
	backup_file "$pq" || return 0
	for kv in "${pq_settings[@]}"; do
		set_conf_key "$pq" "${kv%%=*}" "${kv#*=}" || true
	done
	if ((! DRY_RUN)); then
		if grep -qE '^minlen = 15$' "$pq" && grep -qE '^minclass = 0$' "$pq"; then
			ok "Applied pwquality policy in $pq (at least 15 characters, no composition rules)"
		else
			warn "pwquality policy could not be fully applied to $pq"
			add_action_item 8 HIGH "PWQUALITY_NOT_APPLIED" "Set minlen = 15 and minclass = 0 in $pq"
		fi
	fi

	# 8b faillock
	local fl="/etc/security/faillock.conf"
	if [[ -f "$fl" ]]; then
		backup_file "$fl" || return 0
		set_conf_key "$fl" deny 5 || true
		set_conf_key "$fl" unlock_time 900 || true
		if ((! DRY_RUN)); then
			# even_deny_root is a bare flag; uncomment it or append it
			if ! grep -qE '^[[:space:]]*even_deny_root[[:space:]]*$' "$fl"; then
				if grep -qE '^[[:space:]]*#[[:space:]]*even_deny_root[[:space:]]*$' "$fl"; then
					sed -E -i 's|^[[:space:]]*#[[:space:]]*even_deny_root[[:space:]]*$|even_deny_root|' "$fl"
				else
					echo 'even_deny_root' >>"$fl"
				fi
			fi
			ok "Applied faillock policy in $fl (deny=5, unlock_time=900, even_deny_root)"
		fi
	else
		warn "$fl not found — faillock policy not applied."
	fi

	# No forced password expiry (NIST SP 800-63B): login.defs and account ageing are
	# left as Fedora ships them.
	_sudo_defaults
}

# _sudo_defaults - 8b: commands run with sudo get their own pseudo-terminal, so a
# program started that way can't push keystrokes back into your shell after sudo
# returns. Recent sudo does this by default; the drop-in makes sure of it. The file
# is checked with visudo before it is put in place, since a broken sudoers file
# locks everyone out of sudo.
_sudo_defaults() {
	local f=/etc/sudoers.d/fedora-harden tmp
	[[ -d /etc/sudoers.d ]] && cmd_exists visudo || return 0
	if ((DRY_RUN)); then
		info "Would write $f (Defaults use_pty)"
		return 0
	fi
	tmp="$(mktemp)"
	register_tmp "$tmp"
	printf '%s\n' "# Written by fedora-harden.sh (section 8b). Remove with --rollback." "Defaults use_pty" >"$tmp"
	if ! visudo -cqf "$tmp" >/dev/null 2>&1; then
		warn "The sudo drop-in did not pass visudo; leaving sudo unchanged."
		return 0
	fi
	backup_file "$f" || return 0
	install -m 0440 -o root -g root "$tmp" "$f" && ok "sudo runs commands in their own pseudo-terminal: $f"
	return 0
}
