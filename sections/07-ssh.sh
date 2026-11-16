# shellcheck shell=bash
# ============================================================================
#  SECTION 7 — SSH hardening
# ============================================================================
# sec_07_ssh() - Configure SSH for key-based auth with hardened ciphers
# Disables password auth, enables key-based auth, applies strong cipher suite.
sec_07_ssh() {
	should_run 7 || return 0
	section 7 "SSH hardening"
	# No SSH server, nothing to harden: installing one would add a service to expose.
	if ! pkg_cached openssh-server; then
		info "No SSH server installed — nothing to harden (section 7 skipped)."
		return 0
	fi

	if ! confirm "You are about to harden sshd (disables passwords, root login, limits users). Continue?"; then

		info "Skipped SSH hardening."
		return 0
	fi

	# Validate TARGET_USER to prevent shell injection
	if [[ -n "$TARGET_USER" && ! "$TARGET_USER" =~ ^[a-zA-Z0-9._-]+$ ]]; then
		err "Invalid username: $TARGET_USER (must be alphanumeric, dots, dashes, underscores)"
		return 1
	fi

	# Verify the account that will be allowed to log in has a public key before
	# password authentication is disabled. With AllowUsers set, that is TARGET_USER;
	# otherwise fall back to root's keys (the invoking context).
	local key_home="${HOME:-/root}" key_owner="root"
	if [[ -n "$TARGET_USER" ]]; then
		key_home="$(user_home "$TARGET_USER")"
		key_owner="$TARGET_USER"
	fi
	local key_file="${key_home}/.ssh/authorized_keys"
	# Key types: ssh-ed25519/ssh-rsa/ssh-dss, ecdsa-sha2-*, sk-* (FIDO); optionally after options.
	if ! grep -qE '(^|[[:space:]])(ssh-(ed25519|rsa|dss)|ecdsa-sha2-[a-z0-9]+|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)[[:space:]]+AAAA' \
		"$key_file" 2>/dev/null; then
		warn "No public SSH key found in $key_file (user: $key_owner)."
		warn "Hardening disables password logins — without a key you would LOSE SSH access."
		add_action_item 7 HIGH "SSH_NO_PUBLIC_KEY" \
			"Install a public key for ${key_owner} in ${key_file} (ssh-copy-id from your client), then re-run: sudo ./fedora-harden.sh --only 7"
		if ((ASSUME_YES)); then
			# Never auto-accept a potential lockout in non-interactive mode.
			warn "Skipping SSH hardening in --yes mode until a key is installed."
			return 0
		fi
		if ! confirm "Continue without a verified public key? (Not recommended)"; then
			info "Skipped SSH hardening."
			return 0
		fi
	fi

	# sshd keeps the FIRST value it reads for each option, and Fedora ships
	# 40-redhat-crypto-policies.conf and 50-redhat.conf (X11Forwarding yes, system
	# crypto policy). The hardening drop-in must therefore sort before them.
	local drop="/etc/ssh/sshd_config.d/10-hardening.conf"
	local legacy_drop="/etc/ssh/sshd_config.d/99-hardening.conf"

	local allow_users_line=""
	[[ -n "$TARGET_USER" ]] && allow_users_line="AllowUsers $TARGET_USER"

	local desired
	desired="# Managed by fedora-harden.sh. Sorts before 40-redhat-*/50-redhat.conf so these
# values take precedence (sshd uses the first value it reads for each option).
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 1
X11Forwarding no
AllowAgentForwarding no
${allow_users_line}"

	if ((DRY_RUN)); then
		info "Would write hardened drop-in to $drop"
		[[ -f "$legacy_drop" ]] && info "Would remove legacy drop-in $legacy_drop (overridden by Fedora defaults)"
		run "/usr/sbin/sshd -t"
		run "systemctl restart sshd"
		return 0
	fi

	local changed=0
	install -d -m 755 /etc/ssh/sshd_config.d 2>/dev/null || true
	if [[ -f "$legacy_drop" ]] && grep -q 'fedora-harden' "$legacy_drop" 2>/dev/null; then
		backup_file "$legacy_drop" || return 0
		if rm -f "$legacy_drop"; then
			changed=1
			info "Removed legacy drop-in $legacy_drop (its settings were overridden by Fedora defaults)"
		fi
	fi
	if [[ -f "$drop" ]] && [[ "$(<"$drop")" == "$desired" ]]; then
		ok "$drop already up to date."
	else
		backup_file "$drop" || return 0
		if ! printf '%s\n' "$desired" >"$drop"; then
			warn "Failed to write $drop (filesystem may be read-only or full)"
			add_action_item 7 HIGH "SSHD_DROPIN_WRITE_FAILED" "Could not write $drop — check the filesystem, then re-run: sudo ./fedora-harden.sh --only 7"
			return 0
		fi
		chmod 644 "$drop" 2>/dev/null || true
		changed=1
		ok "Wrote $drop"
	fi

	# Never restart sshd on a configuration it rejects: that is how remote lockouts happen.
	local sshd_test
	if ! sshd_test="$(/usr/sbin/sshd -t 2>&1)"; then
		err "sshd rejected the configuration: ${sshd_test}"
		if ((changed)); then
			warn "Removing $drop so the sshd configuration stays valid."
			rm -f "$drop"
		fi
		add_action_item 7 HIGH "SSHD_CONFIG_INVALID" \
			"sshd -t failed after hardening (${sshd_test//$'\n'/ }). Fix the configuration, then: sudo sshd -t && sudo systemctl restart sshd"
		return 0
	fi
	ok "sshd -t: configuration valid."

	if ((! changed)); then
		info "sshd configuration unchanged — no restart needed."
	elif systemctl is-active --quiet sshd 2>/dev/null; then
		if ! run "systemctl restart sshd"; then
			err "sshd failed to restart — check: journalctl -u sshd"
			add_action_item 7 HIGH "SSHD_RESTART_FAILED" \
				"sshd failed to restart after hardening: sudo journalctl -u sshd; sudo systemctl restart sshd"
			return 0
		fi
	else
		info "sshd is not running — the new configuration applies when it starts."
	fi
	warn "IMPORTANT: Before closing this session, open a SECOND terminal and confirm"
	warn "you can still SSH in with your key. If not, you still have this session to fix it."
}
