# shellcheck shell=bash
# ============================================================================
#  SECTION 10 — auditd
# ============================================================================
# sec_10_auditd() - Configure auditd audit rules
# Tracks identity changes, privilege escalation, kernel module loading, time
# changes, network configuration edits, filesystem mounts, and file deletions
# per inteltechniques.com recommendations. Covers NIST/CIS baseline events.
sec_10_auditd() {
	should_run 10 || return 0
	section 10 "auditd rules"
	pkg_install audit audit-libs
	# Without the audit tools there is nothing to load the rules into; say so plainly
	# instead of failing later with a misleading "check the rules" message.
	if ((! DRY_RUN)) && ! cmd_exists augenrules; then
		warn "The audit package is not installed (and could not be installed) — skipping audit rules."
		add_action_item 10 HIGH "AUDIT_NOT_INSTALLED" \
			"Install the audit tools, then re-run section 10: sudo dnf install audit && sudo ./fedora-harden.sh --only 10"
		return 0
	fi
	if ! run "systemctl enable --now auditd"; then
		warn "auditd could not be started (kernel booted with audit=0, or running in a container?)."
		add_action_item 10 HIGH "AUDITD_NOT_RUNNING" \
			"auditd is not running — check 'journalctl -u auditd' and that the kernel was not booted with audit=0, then: sudo systemctl enable --now auditd"
	fi

	local rules="/etc/audit/rules.d/hardening.rules"
	if ((DRY_RUN)); then
		info "Would write $rules"
	else
		backup_file "$rules" || return 0
		if ! cat 2>/dev/null >"$rules" <<'EOF'
-D
-b 8192
-f 1

# Identity / credential files
-w /etc/passwd    -p wa -k identity
-w /etc/group     -p wa -k identity
-w /etc/shadow    -p wa -k identity
-w /etc/sudoers   -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Login history
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# Privilege escalation
-w /usr/bin/sudo -p x -k sudo_usage
-w /usr/bin/su   -p x -k su_usage

# Daemon config
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/selinux/        -p wa -k selinux

# Scheduled tasks
-w /etc/cron.d/    -p wa -k cron
-w /etc/crontab    -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Kernel modules
-w /sbin/insmod   -p x -k modules
-w /sbin/rmmod    -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -k modules

# setuid/setgid execves that land as root
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid

# System time changes (inteltechniques.com)
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time_change
-w /etc/localtime -p wa -k time_change

# Network configuration changes (inteltechniques.com)
-a always,exit -F arch=b64 -S sethostname,setdomainname -k network_config
-w /etc/hosts        -p wa -k network_config
-w /etc/network/     -p wa -k network_config
-w /etc/sysconfig/network -p wa -k network_config

# File system mounts (inteltechniques.com)
-a always,exit -F arch=b64 -S mount -k mounts

# Files deleted or renamed by users under /etc (inteltechniques.com). Limited to
# /etc: logging every delete everywhere floods the log during builds, browser
# cache churn and game updates for little value.
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F dir=/etc -F auid>=1000 -F auid!=4294967295 -k delete

# Uncomment to lock the ruleset at boot (requires reboot to change):
# -e 2
EOF
		then
			warn "Failed to write $rules (filesystem may be read-only)"
			add_action_item 10 HIGH "AUDIT_RULES_WRITE_FAILED" "Could not write $rules — check the filesystem, then re-run: sudo ./fedora-harden.sh --only 10"
			return 0
		fi
		chmod 640 "$rules" 2>/dev/null || true
		ok "Wrote $rules"
	fi
	local augen_rc=0
	# augenrules regenerates audit.rules (and audit.rules.prev) itself.
	tool_dir_begin /etc/audit || return 0
	run "augenrules --load" || augen_rc=$?
	tool_dir_end /etc/audit
	if ((augen_rc != 0)); then
		warn "augenrules --load failed (exit $augen_rc) — check $rules for syntax errors."
		warn "Audit rules written but not loaded. Re-run 'sudo augenrules --load' after fixing."
	fi
	# auditd sets RefuseManualStop=yes, so `systemctl restart auditd` is refused; the
	# packaged legacy action performs the supported restart (`service` is not installed
	# by default on Fedora 44).
	run "/usr/libexec/initscripts/legacy-actions/auditd/restart || service auditd restart" ||
		warn "auditd restart failed — rules load on next boot (see 'journalctl -u auditd')."
}
