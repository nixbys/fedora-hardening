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

# _ostree_integrity() - Section 24 on image-based systems. /usr comes from the image
# and is read-only, so AIDE would mostly re-check what the image
# already guarantees. What matters is that the booted image is signature-verified
# and what changed in /etc, the only mutable system configuration. Uses only tools
# already in the image (rpm-ostree, ostree); layers nothing.
_ostree_integrity() {
	section 24 "File integrity (image signature + /etc changes)"
	local booted
	booted="$(rpm-ostree status --booted 2>/dev/null | awk '$1 == "●" {print $2; exit}' || true)"
	case "$booted" in
	ostree-image-signed:*)
		ok "Booted image is signature-verified: ${booted#ostree-image-signed:}"
		;;
	ostree-remote-image:* | ostree-remote-registry:*)
		# Verified with the signature policy of the named OSTree remote.
		ok "Booted image is verified through its OSTree remote: ${booted#*:}"
		;;
	ostree-unverified-*)
		warn "Booted image is not signature-verified: $booted"
		add_action_item 24 HIGH "IMAGE_UNSIGNED" \
			"The booted image ($booted) is not signature-verified. Rebase to its ostree-image-signed: reference as documented by the image (rpm-ostree rebase ostree-image-signed:docker://...)."
		;;
	"")
		info "Could not read the booted deployment (rpm-ostree status)."
		;;
	*)
		info "Booted deployment: $booted (OSTree commit, verified by the remote's GPG configuration)."
		;;
	esac

	local checker="/usr/local/sbin/fedora-harden-etc-check"
	info "Tracking /etc changes: a weekly check logs files changed since this run (tag fedora-harden-etc)."
	write_new_file "$checker" 0755 <<'EOF' || return 0
#!/bin/sh
# Written by fedora-harden.sh (section 24): report /etc files changed since the
# baseline recorded at the end of the hardening run. Exits 1 when there are
# changes, so the unit shows as failed (systemctl --failed) until reviewed.
# Accept the current state as the new baseline:
#   sudo sh -c 'ostree admin config-diff | sort > /var/lib/fedora-harden/etc-baseline.txt'
baseline=/var/lib/fedora-harden/etc-baseline.txt
[ -r "$baseline" ] || { echo "No baseline at $baseline"; exit 0; }
new=$(ostree admin config-diff 2>/dev/null | sort | comm -13 "$baseline" -)
if [ -n "$new" ]; then
	printf '%s\n' "$new" | logger -t fedora-harden-etc -p auth.warning
	printf 'Changed in /etc since the baseline:\n%s\n' "$new"
	exit 1
fi
echo "No /etc changes since the baseline."
EOF
	write_new_file /etc/systemd/system/fedora-harden-etc-check.service 0644 <<EOF || return 0
[Unit]
Description=Report /etc changes since the fedora-harden baseline

[Service]
Type=oneshot
ExecStart=$checker
EOF
	write_new_file /etc/systemd/system/fedora-harden-etc-check.timer 0644 <<'EOF' || return 0
[Unit]
Description=Weekly report of /etc changes (fedora-harden)

[Timer]
OnCalendar=weekly
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
EOF
	enable_timer fedora-harden-etc-check.timer ||
		warn "Could not enable fedora-harden-etc-check.timer (journalctl -u fedora-harden-etc-check)."
	ETC_BASELINE_PENDING=1
	add_action_item 24 LOW "ETC_CHANGE_TRACKING" \
		"Weekly /etc change report: journalctl -t fedora-harden-etc. After intended changes, accept them: sudo sh -c 'ostree admin config-diff | sort > /var/lib/fedora-harden/etc-baseline.txt'"
}

# record_etc_baseline() - Record the /etc baseline once every section has run, so
# the weekly check reports only changes made after hardening.
record_etc_baseline() {
	((ETC_BASELINE_PENDING)) || return 0
	local baseline="/var/lib/fedora-harden/etc-baseline.txt"
	if ((DRY_RUN)); then
		info "Would record the /etc baseline in $baseline"
		return 0
	fi
	if [[ -s "$baseline" ]]; then
		info "Keeping the existing /etc baseline ($baseline)."
		return 0
	fi
	install -d -m 700 /var/lib/fedora-harden 2>/dev/null || true
	backup_file "$baseline" || return 0
	if ostree admin config-diff 2>/dev/null | sort >"$baseline"; then
		chmod 600 "$baseline" 2>/dev/null || true
		ok "Recorded the /etc baseline ($(wc -l <"$baseline") changed files relative to the image)."
	else
		warn "Could not record the /etc baseline (ostree admin config-diff failed)."
	fi
}
