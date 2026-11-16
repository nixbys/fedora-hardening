# shellcheck shell=bash
# ============================================================================
#  SECTION 24 — AIDE file integrity
# ============================================================================
# sec_24_ids() - File integrity baseline with AIDE, checked weekly by a timer.
# Runs last, so the baseline includes every change this run made. The baseline is
# recorded in the background (a transient systemd unit): it takes minutes, and the
# run does not need to wait for it. rkhunter is not used: its heuristics give false
# alarms on Fedora after updates, and AIDE already covers file integrity.
sec_24_ids() {
	should_run 24 || return 0
	if ((IS_OSTREE)); then
		_ostree_integrity
		return 0
	fi
	section 24 "AIDE file integrity"

	pkg_install aide
	if ! cmd_exists aide; then
		if ((DRY_RUN)); then
			info "aide is not installed yet — a real run installs it and records the baseline."
		else
			warn "aide is unavailable after the install attempt — no file integrity baseline."
			add_action_item 24 MEDIUM "AIDE_INSTALL_FAILED" "Install AIDE manually: sudo dnf install -y aide"
		fi
		return 0
	fi

	# Weekly check as a systemd timer (journald keeps the result; catches up after the
	# machine was off). Replaces the cron job of earlier versions.
	write_new_file /etc/systemd/system/fedora-harden-aide-check.service 0644 <<'UNIT' || return 0
[Unit]
Description=AIDE file integrity check (fedora-harden)
ConditionPathExists=/var/lib/aide/aide.db.gz

[Service]
Type=oneshot
Nice=19
IOSchedulingClass=idle
ExecStart=/usr/sbin/aide --check
UNIT
	write_new_file /etc/systemd/system/fedora-harden-aide-check.timer 0644 <<'UNIT' || return 0
[Unit]
Description=Weekly AIDE file integrity check (fedora-harden)

[Timer]
OnCalendar=weekly
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
UNIT
	enable_timer fedora-harden-aide-check.timer || true
	if [[ -e /etc/cron.weekly/aide-check ]]; then
		backup_file /etc/cron.weekly/aide-check && run "rm -f /etc/cron.weekly/aide-check"
	fi

	# The baseline itself is recorded at the very end of the run (start_aide_baseline),
	# after everything else has written its files.
	AIDE_BASELINE_PENDING=1
	add_action_item 24 LOW "AIDE_RECHECK" \
		"After package updates, record a new AIDE baseline: sudo sh -c 'aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz'"
}

# start_aide_baseline() - Record the AIDE baseline last, in the background, so it
# includes every file this run wrote (the recovery file included).
start_aide_baseline() {
	((AIDE_BASELINE_PENDING)) || return 0
	# The database is moved into place only when init succeeds.
	local init='aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz'
	if ((DRY_RUN)); then
		info "Would record the AIDE baseline in the background: $init"
	elif [[ -d /run/systemd/system ]] && cmd_exists systemd-run &&
		run "systemd-run --quiet --collect --unit=fedora-harden-aide-init --nice=19 -p IOSchedulingClass=idle /bin/sh -c '$init'"; then
		ok "AIDE baseline is being recorded in the background (systemctl status fedora-harden-aide-init)."
	elif run "$init"; then
		ok "AIDE baseline recorded: /var/lib/aide/aide.db.gz"
	else
		warn "aide --init failed."
		add_action_item 24 MEDIUM "AIDE_INIT_FAILED" "AIDE baseline failed — run: sudo sh -c '$init'"
	fi
}
