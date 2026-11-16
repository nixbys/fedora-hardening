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
