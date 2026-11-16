# shellcheck shell=bash
# ============================================================================
#  SECTION 16 — ClamAV
# ============================================================================
# sec_16_clamav() - ClamAV with automatic signature updates and a weekly scan of
# /home (a timer, idle priority, no resident daemon). On-access scanning of /home
# (inteltechniques.com) is opt-in: it keeps clamd resident (about 1 GB of RAM) and
# delays file access, so it is asked for, never turned on by --yes.
sec_16_clamav() {
	should_run 16 || return 0
	if ((IS_OSTREE)); then
		_clamav_container
		return 0
	fi
	section 16 "ClamAV antivirus"
	pkg_install clamav clamd clamav-update clamav-scanner-systemd
	info "Updating ClamAV signatures (freshclam)..."
	# freshclam can fail if the daemon already holds the lock; suppress for idempotency
	run "timeout 900 freshclam || true"
	run "systemctl enable --now clamav-freshclam || true"
	# Configure clamd BEFORE starting it: Fedora ships /etc/clamd.d/scan.conf with
	# LocalSocket commented out, and clamd refuses to start without a socket
	# ("Please define server type").
	local clamd_conf="/etc/clamd.d/scan.conf" onaccess=0
	confirm "Scan files in /home as they are written (ClamAV on-access: about 1 GB of RAM, slower file access)?" no && onaccess=1
	if ((onaccess)) && [[ -f "$clamd_conf" ]]; then
		backup_file "$clamd_conf" || return 0
		local kv
		local -a clamd_settings=(
			"LocalSocket /run/clamd.scan/clamd.sock"
			# On-access scanning of home directories (inteltechniques.com); clamonacc
			# reads these. The clamd user is excluded to avoid scan loops.
			"OnAccessIncludePath /home"
			"OnAccessExcludeRootUID yes"
			"OnAccessExcludeUname clamscan"
			"OnAccessPrevention no"
			# Scan size limits — handle large archives/ISOs without
			# LibClamAV 'decompress file size exceeds limits' noise
			"MaxFileSize 500M"
			"MaxScanSize 2000M"
			"MaxRecursion 16"
			"StreamMaxLength 500M"
		)
		for kv in "${clamd_settings[@]}"; do
			set_conf_key "$clamd_conf" "${kv%% *}" "${kv#* }" " " || true
		done
		((DRY_RUN)) || ok "Configured clamd socket, on-access scanning (/home) and scan limits in $clamd_conf"
	elif ((onaccess)); then
		info "ClamAV clamd config not found at $clamd_conf — on-access config skipped."
		add_action_item 16 LOW "CLAMAV_ONACCESS_CONFIG" \
			"Manually configure on-access scanning: add 'OnAccessIncludePath /home' to your clamd config (/etc/clamd.d/scan.conf)"
	fi

	if ((onaccess)); then
		if ! run "systemctl enable --now clamd@scan"; then
			warn "clamd@scan failed to start — check: journalctl -u clamd@scan"
		fi
		# clamonacc performs the on-access scanning (fanotify; needs a running clamd@scan).
		if systemctl list-unit-files clamav-clamonacc.service >/dev/null 2>&1; then
			if ! run "systemctl enable --now clamav-clamonacc"; then
				warn "clamav-clamonacc failed to start — on-access scanning inactive (journalctl -u clamav-clamonacc)."
				add_action_item 16 MEDIUM "CLAMAV_ONACCESS_NOT_RUNNING" \
					"On-access scanning is configured but clamonacc is not running: sudo systemctl enable --now clamav-clamonacc"
			fi
		fi
	else
		_clamav_weekly_scan
	fi

	# Post-enable status check and report
	if ((! DRY_RUN)); then
		local freshclam_active=0 clamd_active=0
		if systemctl is-active --quiet clamav-freshclam 2>/dev/null; then
			freshclam_active=1
		fi
		if systemctl is-active --quiet clamd@scan 2>/dev/null || systemctl is-active --quiet clamd@scan.service 2>/dev/null; then
			clamd_active=1
		fi
		# Collect status output safely
		{
			printf '=== Section 16: ClamAV Report ===\n'
			printf 'Generated: %s\n\n' "$RUN_STAMP_HUMAN"
			printf -- '--- clamav-freshclam status ---\n'
			systemctl status clamav-freshclam --no-pager 2>&1 || true
			printf '\n--- clamd@scan status ---\n'
			systemctl status clamd@scan --no-pager 2>&1 || systemctl status clamd@scan.service --no-pager 2>&1 || true
			printf '\n--- ClamAV version / DB ---\n'
			clamscan --version 2>&1 || true
			freshclam --version 2>&1 || true
		} | write_user_report "section-21-clamav-${REPORT_DATE}.txt" || true
		((freshclam_active)) || add_action_item 16 MEDIUM "CLAMAV_FRESHCLAM_NOT_RUNNING" \
			"clamav-freshclam is not running — run: sudo systemctl start clamav-freshclam"
		((clamd_active || ! onaccess)) || add_action_item 16 MEDIUM "CLAMAV_CLAMD_NOT_RUNNING" \
			"clamd@scan is not running — run: sudo systemctl start clamd@scan"
		if cmd_exists clamscan; then
			add_action_item 16 MEDIUM "CLAMAV_INITIAL_SCAN" \
				"Run initial ClamAV home-directory scan (handled automatically in remediation step)."
		else
			add_action_item 16 HIGH "CLAMAV_NOT_INSTALLED" \
				"ClamAV could not be installed — install it, then re-run section 16: sudo dnf install clamav clamd clamav-update && sudo ./fedora-harden.sh --only 16"
		fi
		add_action_item 16 LOW "CLAMAV_REVIEW" \
			"Review ClamAV status: $USER_RESULTS_DIR/section-21-clamav-${REPORT_DATE}.txt"
	fi
}

# _clamav_container() - Section 16 on image-based systems: a weekly scan of /home in
# a throwaway container (Podman quadlet) instead of layering ClamAV into the image.
# The signatures ship in the image, refreshed before each scan (Pull=newer). The
# container sees /home read-only, has no network and a read-only root, and keeps a
# single capability: reading any file (DAC_READ_SEARCH). SELinux labelling is off
# for it because relabelling /home for a container would change every file's label.
_clamav_container() {
	section 16 "ClamAV scan (container, image-based system)"
	if ! cmd_exists podman; then
		warn "podman is not available — scheduled ClamAV container scan not set up."
		add_action_item 16 MEDIUM "CLAMAV_NO_PODMAN" "Install podman (it ships in Fedora Atomic images), then re-run section 16."
		return 0
	fi
	local home_dir quadlet="/etc/containers/systemd/fedora-harden-clamscan.container"
	home_dir="$(readlink -f /home 2>/dev/null || echo /home)"
	write_new_file "$quadlet" 0644 <<EOF || return 0
# Written by fedora-harden.sh (section 16): weekly ClamAV scan of $home_dir in a
# throwaway container. Results: journalctl -u fedora-harden-clamscan
[Unit]
Description=ClamAV scan of home directories in a container (fedora-harden)

[Container]
Image=$CLAMAV_IMAGE
Pull=newer
Entrypoint=clamscan
Exec=--recursive --infected /scan
Volume=$home_dir:/scan:ro
ReadOnly=true
Network=none
DropCapability=all
AddCapability=DAC_READ_SEARCH
NoNewPrivileges=true
SecurityLabelDisable=true

[Service]
Type=oneshot
TimeoutStartSec=6h
EOF
	write_new_file /etc/systemd/system/fedora-harden-clamscan.timer 0644 <<'EOF' || return 0
[Unit]
Description=Weekly ClamAV container scan (fedora-harden)

[Timer]
OnCalendar=weekly
Persistent=true
RandomizedDelaySec=2h

[Install]
WantedBy=timers.target
EOF
	# Check the quadlet before enabling: a typo would otherwise only show in the journal.
	if ((! DRY_RUN)) && [[ -x /usr/libexec/podman/quadlet ]] &&
		! QUADLET_UNIT_DIRS=/etc/containers/systemd /usr/libexec/podman/quadlet -dryrun >/dev/null 2>&1; then
		warn "Podman rejected $quadlet — run: /usr/libexec/podman/quadlet -dryrun"
		add_action_item 16 MEDIUM "CLAMAV_QUADLET_INVALID" "Podman rejected $quadlet — check: QUADLET_UNIT_DIRS=/etc/containers/systemd /usr/libexec/podman/quadlet -dryrun"
		return 0
	fi
	if enable_timer fedora-harden-clamscan.timer; then
		ok "Weekly ClamAV container scan scheduled (fedora-harden-clamscan.timer)."
	else
		warn "Could not enable fedora-harden-clamscan.timer."
	fi
	add_action_item 16 MEDIUM "CLAMAV_FIRST_SCAN" \
		"Run the first ClamAV scan (pulls $CLAMAV_IMAGE): sudo systemctl start fedora-harden-clamscan — results: journalctl -u fedora-harden-clamscan (the unit fails when a file is FOUND)."
	if rpm -q clamav >/dev/null 2>&1; then
		add_action_item 16 LOW "CLAMAV_LAYERED" \
			"ClamAV is layered into this image. Once the container scan works, the layer can go: rpm-ostree uninstall clamav clamd clamav-update (plus clamtk if installed), then reboot."
	fi
}

# _clamav_weekly_scan - Without on-access scanning: a weekly scan of /home by a timer,
# at idle priority, with clamscan (no resident daemon). Results: journalctl -u
# fedora-harden-clamscan.
_clamav_weekly_scan() {
	write_new_file /etc/systemd/system/fedora-harden-clamscan.service 0644 <<'UNIT' || return 0
[Unit]
Description=Weekly ClamAV scan of /home (fedora-harden)

[Service]
Type=oneshot
Nice=19
IOSchedulingClass=idle
ExecStart=/usr/bin/clamscan -r --infected --exclude-dir=/home/.snapshots /home
UNIT
	write_new_file /etc/systemd/system/fedora-harden-clamscan.timer 0644 <<'UNIT' || return 0
[Unit]
Description=Weekly ClamAV scan of /home (fedora-harden)

[Timer]
OnCalendar=weekly
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
UNIT
	if enable_timer fedora-harden-clamscan.timer; then
		ok "Weekly ClamAV scan of /home scheduled (fedora-harden-clamscan.timer); on-access scanning off."
	fi
}
