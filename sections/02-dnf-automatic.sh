# shellcheck shell=bash
# ============================================================================
#  SECTION 2 — automatic security updates (dnf5-plugin-automatic, Fedora 41+)
# ============================================================================
# sec_02_dnf_automatic() - Configure automatic security updates + countme opt-out
# Sets up dnf5-plugin-automatic for mutable systems or rpm-ostreed policy for immutable
# systems to apply security patches automatically. On rpm-ostree, stages updates.
# Sub-section 2b disables the Fedora system-counting mechanism: sets countme=false
# in /etc/dnf/dnf.conf on mutable systems, or masks rpm-ostree-countme.timer on
# immutable ones — per privacyguides.org recommendation.
sec_02_dnf_automatic() {
	should_run 2 || return 0
	section 2 "Automatic security updates"

	# rpm-ostree (image-based) systems; Universal Blue keeps its own updater.
	if ((IS_OSTREE)); then
		_ostree_auto_updates
	else
		_dnf_auto_updates
	fi

	# 3b — DNF countme=false (privacyguides.org: opt out of Fedora system counting)
	# The Fedora Project uses a 'countme' variable to count unique systems accessing
	# its mirrors. privacyguides.org explicitly recommends opting out. On rpm-ostree
	# the equivalent is masking the rpm-ostree-countme timer.
	local dnf_conf="/etc/dnf/dnf.conf"
	if ((IS_OSTREE)); then
		if ((! DRY_RUN)); then
			# The mask is a symlink in /etc; journaled so --rollback unmasks it.
			backup_file /etc/systemd/system/rpm-ostree-countme.timer || return 0
			if systemctl mask rpm-ostree-countme.timer 2>/dev/null; then
				ok "Masked rpm-ostree-countme.timer (privacyguides.org: opt out of system counting)"
			else
				info "rpm-ostree-countme.timer not found or already masked — skipping."
			fi
		else
			info "Would mask rpm-ostree-countme.timer"
		fi
	elif [[ -f "$dnf_conf" ]]; then
		if ((! DRY_RUN)); then
			backup_file "$dnf_conf" || return 0
			if grep -qE '^\s*countme\s*=' "$dnf_conf" 2>/dev/null; then
				sed -i 's|^\s*countme\s*=.*|countme=false|' "$dnf_conf" 2>/dev/null || true
			else
				echo 'countme=false' >>"$dnf_conf" 2>/dev/null || true
			fi
			ok "Set countme=false in $dnf_conf (privacyguides.org: opt out of system counting)"
		else
			info "Would set countme=false in $dnf_conf"
		fi
	else
		info "$dnf_conf not found — skipping countme opt-out."
	fi
}

# _ostree_auto_updates() - Automatic updates on rpm-ostree systems (section 2).
# Universal Blue images (Bazzite, Bluefin, Aurora) update through uupd.timer and
# keep rpm-ostreed's own policy at "none"; enabling rpm-ostreed-automatic as well
# would run two updaters against the same deployments, so leave uupd in charge.
_ostree_auto_updates() {
	if [[ -r /usr/share/ublue-os/image-info.json ]] && systemctl list-unit-files uupd.timer >/dev/null 2>&1; then
		if systemctl is-enabled --quiet uupd.timer 2>/dev/null; then
			ok "Universal Blue image: automatic updates are handled by uupd.timer (system, Flatpaks, distroboxes)."
		elif ! run "systemctl enable --now uupd.timer"; then
			add_action_item 2 HIGH "AUTO_UPDATES_TIMER" "Enable automatic updates: sudo systemctl enable --now uupd.timer"
		fi
		info "Update by hand at any time with: ujust update"
		return 0
	fi
	local ro_conf="/etc/rpm-ostreed.conf"
	[[ ! -f "$ro_conf" ]] && {
		warn "$ro_conf not found; skipping config write."
		return 0
	}

	backup_file "$ro_conf" || return 0
	if ((! DRY_RUN)); then
		# Update existing policy or add new [Daemon] section (batch single sed pass)
		if grep -qE '^\s*AutomaticUpdatePolicy\s*=' "$ro_conf"; then
			sed -i -E 's|^\s*AutomaticUpdatePolicy\s*=.*|AutomaticUpdatePolicy=stage|' "$ro_conf" 2>/dev/null || true
		elif grep -qE '^\[Daemon\]' "$ro_conf"; then
			sed -i '/^\[Daemon\]/a AutomaticUpdatePolicy=stage' "$ro_conf" 2>/dev/null || true
		else
			printf '\n[Daemon]\nAutomaticUpdatePolicy=stage\n' >>"$ro_conf" 2>/dev/null || true
		fi
		ok "Configured rpm-ostreed automatic update staging in $ro_conf"
	else
		info "Would set AutomaticUpdatePolicy=stage in $ro_conf"
	fi

	# Enable timer if available
	if systemctl list-unit-files rpm-ostreed-automatic.timer >/dev/null 2>&1; then
		run "systemctl enable --now rpm-ostreed-automatic.timer" ||
			add_action_item 2 HIGH "AUTO_UPDATES_TIMER" "Enable automatic updates: sudo systemctl enable --now rpm-ostreed-automatic.timer"
	else
		warn "rpm-ostreed-automatic.timer not found; configure automatic updates manually."
	fi
}

# _dnf_auto_updates() - Automatic security updates on dnf systems (section 2).
_dnf_auto_updates() {
	# Handle mutable systems. Fedora 41+ uses dnf5, whose automatic-update plugin is
	# packaged as dnf5-plugin-automatic (timer: dnf5-automatic.timer). It ships
	# /etc/dnf/automatic.conf only as an empty %ghost and reads its defaults from
	# /usr/share/dnf5/dnf5-plugins/automatic.conf, so the override file must be seeded.
	local pkg timer conf="/etc/dnf/automatic.conf" conf_default=""
	if cmd_exists dnf5; then
		pkg="dnf5-plugin-automatic"
		timer="dnf5-automatic.timer"
		conf_default="/usr/share/dnf5/dnf5-plugins/automatic.conf"
	else
		pkg="dnf-automatic"
		timer="dnf-automatic.timer"
	fi

	pkg_install "$pkg"

	if ((DRY_RUN)); then
		[[ -s "$conf" ]] || info "Would seed $conf from ${conf_default:-a minimal [commands] block}"
		info "Would patch $conf: upgrade_type=security, apply_updates=yes, reboot=when-needed"
	else
		backup_file "$conf" || return 0
		if [[ ! -s "$conf" ]]; then
			if [[ -n "$conf_default" && -r "$conf_default" ]]; then
				install -m 0644 "$conf_default" "$conf" ||
					warn "Could not seed $conf from $conf_default"
			else
				printf '[commands]\nupgrade_type = default\napply_updates = no\nreboot = never\nreboot_command = ""\n' >"$conf" ||
					warn "Could not create $conf"
			fi
		fi
		# Batch sed patterns for single-pass efficiency
		batch_sed "$conf" \
			's|^\s*upgrade_type\s*=.*|upgrade_type = security|' \
			's|^\s*apply_updates\s*=.*|apply_updates = yes|' \
			's|^\s*reboot\s*=.*|reboot = when-needed|' \
			's|^\s*reboot_command\s*=.*|reboot_command = "shutdown -r +5 '\''Rebooting for security updates'\''"|' || true
		if grep -qE '^\s*upgrade_type\s*=\s*security' "$conf" 2>/dev/null &&
			grep -qE '^\s*apply_updates\s*=\s*yes' "$conf" 2>/dev/null; then
			ok "Patched $conf (upgrade_type=security, apply_updates=yes, reboot=when-needed)"
		else
			warn "$conf could not be patched for automatic security updates."
			add_action_item 2 HIGH "AUTO_UPDATES_CONFIG" \
				"Set upgrade_type = security and apply_updates = yes under [commands] in $conf"
		fi
	fi

	if ! run "systemctl enable --now $timer"; then
		warn "Could not enable $timer"
		add_action_item 2 HIGH "AUTO_UPDATES_TIMER" "Enable automatic updates: sudo systemctl enable --now $timer"
	fi
}
