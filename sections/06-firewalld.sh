# shellcheck shell=bash
# ============================================================================
#  SECTION 6 — firewalld
# ============================================================================
# sec_06_firewalld() - Harden firewalld with drop-default policy
# Sets default policy to DROP, allows minimal services, enables logging
sec_06_firewalld() {
	should_run 6 || return 0
	section 6 "firewalld — drop-by-default with explicit allow-list"
	# firewalld filters inbound traffic. To see and block what apps send OUT,
	# inteltechniques.com (2026 OS Telemetry Guide) recommends the OpenSnitch
	# application firewall. It is not in Fedora's repositories, so it is only suggested.
	add_action_item 6 LOW "OUTBOUND_APP_FIREWALL" \
		"Optional: OpenSnitch shows and blocks outbound connections per application (inteltechniques.com). It is not packaged by Fedora; install it from https://github.com/evilsocket/opensnitch/releases only if you accept a third-party package."
	pkg_install firewalld
	run "systemctl enable --now firewalld" || warn "systemctl enable --now firewalld failed — checking daemon state."

	# Smart wait for firewalld readiness (max 10 seconds with exponential backoff).
	# Skipped in dry-run: the daemon was not actually started, so waiting is pointless.
	local attempt=0 max_attempts=10
	((DRY_RUN)) && max_attempts=0
	((max_attempts > 0)) && info "Waiting for firewalld to be ready..."
	while ((attempt < max_attempts)); do
		if firewall-cmd --state &>/dev/null; then
			ok "firewalld is ready"
			break
		fi
		((++attempt))
		sleep $((attempt / 3 + 1)) # Exponential backoff: 1s, 1s, 2s, 2s...
	done
	FW_OFFLINE=0
	if ((max_attempts > 0 && attempt >= max_attempts)); then
		add_action_item 6 HIGH "FIREWALLD_NOT_RUNNING" \
			"firewalld is installed but not running. Diagnose with 'journalctl -u firewalld', then run: sudo systemctl enable --now firewalld"
		if cmd_exists firewall-offline-cmd; then
			warn "firewalld is not running — writing permanent configuration with firewall-offline-cmd (applies when firewalld starts)."
			FW_OFFLINE=1
		else
			err "firewalld is not running and firewall-offline-cmd is unavailable — skipping firewall configuration."
			return 0
		fi
	fi

	# firewall-cmd rewrites firewalld.conf and zone files itself (see tool_dir_begin).
	tool_dir_begin /etc/firewalld || return 0
	_firewalld_configure
	tool_dir_end /etc/firewalld
}

# _firewalld_configure() - Section 6: default zone, allowed services, logging.
_firewalld_configure() {
	# Set default zone and configure services (batch permanent operations)
	info "Setting default zone to 'drop'..."
	if ! run "$(fw_cmd) --set-default-zone=drop"; then
		warn "Could not set the default firewalld zone to 'drop'."
		add_action_item 6 HIGH "FIREWALL_DEFAULT_ZONE" "Set the default zone manually: sudo firewall-cmd --set-default-zone=drop"
	fi

	local svc services_to_allow=()
	if confirm "Allow 'mdns' through the firewall?"; then
		services_to_allow+=("mdns")
	fi
	# kde-connect is KDE-specific and requires a custom service XML (not built-in to firewalld).
	# firewalld_ensure_service queries firewall-cmd --get-services internally, so no pre-caching needed.
	if ((HAS_KDE)); then
		if confirm "Allow 'kde-connect' through the firewall?"; then
			firewalld_ensure_service "kde-connect" "KDE Connect" \
				"1714-1764/tcp" "1714-1764/udp"
			services_to_allow+=("kde-connect")
		fi
	fi

	# Bazzite/gaming spins: offer Steam Remote Play and game streaming ports
	if ((IS_GAMING_SPIN)); then
		if confirm "Gaming spin detected (Bazzite). Allow Steam Remote Play + game-streaming ports?"; then
			firewalld_ensure_service "steam-remote-play" "Steam Remote Play" \
				"27031/tcp" "27036/tcp" "27031/udp" "27032/udp" "27033/udp" "27034/udp" "27035/udp" "27036/udp"
			services_to_allow+=("steam-remote-play")
			add_action_item 6 LOW "GAMING_FIREWALL_REVIEW" \
				"Bazzite/gaming spin: review firewall zone after game installs (Steam, Heroic, etc. may request additional ports)."
		else
			info "Skipping Steam Remote Play ports — add manually if needed."
		fi
	fi

	if systemctl is-enabled --quiet sshd 2>/dev/null; then
		info "sshd is enabled — allowing SSH in firewall."
		services_to_allow+=("ssh")
	elif confirm "Allow SSH through the firewall (you'll harden sshd in section 7)?"; then
		services_to_allow+=("ssh")
	fi

	# Add each service with soft-fail guard (INVALID_SERVICE → warn + action item, not abort).
	for svc in "${services_to_allow[@]}"; do
		firewalld_add_service drop "$svc" || true
	done

	run "$(fw_cmd) --set-log-denied=all" || warn "$(fw_cmd) --set-log-denied failed"
	if ((FW_OFFLINE)); then
		run "firewall-offline-cmd --zone=drop --list-all || true"
		warn "firewalld permanent configuration written offline — it is NOT active until firewalld starts."
		return 0
	fi
	if ! run "firewall-cmd --reload"; then
		err "firewall-cmd --reload failed; firewall rules may not be active"
		add_action_item 6 HIGH "FIREWALL_RELOAD_FAILED" "Manually reload firewall: sudo firewall-cmd --reload"
	fi
	run "firewall-cmd --list-all || true"
	ok "firewalld configured."
}
