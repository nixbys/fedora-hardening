# shellcheck shell=bash
# ============================================================================
#  SECTION 11 — DNS over TLS
# ============================================================================
# sec_11_dot() - Configure DNS over TLS (DoT) + NetworkManager MAC randomization
# Sets systemd-resolved to use Quad9 (Swiss non-profit, no IP logging) over TLS with
# DNSSEC where the network allows it, and stops announcing the host name on the local
# network (LLMNR off; mDNS off unless the routine's use cases include gaming or
# creative work, where casting and LAN discovery need it). Also writes a
# NetworkManager drop-in (11b): a random MAC for Wi-Fi scans and connections, a
# stable per-network random MAC for Ethernet (home DHCP reservations keep working),
# and time sync over NTS (11c).
# Alternative no-log DoT provider (not configured automatically but recommended by
# privacyguides.org): Mullvad DNS — 194.242.2.2 / dns.mullvad.net — operates under
# Sweden's strong privacy laws, enforces no-logging, and supports DoT + DoH.
sec_11_dot() {
	should_run 11 || return 0
	section 11 "DNS over TLS via systemd-resolved"
	# Fedora Workstation/Atomic ship systemd-resolved; Server/minimal installs may not.
	if ! systemctl list-unit-files systemd-resolved.service >/dev/null 2>&1; then
		pkg_install systemd-resolved
	fi
	local dropin_dir="/etc/systemd/resolved.conf.d"
	local dropin="${dropin_dir}/99-hardening.conf"
	# Back up the drop-in if it already exists (not the base file, which we don't touch)
	backup_file "$dropin" || return 0
	# Casting and LAN discovery (gaming, creative) need mDNS; otherwise stay quiet.
	local mdns="MulticastDNS=no"
	grep -qE '^USE_CASES=.*(gaming|creative)' /etc/fedora-harden/profile 2>/dev/null &&
		mdns="# MulticastDNS: default (kept for casting and LAN discovery)"
	if ((! DRY_RUN)); then
		install -d -m 755 "$dropin_dir" 2>/dev/null || true
		if ! cat 2>/dev/null >"$dropin" <<EOF
[Resolve]
DNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net 2620:fe::fe#dns.quad9.net 2620:fe::9#dns.quad9.net
FallbackDNS=149.112.112.112#dns.quad9.net
DNSOverTLS=yes
DNSSEC=allow-downgrade
LLMNR=no
$mdns
EOF
		then
			err "Failed to write DNS-over-TLS configuration"
			add_action_item 11 HIGH "DOT_WRITE_FAILED" "Could not write $dropin — check the filesystem, then re-run: sudo ./fedora-harden.sh --only 11"
			return 0
		fi
		ok "Wrote $dropin"
		info "DNS-over-TLS: Quad9 only (Swiss non-profit, no IP logging, malware blocking); LLMNR off"
		info "Alternative no-log options per privacyguides.org:"
		info "  • Mullvad DNS  — 194.242.2.2 / dns.mullvad.net  (Sweden, no-log, DoT+DoH)"
		info "  • AdGuard DNS  — 94.140.14.14 / dns.adguard-dns.com (anonymized, DoT+DoH+DoQ)"
	fi
	if ! systemctl list-unit-files systemd-resolved.service >/dev/null 2>&1 && ((! DRY_RUN)); then
		warn "systemd-resolved is not installed — DNS-over-TLS is NOT active."
		add_action_item 11 HIGH "RESOLVED_MISSING" \
			"Install and enable systemd-resolved for DNS-over-TLS: sudo dnf install -y systemd-resolved && sudo systemctl enable --now systemd-resolved"
	elif ! run "systemctl enable systemd-resolved && systemctl restart systemd-resolved"; then
		warn "systemd-resolved could not be (re)started — DNS-over-TLS settings apply when it next starts."
		add_action_item 11 MEDIUM "RESOLVED_RESTART_FAILED" "Restart systemd-resolved: sudo systemctl enable --now systemd-resolved"
	fi
	# DoT only protects lookups that go through resolved, i.e. when /etc/resolv.conf
	# points at its stub (the Fedora default). Report instead of re-plumbing DNS.
	local resolv_target
	resolv_target="$(readlink -f /etc/resolv.conf 2>/dev/null || true)"
	if [[ "$resolv_target" == /run/systemd/resolve/stub-resolv.conf || "$resolv_target" == /run/systemd/resolve/resolv.conf ]]; then
		ok "/etc/resolv.conf uses systemd-resolved — DNS-over-TLS applies to all lookups."
	elif ((! DRY_RUN)); then
		warn "/etc/resolv.conf does not point to systemd-resolved (${resolv_target:-missing}) — applications bypass DNS-over-TLS."
		add_action_item 11 HIGH "RESOLV_CONF_NOT_RESOLVED" \
			"Route DNS through systemd-resolved: sudo ln -sf ../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf && sudo systemctl restart NetworkManager"
	fi
	run "resolvectl status | head -25 || true"

	# 11b — NetworkManager MAC address randomization (privacyguides.org network privacy)
	info "Configuring NetworkManager MAC address randomization..."
	local nm_mac="/etc/NetworkManager/conf.d/99-mac-randomize.conf"
	if ((DRY_RUN)); then
		info "Would write $nm_mac (Wi-Fi and Ethernet MAC randomization)"
	else
		install -d -m 755 /etc/NetworkManager/conf.d 2>/dev/null || true
		backup_file "$nm_mac" || return 0
		if ! cat 2>/dev/null >"$nm_mac" <<'EOF'
[device]
wifi.scan-rand-mac-address=yes

[connection]
ethernet.cloned-mac-address=stable
wifi.cloned-mac-address=random
EOF
		then
			warn "Failed to write $nm_mac"
		else
			chmod 644 "$nm_mac" 2>/dev/null || true
			ok "Wrote $nm_mac (random MAC for Wi-Fi, stable per-network MAC for Ethernet)"
			run "systemctl restart NetworkManager || true"
		fi
	fi
	_nts_time
	_connectivity_check
}

# _nts_time - 11c: time sync over Network Time Security (authenticated, so time
# cannot be tampered with in transit), with chrony, Fedora's time service.
_nts_time() {
	local conf=/etc/chrony.conf dir=/etc/chrony.sources.d
	local src="$dir/fedora-harden-nts.sources"
	if ! cmd_exists chronyd || [[ ! -f "$conf" ]]; then
		info "chrony is not installed — leaving time sync as it is."
		return 0
	fi
	# chrony prefers authenticated (NTS) sources and keeps the pool only as a
	# cross-check (authselectmode mix, its default), so time still syncs where NTS
	# (TCP 4460) is blocked.
	if ! grep -qx "sourcedir $dir" "$conf"; then
		backup_file "$conf" || return 0
		if ((DRY_RUN)); then
			info "Would add 'sourcedir $dir' to $conf"
		else
			printf '\n# fedora-harden.sh (section 11c): NTS time sources\nsourcedir %s\n' "$dir" >>"$conf"
		fi
	fi
	((DRY_RUN)) || install -d -m 755 "$dir" 2>/dev/null
	write_new_file "$src" 0644 <<'NTS' || return 0
# Written by fedora-harden.sh (section 11c): authenticated time over NTS.
server time.cloudflare.com iburst nts
server nts.netnod.se iburst nts
server ptbtime1.ptb.de iburst nts
NTS
	run "systemctl try-restart chronyd" || true
	ok "Time sync prefers NTS (authenticated) servers: $src"
}

# _connectivity_check - NetworkManager checks connectivity by contacting a Fedora
# server on every network change. That detects captive portals, so turning it off
# is a choice (default: keep).
_connectivity_check() {
	local drop=/etc/NetworkManager/conf.d/99-fedora-harden-connectivity.conf
	[[ -d /etc/NetworkManager ]] || return 0
	if ! confirm "Turn off NetworkManager's connectivity check (it contacts a Fedora server on every network change; captive-portal detection stops)?" no; then
		info "Connectivity check kept (captive portals are detected)."
		return 0
	fi
	write_new_file "$drop" 0644 <<'NMC' || return 0
# Written by fedora-harden.sh (section 11): no connectivity probes.
[connectivity]
enabled=false
NMC
	run "systemctl reload NetworkManager || true"
	ok "Connectivity check off: $drop"
}
