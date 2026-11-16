# shellcheck shell=bash
# ============================================================================
#  SECTION 15 — WireGuard with kill switch
# ============================================================================
# sec_15_wireguard() - Install a WireGuard tunnel (--wireguard-config FILE) that
# cannot leak: a kill switch drops outbound traffic that does not go through the
# tunnel (also while the tunnel is down), and DNS is routed through the tunnel.
# Without a config file the section does nothing.
WG_IF="wg0"
sec_15_wireguard() {
	should_run 15 || return 0
	section 15 "WireGuard tunnel with kill switch and DNS leak protection"
	if [[ -z "$WG_CONFIG" ]]; then
		info "No WireGuard config given — nothing to do. To set up a tunnel that cannot leak, re-run with: --only 15 --wireguard-config /path/to/provider.conf"
		return 0
	fi

	local endpoint_ip endpoint_port has_dns ks_on=0
	_wg_check_config "$WG_CONFIG" || return 0
	endpoint_ip="$_WG_ENDPOINT_IP" endpoint_port="$_WG_ENDPOINT_PORT" has_dns="$_WG_HAS_DNS"

	pkg_install wireguard-tools
	if ((has_dns)); then
		# wg-quick hands DNS to systemd-resolved (resolvconf compatibility).
		pkg_install systemd-resolved
		run "systemctl enable --now systemd-resolved" || true
		if ((! DRY_RUN)) && ! systemctl is-active --quiet systemd-resolved 2>/dev/null; then
			warn "systemd-resolved is not running: wg-quick cannot apply the tunnel's DNS server and will not start the tunnel."
			add_action_item 15 HIGH "WG_NO_RESOLVED" \
				"systemd-resolved must run for the tunnel's DNS (journalctl -u systemd-resolved -b), then: sudo systemctl restart wg-quick@${WG_IF}"
		fi
	fi
	if ((! DRY_RUN)) && ! cmd_exists wg-quick; then
		warn "wg-quick is not available — WireGuard setup skipped."
		return 0
	fi

	local conf="/etc/wireguard/${WG_IF}.conf"
	backup_file "$conf" || return 0
	if ((DRY_RUN)); then
		info "Would install $WG_CONFIG as $conf (mode 600) with DNS routed through the tunnel"
	else
		install -d -m 700 /etc/wireguard
		# The provider's file, with the endpoint pinned to the address checked above
		# (the kill switch allows exactly that address) and DNS routed through the
		# tunnel: "~." makes the tunnel's DNS server answer every lookup.
		if ! awk -v ep="Endpoint = ${endpoint_ip}:${endpoint_port}" '
			/^[ \t]*Endpoint[ \t]*=/ { print ep; next }
			/^[ \t]*(PostUp|PreDown)[ \t]*=.*fedora-harden/ { next }
			{ print }' "$WG_CONFIG" 2>/dev/null >"$conf.new"; then
			warn "Could not prepare $conf"
			rm -f "$conf.new"
			return 0
		fi
		if ((has_dns)); then
			# Insert DNS routing right after [Interface].
			sed -i '0,/^[ \t]*\[Interface\]/s//[Interface]\nPostUp = resolvectl domain %i "~." \&\& resolvectl default-route %i yes  # fedora-harden: DNS through the tunnel/' "$conf.new"
		fi
		chmod 600 "$conf.new" && mv -f "$conf.new" "$conf"
		ok "Installed the tunnel config as $conf (mode 600, endpoint ${endpoint_ip}:${endpoint_port})."
	fi

	# Kill switch (firewalld policies, permanent): outbound traffic from this host may
	# only go into the tunnel (zone fedora-harden-vpn) or to the tunnel endpoint;
	# everything else is rejected — also while the tunnel is down, so nothing leaks.
	if ! cmd_exists firewall-cmd && ! cmd_exists firewall-offline-cmd; then
		warn "firewalld is not installed — the kill switch needs it (section 6). Tunnel installed without a kill switch."
		add_action_item 15 HIGH "WG_NO_KILLSWITCH" "Install firewalld (section 6), then re-run: sudo ./fedora-harden.sh --only 15 --wireguard-config $WG_CONFIG"
	else
		tool_dir_begin /etc/firewalld || return 0
		_wg_kill_switch "$endpoint_ip" "$endpoint_port" && ks_on=1
		tool_dir_end /etc/firewalld
	fi

	if run "systemctl enable --now wg-quick@${WG_IF}"; then
		record_change WG_TUNNEL "$WG_IF"
		ok "Tunnel ${WG_IF} is up and starts at boot."
	else
		warn "The tunnel did not come up — check: journalctl -u wg-quick@${WG_IF}"
		local why
		why="$(journalctl -u "wg-quick@${WG_IF}" -b --no-pager -o cat -n 3 2>/dev/null | tr '\n' ' ')"
		add_action_item 15 HIGH "WG_TUNNEL_DOWN" \
			"WireGuard tunnel ${WG_IF} did not start${why:+ ($why)}.$( ((ks_on)) && echo " The kill switch is active, so outbound traffic is blocked until it does.")"
	fi
	if ((ks_on)); then
		add_action_item 15 LOW "WG_KILLSWITCH_INFO" \
			"Kill switch active: without the tunnel this machine reaches only ${endpoint_ip}:${endpoint_port}. To allow your local network, add a rich rule to policy fedora-harden-killswitch; to remove everything: sudo ./fedora-harden.sh --rollback"
	fi
}

# _wg_check_config <file> - Validate a WireGuard config for a leak-proof tunnel.
# Sets _WG_ENDPOINT_IP, _WG_ENDPOINT_PORT, _WG_HAS_DNS. Returns 1 (with a reason)
# when the config cannot be used.
_wg_check_config() {
	local f="$1" key endpoint host port allowed
	_WG_ENDPOINT_IP="" _WG_ENDPOINT_PORT="" _WG_HAS_DNS=0
	for key in PrivateKey Address PublicKey Endpoint AllowedIPs; do
		if ! grep -qiE "^[[:space:]]*${key}[[:space:]]*=" "$f"; then
			warn "WireGuard config $f has no $key — not installed."
			add_action_item 15 MEDIUM "WG_CONFIG_INVALID" "The WireGuard config $f is incomplete (no $key). Download a complete config from your provider."
			return 1
		fi
	done
	allowed="$(grep -iE '^[[:space:]]*AllowedIPs[[:space:]]*=' "$f" | cut -d= -f2- | tr -d ' ')"
	if [[ ",$allowed," != *",0.0.0.0/0,"* ]]; then
		warn "WireGuard config routes only part of the traffic (AllowedIPs = $allowed) — a kill switch needs a full tunnel. Not installed."
		add_action_item 15 MEDIUM "WG_SPLIT_TUNNEL" \
			"$f is a split tunnel (AllowedIPs = $allowed). Use a full-tunnel config (AllowedIPs = 0.0.0.0/0, ::/0) for leak protection."
		return 1
	fi
	if [[ ",$allowed," != *",::/0,"* ]]; then
		# Not a leak: the kill switch rejects IPv6 outside the tunnel. But IPv6 stops working.
		warn "The WireGuard config carries IPv4 only (no ::/0): with the kill switch, IPv6 traffic is blocked."
		add_action_item 15 LOW "WG_NO_IPV6" \
			"$f routes only IPv4 through the tunnel (AllowedIPs has no ::/0), so the kill switch blocks IPv6. Use your provider's config with IPv6 (AllowedIPs = 0.0.0.0/0, ::/0) if you need it."
	fi
	if (($(grep -ciE '^[[:space:]]*\[Peer\]' "$f") != 1)); then
		warn "WireGuard config must have exactly one [Peer] — not installed."
		return 1
	fi
	endpoint="$(grep -iE '^[[:space:]]*Endpoint[[:space:]]*=' "$f" | head -1 | cut -d= -f2- | tr -d ' ')"
	port="${endpoint##*:}"
	host="${endpoint%:*}"
	host="${host#[}"
	host="${host%]}"
	if [[ ! "$port" =~ ^[0-9]+$ ]]; then
		warn "WireGuard endpoint '$endpoint' has no port — not installed."
		return 1
	fi
	if [[ ! "$host" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
		# A hostname would need DNS before the tunnel is up, which the kill switch
		# blocks: pin the address it resolves to now.
		local ip
		ip="$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR == 1 {print $1}')"
		if [[ -z "$ip" ]]; then
			warn "Cannot resolve the WireGuard endpoint $host — not installed."
			return 1
		fi
		info "Endpoint $host resolves to $ip; the tunnel and kill switch use that address."
		add_action_item 15 LOW "WG_ENDPOINT_PINNED" \
			"The WireGuard endpoint $host was pinned to $ip. If your provider changes that address, re-run section 15."
		host="$ip"
	fi
	grep -qiE '^[[:space:]]*DNS[[:space:]]*=' "$f" && _WG_HAS_DNS=1
	if ((! _WG_HAS_DNS)); then
		add_action_item 15 MEDIUM "WG_NO_DNS" \
			"The WireGuard config sets no DNS server, so DNS lookups do not go through the tunnel. Add your provider's DNS (DNS = ...) under [Interface] and re-run section 15."
	fi
	_WG_ENDPOINT_IP="$host" _WG_ENDPOINT_PORT="$port"
}

# _wg_kill_switch <endpoint-ip> <port> - firewalld policies: the host may send to the
# tunnel zone and to the endpoint; every other outbound packet is rejected.
_wg_kill_switch() {
	local ip="$1" port="$2" fw
	fw="$(fw_cmd)"
	local -a cmds=(
		"--permanent --new-zone=fedora-harden-vpn"
		"--permanent --zone=fedora-harden-vpn --add-interface=${WG_IF}"
		"--permanent --new-policy=fedora-harden-vpn-out"
		# firewall-cmd accepts one of these options per call (ingress/egress zone,
		# target/priority cannot be combined).
		"--permanent --policy=fedora-harden-vpn-out --add-ingress-zone=HOST"
		"--permanent --policy=fedora-harden-vpn-out --add-egress-zone=fedora-harden-vpn"
		"--permanent --policy=fedora-harden-vpn-out --set-target=ACCEPT"
		"--permanent --policy=fedora-harden-vpn-out --set-priority=-200"
		"--permanent --new-policy=fedora-harden-killswitch"
		"--permanent --policy=fedora-harden-killswitch --add-ingress-zone=HOST"
		"--permanent --policy=fedora-harden-killswitch --add-egress-zone=ANY"
		"--permanent --policy=fedora-harden-killswitch --set-target=REJECT"
		"--permanent --policy=fedora-harden-killswitch --set-priority=-100"
		"--permanent --policy=fedora-harden-killswitch --add-service=dhcp"
		"--permanent --policy=fedora-harden-killswitch --add-service=dhcpv6"
		"--permanent --policy=fedora-harden-killswitch --add-rich-rule='rule family=ipv4 destination address=${ip} port port=${port} protocol=udp accept'"
	)
	local c failed=0 info=""
	for c in "${cmds[@]}"; do
		# On a re-run the objects already exist; the check below judges the result.
		run "$fw $c >/dev/null 2>&1 || true"
	done
	((FW_OFFLINE)) || run "firewall-cmd --reload" || failed=1
	if ((! DRY_RUN)); then
		info="$($fw --permanent --info-policy=fedora-harden-killswitch 2>/dev/null || true)"
		[[ "$info" == *"target: REJECT"* && "$info" == *"egress-zones: ANY"* && "$info" == *"address=\"${ip}\""* ]] || failed=1
	fi
	if ((failed)); then
		warn "firewalld did not accept the kill switch — outbound traffic is NOT restricted."
		add_action_item 15 HIGH "WG_KILLSWITCH_FAILED" "The kill switch could not be loaded: check 'sudo firewall-cmd --list-all-policies' and journalctl -u firewalld."
		return 1
	fi
	ok "Kill switch on: outbound traffic goes through ${WG_IF} or to ${ip}:${port} only."
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
