# shellcheck shell=bash
# ============================================================================
#  SECTION 21 — Disable unnecessary services (interactive)
# ============================================================================
# sec_21_services() - Disable unnecessary services
# Disables avahi, cups, bluetooth, modemmanager and similar auto-start services.
sec_21_services() {
	should_run 21 || return 0
	section 21 "Disable unnecessary services (interactive)"
	local svc
	# Each entry: "service:default answer:description". Unencrypted remote shells are
	# switched off by default; services people use (printing, discovery, Bluetooth,
	# modems, network storage) only when asked — never silently under --yes.
	local candidates=(
		"avahi-daemon:no:mDNS/Bonjour (local network discovery)"
		"cups:no:Local/network printing daemon"
		"cups-browsed:no:Auto-discovery of network printers"
		"bluetooth:no:Bluetooth stack"
		"ModemManager:no:Mobile broadband / 4G modem manager"
		"iscsi:no:iSCSI initiator (network block storage)"
		"iscsid:no:iSCSI daemon"
		"nfs-server:no:NFS server (network file sharing)"
		"rpcbind:no:RPC portmapper (required by NFS)"
		"telnet.socket:yes:Telnet socket (unencrypted remote shell)"
		"rsh.socket:yes:RSH socket (unencrypted remote shell)"
		"rlogin.socket:yes:RLogin socket (unencrypted remote login)"
	)

	# On tiling/minimal WMs (Sway, Hyprland, i3), bluetooth is typically unwanted —
	# note it for the user but the interactive prompt already handles it.
	if ((HAS_SWAY || HAS_HYPRLAND || HAS_I3)); then
		info "Tiling WM detected: consider disabling bluetooth unless you use BT peripherals."
	fi
	local def desc
	for entry in "${candidates[@]}"; do
		svc="${entry%%:*}"
		def="${entry#*:}"
		desc="${def#*:}"
		def="${def%%:*}"
		if systemctl is-enabled --quiet "$svc" 2>/dev/null || systemctl is-active --quiet "$svc" 2>/dev/null; then
			if confirm "Disable $svc ($desc)?" "$def"; then
				run "systemctl disable --now $svc || true"
			fi
		fi
	done
	_sandbox_exposed_services
	info "Service security overview (higher = less sandboxed):"
	run "systemd-analyze security --no-pager | head -25 || true"
}
