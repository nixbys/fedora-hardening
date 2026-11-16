# shellcheck shell=bash
# ============================================================================
#  SECTION 23 — USBGuard
# ============================================================================
# sec_23_usbguard() - Install and configure USBGuard
# Configures device control policy; note: can lock out input devices if misconfigured.
sec_23_usbguard() {
	should_run 23 || return 0
	section 23 "USBGuard — ⚠ BE CAREFUL ⚠"
	if ((GUI_FULL_MODE)); then
		gui_alert warning "USBGuard can block unapproved USB devices, including keyboard/mouse.\n\nBefore continuing, connect all required USB devices and ensure you have an alternate recovery path."
	else
		cat <<'EOF'
USBGuard will block every USB device that isn't in its policy file,
including your keyboard and mouse if they are USB. The policy is generated
from currently connected devices, so BEFORE continuing:

  1. Plug in every USB device you use (keyboard, mouse, webcam, YubiKey...)
  2. Have a way to reach the machine without USB input if possible (serial,
     SSH from another host, PS/2 keyboard, etc.) in case the policy misfires.

You can later manage devices with:
  sudo usbguard list-devices
  sudo usbguard allow-device <ID> [--permanent]
EOF
	fi
	# Opt-in: a new keyboard or dock would be blocked, so --yes never turns it on.
	if ! confirm "Install and enable USBGuard with the current devices whitelisted?" no; then
		info "Skipped USBGuard."
		return 0
	fi

	pkg_install usbguard usbguard-tools
	if ((DRY_RUN)); then
		info "Would generate policy: usbguard generate-policy > /etc/usbguard/rules.conf"
	else
		umask 077
		local tmp_usbguard="/tmp/usbguard-rules-$$-$RANDOM-$SECONDS.conf"
		register_tmp "$tmp_usbguard"
		if ! usbguard generate-policy >"$tmp_usbguard" 2>/dev/null; then
			warn "usbguard generate-policy failed — daemon may not be running yet or no USB devices enumerable."
			rm -f "$tmp_usbguard" 2>/dev/null || true
			add_action_item 23 HIGH "USBGUARD_POLICY_MISSING" \
				"USBGuard policy not generated — reboot, plug in all USB devices, then run: sudo usbguard generate-policy > /etc/usbguard/rules.conf && sudo systemctl enable --now usbguard"
			return 0
		fi
		backup_file /etc/usbguard/rules.conf
		if ! install -m 0600 -o root -g root "$tmp_usbguard" /etc/usbguard/rules.conf 2>/dev/null; then
			warn "Failed to install USBGuard rules (filesystem may be read-only)"
			rm -f "$tmp_usbguard" 2>/dev/null || true
			add_action_item 23 HIGH "USBGUARD_INSTALL_FAILED" \
				"USBGuard rules could not be written — run: sudo install -m 0600 /tmp/usbguard-rules.conf /etc/usbguard/rules.conf"
			return 0
		fi
		rm -f "$tmp_usbguard" 2>/dev/null || true
		ok "Wrote /etc/usbguard/rules.conf (0600 root:root)"
	fi
	run "systemctl enable --now usbguard || true"

	if pkg_cached plasma-workspace; then
		if confirm "Install graphical USBGuard notifier (usbguard-notifier)?"; then
			pkg_install usbguard-notifier || true
		fi
	fi
}
