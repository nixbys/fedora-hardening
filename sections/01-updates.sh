# shellcheck shell=bash
# ============================================================================
#  SECTION 1 — System updates
# ============================================================================
# Full system update (dnf, or rpm-ostree on image-based systems), firmware updates with
# fwupd (privacyguides.org) and current CPU microcode (Intel: microcode_ctl; AMD:
# linux-firmware) against Spectre/Meltdown-class flaws. Optionally installs hardware
# security key support (YubiKey/FIDO2/PIV: pcsc-lite, opensc, libfido2, yubico-piv-tool,
# yubikey-manager, pam-u2f) and reminds the user to have the key plugged in before
# section 23 (USBGuard) runs. Recommends a reboot afterwards.
sec_01_updates() {
	should_run 1 || return 0
	section 1 "System updates"
	pkg_upgrade
	ok "System packages updated. A reboot is recommended when the script finishes."

	# Install fwupd for firmware updates and check for available updates (privacyguides.org)
	if ! cmd_exists fwupdmgr; then
		pkg_install fwupd
		unset '_CMD_CACHE[fwupdmgr]' # Invalidate stale cache after install
	fi
	if cmd_exists fwupdmgr; then
		info "Refreshing fwupd metadata and checking for firmware updates..."
		run "timeout 300 fwupdmgr refresh --force || true"
		run "timeout 300 fwupdmgr get-updates || true"
		info "Apply firmware updates with: sudo fwupdmgr update"
	fi

	# Ensure CPU microcode is installed (privacyguides.org — patches Spectre/Meltdown/etc.)
	local cpu_vendor
	cpu_vendor="$(awk -F: '/^vendor_id/{print $2; exit}' /proc/cpuinfo 2>/dev/null | tr -d ' ')"
	case "${cpu_vendor:-}" in
	GenuineIntel)
		pkg_cached microcode_ctl || pkg_install microcode_ctl
		ok "Intel microcode package ensured."
		;;
	AuthenticAMD)
		pkg_cached linux-firmware || pkg_install linux-firmware
		ok "AMD microcode (linux-firmware) ensured."
		;;
	*)
		info "CPU vendor not Intel/AMD ('${cpu_vendor:-unknown}') — skipping microcode install."
		;;
	esac

	# ── Hardware security key support (YubiKey, FIDO2, PIV smart cards) ──────
	# Ask if the user owns a hardware security key. If yes, install support packages
	# and remind them to have the key physically accessible during section 23 (USBGuard),
	# since USBGuard will prompt to allow or block every new USB device — a key that
	# is unplugged at that point would need to be explicitly allowed afterwards.
	if confirm "Do you use a hardware security key (YubiKey, FIDO2 token, PIV smart card)?"; then
		info "Installing hardware security key support packages..."
		if ((IS_OSTREE)); then
			# Image-based: layer only what must be on the host (smart-card daemon and
			# drivers, FIDO2 library); the management app is a Flatpak that updates
			# on its own instead of a layer re-applied to every image.
			pkg_install pcsc-lite pcsc-lite-libs opensc libfido2
			if cmd_exists flatpak; then
				run "timeout 120 flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo" || true
				flatpak_install_or_update flathub com.yubico.yubioath
			fi
		else
			pkg_install pcsc-lite pcsc-lite-libs opensc libfido2 yubico-piv-tool yubikey-manager
		fi
		run "systemctl enable --now pcscd.socket || true"
		ok "Hardware key support packages installed and pcscd.socket enabled."
		if confirm "Install pam_u2f for PAM/sudo authentication via FIDO2/U2F key?"; then
			pkg_install pam-u2f
			info "pam_u2f installed — configure /etc/pam.d/ manually to add the U2F factor."
			info "  Reference: https://developers.yubico.com/pam-u2f/"
			add_action_item 1 MEDIUM "HWKEY_PAM_U2F" \
				"pam-u2f was installed. Configure PAM (/etc/pam.d/sudo, /etc/pam.d/system-auth) to require your hardware key for authentication. See: https://developers.yubico.com/pam-u2f/"
		fi
		printf '\n%s╔══════════════════════════════════════════════════════════════╗%s\n' "$C_YEL" "$C_RST"
		printf '%s║  ⚠  HARDWARE KEY REMINDER — READ BEFORE SECTION 23            ║%s\n' "$C_YEL" "$C_RST"
		printf '%s║                                                              ║%s\n' "$C_YEL" "$C_RST"
		printf '%s║  Section 23 (USBGuard) will prompt you to ALLOW or BLOCK      ║%s\n' "$C_YEL" "$C_RST"
		printf '%s║  every USB device it sees at configuration time.             ║%s\n' "$C_YEL" "$C_RST"
		printf '%s║                                                              ║%s\n' "$C_YEL" "$C_RST"
		printf '%s║  • Plug in your hardware key BEFORE section 23 runs so it     ║%s\n' "$C_YEL" "$C_RST"
		printf '%s║    gets added to the allowlist automatically.                ║%s\n' "$C_YEL" "$C_RST"
		printf '%s║  • If you miss it, run afterwards:                           ║%s\n' "$C_YEL" "$C_RST"
		printf '%s║     sudo usbguard generate-policy >> /etc/usbguard/rules.conf║%s\n' "$C_YEL" "$C_RST"
		printf '%s║    or use the USBGuard GUI / CLI to allow the device.        ║%s\n' "$C_YEL" "$C_RST"
		printf '%s╚══════════════════════════════════════════════════════════════╝%s\n\n' "$C_YEL" "$C_RST"
		add_action_item 1 HIGH "HWKEY_USBGUARD_READY" \
			"Hardware security key support enabled: ensure your key is plugged in BEFORE section 23 (USBGuard) runs so it is added to the allowlist. If missed, run: sudo usbguard generate-policy >> /etc/usbguard/rules.conf"
	fi
	_phone_home_off
	_firmware_security_report
}

# _phone_home_off - 1c: keep reports about this machine from being sent on their
# own. Fedora's defaults are already private here; this makes sure they stay so
# (DNF countme is section 2b; GNOME usage statistics are section 13).
_phone_home_off() {
	local f
	# fwupd: no automatic upload of firmware update reports.
	for f in /etc/fwupd/remotes.d/lvfs.conf /etc/fwupd/remotes.d/lvfs-testing.conf; do
		grep -qsE '^AutomaticReports=true' "$f" || continue
		backup_file "$f" || continue
		run "sed -i 's/^AutomaticReports=true/AutomaticReports=false/' '$f'" && ok "fwupd: automatic reports off ($f)"
	done
	# ABRT: crash reports are not sent automatically.
	if cmd_exists abrt-auto-reporting && [[ "$(abrt-auto-reporting 2>/dev/null)" != disabled ]]; then
		backup_file /etc/abrt/abrt.conf || return 0
		run "abrt-auto-reporting disabled" && ok "ABRT: automatic crash reporting off"
	fi
}

# _firmware_security_report - 1d: fwupd's Host Security ID (HSI) shows firmware
# protections only the owner can change (Secure Boot, TPM, DMA protection, BIOS
# write protection). Read-only; failing checks become follow-up items.
_firmware_security_report() {
	cmd_exists fwupdmgr || return 0
	((DRY_RUN)) && {
		info "Would read the firmware security report (fwupdmgr security)"
		return 0
	}
	local out level failed
	out="$(timeout 60 fwupdmgr security --force --no-unreported-check 2>/dev/null)" || return 0
	level="$(grep -oE 'HSI:[0-9]+' <<<"$out" | head -n 1)"
	[[ -n "$level" ]] && info "Firmware security (fwupd Host Security ID): $level"
	failed="$(grep -E '✘' <<<"$out" | sed 's/^[[:space:]]*//' | head -n 5 | paste -sd';' - | sed 's/;/; /g')"
	[[ -n "$failed" ]] && add_action_item 1 LOW "FIRMWARE_SECURITY" \
		"Firmware protections that only you can change (BIOS/UEFI setup): ${failed}. Details: fwupdmgr security"
	return 0
}
