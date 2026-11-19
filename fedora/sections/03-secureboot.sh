# shellcheck shell=bash
# ============================================================================
#  SECTION 3 — Secure Boot verification
# ============================================================================
# A GRUB password stays a manual task.
sec_03_secureboot() {
	should_run 3 || return 0
	section 3 "Secure Boot verification"
	if ! cmd_exists mokutil; then
		ensure_command_dep mokutil "Secure Boot verification" mokutil || true
	fi
	if cmd_exists mokutil; then
		local sb
		sb="$(mokutil --sb-state 2>/dev/null || true)"
		info "$sb"
		if grep -qi "enabled" <<<"$sb"; then
			ok "Secure Boot is enabled."
		else
			warn "Secure Boot is NOT enabled. Enable it in UEFI firmware settings."
		fi
	else
		warn "mokutil is unavailable after dependency checks — cannot verify Secure Boot state."
	fi
	if ((GUI_FULL_MODE)); then
		gui_alert info "GRUB password setup (guide section 3b) is manual.\n\nRun: sudo grub2-mkpasswd-pbkdf2\nThen add password_pbkdf2 lines in /etc/grub.d/40_custom and regenerate grub.cfg."
	else
		cat <<'EOF'
NOTE on GRUB password (guide §3b):
  Setting a GRUB password requires interactive use of 'grub2-mkpasswd-pbkdf2'.
  This script does NOT automate it. To do it manually:
      sudo grub2-mkpasswd-pbkdf2
      # copy the hash into /etc/grub.d/40_custom as:
      #   set superusers="root"
      #   password_pbkdf2 root <HASH>
      sudo grub2-mkconfig -o /boot/efi/EFI/fedora/grub.cfg   # UEFI
      sudo grub2-mkconfig -o /boot/grub2/grub.cfg            # legacy BIOS
EOF
	fi
}
