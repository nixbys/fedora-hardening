# shellcheck shell=bash
# ============================================================================
#  SECTION 5 — SELinux
# ============================================================================
# sec_05_selinux() - Verify SELinux is enforcing and install tools
# Confirms SELinux is in enforcing mode; installs debugging and management tools
# (policycoreutils, selinux-policy-devel). Logs policy violations.
sec_05_selinux() {
	should_run 5 || return 0
	section 5 "SELinux (verify enforcing + install tools)"
	local mode cfg="/etc/selinux/config" cfg_mode=""
	mode="$(getenforce 2>/dev/null || echo unknown)"
	[[ -f "$cfg" ]] && cfg_mode="$(awk -F= '/^[[:space:]]*SELINUX=/{print $2; exit}' "$cfg")"
	info "Current SELinux mode: $mode (configured: ${cfg_mode:-unset})"

	case "$mode" in
	Enforcing)
		ok "SELinux is enforcing."
		if [[ -n "$cfg_mode" && "$cfg_mode" != enforcing ]]; then
			backup_file "$cfg" || return 0
			set_conf_key "$cfg" SELINUX enforcing "=" || true
			((DRY_RUN)) || ok "Set SELINUX=enforcing in $cfg so it persists across reboots."
		fi
		;;
	Permissive)
		# Labels are maintained in permissive mode, so switching to enforcing is safe.
		warn "SELinux is permissive — switching to enforcing now and in $cfg."
		run "setenforce 1" || warn "setenforce 1 failed"
		if [[ -f "$cfg" ]]; then
			backup_file "$cfg" || return 0
			set_conf_key "$cfg" SELINUX enforcing "=" || true
		fi
		;;
	Disabled)
		if [[ "$cfg_mode" == enforcing || "$cfg_mode" == permissive ]]; then
			# Config already enables SELinux, so it is disabled at runtime by the kernel
			# command line (selinux=0) or the environment (containers).
			warn "SELinux is disabled at runtime although $cfg says SELINUX=$cfg_mode."
			add_action_item 5 HIGH "SELINUX_DISABLED_RUNTIME" \
				"SELinux is disabled at boot. Remove the kernel argument: sudo grubby --update-kernel ALL --remove-args selinux — then reboot (a relabel may run)."
		elif [[ -f "$cfg" ]]; then
			# Going straight from disabled to enforcing can leave the system unbootable:
			# files created while SELinux was off carry no labels. Fedora's procedure is
			# permissive + full relabel on the next boot, then enforcing.
			warn "SELinux is disabled — enabling it in PERMISSIVE mode with a full relabel on next boot."
			backup_file "$cfg" || return 0
			set_conf_key "$cfg" SELINUX permissive "=" || true
			if ((DRY_RUN)); then
				info "Would schedule a relabel: touch /.autorelabel"
			elif touch /.autorelabel; then
				record_change FILE_CREATE /.autorelabel
			else
				warn "Could not create /.autorelabel"
			fi
			add_action_item 5 HIGH "SELINUX_ENABLE_ENFORCING" \
				"Reboot to relabel the filesystem in permissive mode, check 'sudo ausearch -m avc -ts boot', then: sudo setenforce 1 && sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config"
		else
			warn "$cfg not found — cannot enable SELinux."
			add_action_item 5 HIGH "SELINUX_CONFIG_MISSING" "Install selinux-policy-targeted and configure /etc/selinux/config"
		fi
		;;
	*)
		warn "Could not determine the SELinux mode (getenforce unavailable)."
		;;
	esac
	if ((IS_OSTREE)); then
		pkg_install setroubleshoot-server
		info "seinfo/sesearch (setools) are in the $TOOLS_BOX box on image-based systems (section 18)."
	else
		pkg_install setools-console setroubleshoot-server
	fi
	info "Use 'sudo ausearch -m avc -ts recent | audit2why' to diagnose denials."
}
