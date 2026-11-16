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

# fw_cmd() - Print the firewalld CLI to use for permanent configuration.
# firewall-cmd talks to the running daemon; when firewalld cannot start (broken
# nftables backend, minimal containers, ...) firewall-offline-cmd edits the same
# permanent configuration on disk so the policy applies as soon as firewalld starts.
FW_OFFLINE=0
fw_cmd() {
	if ((FW_OFFLINE)); then echo firewall-offline-cmd; else echo firewall-cmd; fi
}

# firewalld_ensure_service() - Register a custom firewalld service XML if not already known.
# Firewalld only ships built-in definitions for well-known services; KDE Connect and
# similar require a custom XML file before --add-service can reference them.
# Usage: firewalld_ensure_service <name> <short-desc> <port/proto> [<port/proto>...]
firewalld_ensure_service() {
	local svc_name="${1}"
	shift
	local svc_short="${1}"
	shift
	local svc_dir="/etc/firewalld/services"
	local svc_file="${svc_dir}/${svc_name}.xml"

	# Already known to firewalld — nothing to do.
	if "$(fw_cmd)" --get-services 2>/dev/null | grep -qw "${svc_name}"; then
		return 0
	fi

	if ((DRY_RUN)); then
		info "Would create firewalld service definition: ${svc_name}"
		return 0
	fi

	install -d -m 750 "${svc_dir}" 2>/dev/null || true
	{
		printf '<?xml version="1.0" encoding="utf-8"?>\n'
		printf '<service>\n'
		printf '  <short>%s</short>\n' "${svc_short}"
		local portproto port proto
		for portproto in "$@"; do
			port="${portproto%%/*}"
			proto="${portproto##*/}"
			printf '  <port port="%s" protocol="%s"/>\n' "${port}" "${proto}"
		done
		printf '</service>\n'
	} >"${svc_file}"
	chmod 640 "${svc_file}" 2>/dev/null || true
	((FW_OFFLINE)) || firewall-cmd --reload &>/dev/null || true
	info "Created firewalld service definition: ${svc_name}"
}

# firewalld_add_service() - Add a service to a firewalld zone (permanent), soft-failing on
# INVALID_SERVICE (exit 101) instead of aborting the script under set -e.
# Queues an action item for manual follow-up when the service is not recognised.
# Usage: firewalld_add_service <zone> <service>
firewalld_add_service() {
	local zone="${1}" svc="${2}"
	if ((DRY_RUN)); then
		info "Would run: firewall-cmd --zone=${zone} --add-service=${svc} --permanent"
		return 0
	fi
	local fw perm=(--permanent) out ec
	fw="$(fw_cmd)"
	((FW_OFFLINE)) && perm=() # firewall-offline-cmd only edits permanent config
	log "[RUN]   ${fw} --zone=${zone} --add-service=${svc} ${perm[*]}"
	# Capture output and exit code without triggering set -e abort on failure
	out=$("${fw}" --zone="${zone}" --add-service="${svc}" "${perm[@]}" 2>&1) || ec=$?
	ec=${ec:-0}
	if ((ec == 0)); then
		ok "firewalld: added service '${svc}' to zone '${zone}'."
		return 0
	fi
	if ((ec == 101)) || [[ "${out}" == *"INVALID_SERVICE"* ]]; then
		warn "firewalld: service '${svc}' not recognised — skipping. (${out})"
		add_action_item "6" "MEDIUM" "FW_INVALID_SVC_${svc^^}" \
			"firewalld service '${svc}' is not registered. Create /etc/firewalld/services/${svc}.xml then run: firewall-cmd --zone=${zone} --add-service=${svc} --permanent && firewall-cmd --reload"
		return 1
	fi
	warn "${fw} --add-service=${svc} failed (exit ${ec}): ${out}"
	add_action_item "6" "HIGH" "FW_ADD_SVC_FAILED_${svc^^}" \
		"Could not allow '${svc}' in zone '${zone}' — run: sudo firewall-cmd --zone=${zone} --add-service=${svc} --permanent && sudo firewall-cmd --reload"
	return 1
}
