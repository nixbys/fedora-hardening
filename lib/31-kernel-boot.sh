# shellcheck shell=bash
# ---------- Kernel boot hardening (section 9, opt-in) ------------------------
# Memory-safety options on the kernel command line. They cost about 1-5% in some
# workloads (init_on_free zeroes freed memory), so they are opt-in: asked, or
# --kernel-hardening; never by default with --yes, and not offered for gaming.
KERNEL_HARDENING_ARGS=(init_on_free=1 slab_nomerge page_alloc.shuffle=1 randomize_kstack_offset=on)

_kernel_boot_hardening() {
	local current add=() a profile
	profile="$PROFILE_ARG"
	[[ -n "$profile" ]] || profile="$(sed -n 's/^USE_CASES=//p' /etc/fedora-harden/profile 2>/dev/null | tr -d '"' || true)"
	if [[ ",${profile// /,}," == *,gaming,* ]] && ((! KERNEL_HARDENING)); then
		info "Kernel boot hardening skipped for the gaming use case (it costs a few % of performance); --kernel-hardening turns it on."
		return 0
	fi
	if systemd-detect-virt --container --quiet 2>/dev/null; then
		info "Kernel boot hardening needs a booted system (this is a container) — skipped."
		return 0
	fi
	if ((IS_OSTREE)); then
		current="$(rpm-ostree kargs 2>/dev/null || true)"
	elif have_cmd grubby; then
		current="$(grubby --info=DEFAULT 2>/dev/null | sed -n 's/^args="\(.*\)"$/\1/p' || true)"
	else
		info "Kernel boot hardening: neither rpm-ostree nor grubby is available — skipped."
		return 0
	fi
	for a in "${KERNEL_HARDENING_ARGS[@]}"; do
		[[ " $current " == *" $a "* ]] || add+=("$a")
	done
	if ((${#add[@]} == 0)); then
		ok "Kernel boot hardening options are already set."
		return 0
	fi
	if ((! KERNEL_HARDENING)); then
		confirm "Add kernel boot hardening (${add[*]})? It makes memory bugs harder to exploit and costs about 1-5% in some workloads." no || {
			info "Kernel boot hardening not added (opt-in: --kernel-hardening)."
			return 0
		}
	fi
	if ((IS_OSTREE)); then
		local -a opts=()
		for a in "${add[@]}"; do opts+=("--append-if-missing=$a"); done
		run "rpm-ostree kargs ${opts[*]}" || {
			warn "rpm-ostree could not add the kernel options."
			return 0
		}
	else
		run "grubby --update-kernel=ALL --args='${add[*]}'" || {
			warn "grubby could not add the kernel options."
			return 0
		}
	fi
	record_change KERNEL_ARGS "${add[*]}"
	ok "Kernel boot hardening added: ${add[*]} (takes effect after a reboot)."
	add_action_item 9 LOW "KERNEL_ARGS_REBOOT" "Reboot to apply the kernel boot hardening options (${add[*]}); --rollback removes them."
}
