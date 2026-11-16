# shellcheck shell=bash
# ---------- Safety point ----------------------------------------------------
# ostree_deployment_index <checksum> - Index of a deployment in `ostree admin status`
# (what `ostree admin pin` takes), or nothing.
ostree_deployment_index() {
	ostree admin status 2>/dev/null | awk -v c="$1" '
		/^[* ] [^ ]+ [0-9a-f]{64}\.[0-9]+/ { split($3, a, "."); if (a[1] == c) { print n; exit } n++ }'
}

# safety_point() - Before changing anything, keep a way back to the system as it was:
# on image-based Fedora the booted deployment is pinned (it stays bootable from the
# boot menu, whatever updates follow); on traditional Fedora with Btrfs a read-only
# snapshot of / is taken (the three newest are kept). Elsewhere --rollback is the
# way back.
safety_point() {
	((DRY_RUN)) && {
		info "Would set a safety point before changing anything (pinned deployment or / snapshot)"
		return 0
	}
	if ((IS_OSTREE)) && cmd_exists ostree; then
		local csum idx
		csum="$(ostree admin status 2>/dev/null | awk '/^\* [^ ]+ [0-9a-f]{64}\.[0-9]+/ { split($3, a, "."); print a[1]; exit }')"
		[[ -n "$csum" ]] || return 0
		if ostree admin status 2>/dev/null | awk -v c="$csum" '
			/^[* ] / { cur = ($3 ~ "^" c) } cur && /Pinned: yes/ { found = 1 } END { exit !found }'; then
			info "Safety point: the booted deployment is already pinned."
			return 0
		fi
		idx="$(ostree_deployment_index "$csum")"
		if [[ -n "$idx" ]] && ostree admin pin "$idx" >/dev/null 2>&1; then
			record_change OSTREE_PIN "$csum"
			ok "Safety point: the booted deployment is pinned (boot it from the boot menu to go back)."
		else
			warn "Could not pin the booted deployment — --rollback remains the way back."
		fi
		return 0
	fi
	[[ "$(findmnt -no FSTYPE / 2>/dev/null || true)" == btrfs ]] && cmd_exists btrfs || return 0
	local dir=/var/lib/fedora-harden/root-snapshots snap old
	snap="$dir/before-$RUN_STAMP"
	install -d -m 700 "$dir" 2>/dev/null || return 0
	if btrfs subvolume snapshot -r / "$snap" >/dev/null 2>&1; then
		record_change ROOT_SNAPSHOT "$snap"
		ok "Safety point: read-only snapshot of / at $snap"
		# Keep the three newest safety points.
		while IFS= read -r old; do
			btrfs subvolume delete "$old" >/dev/null 2>&1 || true
		done < <(find "$dir" -mindepth 1 -maxdepth 1 -name 'before-*' 2>/dev/null | sort -r | tail -n +4)
	else
		warn "Could not snapshot / — --rollback remains the way back."
	fi
}
