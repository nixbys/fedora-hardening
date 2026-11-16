# shellcheck shell=bash
# ============================================================================
#  SECTION 2 — automatic security updates (dnf5-plugin-automatic, Fedora 41+)
# ============================================================================
# sec_02_dnf_automatic() - Configure automatic security updates + countme opt-out
# Sets up dnf5-plugin-automatic for mutable systems or rpm-ostreed policy for immutable
# systems to apply security patches automatically. On rpm-ostree, stages updates.
# Sub-section 2b disables the Fedora system-counting mechanism: sets countme=false
# in /etc/dnf/dnf.conf on mutable systems, or masks rpm-ostree-countme.timer on
# immutable ones — per privacyguides.org recommendation.
sec_02_dnf_automatic() {
	should_run 2 || return 0
	section 2 "Automatic security updates"

	# rpm-ostree (image-based) systems; Universal Blue keeps its own updater.
	if ((IS_OSTREE)); then
		_ostree_auto_updates
	else
		_dnf_auto_updates
	fi

	# 3b — DNF countme=false (privacyguides.org: opt out of Fedora system counting)
	# The Fedora Project uses a 'countme' variable to count unique systems accessing
	# its mirrors. privacyguides.org explicitly recommends opting out. On rpm-ostree
	# the equivalent is masking the rpm-ostree-countme timer.
	local dnf_conf="/etc/dnf/dnf.conf"
	if ((IS_OSTREE)); then
		if ((! DRY_RUN)); then
			# The mask is a symlink in /etc; journaled so --rollback unmasks it.
			backup_file /etc/systemd/system/rpm-ostree-countme.timer || return 0
			if systemctl mask rpm-ostree-countme.timer 2>/dev/null; then
				ok "Masked rpm-ostree-countme.timer (privacyguides.org: opt out of system counting)"
			else
				info "rpm-ostree-countme.timer not found or already masked — skipping."
			fi
		else
			info "Would mask rpm-ostree-countme.timer"
		fi
	elif [[ -f "$dnf_conf" ]]; then
		if ((! DRY_RUN)); then
			backup_file "$dnf_conf" || return 0
			if grep -qE '^\s*countme\s*=' "$dnf_conf" 2>/dev/null; then
				sed -i 's|^\s*countme\s*=.*|countme=false|' "$dnf_conf" 2>/dev/null || true
			else
				echo 'countme=false' >>"$dnf_conf" 2>/dev/null || true
			fi
			ok "Set countme=false in $dnf_conf (privacyguides.org: opt out of system counting)"
		else
			info "Would set countme=false in $dnf_conf"
		fi
	else
		info "$dnf_conf not found — skipping countme opt-out."
	fi
}
