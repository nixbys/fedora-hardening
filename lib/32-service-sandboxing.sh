# shellcheck shell=bash
# ---------- Sandboxing of exposed services (section 21) -----------------------
# For network services that are running, a drop-in with conservative systemd
# sandboxing; kept only when the service restarts cleanly with it. sshd is left
# alone on purpose: its sandbox would also apply to every login session it starts.
_sandbox_dropin() { # _sandbox_dropin <service> — the directives for that service
	case "$1" in
	cups)
		# cupsd runs filters and backends (USB, network); keep it able to.
		cat <<'EOF'
[Service]
PrivateTmp=yes
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
LockPersonality=yes
EOF
		;;
	avahi-daemon)
		cat <<'EOF'
[Service]
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
NoNewPrivileges=yes
LockPersonality=yes
EOF
		;;
	*) return 1 ;;
	esac
}

_exposure() { # _exposure <service> — systemd-analyze's exposure score (lower is better)
	systemd-analyze security --no-pager "$1.service" 2>/dev/null | sed -n 's/.*Overall exposure level for [^:]*: \([0-9.]*\).*/\1/p' || true
}

_sandbox_exposed_services() {
	local svc drop before after
	for svc in cups avahi-daemon; do
		systemctl is-active --quiet "$svc" 2>/dev/null || continue
		drop="/etc/systemd/system/$svc.service.d/50-fedora-harden-sandbox.conf"
		[[ -e "$drop" ]] && continue
		before="$(_exposure "$svc")"
		_sandbox_dropin "$svc" | write_new_file "$drop" 0644 || continue
		((DRY_RUN)) && continue
		if run "systemctl daemon-reload && systemctl restart $svc" && systemctl is-active --quiet "$svc"; then
			after="$(_exposure "$svc")"
			ok "Sandboxed $svc (exposure ${before:-?} → ${after:-?}; lower is better)."
		else
			warn "$svc did not start with the sandbox — removed it again."
			rm -f "$drop"
			systemctl daemon-reload 2>/dev/null || true
			systemctl restart "$svc" 2>/dev/null || true
			add_action_item 21 LOW "SANDBOX_FAILED_${svc//-/_}" \
				"$svc did not start with the sandbox drop-in, so it runs without it. Check: journalctl -u $svc -b"
		fi
	done
	systemctl is-active --quiet sshd 2>/dev/null &&
		info "sshd is not sandboxed: a sandbox would also restrict every SSH login session."
	return 0
}
