# shellcheck shell=bash
# ============================================================================
#  SECTION 9 — Kernel sysctl
# ============================================================================
# Network (spoofing, ICMP, redirects, forwarding), ASLR (randomize_va_space,
# mmap_rnd_bits), BPF JIT hardening, kexec off, ptrace restriction, sysrq off, TCP
# timestamp privacy, IPv6 privacy extensions and no core dumps. Based on Madaidan's
# Linux Hardening Guide (linked by privacyguides.org).
sec_09_sysctl() {
	should_run 9 || return 0
	section 9 "Kernel & network sysctl hardening"
	local f="/etc/sysctl.d/99-hardening.conf"
	if ((DRY_RUN)); then
		info "Would write $f with guide's full sysctl set"
	else
		install -d -m 755 /etc/sysctl.d 2>/dev/null || true
		backup_file "$f" || return 0
		if ! cat 2>/dev/null >"$f" <<'EOF'
# /etc/sysctl.d/99-hardening.conf
# Installed by fedora-harden.sh

# ── Network Hardening ──────────────────────────────────────────────────
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1

# Uncomment to fully disable IPv6:
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1

net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# ── Kernel Hardening ───────────────────────────────────────────────────
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.sysrq = 0

# Prevent kexec — stops loading a new kernel without a full reboot, which
# blocks a major attack vector for persistent compromise (Madaidan / privacyguides.org)
kernel.kexec_load_disabled = 1

# Harden BPF JIT and restrict unprivileged BPF — limits exploitation of BPF
# subsystem vulnerabilities (Madaidan Linux Hardening Guide, linked by privacyguides.org)
net.core.bpf_jit_harden = 2
kernel.unprivileged_bpf_disabled = 1

# NOTE: 'kernel.unprivileged_userns_clone' is an Ubuntu-specific knob
# and does not exist on the Fedora kernel. The Fedora equivalent is
# 'user.max_user_namespaces', but setting it to 0 breaks Flatpak,
# podman, browsers, and systemd user services — so it is left at the
# default intentionally. Uncomment only if you understand the impact.
# user.max_user_namespaces = 0

kernel.randomize_va_space = 2

# Increase ASLR entropy on 64-bit systems for stronger randomization
# (Madaidan Linux Hardening Guide; these are the maximum safe values on x86_64)
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16

# Core dumps of setuid programs are not written (they can contain secrets).
fs.suid_dumpable = 0
fs.protected_fifos = 2
fs.protected_regular = 2
fs.protected_symlinks = 1
fs.protected_hardlinks = 1

# ── IPv6 Privacy Extensions ───────────────────────────────────────────
# Randomize temporary IPv6 source addresses (privacyguides.org)
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2

# ── Network Privacy ───────────────────────────────────────────────────
# Disable TCP timestamps to reduce remote clock-skew fingerprinting
net.ipv4.tcp_timestamps = 0
EOF
		then
			err "Failed to write sysctl configuration"
			add_action_item 9 HIGH "SYSCTL_WRITE_FAILED" "Could not write $f — check the filesystem, then re-run: sudo ./fedora-harden.sh --only 9"
			return 0
		fi
		chmod 644 "$f" 2>/dev/null || true
		# Development: debuggers attach to running programs (ptrace_scope stays at
		# Fedora's default for the dev use case).
		if grep -qE '^USE_CASES=.*\bdev\b' /etc/fedora-harden/profile 2>/dev/null; then
			sed -i 's/^kernel.yama.ptrace_scope = 1$/# kernel.yama.ptrace_scope = 1  (not set: the dev use case attaches debuggers)/' "$f"
		fi
		ok "Wrote $f"
	fi
	_module_blocklist
	_io_uring
	# sysctl --system exits non-zero if ANY key cannot be applied (key absent on this
	# kernel, read-only in a container, ...). The drop-in still applies at boot, so
	# report the rejected keys instead of aborting the remaining sections.
	if ! run "sysctl --system >/dev/null"; then
		local rejected=""
		[[ -s "$ERROR_CAPTURE_FILE" ]] &&
			rejected="$(grep -oE 'key "[^"]+"' "$ERROR_CAPTURE_FILE" | tr -d '"' | sed 's/^key //' | sort -u | paste -sd, - | sed 's/,/, /g')"
		warn "sysctl --system could not apply some keys${rejected:+: $rejected}"
		add_action_item 9 MEDIUM "SYSCTL_APPLY_PARTIAL" \
			"Some sysctl keys were rejected by the running kernel${rejected:+ ($rejected)}. Check with: sudo sysctl --system — unsupported keys can be removed from $f"
	fi
	run "sysctl kernel.kptr_restrict || true"
	_kernel_boot_hardening
}

# _module_blocklist - 9b: rarely used kernel modules are a common source of kernel
# security holes, and Fedora loads them on demand. Block network protocols and
# filesystems a desktop does not use; a module that is loaded right now is left
# alone (something on this machine uses it).
_module_blocklist() {
	local f=/etc/modprobe.d/fedora-harden-blocklist.conf m out="" loaded
	loaded="$(cut -d' ' -f1 /proc/modules 2>/dev/null)"
	for m in dccp sctp rds tipc cramfs freevxfs jffs2 hfs; do
		grep -qx "$m" <<<"$loaded" && continue
		out+="install $m /bin/false"$'\n'"blacklist $m"$'\n'
	done
	[[ -n "$out" ]] || return 0
	write_new_file "$f" 0644 <<MODS || return 0
# Written by fedora-harden.sh (section 9b): kernel modules a desktop does not use.
# To use one again, remove its two lines (or run --rollback).
${out%$'\n'}
MODS
	ok "Blocked unused kernel modules: $f"
}

# _io_uring - 9c: io_uring has been one of the most exploited kernel interfaces
# (Google turned it off on ChromeOS and Android, and for its production servers).
# kernel.io_uring_disabled=1 keeps it for root only; ordinary programs fall back to
# regular I/O. Off by default for the dev use case, where databases and QEMU use it.
_io_uring() {
	local f=/etc/sysctl.d/98-io-uring.conf default=yes
	[[ -r /proc/sys/kernel/io_uring_disabled ]] || return 0
	grep -qE '^USE_CASES=.*\bdev\b' /etc/fedora-harden/profile 2>/dev/null && default=no
	confirm "Limit io_uring (a frequently exploited kernel interface) to root?" "$default" || return 0
	write_new_file "$f" 0644 <<'CONF' || return 0
# Written by fedora-harden.sh (section 9c): io_uring for root only. Programs that
# need it for speed (some databases, QEMU) fall back to regular I/O. To allow it
# again, delete this file (or run --rollback) and reboot.
kernel.io_uring_disabled = 1
CONF
	ok "io_uring limited to root: $f"
}
