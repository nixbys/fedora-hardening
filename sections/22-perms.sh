# shellcheck shell=bash
# ============================================================================
#  SECTION 22 — File permission hardening
# ============================================================================
# sec_22_perms() - Harden file permissions, umask, core dumps, hostname & username privacy
# Tightens permissions on shadow files, /tmp, and compiler access (20a). Sets umask 077
# for restrictive default file creation (20b). Disables core dumps via limits.d (20c).
# Checks hostname for identity leakage (20d) and flags non-generic usernames (20e) per
# privacyguides.org and inteltechniques.com recommendations.
sec_22_perms() {
	should_run 22 || return 0
	section 22 "File permission hardening"
	# Fedora defaults are already strict, but re-affirm.
	run "chmod 000 /etc/shadow"
	run "chmod 000 /etc/gshadow"
	run "chmod 644 /etc/passwd"
	run "chmod 644 /etc/group"
	run "chmod 1777 /tmp"

	if [[ -n "$TARGET_USER" ]]; then
		local home
		home="$(user_home "$TARGET_USER")"
		if [[ -n "$home" && -d "$home" ]]; then
			run "chmod 700 '$home'"
		fi
	fi

	if ((IS_OSTREE)); then
		warn "Skipping /usr/bin compiler permission changes on immutable rpm-ostree systems."
	else
		if confirm "Restrict compiler toolchain (/usr/bin/gcc, g++, make) to mode 0750?"; then
			for bin in /usr/bin/gcc /usr/bin/g++ /usr/bin/make; do
				[[ -e "$bin" ]] && run "chmod 750 '$bin'"
			done
		fi
	fi

	info "Baseline of SUID files (saved for diffing later):"
	run "find / -xdev -perm /4000 -type f 2>/dev/null | sort > /root/suid-baseline-${RUN_DATE_YMD}.txt || true"
	info "Saved SUID baseline to /root/suid-baseline-*.txt"

	# 20a2 — Swap: memory written to unencrypted disk swap survives power-off.
	# Source: privacyguides.org — Linux Overview (Swap and ZRAM).
	local swap_dev swap_type backing plain_swaps=""
	while read -r swap_dev swap_type _; do
		[[ -z "$swap_dev" || "$swap_dev" == Filename || "$swap_dev" == /dev/zram* ]] && continue
		backing="$swap_dev"
		if [[ "$swap_type" == file ]]; then
			# findmnt fails when the file's mount is not visible (containers, CI runners);
			# without "|| true" the ERR trap would abort the whole run.
			backing="$(findmnt -no SOURCE -T "$swap_dev" 2>/dev/null || true)"
			backing="${backing%%[*}"
			[[ -n "$backing" ]] || backing="$swap_dev"
		fi
		lsblk -s -no TYPE "$backing" 2>/dev/null | grep -qx crypt || plain_swaps+="$swap_dev "
	done </proc/swaps
	if [[ -n "$plain_swaps" ]]; then
		warn "Unencrypted swap in use: ${plain_swaps% } — memory contents can be written to disk in the clear."
		add_action_item 22 HIGH "SWAP_UNENCRYPTED" \
			"Swap on ${plain_swaps% } is not encrypted. Use ZRAM (Fedora's default: zram-generator) and disable disk swap, or put swap inside LUKS (privacyguides.org)."
	else
		ok "Swap is ZRAM or encrypted (or not in use)."
	fi

	# 22b — umask 077 for regular users (inteltechniques.com: new files private).
	# Not for root and system accounts: files root creates for services (configs,
	# keys) must stay readable by them, a known source of hard-to-trace breakage.
	local umask_f="/etc/profile.d/99-umask.sh"
	if ! grep -qs 'id -u' "$umask_f"; then
		write_new_file "$umask_f" 0644 <<'UMASK' && ((! DRY_RUN)) && ok "Wrote $umask_f (umask 077 for regular users — new files private by default)"
# Written by fedora-harden.sh (section 22b): new files private for regular users.
# Root and system accounts keep the default, so services can read what root creates.
if [ "$(id -u)" -ge 1000 ]; then
	umask 077
fi
UMASK
	else
		info "$umask_f already limits umask 077 to regular users — leaving unchanged."
	fi

	# 20c — Core dump suppression via limits.d (privacyguides.org)
	local coredump_f="/etc/security/limits.d/99-coredump.conf"
	if ((DRY_RUN)); then
		info "Would write $coredump_f (disable core dumps)"
	elif [[ ! -f "$coredump_f" ]]; then
		backup_file "$coredump_f" || return 0
		if ! cat 2>/dev/null >"$coredump_f" <<'EOF'
* soft core 0
* hard core 0
EOF
		then
			warn "Failed to write $coredump_f"
		else
			chmod 644 "$coredump_f" 2>/dev/null || true
			ok "Wrote $coredump_f (core dumps disabled via PAM limits)"
		fi
	else
		info "$coredump_f already exists — leaving unchanged."
	fi

	# 20d — hostname privacy check (inteltechniques.com: non-identifying hostname)
	local current_hostname
	current_hostname="$(hostname -s 2>/dev/null || true)"
	local real_name="${TARGET_USER:-$(logname 2>/dev/null || true)}"
	if [[ -n "$current_hostname" && -n "$real_name" ]]; then
		if grep -qi "$real_name" <<<"$current_hostname" 2>/dev/null; then
			warn "Hostname '$current_hostname' appears to contain your username — consider a non-identifying hostname."
			add_action_item 22 MEDIUM "HOSTNAME_PRIVACY" \
				"Hostname '$current_hostname' may leak identity — change with: sudo hostnamectl set-hostname <generic-name>"
		fi
	fi

	# 20e — username privacy check (privacyguides.org: use generic username, not real name)
	# privacyguides.org recommends: "Consider using generic terms like 'user' rather than
	# your actual name" to limit the amount of personal data exposed by the OS.
	local cur_user="${TARGET_USER:-$(logname 2>/dev/null || true)}"
	if [[ -n "$cur_user" ]]; then
		# Flag if username is a simple word (all letters) and not already a generic term
		case "$cur_user" in
		root | user | admin | nobody | guest | fedora | linux) ;;
		*)
			info "Current username: '$cur_user' — privacyguides.org recommends a generic username" \
				"(e.g., 'user') rather than a real name to limit OS-level personal-data exposure."
			add_action_item 22 LOW "USERNAME_PRIVACY" \
				"Consider a non-identifying system username instead of '$cur_user' (privacyguides.org recommendation)"
			;;
		esac
	fi
}
