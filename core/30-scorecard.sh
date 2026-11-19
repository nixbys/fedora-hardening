# shellcheck shell=bash
# ---------- Protection scorecard (--score, summary, --report) ----------------
# Checks the LIVE system, not what this run did: each line says whether something
# protects the machine now and, if not, how to fix it. Read-only, nothing leaves the
# machine. Rows: "state|label|detail|fix" with state ok, no, na (not applicable) or
# info (advice).
declare -ga SCORE_ROWS=()

_score() { # _score <ok|no|na|info> <label> <detail> [fix]
	SCORE_ROWS+=("$1|$2|$3|${4:-}")
}

# _score_user_cmd <cmd...> - Run a read-only settings query as the desktop user.
_score_user_cmd() {
	local user="${TARGET_USER:-${SUDO_USER:-}}"
	[[ -n "$user" && "$user" != root ]] && id "$user" >/dev/null 2>&1 || return 1
	runuser -u "$user" -- "$@" 2>/dev/null
}

protection_scorecard() {
	SCORE_ROWS=()
	local src v user="${TARGET_USER:-${SUDO_USER:-}}"

	# Disk encryption: is the root file system (the OSTree sysroot on image-based
	# systems) on a LUKS device?
	src="$(findmnt -no SOURCE /sysroot 2>/dev/null || true)"
	[[ -n "$src" ]] || src="$(findmnt -no SOURCE / 2>/dev/null || true)"
	src="${src%%\[*}"
	if [[ "$src" != /dev/* ]]; then
		_score na "Disk encryption" "no disk behind / (container or network root)"
	elif lsblk -s -no TYPE "$src" 2>/dev/null | grep -qx crypt; then
		_score ok "Disk encryption" "the system disk is encrypted (LUKS)"
	else
		_score no "Disk encryption" "the system disk is not encrypted" \
			"Encryption is chosen at install time (Anaconda: Encrypt my data). An installed system needs a reinstall, or an offline 'cryptsetup reencrypt' with a full backup first."
	fi

	# Secure Boot, from the firmware variable (no extra tools needed).
	v="$(od -An -t u1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>/dev/null | awk '{print $NF}' || true)"
	if [[ ! -d /sys/firmware/efi ]]; then
		_score na "Secure Boot" "legacy BIOS boot (no UEFI)"
	elif [[ "$v" == 1 ]]; then
		_score ok "Secure Boot" "on"
	else
		_score no "Secure Boot" "off" "Turn on Secure Boot in the UEFI firmware setup (Fedora's shim is signed), then check: mokutil --sb-state"
	fi

	# Kernel lockdown: Fedora turns on "integrity" under Secure Boot, which stops even
	# root from loading unsigned kernel modules or writing to kernel memory.
	v="$(sed -n 's/.*\[\([a-z]*\)\].*/\1/p' /sys/kernel/security/lockdown 2>/dev/null || true)"
	case "$v" in
	integrity | confidentiality) _score ok "Kernel lockdown" "$v" ;;
	none) _score no "Kernel lockdown" "off" "Turn on Secure Boot (Fedora then enables lockdown=integrity). Unsigned third-party modules such as NVIDIA's need signing first: see section 3." ;;
	*) _score na "Kernel lockdown" "not reported by this kernel" ;;
	esac

	# Firewall, automatic updates and mandatory access control: the platform file.
	platform_score_rows

	# SSH server: off, or keys only without root login
	if ! systemctl is-active --quiet sshd 2>/dev/null && ! systemctl is-enabled --quiet sshd 2>/dev/null; then
		_score ok "SSH server" "off"
	else
		v="$(sshd -T 2>/dev/null | awk '$1 == "passwordauthentication" || $1 == "permitrootlogin" {print $1 "=" $2}' | sort | paste -sd' ' - || true)"
		if [[ "$v" == *"passwordauthentication=no"* && "$v" == *"permitrootlogin=no"* ]]; then
			_score ok "SSH server" "on, keys only, no root login"
		else
			_score no "SSH server" "on and accepts passwords or root logins" "Run section 7: sudo $SCRIPT_NAME --only 7 (copy your SSH key first), or turn it off: sudo systemctl disable --now sshd"
		fi
	fi

	# DNS over TLS: resolved uses it and /etc/resolv.conf goes through resolved
	v="$(readlink -f /etc/resolv.conf 2>/dev/null || true)"
	if systemctl is-active --quiet systemd-resolved 2>/dev/null &&
		resolvectl status 2>/dev/null | grep -q '+DNSOverTLS' && [[ "$v" == /run/systemd/resolve/* ]]; then
		_score ok "DNS over TLS" "DNS lookups are encrypted"
	else
		_score no "DNS over TLS" "DNS lookups are sent in the clear" "Run section 11: sudo $SCRIPT_NAME --only 11"
	fi

	# Backups of home: section 20's snapshots/copies, or Snapper's home config
	if systemctl is-enabled --quiet fedora-harden-snapshot.timer 2>/dev/null ||
		{ have_cmd snapper && snapper -c home get-config >/dev/null 2>&1; }; then
		_score ok "Home snapshots" "home is snapshotted or copied regularly"
	else
		_score no "Home snapshots" "no regular snapshots or copies of home" "Run section 20: sudo $SCRIPT_NAME --only 20"
	fi

	# Screen lock (GNOME and KDE settings of the desktop user)
	if ((! HAS_DESKTOP)); then
		_score na "Screen lock" "no desktop"
	elif v="$(_score_user_cmd gsettings get org.gnome.desktop.screensaver lock-enabled)" && [[ -n "$v" ]]; then
		if [[ "$v" == true ]]; then
			_score ok "Screen lock" "the screen locks when idle"
		else
			_score no "Screen lock" "the screen does not lock" "Run section 13: sudo $SCRIPT_NAME --only 13"
		fi
	elif have_cmd kreadconfig6 || have_cmd kreadconfig5; then
		v="$(_score_user_cmd "$(command -v kreadconfig6 || command -v kreadconfig5)" --file kscreenlockerrc --group Daemon --key Autolock || true)"
		if [[ "$v" != false ]]; then
			_score ok "Screen lock" "the screen locks when idle"
		else
			_score no "Screen lock" "the screen does not lock" "Run section 13: sudo $SCRIPT_NAME --only 13"
		fi
	else
		_score na "Screen lock" "not checked on this desktop"
	fi

	# Flatpak apps kept out of home and the host file system
	if ! have_cmd flatpak; then
		_score na "Flatpak restrictions" "Flatpak not installed"
	elif v="$(flatpak override --system --show 2>/dev/null)" && [[ "$v" == *'!home'* && "$v" == *'!host'* ]]; then
		_score ok "Flatpak restrictions" "apps cannot read home or the host file system unless granted"
	else
		_score no "Flatpak restrictions" "apps can read home or the host file system" "Run section 4: sudo $SCRIPT_NAME --only 4"
	fi

	# Firmware security level (fwupd Host Security ID), when fwupd can tell
	if have_cmd fwupdmgr && v="$(timeout 60 fwupdmgr security </dev/null 2>/dev/null | grep -oE 'HSI:[0-9]' | head -n 1)" && [[ -n "$v" ]]; then
		if [[ "$v" == HSI:0 ]]; then
			_score no "Firmware security" "$v: basic firmware protections are missing" "Run 'fwupdmgr security' to see which (BIOS write protection, Secure Boot, TPM, DMA protection) and turn them on in the firmware setup."
		else
			_score ok "Firmware security" "$v (fwupd Host Security ID; higher is better)"
		fi
	else
		_score na "Firmware security" "fwupd cannot rate this firmware"
	fi

	# Daily account with admin rights: advice only
	if [[ -n "$user" && "$user" != root ]] && id -nG "$user" 2>/dev/null | grep -qw wheel; then
		_score info "Admin rights" "your everyday account can use sudo" \
			"Optional: create a separate admin account, check that it can use sudo, then remove the everyday account from the wheel group."
	fi
	return 0
}

# show_protection_scorecard - Print the scorecard (terminal) or show it in the window.
show_protection_scorecard() {
	local row state label detail fix tag col ok=0 total=0
	protection_scorecard
	if ((GUI_FULL_MODE)); then
		for row in "${SCORE_ROWS[@]}"; do
			IFS='|' read -r state label detail fix <<<"$row"
			gui_send SCORE "$state" "$label" "$detail" "$fix"
		done
		return 0
	fi
	printf '\n%s══════════════════════ Protection now ══════════════════════%s\n' "$C_CYN" "$C_RST"
	for row in "${SCORE_ROWS[@]}"; do
		IFS='|' read -r state label detail fix <<<"$row"
		case "$state" in
		ok) tag="[ OK ]" col="$C_GRN" ;;
		no) tag="[ NO ]" col="$C_RED" ;;
		info) tag="[INFO]" col="$C_BLU" ;;
		*) tag="[ -- ]" col="" ;;
		esac
		[[ "$state" == ok || "$state" == no ]] && ((++total))
		[[ "$state" == ok ]] && ((++ok))
		printf '  %s%s%s %-22s %s\n' "$col" "$tag" "$C_RST" "$label" "$detail"
		[[ -n "$fix" && "$state" != ok ]] && printf '         → %s\n' "$fix"
	done
	printf '  %d of %d protections in place (checked on the live system).\n' "$ok" "$total"
	return 0
}
