# shellcheck shell=bash
# ============================================================================
#  Personal setup (section 19) and the recovery file
# ============================================================================
# Section 19 tailors the machine to its use cases. Besides the routine timers it
# offers, once each: ready-made boxes for development and DaVinci Resolve (nothing
# layered), the private-browsing browsers, a Flathub limited to verified apps, a
# security key for sudo and login, unlocking the encrypted disk with the TPM or a
# FIDO2 key, and pointers to OpenSnitch. Every one is a question (off under --yes
# unless a use case implies it) and is undone by --rollback.
#
# After every run the recovery file (root-only, no secrets) records what this
# machine was set up with; --restore replays it after a reinstall or a recovery.

RECOVERY_FILE="/etc/fedora-harden/machine.conf"
DEV_BOX_PKGS="gcc gcc-c++ make cmake git python3 python3-pip"
declare -ga BOXES_MADE=()      # boxes created or already present this run
declare -gA SETUP_CHOICES=()   # personal choices made this run (recovery file)
declare -gA RESTORE_ANSWERS=() # answers loaded by --restore, by question key
declare -gA ANSWERS=()         # answers given this run, by question key
declare -gA ANSWER_TEXT=()     # the question behind each key

# _answer_key <question> - Short stable key for a question (recovery file).
_answer_key() {
	printf '%s' "$1" | sha256sum | cut -c1-12
}

# _personal_setup <use cases> - Section 19's personal choices.
_personal_setup() {
	local uses="$1"
	_use_case_boxes "$uses"
	[[ " $uses " == *" private "* ]] && _private_browsing
	_flathub_verified
	_security_key_login
	_disk_unlock
	_opensnitch_pointer
	return 0
}

# _has_nvidia - True when an NVIDIA GPU is driven by the proprietary driver.
_has_nvidia() {
	[[ -e /proc/driver/nvidia/version ]] || lspci 2>/dev/null | grep -qiE 'vga.*nvidia|3d.*nvidia'
}

# _use_case_boxes <use cases> - dev: a box with compilers and build tools;
# creative: the davincibox container for DaVinci Resolve (as Bazzite does).
# Created for the person in the background; upgraded weekly by the routine.
_use_case_boxes() {
	local uses="$1" user="${TARGET_USER:-${SUDO_USER:-}}" tool release
	[[ " $uses " == *" dev "* || " $uses " == *" creative "* ]] || return 0
	if [[ -z "$user" || "$user" == root ]]; then
		info "No desktop user (run with sudo or --user NAME) — use-case boxes not created."
		return 0
	fi
	tool="$(image_box_tool)"
	if ! cmd_exists "$tool" && ((! IS_OSTREE)); then
		pkg_install "$tool"
	fi
	if ((! DRY_RUN)) && ! cmd_exists "$tool"; then
		info "$tool is not available — use-case boxes not created."
		return 0
	fi
	release="${FEDORA_MAJOR:-0}"
	((release > 0)) || release="$(rpm -E %fedora 2>/dev/null || echo 45)"
	if [[ " $uses " == *" dev "* ]] &&
		confirm "Create a 'dev' $tool box with compilers and build tools ($DEV_BOX_PKGS), so they stay out of the system?" yes; then
		_make_box "$user" "$tool" dev "registry.fedoraproject.org/fedora-toolbox:$release" "$DEV_BOX_PKGS"
	fi
	if [[ " $uses " == *" creative "* ]]; then
		if cmd_exists ujust && ujust --list 2>/dev/null | grep -q install-resolve; then
			return 0 # Bazzite's own installer does the same (action item from section 19)
		fi
		confirm "Create the 'davincibox' container for DaVinci Resolve (the davincibox project, as Bazzite does)?" yes || return 0
		local image="ghcr.io/zelikos/davincibox-opencl:latest" setup
		_has_nvidia && image="ghcr.io/zelikos/davincibox:latest"
		_make_box "$user" "$tool" davincibox "$image" ""
		_render_groups "$user"
		if [[ "$tool" == distrobox ]]; then
			setup="distrobox enter davincibox -- setup-davinci squashfs-root/AppRun distrobox"
		else
			setup="toolbox run --container davincibox setup-davinci squashfs-root/AppRun toolbox"
		fi
		add_action_item 19 LOW "DAVINCIBOX_SETUP" \
			"Install DaVinci Resolve into davincibox: download the Linux installer from blackmagicdesign.com, run '<installer>.run --appimage-extract' in its folder, then: $setup — Resolve then appears in your app menu."
	fi
}

# _make_box <user> <tool> <name> <image> [packages] - Create a box for the person,
# in the background (images are large). Journaled for --rollback.
_make_box() {
	local user="$1" tool="$2" name="$3" image="$4" extra="${5:-}" uid home box_cmd
	uid="$(id -u "$user" 2>/dev/null)" || return 0
	home="$(user_home "$user")" || return 0
	if runuser -u "$user" -- podman container exists "$name" 2>/dev/null; then
		ok "The '$name' box already exists for $user."
		BOXES_MADE+=("$name")
		return 0
	fi
	if [[ "$tool" == distrobox ]]; then
		box_cmd="distrobox create --yes --name $name --image $image"
		[[ -n "$extra" ]] && box_cmd+=" --additional-packages '$extra'"
		# The build tools work from the host's terminal too.
		[[ "$name" == dev ]] && box_cmd+=" && for b in gcc g++ make cmake; do distrobox enter $name -- distrobox-export --bin /usr/bin/\$b --export-path '$home/.local/bin'; done"
	else
		box_cmd="toolbox --assumeyes create --image $image $name"
		[[ -n "$extra" ]] && box_cmd+=" && toolbox run --container $name sudo dnf install -y $extra"
	fi
	if ((DRY_RUN)); then
		info "Would create the $tool box '$name' ($image) for $user in the background"
		return 0
	fi
	if [[ ! -d /run/systemd/system ]] || ! cmd_exists systemd-run; then
		add_action_item 19 LOW "BOX_${name^^}" "Create the '$name' box (as $user): $box_cmd"
		return 0
	fi
	local -a env=(--setenv=HOME="$home")
	[[ -d "/run/user/$uid" ]] && env+=(--setenv=XDG_RUNTIME_DIR="/run/user/$uid")
	log "[RUN]   systemd-run --uid=$uid --unit=fedora-harden-box-$name: $box_cmd"
	if systemd-run --quiet --no-block --collect --unit="fedora-harden-box-$name" --uid="$uid" \
		"${env[@]}" /bin/bash -c "$box_cmd" 2>/dev/null; then
		record_change BOX "$user:$tool:$name"
		BOXES_MADE+=("$name")
		ok "Creating the '$name' box for $user in the background (journalctl -u fedora-harden-box-$name)."
	else
		warn "Could not start creating the '$name' box."
		add_action_item 19 LOW "BOX_${name^^}" "Create the '$name' box (as $user): $box_cmd"
	fi
}

# _render_groups <user> - GPU compute in davincibox needs the render and video groups.
_render_groups() {
	local user="$1" g
	for g in render video; do
		getent group "$g" >/dev/null || continue
		id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -qx "$g" && continue
		if run "usermod -aG $g '$user'"; then
			record_change GROUP_ADD "$user:$g"
		fi
	done
}

# _private_browsing - The "private" use case: Tor Browser (through its launcher,
# which verifies the download) and Mullvad Browser, both from Flathub.
_private_browsing() {
	if ! cmd_exists flatpak || ! flatpak remotes --columns=name 2>/dev/null | grep -qx flathub; then
		((DRY_RUN)) || {
			warn "Flathub is not set up (section 4) — private-browsing browsers not installed."
			return 0
		}
	fi
	info "Private browsing: Tor Browser and Mullvad Browser (Flathub). Only Tor Browser hides who you are; see the README."
	flatpak_install_or_update flathub org.torproject.torbrowser-launcher
	flatpak_install_or_update flathub net.mullvad.MullvadBrowser
	SETUP_CHOICES[PRIVATE_BROWSING]=yes
}

# _flathub_verified - Optionally show only Flathub apps published by their own
# developers (the "verified" subset).
_flathub_verified() {
	cmd_exists flatpak || return 0
	local subset
	subset="$(flatpak remotes --columns=name,subset 2>/dev/null | awk '$1 == "flathub" {print $2}' || true)"
	[[ -n "$subset" ]] || return 0 # no Flathub remote
	if [[ "$subset" == verified ]]; then
		SETUP_CHOICES[FLATHUB_VERIFIED]=yes
		return 0
	fi
	confirm "Show only verified Flathub apps (published by their own developers)? Unverified apps disappear from app stores." no || {
		SETUP_CHOICES[FLATHUB_VERIFIED]=no
		return 0
	}
	if run "flatpak remote-modify --subset=verified flathub"; then
		record_change FLATPAK_SUBSET "flathub:${subset/#-/}"
		SETUP_CHOICES[FLATHUB_VERIFIED]=yes
		ok "Flathub now offers verified apps only (undo: flatpak remote-modify --subset= flathub)."
	fi
}

# _security_key_login - Optionally require the person's security key, as a second
# factor, for sudo and login (pam-u2f through authselect). The key is registered
# first; without a registration nothing changes.
_security_key_login() {
	local user="${TARGET_USER:-${SUDO_USER:-}}" home keys
	[[ -n "$user" && "$user" != root ]] || return 0
	cmd_exists pamu2fcfg && cmd_exists authselect || return 0 # section 1 installs pam-u2f for key owners
	if authselect current 2>/dev/null | grep -q 'with-pam-u2f'; then
		SETUP_CHOICES[PAM_U2F]=yes
		return 0
	fi
	confirm "Require your security key, besides your password, for sudo and login (pam-u2f)? Keep a second key registered: losing the only key locks you out." no || {
		SETUP_CHOICES[PAM_U2F]=no
		return 0
	}
	if ! authselect current >/dev/null 2>&1; then
		add_action_item 19 MEDIUM "PAM_U2F_NO_AUTHSELECT" \
			"This system's PAM is not managed by authselect; add pam_u2f by hand (see man pam_u2f) or run: sudo authselect select local --force"
		return 0
	fi
	home="$(user_home "$user")"
	keys="$home/.config/Yubico/u2f_keys"
	if ((DRY_RUN)); then
		info "Would register $user's security key ($keys) and run: authselect enable-feature with-pam-u2f-2fa"
		return 0
	fi
	if [[ ! -s "$keys" ]]; then
		info "Touch your security key when it blinks (registering it for $user)..."
		backup_file "$keys" || return 0
		install -d -m 700 -o "$user" -g "$user" "$home/.config/Yubico" 2>/dev/null
		if ! runuser -u "$user" -- pamu2fcfg -u "$user" >"$keys" 2>/dev/null || [[ ! -s "$keys" ]]; then
			rm -f "$keys"
			warn "No security key was registered — sudo and login are unchanged."
			return 0
		fi
		chown "$user:" "$keys" && chmod 600 "$keys"
	fi
	if run "authselect enable-feature with-pam-u2f-2fa"; then
		record_change AUTHSELECT_FEATURE with-pam-u2f-2fa
		SETUP_CHOICES[PAM_U2F]=yes
		ok "sudo and login now ask for the security key too. Register a second key: pamu2fcfg -n >> $keys"
	fi
}

# _luks_root_device - The LUKS partition under the root filesystem, if any.
_luks_root_device() {
	local src
	src="$(findmnt -no SOURCE /sysroot 2>/dev/null || findmnt -no SOURCE / 2>/dev/null)"
	src="${src%%[*}"
	[[ -n "$src" ]] || return 1
	lsblk -nrso NAME,FSTYPE "$src" 2>/dev/null | awk '$2 == "crypto_LUKS" {print "/dev/" $1; exit}' | grep .
}

# _disk_unlock - When the root disk is already encrypted, optionally unlock it with
# the TPM plus a PIN, or a FIDO2 key. The passphrase stays as a fallback; no
# keyslot is ever removed except the one added here (by --rollback).
_disk_unlock() {
	local dev kind="" opt name
	dev="$(_luks_root_device)" || return 0
	cmd_exists systemd-cryptenroll || return 0
	if systemd-cryptenroll "$dev" 2>/dev/null | grep -qE 'tpm2|fido2'; then
		SETUP_CHOICES[LUKS_UNLOCK]="$(systemd-cryptenroll "$dev" 2>/dev/null | awk '/tpm2|fido2/ {print ($0 ~ /tpm2/ ? "tpm2" : "fido2"); exit}')"
		return 0
	fi
	if [[ -e /dev/tpmrm0 ]] &&
		confirm "Unlock the encrypted disk with the TPM plus a PIN instead of the long passphrase? (The passphrase keeps working.)" no; then
		kind=tpm2
	elif systemd-cryptenroll --fido2-device=list 2>/dev/null | grep -q /dev/ &&
		confirm "Unlock the encrypted disk with your FIDO2 security key? (The passphrase keeps working.)" no; then
		kind=fido2
	fi
	if [[ -z "$kind" ]]; then
		SETUP_CHOICES[LUKS_UNLOCK]=passphrase
		return 0
	fi
	if ((DRY_RUN)); then
		info "Would enroll $kind for $dev, add $kind-device=auto to /etc/crypttab and rebuild the initramfs"
		return 0
	fi
	if ((GUI_FULL_MODE)); then # enrollment asks for the passphrase in a terminal
		add_action_item 19 LOW "LUKS_$kind" \
			"Unlock the disk with $kind: in a terminal run sudo ./fedora-harden.sh --only 19 (it asks for the passphrase there)."
		return 0
	fi
	info "Enter the disk passphrase, then $([[ $kind == tpm2 ]] && echo 'choose a PIN' || echo 'touch the key')..."
	if [[ "$kind" == tpm2 ]]; then
		systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=yes "$dev" || {
			warn "TPM enrollment did not complete — the disk still unlocks with the passphrase only."
			return 0
		}
	else
		systemd-cryptenroll --fido2-device=auto "$dev" || {
			warn "FIDO2 enrollment did not complete — the disk still unlocks with the passphrase only."
			return 0
		}
	fi
	record_change LUKS_TOKEN "$dev:$kind"
	# Ask for the token at boot: <name> <device> <key> <options>
	opt="$kind-device=auto"
	name="$(awk -v u="$(blkid -s UUID -o value "$dev")" '$2 == "UUID=" u {print $1}' /etc/crypttab 2>/dev/null || true)"
	if [[ -n "$name" ]] && backup_file /etc/crypttab; then
		awk -v n="$name" -v o="$opt" 'BEGIN{OFS="\t"} $1 == n && $4 !~ o {$4 = ($4 == "" || $4 == "none") ? o : $4 "," o} {print}' \
			/etc/crypttab >/etc/crypttab.fh-new && cat /etc/crypttab.fh-new >/etc/crypttab
		rm -f /etc/crypttab.fh-new
	fi
	if ((IS_OSTREE)); then
		if run "rpm-ostree initramfs --enable"; then
			record_change OSTREE_INITRAMFS enable
		fi
	else
		run "dracut -f" || true
	fi
	SETUP_CHOICES[LUKS_UNLOCK]="$kind"
	ok "The disk unlocks with $kind from the next boot (the passphrase still works)."
}

# _opensnitch_pointer - OpenSnitch (an application firewall that asks before apps
# connect out) is not packaged by Fedora; the script installs nothing from outside
# Fedora and Flathub, so it only points to it when the person wants it.
_opensnitch_pointer() {
	confirm "Would you like an application firewall that asks before apps connect to the internet (OpenSnitch)?" no || {
		SETUP_CHOICES[OPENSNITCH]=no
		return 0
	}
	SETUP_CHOICES[OPENSNITCH]=wanted
	add_action_item 19 LOW "OPENSNITCH" \
		"OpenSnitch is not packaged by Fedora, so the script does not install it. Its signed RPMs are on github.com/evilsocket/opensnitch/releases (on an image-based system they must be layered). Expect many questions at first."
}
