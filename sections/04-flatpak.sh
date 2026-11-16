# shellcheck shell=bash
# ============================================================================
#  SECTION 4 — Flatpak / Flathub
# ============================================================================
# sec_04_flatpak() - Configure Flatpak for app sandboxing
# Installs Flatpak, adds Flathub, and offers Flatseal for permission management.
# Optionally installs Firejail for sandboxing non-Flatpak applications
# (inteltechniques.com recommendation); runs firecfg for desktop integration.
sec_04_flatpak() {
	should_run 4 || return 0
	section 4 "Flatpak + Flathub"
	if ! cmd_exists flatpak; then
		pkg_install flatpak
	else
		info "Flatpak already present."
	fi
	run "timeout 120 flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo" ||
		warn "Could not add the Flathub remote (network?) — Flatpak installs below may fail."
	run "timeout 1800 flatpak update -y || true"
	if confirm "Install Flatseal (graphical Flatpak permission manager)?"; then
		flatpak_install_or_update flathub com.github.tchx84.Flatseal
	fi

	# Flatpak's defaults let many apps bypass their sandbox through broad filesystem
	# access; revoke it globally and let apps use portals (file pickers) instead.
	# Source: privacyguides.org — Linux Overview (Flatpak) and "Linux Application
	# Sandboxing" (revoke filesystem=host / filesystem=home). Re-grant per app with
	# Flatseal or `flatpak override --filesystem=...`; undo all: --rollback.
	if cmd_exists flatpak; then
		local fp_global="/var/lib/flatpak/overrides/global"
		if confirm "Block Flatpak apps from reading the whole system (host, host-os, host-etc)?"; then
			backup_file "$fp_global" || return 0
			if run "flatpak override --system --nofilesystem=host --nofilesystem=host-os --nofilesystem=host-etc"; then
				ok "Flatpak apps can no longer read the host filesystem (portals still work)."
			else
				warn "Could not set the global Flatpak override."
			fi
		fi
		# Home-directory access is needed by more apps (editors, IDEs), so it is opt-in.
		if confirm "Also block Flatpak apps from your home directory? (apps then use file portals; some may need a per-app exception)" no; then
			backup_file "$fp_global" || return 0
			run "flatpak override --system --nofilesystem=home" &&
				ok "Flatpak apps can no longer read your home directory."
		fi
	fi

	# Metadata removal for files you share (photos, PDFs, documents).
	# Source: inteltechniques.com — Extreme Privacy (mat2).
	# Image-based systems get the Flatpak (it uses mat2) instead of a layered package.
	if ((IS_OSTREE)); then
		if cmd_exists flatpak && confirm "Install Metadata Cleaner (Flatpak; removes metadata such as GPS location from files before sharing)?"; then
			flatpak_install_or_update flathub io.gitlab.metadatacleaner.metadatacleaner
		fi
	elif confirm "Install mat2 (remove metadata such as GPS location from files before sharing)?"; then
		pkg_install mat2
	fi

	# Firejail is opt-in and off under --yes: privacyguides.org's "Linux Application
	# Sandboxing" notes it is a large setuid binary with a large attack surface that
	# can weaken security. Prefer Flatpak apps with tightened permissions.
	if confirm "Install Firejail? (not recommended by privacyguides.org: setuid sandbox with a large attack surface)" no; then
		pkg_install firejail
		unset '_CMD_CACHE[firecfg]' # Invalidate stale cache after install
		if cmd_exists firecfg; then
			info "Running firecfg to create desktop integration symlinks..."
			run "firecfg || true"
			ok "Firejail installed. Run 'firecfg --list' to see sandboxed apps."
		fi
	fi

	add_action_item 4 MEDIUM "FLATPAK_PERMISSIONS" \
		"Review each Flatpak app in Flatseal: remove network, device=all, PulseAudio, X11 (for Wayland-native apps) and org.freedesktop.secrets access where an app does not need it (privacyguides.org)."
}
