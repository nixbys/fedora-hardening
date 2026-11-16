# shellcheck shell=bash
# ============================================================================
#  SECTION 14 — Firefox
# ============================================================================
# Firefox Flatpak with arkenfox and three extensions (uBlock Origin, LocalCDN,
# Multi-Account Containers); the enterprise policy also turns off telemetry, studies and
# Pocket. Also checks for an active VPN and recommends one when there is none.
sec_14_firefox() {
	should_run 14 || return 0
	section 14 "Firefox hardening (Flatpak preferred + arkenfox + privacy extensions)"

	# Flatpak is preferred for Firefox due to stronger app sandboxing.
	if ! cmd_exists flatpak; then
		warn "flatpak is not available yet; attempting to install it now."
		pkg_install flatpak
		if ((IS_OSTREE)); then
			warn "On rpm-ostree, reboot is required before the newly layered flatpak command is usable."
			warn "Rerun section 14 after reboot."
			return 0
		fi
	fi

	# Keep native RPM Firefox if present, but prefer Flatpak as the managed baseline.
	if pkg_cached firefox; then
		info "Detected native RPM Firefox. Keeping it installed, but Flatpak Firefox remains the hardened preferred browser."
	fi

	run "timeout 120 flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo" ||
		warn "Could not add the Flathub remote (network?) — Flatpak installs below may fail."
	flatpak_install_or_update flathub org.mozilla.firefox

	local ff_user="${TARGET_USER:-${SUDO_USER:-}}"
	if [[ -z "$ff_user" || "$ff_user" == "root" ]]; then
		warn "No non-root user available for profile hardening; installed Firefox Flatpak only."
		return 0
	fi
	if ! id -u "$ff_user" >/dev/null 2>&1; then
		warn "User '$ff_user' does not exist; skipping Firefox profile hardening."
		return 0
	fi

	local home ff_root profiles_ini profile_marker profile_path profile_dir
	home="$(user_home "$ff_user")"
	if [[ -z "$home" ]]; then
		warn "Could not resolve home directory for $ff_user; skipping Firefox profile hardening."
		return 0
	fi
	ff_root="$home/.var/app/org.mozilla.firefox/.mozilla/firefox"
	profiles_ini="$ff_root/profiles.ini"

	# Ensure profile scaffolding exists; if not, ask Firefox to create one.
	if [[ ! -f "$profiles_ini" ]]; then
		run "sudo -u '$ff_user' flatpak run --command=firefox org.mozilla.firefox -CreateProfile hardening-default || true"
	fi

	if [[ ! -f "$profiles_ini" ]]; then
		warn "Firefox profile metadata not found at $profiles_ini"
		warn "Launch Firefox once as '$ff_user' and rerun section 14 to apply arkenfox and extension policy."
		return 0
	fi

	profile_marker="$(awk -F= '
        /^\[Profile[0-9]+\]$/ {in_profile=1; path=""; def=0; rel=1; next}
        /^\[/ && $0 !~ /^\[Profile[0-9]+\]$/ {if (in_profile && def==1 && path!="") {print rel ":" path; exit} in_profile=0}
        in_profile && $1=="Path" {path=$2}
        in_profile && $1=="Default" {def=$2}
        in_profile && $1=="IsRelative" {rel=$2}
        END {if (in_profile && def==1 && path!="") print rel ":" path}
    ' "$profiles_ini")"

	if [[ -z "$profile_marker" ]]; then
		warn "Could not identify Firefox default profile from $profiles_ini; skipping arkenfox deployment."
	else
		if [[ "${profile_marker%%:*}" == "1" ]]; then
			profile_path="${profile_marker#*:}"
			profile_dir="$ff_root/$profile_path"
		else
			profile_dir="${profile_marker#*:}"
		fi

		if [[ -d "$profile_dir" ]]; then
			if ((DRY_RUN)); then
				info "Would install arkenfox ${ARKENFOX_VERSION} user.js (+ privacy overrides) into $profile_dir/user.js"
			else
				local tmp_arken="/tmp/arkenfox-user-$$-$RANDOM-$SECONDS.js"
				register_tmp "$tmp_arken"
				# Pinned release + checksum: a moving branch could change browser
				# settings (proxies, DNS) without review. Bump both together.
				if download_file "https://raw.githubusercontent.com/arkenfox/user.js/${ARKENFOX_VERSION}/user.js" "$tmp_arken" &&
					printf '%s  %s\n' "$ARKENFOX_SHA256" "$tmp_arken" | sha256sum -c --quiet - 2>/dev/null; then
					# Overrides appended after arkenfox (the user-overrides.js convention).
					cat 2>/dev/null >>"$tmp_arken" <<'ARKOVERRIDES'

/*** fedora-harden.sh overrides ***/
// Global Privacy Control + Do Not Track (inteltechniques.com, Extreme Privacy 5th ed.)
user_pref("privacy.globalprivacycontrol.enabled", true);
user_pref("privacy.donottrackheader.enabled", true);
// DNS over HTTPS so Encrypted Client Hello can hide the site name (SNI);
// mode 2 falls back to system DNS (DNS-over-TLS, section 11) for captive portals.
user_pref("network.trr.mode", 2);
user_pref("network.trr.uri", "https://dns.quad9.net/dns-query");
user_pref("network.trr.custom_uri", "https://dns.quad9.net/dns-query");
user_pref("network.dns.echconfig.enabled", true);
user_pref("network.dns.http3_echconfig.enabled", true);
ARKOVERRIDES
					backup_file "$profile_dir/user.js" || return 0
					if ! install -m 0600 -o "$ff_user" -g "$ff_user" "$tmp_arken" "$profile_dir/user.js" 2>/dev/null; then
						warn "Failed to install arkenfox user.js (filesystem may be read-only)"
					else
						ok "Installed arkenfox ${ARKENFOX_VERSION} user.js with GPC, DNT and DNS-over-HTTPS into $profile_dir"
					fi
				else
					warn "arkenfox ${ARKENFOX_VERSION} download failed or did not match its checksum; Firefox keeps its current settings."
					add_action_item 14 MEDIUM "ARKENFOX_NOT_INSTALLED" \
						"arkenfox user.js was not installed (download or checksum failed). Re-run: sudo ./fedora-harden.sh --only 14"
				fi
				rm -f "$tmp_arken" 2>/dev/null || true
			fi
		else
			warn "Resolved Firefox profile directory '$profile_dir' does not exist; skipping arkenfox deployment."
		fi
	fi

	# Install requested extensions via Firefox enterprise policy.
	local policy_dir policy_file
	policy_dir="$ff_root/distribution"
	policy_file="$policy_dir/policies.json"

	if ((DRY_RUN)); then
		info "Would write Firefox extension policy to $policy_file"
	else
		install -d -m 0700 -o "$ff_user" -g "$ff_user" "$policy_dir" 2>/dev/null || true
		local tmp_policy="/tmp/firefox-policies-$$-$RANDOM-$SECONDS.json"
		register_tmp "$tmp_policy"
		if ! cat 2>/dev/null >"$tmp_policy" <<'EOF'
{
  "policies": {
    "DisableTelemetry": true,
    "DisableFirefoxStudies": true,
    "DisablePocket": true,
    "OverrideFirstRunPage": "",
    "OverridePostUpdatePage": "",
    "Extensions": {
      "Install": [
        "https://addons.mozilla.org/firefox/downloads/latest/ublock-origin/latest.xpi",
        "https://addons.mozilla.org/firefox/downloads/latest/localcdn-fork-of-decentraleyes/latest.xpi",
        "https://addons.mozilla.org/firefox/downloads/latest/multi-account-containers/latest.xpi"
      ]
    },
    "ExtensionSettings": {
      "*": {
        "installation_mode": "allowed"
      }
    }
  }
}
EOF
		then
			warn "Failed to write Firefox policy JSON"
			rm -f "$tmp_policy" 2>/dev/null || true
			return 1
		fi
		if ! install -m 0600 -o "$ff_user" -g "$ff_user" "$tmp_policy" "$policy_file" 2>/dev/null; then
			warn "Failed to install Firefox policy (filesystem may be read-only)"
			rm -f "$tmp_policy" 2>/dev/null || true
			return 1
		fi
		rm -f "$tmp_policy" 2>/dev/null || true
		ok "Installed Firefox extension policy at $policy_file"
	fi

	run "sudo -u '$ff_user' xdg-settings set default-web-browser org.mozilla.firefox.desktop || true"
	info "Firefox hardening complete for user '$ff_user' (Flatpak + arkenfox + uBlock Origin/LocalCDN/Multi-Account Containers policy + telemetry disabled)."
	info "Restart Firefox to apply enterprise policy installs and arkenfox preferences."

	# --- 14b: VPN detection and recommendation ---------------------------------
	info "Checking for an active VPN connection (system or browser)..."
	local vpn_found=0 vpn_source=""

	# Check for WireGuard interfaces
	if ip link show 2>/dev/null | grep -qE '^[0-9]+: wg[0-9]+'; then
		vpn_found=1 vpn_source="WireGuard interface"
	fi

	# Check active NetworkManager VPN connections
	if ! ((vpn_found)) && cmd_exists nmcli; then
		if nmcli connection show --active 2>/dev/null | grep -qi 'vpn'; then
			vpn_found=1 vpn_source="NetworkManager VPN"
		fi
	fi

	# Check running VPN daemon processes
	local _vp
	for _vp in openvpn mullvad protonvpn; do
		if ! ((vpn_found)) && pgrep -x "$_vp" >/dev/null 2>&1; then
			vpn_found=1 vpn_source="$_vp process"
		fi
	done

	# Check Mullvad CLI status if available
	if ! ((vpn_found)) && cmd_exists mullvad; then
		local _ms
		_ms="$(mullvad status 2>/dev/null || true)"
		if [[ "$_ms" == *"Connected"* ]]; then
			vpn_found=1 vpn_source="Mullvad VPN"
		fi
	fi

	# Check Firefox profile extensions directory for known VPN extension patterns
	if ! ((vpn_found)) && [[ -d "$ff_root" ]]; then
		if find "$ff_root" -maxdepth 5 \( -iname '*vpn*' -o -iname '*mullvad*' -o -iname '*proton*' -o -iname '*ivpn*' \) 2>/dev/null | grep -q .; then
			vpn_found=1 vpn_source="browser VPN extension"
		fi
	fi

	if ((vpn_found)); then
		ok "VPN detected ($vpn_source) — no action needed."
	else
		warn "No active VPN detected on this system or in Firefox."
		if ((! GUI_FULL_MODE)); then
			cat <<'VPNEOF'

  ╔══════════════════════════════════════════════════════════════════════╗
  ║  VPN Recommendations (privacyguides.org + inteltechniques.com)      ║
  ╚══════════════════════════════════════════════════════════════════════╝

  All three options below are audited, open-source, no-logs VPNs. They
  support WireGuard and accept anonymous payment methods (cash / Monero).
  Section 15 installs a provider's WireGuard config with a kill switch.

  1. Mullvad VPN — https://mullvad.net
     • No account e-mail needed; each account is a random 16-digit number
     • Accepts cash, Monero, and other crypto; no payment record tied to identity
     • Audited no-logs policy; open-source Linux app + browser extension
     • Top pick by privacyguides.org AND Michael Bazzell (inteltechniques.com)
     • Install:  flatpak install flathub net.mullvad.MullvadVpn
       or download the native app:  https://mullvad.net/en/download/linux

  2. ProtonVPN — https://protonvpn.com
     • Based in Switzerland; independently audited no-logs; open-source apps
     • Free tier available; strong integration with Proton Mail/Drive ecosystem
     • Supports WireGuard, OpenVPN, and Stealth protocol (censorship bypass)
     • Recommended by privacyguides.org
     • Install:  flatpak install flathub com.protonvpn.desktop
       or see:   https://protonvpn.com/support/linux-vpn-setup/

  3. IVPN — https://ivpn.net
     • No e-mail or personal info required to create an account
     • Accepts cash and Monero; audited no-logs; multi-hop routing available
     • Supports WireGuard + OpenVPN; includes ad/tracker blocking (AntiTracker)
     • Recommended by privacyguides.org AND Michael Bazzell (inteltechniques.com)
     • Install:  https://ivpn.net/apps-linux/

  WireGuard with a kill switch (after choosing a provider): download its
  WireGuard config (full tunnel), then let section 15 install it:
    sudo ./fedora-harden.sh --only 15 --wireguard-config <provider>.conf

VPNEOF
		else
			gui_alert warning "No VPN detected.\n\nRecommended VPNs (privacyguides.org + inteltechniques.com):\n• Mullvad VPN — mullvad.net (flatpak install flathub net.mullvad.MullvadVpn)\n• ProtonVPN — protonvpn.com (flatpak install flathub com.protonvpn.desktop)\n• IVPN — ivpn.net"
		fi
		add_action_item 14 MEDIUM "NO_VPN_DETECTED" \
			"No VPN detected — install Mullvad (recommended), ProtonVPN, or IVPN. See section 14b output and section 15 for WireGuard setup."
	fi
}
