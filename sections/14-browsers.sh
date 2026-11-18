# shellcheck shell=bash
# ============================================================================
#  SECTION 14 — Browsers
# ============================================================================
# 14a  Firefox Flatpak with arkenfox and three extensions (uBlock Origin, LocalCDN,
#      Multi-Account Containers); the enterprise policy also turns off telemetry,
#      studies and Pocket.
# 14b  Checks for an active VPN and recommends one when there is none.
# 14c  Brave, Chromium and Chrome, when installed: an admin policy that turns off
#      their telemetry and extras and turns on their tracking protections.
# 14d  Tor Browser and Mullvad Browser, offered (opt-in) as private browsers.
sec_14_browsers() {
	should_run 14 || return 0
	section 14 "Browsers (Firefox + arkenfox, Chromium-based policies, private browsers)"
	_harden_firefox || true
	_vpn_check
	_chromium_policies
	_offer_private_browsers
}

# _harden_firefox - 14a: Firefox Flatpak, arkenfox and the enterprise policy.
_harden_firefox() {
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

}

# _vpn_check - 14b: VPN detection and recommendation.
_vpn_check() {
	info "Checking for an active VPN connection (system or browser)..."
	local vpn_found=0 vpn_source="" ff_root="" _vpn_user _vpn_home
	# Firefox profile root, to look for a VPN browser extension below.
	_vpn_user="${TARGET_USER:-${SUDO_USER:-}}"
	if [[ -n "$_vpn_user" && "$_vpn_user" != root ]]; then
		_vpn_home="$(user_home "$_vpn_user")"
		[[ -n "$_vpn_home" ]] && ff_root="$_vpn_home/.var/app/org.mozilla.firefox/.mozilla/firefox"
	fi

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

# _chromium_policy <brave|chromium> - The managed policy (JSON) for a Chromium-based
# browser: no telemetry or extras, tracking protections on. DNS stays with the
# system resolver (section 11's DNS over TLS) so there is one encrypted DNS path,
# and it follows a VPN's DNS when one is up.
_chromium_policy() {
	local brave=""
	[[ "$1" == brave ]] && brave='
  "BraveRewardsDisabled": true,
  "BraveWalletDisabled": true,
  "BraveVPNDisabled": true,
  "BraveAIChatEnabled": false,
  "BraveLocalAIEnabled": false,
  "BraveNewsDisabled": true,
  "BraveTalkDisabled": true,
  "BraveP3AEnabled": false,
  "BraveStatsPingEnabled": false,
  "BraveWebDiscoveryEnabled": false,
  "BraveGlobalPrivacyControlEnabled": true,
  "BraveDeAmpEnabled": true,
  "BraveDebouncingEnabled": true,
  "BraveTrackingQueryParametersFilteringEnabled": true,
  "BraveReduceLanguageEnabled": true,
  "DefaultBraveAdblockSetting": 2,
  "DefaultBraveFingerprintingV2Setting": 3,
  "DefaultBraveHttpsUpgradeSetting": 2,
  "TorDisabled": true,'
	cat <<JSON
{${brave}
  "MetricsReportingEnabled": false,
  "UrlKeyedAnonymizedDataCollectionEnabled": false,
  "FeedbackSurveysEnabled": false,
  "UserFeedbackAllowed": false,
  "SpellCheckServiceEnabled": false,
  "SearchSuggestEnabled": false,
  "AlternateErrorPagesEnabled": false,
  "NetworkPredictionOptions": 2,
  "BackgroundModeEnabled": false,
  "ShoppingListEnabled": false,
  "SafeBrowsingProtectionLevel": 1,
  "BlockThirdPartyCookies": true,
  "HttpsOnlyMode": "force_enabled",
  "DnsOverHttpsMode": "off",
  "WebRtcIPHandling": "default_public_interface_only",
  "PrivacySandboxPromptEnabled": false,
  "PrivacySandboxAdTopicsEnabled": false,
  "PrivacySandboxSiteEnabledAdsEnabled": false,
  "PrivacySandboxAdMeasurementEnabled": false,
  "AutofillAddressEnabled": false,
  "AutofillCreditCardEnabled": false,
  "PaymentMethodQueryEnabled": false
}
JSON
}

# _chromium_policies - 14c: managed policies for the Chromium-based browsers that
# are installed (native package or Flatpak). Brave's Flatpak reads the host's
# /etc/brave/policies; Chromium's Flatpak reads them through an extension point
# under /var/lib/flatpak, linked here to /etc/chromium.
_chromium_policies() {
	local brave=0 chromium=0 chromium_flatpak=0 chrome=0 names=()
	{ pkg_cached brave-browser || flatpak info com.brave.Browser &>/dev/null; } && brave=1
	pkg_cached chromium && chromium=1
	flatpak info org.chromium.Chromium &>/dev/null && chromium=1 chromium_flatpak=1
	pkg_cached google-chrome-stable && chrome=1
	((brave)) && names+=(Brave)
	((chromium)) && names+=(Chromium)
	((chrome)) && names+=(Chrome)
	if ((${#names[@]} == 0)); then
		info "No Brave, Chromium or Chrome installed — no Chromium-based policies needed."
		return 0
	fi
	info "Chromium-based browsers found: ${names[*]}. A managed policy turns off their telemetry and extras; they will show 'Managed by your organization'."
	confirm "Apply privacy policies to ${names[*]}?" || return 0

	if ((brave)); then
		_chromium_policy brave | write_new_file /etc/brave/policies/managed/fedora-harden.json 644 &&
			ok "Brave: telemetry, Rewards, Wallet, VPN, AI chat and Tor windows off; ad, tracker and fingerprinting protection on (/etc/brave/policies/managed)."
		# Brave's Flatpak reads the policy through host-etc, which section 4's global
		# override blocks. Flatpak can't expose a single /etc folder, so Brave alone
		# gets /etc read-only (no secrets there are readable by a user anyway).
		if flatpak info com.brave.Browser &>/dev/null &&
			grep -q 'host-etc' /var/lib/flatpak/overrides/global 2>/dev/null; then
			backup_file /var/lib/flatpak/overrides/com.brave.Browser &&
				run "flatpak override --system --filesystem=host-etc:ro com.brave.Browser" &&
				ok "Brave Flatpak may read /etc (read-only) so it can load the policy."
		fi
	fi
	if ((chromium)); then
		_chromium_policy chromium | write_new_file /etc/chromium/policies/managed/fedora-harden.json 644 &&
			ok "Chromium: telemetry and Privacy Sandbox off, third-party cookies blocked, HTTPS only (/etc/chromium/policies/managed)."
		if ((chromium_flatpak)); then
			local ext
			ext="/var/lib/flatpak/extension/org.chromium.Chromium.Extension.system-policies/$(uname -m)/1"
			if [[ "$(readlink "$ext" 2>/dev/null)" != /etc/chromium ]]; then
				if ((DRY_RUN)); then
					info "Would link $ext -> /etc/chromium (Chromium Flatpak policy extension)"
				elif backup_file "$ext"; then
					install -d -m 755 "$(dirname "$ext")" && ln -sfn /etc/chromium "$ext" &&
						ok "Chromium Flatpak reads the policy through $ext."
				fi
			fi
		fi
	fi
	if ((chrome)); then
		_chromium_policy chrome | write_new_file /etc/opt/chrome/policies/managed/fedora-harden.json 644 &&
			ok "Chrome: telemetry and Privacy Sandbox off, third-party cookies blocked, HTTPS only (/etc/opt/chrome/policies/managed)."
		add_action_item 14 LOW "CHROME_INSTALLED" \
			"Google Chrome is installed. Even with the policy it reports to Google; Brave or Firefox (both hardened by section 14) protect privacy better."
	fi
	info "Restart the browser, then check chrome://policy (brave://policy) to see the policy in effect."
}

# _offer_private_browsers - 14d: Tor Browser and Mullvad Browser, opt-in. The
# "private" use case (section 19) installs them without asking.
_offer_private_browsers() {
	local profile="$PROFILE_ARG"
	[[ -n "$profile" ]] || profile="$(sed -n 's/^USE_CASES=//p' /etc/fedora-harden/profile 2>/dev/null | tr -d '"' || true)"
	if [[ ",${profile// /,}," == *,private,* ]]; then
		info "Tor Browser and Mullvad Browser come with the 'private' use case (section 19)."
		return 0
	fi
	if flatpak info org.torproject.torbrowser-launcher &>/dev/null && flatpak info net.mullvad.MullvadBrowser &>/dev/null; then
		info "Tor Browser and Mullvad Browser are installed; Flatpak keeps them updated."
		return 0
	fi
	confirm "Install Tor Browser and Mullvad Browser for private browsing?" no || return 0
	_private_browsing
}
