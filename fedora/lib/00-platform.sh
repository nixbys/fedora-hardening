# shellcheck shell=bash
# ---------- Platform: Fedora (Workstation, Server, Atomic desktops, remixes) -----
# Everything core/ needs from a distribution family. A family provides:
#   SECTIONS, PLATFORM_PKG_LABEL, PLATFORM_RELEASE, PLATFORM_GUI_PACKAGES
#   platform_detect          os-release and variant detection (sets IS_OSTREE, HAS_*)
#   list_sections            the --list text; its first block names the sections
#   section_compatible N     whether section N applies to this machine
#   pkg_cached, pkg_install, pkg_upgrade   the package backend (journals PKG_INSTALL)
#   safety_point             a way back before the first change (see 37-safety-point.sh)
#   platform_score_rows      scorecard rows for the firewall, updates and MAC
#   platform_run_sections    the sections, in order
#   platform_after_run       steps that must come after everything else was written
#   platform_undo_change T D, platform_undo_finish   --rollback of family entries
#   platform_reload_paths P...  reload family services after --rollback restored files P
# core/ must not call distribution tools itself; the static tier checks that.

# Sections run in numeric order, which follows the dependency flow. --only/--skip accept these.
SECTIONS=(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24)
PLATFORM_PKG_LABEL="dnf (mutable)" # rpm-ostree on image-based systems (platform_detect)
PLATFORM_RELEASE="unknown"         # Fedora release, for the recovery file
PLATFORM_GUI_PACKAGES=(python3-gobject gobject-introspection gtk4 libadwaita)

# Fedora variant flags (platform_detect)
IS_KINOITE=0             # Set to 1 if Fedora Kinoite (immutable + KDE)
IS_SILVERBLUE=0          # Set to 1 if Fedora Silverblue (immutable + GNOME)
IS_ONYX=0                # Set to 1 if Fedora Onyx (immutable + GNOME, Atomic)
IS_SERICEA=0             # Set to 1 if Fedora Sericea (immutable + Sway, Atomic)
IS_LAZURITE=0            # Set to 1 if Fedora Lazurite (immutable + LXQt, Atomic)
IS_VAUXITE=0             # Set to 1 if Fedora Vauxite (immutable + XFCE, Atomic)
IS_BAZZITE=0             # Set to 1 if Bazzite (gaming remix, KDE or GNOME)
IS_AURORA=0              # Set to 1 if Aurora (Universal Blue KDE remix)
IS_SERVER=0              # Set to 1 if Fedora Server
IS_WORKSTATION=0         # Set to 1 if Fedora Workstation
IS_IOT=0                 # Set to 1 if Fedora IoT (immutable)
IS_CLOUD=0               # Set to 1 if Fedora Cloud
IS_COREOS=0              # Set to 1 if Fedora CoreOS (immutable)
IS_ATOMIC_DESKTOP=0      # Set to 1 if Atomic Desktop variant
IS_GAMING_SPIN=0         # Set to 1 if gaming-oriented spin (Bazzite, etc.)
FEDORA_VARIANT="unknown" # Human-readable Fedora variant name
FEDORA_MAJOR=0           # Fedora major version number
# platform_detect - Read /etc/os-release and set the variant and desktop flags.
platform_detect() {
	# Distro check: Verify this is a Fedora system and detect variant
	# Sources /etc/os-release to extract distribution metadata
	if [[ ! -r /etc/os-release ]]; then
		err "Cannot read /etc/os-release — is this Fedora?"
		exit 1
	fi
	# shellcheck source=/dev/null
	. /etc/os-release
	[[ "${ID:-}" == "fedora" ]] || warn "Distro ID is '${ID:-unknown}', not 'fedora'. Proceeding anyway."
	if [[ -e /run/ostree-booted ]]; then
		IS_OSTREE=1
	fi
	FEDORA_VARIANT="${VARIANT_ID:-${VARIANT:-unknown}}"
	detect_fedora_release_type
	detect_desktop_envs
	((IS_KINOITE)) && HAS_KDE=1
	if [[ "${VERSION_ID:-}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
		FEDORA_MAJOR="${VERSION_ID%%.*}"
	fi
	if ((FEDORA_MAJOR > 0 && FEDORA_MAJOR < 44)); then
		warn "Fedora version is '${VERSION_ID:-unknown}' — guide targets Fedora 44+."
		confirm "Proceed on this older version?" || exit 0
	fi
	info "Host: $HOST_LABEL   Distro: ${PRETTY_NAME:-?}   Kernel: $KERNEL_LABEL"
	info "Variant: ${FEDORA_VARIANT}"
	info "Release flags: workstation=$IS_WORKSTATION server=$IS_SERVER iot=$IS_IOT cloud=$IS_CLOUD coreos=$IS_COREOS ostree=$IS_OSTREE atomic_desktop=$IS_ATOMIC_DESKTOP"
	if ((IS_OSTREE)); then
		info "Detected rpm-ostree (immutable) host. Using rpm-ostree for package/update actions."
	fi
	if ((IS_KINOITE)); then
		info "Detected Fedora Kinoite variant."
	fi
	if ((IS_SILVERBLUE)); then
		info "Detected Fedora Silverblue variant. KDE-only tweaks will be skipped where incompatible."
	fi
	if ((IS_WORKSTATION)); then
		info "Detected Fedora Workstation variant. Desktop-focused sections are enabled."
	fi
	if ((IS_SERVER)); then
		info "Detected Fedora Server release profile."
	fi
	if ((IS_IOT)); then
		info "Detected Fedora IoT release profile."
	fi
	if ((IS_CLOUD)); then
		info "Detected Fedora Cloud release profile."
	fi
	if ((IS_COREOS)); then
		info "Detected Fedora CoreOS release profile."
	fi
	info "Fedora major version detected: ${FEDORA_MAJOR}"
	PLATFORM_RELEASE="$FEDORA_MAJOR"
	((FEDORA_MAJOR > 0)) || PLATFORM_RELEASE="$(rpm -E %fedora 2>/dev/null || echo unknown)"
	((IS_OSTREE)) && PLATFORM_PKG_LABEL="rpm-ostree (immutable)"
	return 0
}

list_sections() {
	cat <<'EOF'
   1  System updates (incl. fwupd firmware/microcode + hardware key support)
   2  Automatic updates
   3  Secure Boot verify
   4  Flatpak / Flathub, global Flatpak restrictions, mat2 (Firejail opt-in)
   5  SELinux tools
   6  firewalld
   7  SSH hardening
   8  PAM/password policy (incl. sudo use_pty)
   9  Kernel sysctl (incl. IPv6 privacy extensions, io_uring for root only)
  10  auditd (incl. time/network/mount rules, deletes under /etc)
  11  DNS over TLS (11b: NetworkManager MAC address randomization)
  12  Fail2Ban
  13  Desktop environment settings (auto-dispatches by detected DE):
       KDE Plasma  — kwriteconfig6/5: screen lock, recent-docs, BT opt-out
       GNOME/Onyx  — gsettings: lock, location off, privacy (mic off if asked)
       Budgie      — gsettings (GNOME backend): same privacy stack
       Cinnamon    — org.cinnamon.desktop.screensaver + GNOME privacy schemas
       MATE        — org.mate.screensaver + org.mate.power-manager
       XFCE/Vauxite— xfconf-query: screensaver + power manager idle
       Sway/Sericea— writes swaylock.conf + swayidle.conf
       Hyprland    — writes hypridle.conf (lock 5 min, suspend 10 min)
       i3          — xss-lock + i3lock drop-in via config.d/
       LXQt/Lazurite — lxqt-screensaver.conf + lxqt-powermanagement.conf
  14  Browsers: Firefox + arkenfox, Brave/Chromium/Chrome policies, VPN check, Tor/Mullvad Browser (opt-in)
  15  WireGuard tunnel with kill switch (--wireguard-config FILE)
  16  ClamAV (weekly scan of /home, on-access opt-in; image-based: container scan)
  17  OpenSCAP (image-based: from a container)
  18  Container security (Podman + toolbox/distrobox / containerized-mindset setup)
  19  Your routine: upkeep, health and drift checks for your use cases (--profile)
  20  Home snapshots (Btrfs) or incremental copies, as often as the machine is used
  21  Service trim
  22  File permissions (incl. umask 077 for users, core dump limits, hostname privacy)
  23  USBGuard
  24  AIDE file integrity (image-based: image signature + /etc change report)

 Execution order: 1 to 24. The numbers follow the dependency flow.

 DE detection (section 13 auto-dispatches — all detected DEs are hardened):
    Running session: XDG_CURRENT_DESKTOP / DESKTOP_SESSION
    Installed tools: kwriteconfig, gnome-shell, cinnamon, mate-session,
                     xfce4-session, startlxqt, sway, Hyprland, i3, budgie-desktop
    Spin → DE:  Kinoite/Aurora→KDE  Silverblue/Onyx→GNOME  Sericea→Sway
                Lazurite→LXQt  Vauxite→XFCE  Bazzite→KDE or GNOME

 Supported Fedora variants (auto-detected):
    Workstation, Server, IoT, Cloud, CoreOS
    Kinoite (KDE), Silverblue (GNOME), Onyx (GNOME Atomic)
    Sericea (Sway Atomic), Lazurite (LXQt Atomic), Vauxite (XFCE Atomic)
    Bazzite (gaming), Aurora / Universal Blue (KDE)
    XFCE/LXQt/Cinnamon/MATE/Budgie spins (mutable)
EOF
}

# Check once that the repositories answer (bounded time). An unreachable repository
# that drops packets makes every dnf call wait out its timeouts and retries; without
# this check one such repository stalled a run for well over half an hour. When it
# fails, package work is skipped with one follow-up.
_DNF_REPOS_CHECKED=0
_DNF_REPOS_OK=1
dnf_repos_ready() {
	((DRY_RUN)) && return 0
	if ((! _DNF_REPOS_CHECKED)); then
		_DNF_REPOS_CHECKED=1
		info "Checking that the package repositories answer (dnf makecache)..."
		if ! timeout "${DNF_CHECK_TIMEOUT:-600}" dnf makecache -q >/dev/null 2>"${ERROR_CAPTURE_FILE:-/dev/null}"; then
			_DNF_REPOS_OK=0
			warn "The package repositories did not answer — package installs and upgrades are skipped this run."
			add_action_item 0 HIGH "PKG_REPOS_UNREACHABLE" \
				"The package repositories could not be reached (network, proxy or a broken .repo file in /etc/yum.repos.d — see 'sudo dnf makecache'). Fix that, then re-run the script; sections that need packages will complete."
		fi
	fi
	((_DNF_REPOS_OK))
}

# On rpm-ostree systems the upgrade is staged for the next boot. Failures are
# warnings, not fatal: transient repository conflicts or network issues must not
# abort the remaining sections.
pkg_upgrade() {
	local rc=0
	if ((IS_OSTREE)); then
		run "rpm-ostree upgrade" || rc=$?
		if ((rc != 0)); then
			local stderr_content=""
			[[ -f "$ERROR_CAPTURE_FILE" ]] && stderr_content=$(<"$ERROR_CAPTURE_FILE")
			if [[ "$stderr_content" =~ depsolve|conflicting[[:space:]]requests|cannot[[:space:]]install[[:space:]]both ]]; then
				warn "rpm-ostree upgrade failed due to a package resolution conflict; continuing without staging an upgrade."
			else
				warn "rpm-ostree upgrade failed (exit $rc); continuing without staging an upgrade."
			fi
			warn "Continuing with remaining hardening sections."
		else
			warn "rpm-ostree upgrades are staged and applied on reboot. Reboot when this script completes."
		fi
	else
		dnf_repos_ready || return 0
		run "dnf upgrade --refresh -y" || rc=$?
		if ((rc != 0)); then
			warn "dnf upgrade failed (exit $rc) — check repo availability and re-run manually."
			warn "Continuing with remaining hardening sections."
		fi
	fi
	return 0
}

# Fill _PKG_PENDING_CACHE from the staged/pending rpm-ostree layer (once per run), so
# pkg_install does not re-request packages that a previous run layered before a reboot
# ("Package X is already requested").
_OSTREE_STAGED_LOADED=0
_load_ostree_staged_packages() {
	((_OSTREE_STAGED_LOADED)) && return 0
	((IS_OSTREE)) || return 0
	_OSTREE_STAGED_LOADED=1
	local pkg
	# Parse LayeredPackages tokens in one awk pass to avoid extra sed/tr/grep forks.
	while IFS= read -r pkg; do
		[[ -n "$pkg" ]] && _PKG_PENDING_CACHE[$pkg]=1
	done < <(
		local out rc=0
		out=$(rpm-ostree status 2>&1) || rc=$?
		if ((rc != 0)); then
			warn "Failed to query rpm-ostree staged packages"
			return 1
		fi
		# Use a here-string to avoid a fork for the echo process.
		awk '
            /LayeredPackages:/ {
                sub(/.*LayeredPackages:[[:space:]]*/, "", $0)
                for (i=1; i<=NF; i++) {
                    if ($i !~ /^\(/) print $i
                }
            }
        ' <<<"$out"
	)
}

# dnf, or rpm-ostree on image-based systems. Skips packages already installed and, on
# rpm-ostree, ones a previous run staged before a reboot (requesting them again fails
# with "Package X is already requested"). Honors --dry-run.
pkg_install() {
	local pkgs=("$@") needed=() pkg
	((${#pkgs[@]} == 0)) && return 0

	# On rpm-ostree, pre-load staged packages so we don't re-request them.
	((IS_OSTREE)) && _load_ostree_staged_packages

	# Filter already-cached/installed packages from install list (caching optimization)
	for pkg in "${pkgs[@]}"; do
		# On rpm-ostree, skip packages already queued (this run or a prior pending layer).
		if ((IS_OSTREE)) && [[ "${_PKG_PENDING_CACHE[$pkg]:-0}" -eq 1 ]]; then
			info "Package '${pkg}' already in rpm-ostree pending layer — skipping."
			continue
		fi
		pkg_cached "$pkg" || needed+=("$pkg")
	done

	((${#needed[@]} == 0)) && {
		info "All packages already installed (cached)."
		return 0
	}

	if ((DRY_RUN)); then
		if ((IS_OSTREE)); then
			info "Would run: rpm-ostree install ${needed[*]}"
		else
			info "Would run: dnf install -y ${needed[*]}"
		fi
		return 0
	fi

	if ((IS_OSTREE)); then
		local out rc
		log "[RUN]   rpm-ostree install ${needed[*]}"
		# Capture output and exit code without triggering set -e abort on failure
		out="$(rpm-ostree install "${needed[@]}" 2>&1)" || rc=$?
		rc=${rc:-0}
		# Logging must never abort the run (set -e), even if the log is unwritable.
		[[ -n "${out}" ]] && printf '%s\n' "$out" | log_stream

		if ((rc != 0)); then
			# Idempotent rpm-ostree no-op cases should not abort under strict mode.
			if [[ "$out" =~ already[[:space:]]requested|already[[:space:]]provided|No[[:space:]]packages[[:space:]]in[[:space:]]transaction|is[[:space:]]already[[:space:]]provided ]]; then
				warn "rpm-ostree reports package(s) already queued/provided; treating as up-to-date."
			else
				# As with dnf: a package that cannot be layered (not in the image's
				# repositories — Bazzite ships without Fedora's — or no network) must
				# not abort the remaining sections; callers check for what they need.
				capture_error_context "$(source_line "${BASH_SOURCE[1]:-$0}" "${BASH_LINENO[0]:-?}")" "rpm-ostree install ${needed[*]}" "$rc" "/dev/null" || true
				local reason
				reason="$(grep -m1 -iE 'error|not found' <<<"$out" || true)"
				warn "rpm-ostree could not layer: ${needed[*]}${reason:+ — $reason}"
				add_action_item "${CURRENT_SECTION:-0}" MEDIUM "PKG_INSTALL_FAILED_${needed[0]//[^a-zA-Z0-9]/_}" \
					"Package layering failed${reason:+ ($reason)}: sudo rpm-ostree install ${needed[*]} — if the image does not carry the package, use a Flatpak or a toolbox/distrobox instead."
				return 0
			fi
		fi

		# Mark requested packages as pending to avoid redundant layering attempts this run.
		for pkg in "${needed[@]}"; do
			_PKG_PENDING_CACHE[$pkg]=1
		done
		record_change PKG_INSTALL "${needed[*]}"
		warn "Layered packages are applied on reboot. Reboot when this script completes."
	else
		if ! dnf_repos_ready; then
			warn "Skipping install of ${needed[*]} (repositories unreachable)."
			return 0
		fi
		# Record every package the transaction adds (dependencies and weak
		# dependencies included), so --rollback removes exactly what came in.
		local pkgs_before=""
		((DRY_RUN)) || pkgs_before="$(rpm -qa --qf '%{NAME}.%{ARCH}\n' 2>/dev/null | sort -u)"
		if ! run "dnf install -y ${needed[*]}"; then
			# A missing/renamed package must not abort every remaining section; the
			# callers check for the commands they need and skip what is unavailable.
			warn "dnf install failed for: ${needed[*]}"
			add_action_item "${CURRENT_SECTION:-0}" MEDIUM "PKG_INSTALL_FAILED_${needed[0]//[^a-zA-Z0-9]/_}" \
				"Package install failed: sudo dnf install -y ${needed[*]}"
			return 0
		fi
		# Keep package cache coherent after successful mutable-system installs.
		for pkg in "${needed[@]}"; do
			_PKG_CACHE[$pkg]=0
		done
		local added=""
		if [[ -n "$pkgs_before" ]]; then
			added="$(comm -13 <(printf '%s\n' "$pkgs_before") <(rpm -qa --qf '%{NAME}.%{ARCH}\n' 2>/dev/null | sort -u) | tr '\n' ' ')"
		fi
		added="${added% }"
		record_change PKG_INSTALL "${added:-${needed[*]}}"
		# New binaries may now exist; refresh command cache.
		unset _CMD_CACHE
		declare -gA _CMD_CACHE=()
	fi
}

# The pet-container tool to use on this system: distrobox on Universal Blue images
# (they ship distrobox, not toolbox), toolbox elsewhere.
image_box_tool() {
	if [[ -r /usr/share/ublue-os/image-info.json ]] && cmd_exists distrobox; then
		echo distrobox
	elif cmd_exists toolbox || ! cmd_exists distrobox; then
		echo toolbox
	else
		echo distrobox
	fi
}

# Whether a package is installed, cached for the run (avoids repeated rpm -q).
declare -gA _PKG_CACHE=()         # Session cache for package status
declare -gA _PKG_PENDING_CACHE=() # rpm-ostree pending/staged layer packages (pre-loaded from live status + current-run requests)
pkg_cached() {
	local pkg="$1"
	if [[ -v _PKG_CACHE[$pkg] ]]; then
		return "${_PKG_CACHE[$pkg]}"
	fi
	# Several names the script uses are only *provided* by another package on
	# Fedora 44/45 (clamav-update → clamav-freshclam, wget → wget2-wget,
	# dnf-automatic → dnf5-plugin-automatic). `rpm -q <name>` misses those, which
	# made every run re-attempt the install; --whatprovides resolves them.
	if rpm -q "$pkg" >/dev/null 2>&1 || rpm -q --whatprovides "$pkg" >/dev/null 2>&1; then
		_PKG_CACHE[$pkg]=0
		return 0
	else
		_PKG_CACHE[$pkg]=1
		return 1
	fi
}

# Classify the Fedora edition from os-release: official variants, Atomic desktops and
# remixes (Bazzite, Aurora, Universal Blue). Sets the IS_* flags.
detect_fedora_release_type() {
	local release_blob
	release_blob="${NAME:-} ${PRETTY_NAME:-} ${VARIANT:-} ${VARIANT_ID:-} ${CPE_NAME:-} ${PLATFORM_ID:-} ${ID_LIKE:-}"
	release_blob="${release_blob,,}"

	# Official Fedora variants
	[[ "$release_blob" == *"workstation"* ]] && IS_WORKSTATION=1
	[[ "$release_blob" == *"server"* ]] && IS_SERVER=1
	[[ "$release_blob" == *"kinoite"* ]] && IS_KINOITE=1
	[[ "$release_blob" == *"silverblue"* ]] && IS_SILVERBLUE=1
	[[ "$release_blob" == *"onyx"* ]] && IS_ONYX=1
	[[ "$release_blob" == *"sericea"* ]] && IS_SERICEA=1
	[[ "$release_blob" == *"lazurite"* ]] && IS_LAZURITE=1
	[[ "$release_blob" == *"vauxite"* ]] && IS_VAUXITE=1
	[[ "$release_blob" == *"iot"* ]] && IS_IOT=1
	[[ "$release_blob" == *"cloud"* ]] && IS_CLOUD=1
	[[ "$release_blob" == *"coreos"* ]] && IS_COREOS=1

	# Universal Blue / community remixes
	if [[ "$release_blob" == *"bazzite"* ]]; then
		IS_BAZZITE=1
		IS_GAMING_SPIN=1
	fi
	if [[ "$release_blob" == *"aurora"* && "$release_blob" == *"universal blue"* ]] ||
		[[ "${ID:-}" == "aurora" ]] || [[ "${VARIANT_ID:-}" == "aurora" ]]; then
		IS_AURORA=1
	fi
	# Generic Universal Blue detection (bluefin, aurora, etc. share a common base)
	if [[ "${ID_LIKE:-}" == *"fedora"* ]] &&
		[[ "$release_blob" == *"universal blue"* || "$release_blob" == *"bluefin"* ||
			"$release_blob" == *"aurora"* ]]; then
		IS_AURORA=1
	fi

	# Fedora Atomic desktops: Kinoite, Silverblue, Onyx, Sericea, Lazurite, Vauxite,
	# and any other Fedora Atomic variant
	if ((IS_KINOITE || IS_SILVERBLUE || IS_ONYX || IS_SERICEA || IS_LAZURITE || IS_VAUXITE)) ||
		((IS_BAZZITE || IS_AURORA)) ||
		[[ "$release_blob" == *"atomic"* && "$release_blob" == *"fedora"* ]]; then
		IS_ATOMIC_DESKTOP=1
	fi
}

# Running-session hints (XDG_CURRENT_DESKTOP) plus installed packages; sets HAS_* for
# KDE, GNOME, Sway, Hyprland, i3, XFCE, Cinnamon, MATE, Budgie and LXQt.
detect_desktop_envs() {
	local detected=()
	local xdg_blob="${XDG_CURRENT_DESKTOP:-}:${DESKTOP_SESSION:-}"
	xdg_blob="${xdg_blob,,}"

	# ── Running session hints ────────────────────────────────────────────────
	if [[ "$xdg_blob" == *"kde"* || "$xdg_blob" == *"plasma"* ]]; then
		HAS_KDE=1
		[[ ",${detected[*]}," == *",kde,"* ]] || detected+=("kde")
	fi
	if [[ "$xdg_blob" == *"gnome"* ]]; then
		HAS_GNOME=1
		[[ ",${detected[*]}," == *",gnome,"* ]] || detected+=("gnome")
	fi
	if [[ "$xdg_blob" == *"budgie"* ]]; then
		HAS_BUDGIE=1
		[[ ",${detected[*]}," == *",budgie,"* ]] || detected+=("budgie")
	fi
	if [[ "$xdg_blob" == *"cinnamon"* ]]; then
		HAS_CINNAMON=1
		[[ ",${detected[*]}," == *",cinnamon,"* ]] || detected+=("cinnamon")
	fi
	if [[ "$xdg_blob" == *"mate"* ]]; then
		HAS_MATE=1
		[[ ",${detected[*]}," == *",mate,"* ]] || detected+=("mate")
	fi
	if [[ "$xdg_blob" == *"xfce"* ]]; then
		HAS_XFCE=1
		[[ ",${detected[*]}," == *",xfce,"* ]] || detected+=("xfce")
	fi
	if [[ "$xdg_blob" == *"lxqt"* ]]; then
		HAS_LXQT=1
		[[ ",${detected[*]}," == *",lxqt,"* ]] || detected+=("lxqt")
	fi
	if [[ "$xdg_blob" == *"sway"* ]]; then
		HAS_SWAY=1
		[[ ",${detected[*]}," == *",sway,"* ]] || detected+=("sway")
	fi
	if [[ "$xdg_blob" == *"hyprland"* ]]; then
		HAS_HYPRLAND=1
		[[ ",${detected[*]}," == *",hyprland,"* ]] || detected+=("hyprland")
	fi
	if [[ "$xdg_blob" == *"i3"* ]]; then
		HAS_I3=1
		[[ ",${detected[*]}," == *",i3,"* ]] || detected+=("i3")
	fi

	# ── Installed-package / command hints ────────────────────────────────────
	if cmd_exists kwriteconfig6 || cmd_exists kwriteconfig5 || pkg_cached plasma-workspace; then
		HAS_KDE=1
		[[ ",${detected[*]}," == *",kde,"* ]] || detected+=("kde")
	fi
	if cmd_exists gnome-shell || pkg_cached gnome-shell || pkg_cached gnome-session; then
		HAS_GNOME=1
		[[ ",${detected[*]}," == *",gnome,"* ]] || detected+=("gnome")
	fi
	if pkg_cached budgie-desktop || pkg_cached budgie-desktop-view; then
		HAS_BUDGIE=1
		[[ ",${detected[*]}," == *",budgie,"* ]] || detected+=("budgie")
	fi
	if cmd_exists cinnamon || pkg_cached cinnamon; then
		HAS_CINNAMON=1
		[[ ",${detected[*]}," == *",cinnamon,"* ]] || detected+=("cinnamon")
	fi
	if cmd_exists mate-session || pkg_cached mate-session-manager; then
		HAS_MATE=1
		[[ ",${detected[*]}," == *",mate,"* ]] || detected+=("mate")
	fi
	if cmd_exists xfce4-session || pkg_cached xfce4-session; then
		HAS_XFCE=1
		[[ ",${detected[*]}," == *",xfce,"* ]] || detected+=("xfce")
	fi
	if cmd_exists startlxqt || pkg_cached lxqt-session; then
		HAS_LXQT=1
		[[ ",${detected[*]}," == *",lxqt,"* ]] || detected+=("lxqt")
	fi
	if cmd_exists sway || pkg_cached sway; then
		HAS_SWAY=1
		[[ ",${detected[*]}," == *",sway,"* ]] || detected+=("sway")
	fi
	if cmd_exists Hyprland || cmd_exists hyprland || pkg_cached hyprland; then
		HAS_HYPRLAND=1
		[[ ",${detected[*]}," == *",hyprland,"* ]] || detected+=("hyprland")
	fi
	if cmd_exists i3 || pkg_cached i3; then
		HAS_I3=1
		[[ ",${detected[*]}," == *",i3,"* ]] || detected+=("i3")
	fi

	# Sericea and Lazurite Atomic spins imply their respective DEs
	((IS_SERICEA)) && {
		HAS_SWAY=1
		[[ ",${detected[*]}," == *",sway,"* ]] || detected+=("sway")
	}
	((IS_LAZURITE)) && {
		HAS_LXQT=1
		[[ ",${detected[*]}," == *",lxqt,"* ]] || detected+=("lxqt")
	}
	((IS_VAUXITE)) && {
		HAS_XFCE=1
		[[ ",${detected[*]}," == *",xfce,"* ]] || detected+=("xfce")
	}
	# Onyx is GNOME Atomic; Kinoite/Aurora are KDE
	((IS_ONYX)) && {
		HAS_GNOME=1
		[[ ",${detected[*]}," == *",gnome,"* ]] || detected+=("gnome")
	}
	((IS_AURORA)) && {
		HAS_KDE=1
		[[ ",${detected[*]}," == *",kde,"* ]] || detected+=("kde")
	}
	# Bazzite ships both KDE and GNOME editions — honour running session above; default to KDE
	if ((IS_BAZZITE)) && ((! HAS_KDE && ! HAS_GNOME)); then
		HAS_KDE=1
		[[ ",${detected[*]}," == *",kde,"* ]] || detected+=("kde")
	fi

	((${#detected[@]} > 0)) && HAS_DESKTOP=1
	local IFS=','
	DESKTOP_ENVS="${detected[*]:-}"
}

# Whether a section applies to this system (release type, desktop, platform), e.g.
# section 14 needs a desktop. Usage: section_compatible <section_number>
section_compatible() {
	local s="$1"
	case "$s" in
	13)
		# Section 13 requires at least one desktop environment to be installed.
		if ((! HAS_DESKTOP)); then
			info "Skipping section 13: no desktop environment detected on this host."
			return 1
		fi
		;;
	14)
		# Section 14 is desktop-focused and should run if any desktop environment is installed.
		if ((! HAS_DESKTOP)); then
			info "Skipping section 14: no desktop environment detected on this host."
			return 1
		fi
		;;
	23)
		# Section 23 can interfere with remote access if USB input devices are not whitelisted.
		if ((IS_SERVER)) && ((! ASSUME_YES)); then
			warn "Section 23 (USBGuard) can disrupt remote-only server access if input devices are blocked."
		fi
		# Sway/Hyprland/i3 users: input-device whitelists in compositors must allow USB keyboards/mice.
		if ((HAS_SWAY || HAS_HYPRLAND || HAS_I3)) && ((! ASSUME_YES)); then
			warn "Section 23 (USBGuard): tiling WM users should whitelist USB input devices in their compositor config."
		fi
		;;
	esac
	return 0
}

# platform_score_rows - Scorecard rows that depend on Fedora's tools.
platform_score_rows() {
	local v zone policy
	# Firewall
	if systemctl is-active --quiet firewalld 2>/dev/null; then
		zone="$(firewall-cmd --get-default-zone 2>/dev/null || true)"
		_score ok "Firewall" "firewalld is running (default zone: ${zone:-unknown})"
	else
		_score no "Firewall" "firewalld is not running" "sudo systemctl enable --now firewalld, or run section 6: sudo $SCRIPT_NAME --only 6"
	fi

	# Automatic updates
	if ((IS_OSTREE)); then
		policy="$(sed -n 's/^AutomaticUpdatePolicy=//p' /etc/rpm-ostreed.conf 2>/dev/null | tail -n 1 || true)"
		if systemctl is-enabled --quiet uupd.timer 2>/dev/null; then
			_score ok "Automatic updates" "uupd updates the system, Flatpaks and boxes"
		elif [[ "$policy" =~ ^(stage|apply)$ ]] && systemctl is-enabled --quiet rpm-ostreed-automatic.timer 2>/dev/null; then
			_score ok "Automatic updates" "rpm-ostree stages updates automatically ($policy)"
		else
			_score no "Automatic updates" "system updates are not staged automatically" "Run section 2: sudo $SCRIPT_NAME --only 2"
		fi
	elif systemctl is-enabled --quiet dnf5-automatic.timer 2>/dev/null ||
		systemctl is-enabled --quiet dnf-automatic.timer 2>/dev/null ||
		systemctl is-enabled --quiet dnf-automatic-install.timer 2>/dev/null; then
		_score ok "Automatic updates" "dnf automatic updates are enabled"
	else
		_score no "Automatic updates" "no automatic updates" "Run section 2: sudo $SCRIPT_NAME --only 2"
	fi

	# SELinux
	v="$(getenforce 2>/dev/null || echo unknown)"
	if [[ "$v" == Enforcing ]]; then
		_score ok "SELinux" "enforcing"
	else
		_score no "SELinux" "${v,,}" "Run section 5: sudo $SCRIPT_NAME --only 5 (a disabled system is relabelled first)"
	fi
}

# platform_run_sections - The sections, in the order that follows the dependency flow.
platform_run_sections() {
	sec_01_updates
	sec_02_dnf_automatic
	sec_03_secureboot
	sec_04_flatpak
	sec_05_selinux
	sec_06_firewalld
	sec_07_ssh
	sec_08_pam
	sec_09_sysctl
	sec_10_auditd
	sec_11_dot
	sec_12_fail2ban
	sec_13_desktop
	sec_14_browsers
	sec_15_wireguard
	sec_16_clamav
	sec_17_openscap
	sec_18_containers
	sec_19_routine
	sec_20_snapshots
	sec_21_services
	sec_22_perms
	sec_23_usbguard
	sec_24_ids
	record_routine_state
}

# platform_after_run - The /etc and AIDE baselines (section 24), recorded last.
platform_after_run() {
	record_etc_baseline
	start_aide_baseline
}

# ---------- --rollback of Fedora entries -------------------------------------
# platform_reload_paths <path>... - After --rollback restored these files, reload
# the services that read them (firewalld here; core handles systemd, sysctl, audit
# and sshd).
platform_reload_paths() {
	local p
	for p in "$@"; do
		if [[ "$p" == /etc/firewalld/* ]]; then
			systemctl is-active --quiet firewalld 2>/dev/null && { firewall-cmd --reload >/dev/null 2>&1 || true; }
			return 0
		fi
	done
	return 0
}

# Packages removed with dnf are collected over the whole journal and removed in one
# transaction by platform_undo_finish.
declare -ga _RB_PKGS=()

# platform_undo_change <type> <detail> - Undo one journal entry; 1 = unknown type.
platform_undo_change() {
	local ctype="$1" detail="$2"
	case "$ctype" in
	PKG_INSTALL)
		if ((IS_OSTREE)); then
			if ((DRY_RUN)); then
				info "Would run: rpm-ostree uninstall $detail"
			elif run "rpm-ostree uninstall $detail" 2>/dev/null; then
				ok "rpm-ostree uninstall queued: $detail (reboot required)"
				_rjl "  [OK]   RPM_OSTREE_UNINSTALL  $detail"
				((++_RBJ_RESTORED))
			else
				warn "rpm-ostree uninstall failed for: $detail (may not have been layered)"
				_rjl "  [WARN] RPM_OSTREE_UNINSTALL  $detail"
				((++_RBJ_ERRORS))
			fi
		else
			# Removed together after the loop: one transaction also removes the
			# dependencies they pulled in, even ones shared between installs.
			read -ra _rb_more <<<"$detail"
			_RB_PKGS+=("${_rb_more[@]}")
		fi
		;;

	OSTREE_PIN)
		# The booted deployment pinned before the run (its checksum).
		local pidx
		pidx="$(ostree_deployment_index "$detail")"
		if ((DRY_RUN)); then
			info "Would unpin the safety-point deployment ${detail:0:12}"
		elif [[ -z "$pidx" ]]; then
			_rjl "  [SKIP] OSTREE_PIN  ${detail:0:12} (no longer deployed)"
		elif ostree admin pin --unpin "$pidx" >/dev/null 2>&1; then
			ok "Unpinned the safety-point deployment ${detail:0:12}"
			_rjl "  [OK]   OSTREE_PIN  $detail"
			((++_RBJ_RESTORED))
		else
			warn "Could not unpin deployment ${detail:0:12}: sudo ostree admin pin --unpin $pidx"
			((++_RBJ_ERRORS))
		fi
		;;

	KERNEL_ARGS)
		# kernel command-line options this run added
		if ((DRY_RUN)); then
			info "Would remove kernel options: $detail"
		elif { ((IS_OSTREE)) && read -ra _rb_kargs <<<"$detail" &&
			rpm-ostree kargs "${_rb_kargs[@]/#/--delete-if-present=}" >/dev/null 2>&1; } ||
			{ ((! IS_OSTREE)) && grubby --update-kernel=ALL --remove-args="$detail" 2>/dev/null; }; then
			ok "Removed kernel options: $detail (after a reboot)"
			_rjl "  [OK]   KERNEL_ARGS  $detail"
			((++_RBJ_RESTORED))
		else
			warn "Could not remove kernel options: $detail"
			_rjl "  [WARN] KERNEL_ARGS  $detail"
			((++_RBJ_ERRORS))
		fi
		;;

	AUTHSELECT_FEATURE)
		if ((DRY_RUN)); then
			info "Would run: authselect disable-feature $detail"
		elif authselect disable-feature "$detail" >/dev/null 2>&1; then
			ok "authselect feature $detail disabled"
			((++_RBJ_RESTORED))
		else
			warn "Could not disable authselect feature $detail"
			((++_RBJ_ERRORS))
		fi
		;;

	OSTREE_INITRAMFS)
		if ((DRY_RUN)); then
			info "Would run: rpm-ostree initramfs --disable"
		elif rpm-ostree initramfs --disable >/dev/null 2>&1; then
			ok "Local initramfs regeneration turned off (applies at the next boot)"
			((++_RBJ_RESTORED))
		else
			warn "Could not run rpm-ostree initramfs --disable"
			((++_RBJ_ERRORS))
		fi
		;;
	*) return 1 ;;
	esac
	return 0
}

# platform_undo_finish - Remove the packages the journal installed, keeping what
# something else still needs.
platform_undo_finish() {
	local -a rb_pkgs=("${_RB_PKGS[@]}")
	_RB_PKGS=()
	if ((${#rb_pkgs[@]})); then
		# dnf refuses to remove protected packages (systemd, systemd-udev, dnf, ...);
		# a minimal system can pull them in as dependencies. They stay installed.
		local -A protected=()
		local pname pfile kept=()
		for pfile in /etc/dnf/protected.d/*.conf /usr/share/dnf5/protected.d/*.conf; do
			[[ -r "$pfile" ]] || continue
			while read -r pname; do
				[[ -n "$pname" && "$pname" != \#* ]] && protected[$pname]=1
			done <"$pfile"
		done
		protected[dnf5]=1 protected[dnf]=1
		for pname in "${rb_pkgs[@]}"; do
			if [[ -n "${protected[${pname%.*}]:-}" ]]; then
				info "Keeping protected package $pname (pulled in as a dependency)."
			else
				kept+=("$pname")
			fi
		done
		rb_pkgs=("${kept[@]}")
	fi
	# Never remove what something outside this list still needs: a package the user
	# installed later can depend on one this run pulled in, and dnf would remove the
	# user's package with it. rpm's own test names every such requirement; keep its
	# provider and test again until the rest can go.
	if ((${#rb_pkgs[@]})) && ((! DRY_RUN)); then
		local -a present=()
		for pname in "${rb_pkgs[@]}"; do
			rpm -q "$pname" >/dev/null 2>&1 && present+=("$pname")
		done
		rb_pkgs=("${present[@]}")
		local _try cap prov test_out changed
		for ((_try = 0; _try < 10 && ${#rb_pkgs[@]} > 0; _try++)); do
			test_out="$(rpm -e --test "${rb_pkgs[@]}" 2>&1)" && break
			changed=0
			local -A still_needed=()
			while IFS= read -r cap; do
				[[ -n "$cap" ]] || continue
				while IFS= read -r prov; do
					[[ -n "$prov" ]] && still_needed[$prov]=1
				done < <(rpm -q --whatprovides --qf '%{NAME}.%{ARCH}\n' "$cap" 2>/dev/null)
			done < <(sed -n 's/^[[:space:]]*\(.*\) is needed by (installed) .*/\1/p' <<<"$test_out")
			kept=()
			for pname in "${rb_pkgs[@]}"; do
				if [[ -n "${still_needed[$pname]:-}" ]]; then
					info "Keeping $pname: a package installed outside this run still needs it."
					_rjl "  [KEEP] PKG_REMOVE  $pname (still needed)"
					changed=1
				else
					kept+=("$pname")
				fi
			done
			unset still_needed
			rb_pkgs=("${kept[@]}")
			((changed)) || break
		done
	fi
	if ((${#rb_pkgs[@]})); then
		if ((DRY_RUN)); then
			info "Would run: dnf remove -y ${rb_pkgs[*]}"
		elif run "dnf remove -y ${rb_pkgs[*]}" 2>/dev/null; then
			ok "Packages removed (with the dependencies they pulled in): ${rb_pkgs[*]}"
			_rjl "  [OK]   PKG_REMOVE  ${rb_pkgs[*]}"
			((++_RBJ_RESTORED))
		else
			# One transaction fails as a whole (a protected or pre-existing package):
			# fall back to one package at a time.
			local pkg
			for pkg in "${rb_pkgs[@]}"; do
				if run "dnf remove -y $pkg" 2>/dev/null; then
					ok "Package removed: $pkg"
					_rjl "  [OK]   PKG_REMOVE  $pkg"
					((++_RBJ_RESTORED))
				elif rpm -q "$pkg" >/dev/null 2>&1; then
					# Still installed: another installed package (often a protected one
					# such as systemd-udev) needs it. Leaving it is correct.
					info "Keeping $pkg: an installed package still needs it."
					_rjl "  [KEEP] PKG_REMOVE  $pkg (still required)"
				else
					_rjl "  [SKIP] PKG_REMOVE  $pkg (already absent)"
				fi
			done
		fi
	fi
}
