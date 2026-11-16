# shellcheck shell=bash
# ============================================================================
#  SECTION 13 — Desktop environment privacy & screen-lock settings
# ============================================================================
# sec_13_desktop() - Apply security and privacy settings for every detected DE.
#
# Single entry-point that auto-dispatches to per-DE sub-handlers based on the
# HAS_* flags set by detect_desktop_envs(). Multiple DEs can be active at once
# (e.g. GNOME + KDE on a multi-seat box); all detected ones are hardened.
#
# DE coverage (each block runs only if the corresponding HAS_* flag is set):
#   KDE Plasma    — kwriteconfig6/5: screen lock, recent-docs off, BT opt-out
#   GNOME/Onyx    — gsettings: screen lock, location off, privacy (mic off if asked)
#   Budgie        — gsettings (GNOME backend): same privacy stack as GNOME
#   Cinnamon      — gsettings: org.cinnamon.desktop.screensaver + GNOME privacy
#   MATE          — gsettings: org.mate.screensaver + power-manager
#   XFCE/Vauxite  — xfconf-query: screensaver lock + power manager idle
#   Sway/Sericea  — writes ~/.config/swaylock/config + ~/.config/swayidle/config
#   Hyprland      — writes ~/.config/hypr/hypridle.conf
#   i3            — xss-lock + i3lock drop-in in ~/.config/i3/config.d/
#   LXQt/Lazurite — writes lxqt-screensaver.conf + lxqt-powermanagement.conf
#
# Spin → DE mapping (inferred by detect_fedora_release_type + detect_desktop_envs):
#   Kinoite/Aurora/Bazzite-KDE → KDE
#   Silverblue/Onyx/Bazzite-GNOME → GNOME
#   Sericea → Sway    |  Lazurite → LXQt    |  Vauxite → XFCE
#   XFCE/LXQt/Cinnamon/MATE/Budgie spins → respective DE
sec_13_desktop() {
	should_run 13 || return 0
	section 13 "Desktop environment settings (all detected DEs)"

	if ((! HAS_DESKTOP)); then
		info "No desktop environment detected — skipping section 13."
		return 0
	fi

	if [[ -z "$TARGET_USER" ]]; then
		warn "No target user — cannot apply per-user DE settings."
		return 0
	fi

	local user_home applied_des=()
	user_home="$(user_home "$TARGET_USER")"

	# X11 lets any app read other windows and keystrokes; Wayland isolates them.
	# Source: privacyguides.org — Linux Overview ("Wayland ... more secure than X11").
	local sid stype x11_sessions=0
	cmd_exists loginctl && while read -r sid; do
		stype="$(loginctl show-session "$sid" -p Type --value 2>/dev/null)"
		[[ "$stype" == x11 ]] && ((++x11_sessions))
	done < <(loginctl list-sessions --no-legend 2>/dev/null | awk -v u="$TARGET_USER" '$3 == u {print $1}')
	if ((x11_sessions > 0)); then
		warn "$TARGET_USER is logged in to an X11 session; Wayland isolates applications from each other."
		add_action_item 13 MEDIUM "X11_SESSION" \
			"Log in to the Wayland session instead of X11 (choose it on the login screen) — X11 lets any app capture other windows and keystrokes (privacyguides.org)."
	fi

	info "Detected desktop(s): ${DESKTOP_ENVS:-unknown}  (spin: ${FEDORA_VARIANT})"

	# ── KDE Plasma ────────────────────────────────────────────────────────────
	if ((HAS_KDE)); then
		info "--- KDE Plasma settings ---"
		local KW=""
		for c in kwriteconfig6 kwriteconfig5; do
			cmd_exists "$c" && KW="$c" && break
		done
		if [[ -z "$KW" ]]; then
			warn "kwriteconfig6/5 not found — KDE may not be fully installed; skipping KDE tweaks."
			add_action_item 13 MEDIUM "KDE_KWRITECONFIG_MISSING" \
				"kwriteconfig6/5 not found. After installing plasma-desktop, rerun: sudo ./fedora-harden.sh --only 13"
		else
			info "Using $KW for KDE settings"
			run "sudo -u '$TARGET_USER' '$KW' --file kscreenlockerrc --group Daemon --key Timeout 5"
			run "sudo -u '$TARGET_USER' '$KW' --file kscreenlockerrc --group Daemon --key Lock true"
			run "sudo -u '$TARGET_USER' '$KW' --file kscreenlockerrc --group Daemon --key LockGrace 0"
			run "sudo -u '$TARGET_USER' '$KW' --file kdeglobals --group RecentDocuments --key UseRecent false"
			if confirm "Disable Bluetooth entirely (only if you use no BT peripherals)?"; then
				run "systemctl disable --now bluetooth || true"
				if [[ -f /etc/bluetooth/main.conf ]]; then
					backup_file /etc/bluetooth/main.conf
					run "sed -i 's|^#\?AutoEnable=.*|AutoEnable=false|' /etc/bluetooth/main.conf"
				fi
			fi
			ok "KDE: screen lock, recent-docs disabled."
			info "KDE GUI-only: KWallet master password, Privacy tab, Activity tracking → System Settings."
			applied_des+=("KDE")
		fi
	fi

	# ── GNOME (Silverblue, Onyx, Workstation GNOME) ──────────────────────────
	if ((HAS_GNOME)); then
		info "--- GNOME settings ---"
		if ((! DRY_RUN)); then
			log "[RUN]   sudo -u '$TARGET_USER' gsettings batch (GNOME privacy)"
			user_session_run "$TARGET_USER" '
				gsettings set org.gnome.desktop.session idle-delay 300
				gsettings set org.gnome.desktop.screensaver lock-enabled true
				gsettings set org.gnome.desktop.screensaver lock-delay 0
				gsettings set org.gnome.system.location enabled false
				gsettings set org.gnome.desktop.privacy remove-old-temp-files true
				gsettings set org.gnome.desktop.privacy remove-old-trash-files true
				gsettings set org.gnome.desktop.privacy old-files-age 7
				gsettings set org.gnome.desktop.privacy send-software-usage-stats false
				gsettings set org.gnome.desktop.privacy report-technical-problems false
				gsettings set org.gnome.desktop.privacy remember-recent-files false
			' 2>/dev/null || true
		else
			info "Would apply GNOME gsettings: screen lock, location off, privacy"
		fi
		((DRY_RUN)) || verify_user_setting "GNOME: screen lock, location off, privacy" true \
			"gsettings get org.gnome.desktop.screensaver lock-enabled" || true
		info "GNOME GUI-only: Online Accounts, Sharing, Bluetooth → GNOME Settings."
		applied_des+=("GNOME")
	fi

	# ── Budgie (GNOME gsettings backend) ─────────────────────────────────────
	if ((HAS_BUDGIE)); then
		info "--- Budgie settings ---"
		if ((! DRY_RUN)); then
			log "[RUN]   sudo -u '$TARGET_USER' gsettings batch (Budgie/GNOME privacy)"
			user_session_run "$TARGET_USER" '
				gsettings set org.gnome.desktop.session idle-delay 300
				gsettings set org.gnome.desktop.screensaver lock-enabled true
				gsettings set org.gnome.desktop.screensaver lock-delay 0
				gsettings set org.gnome.system.location enabled false
				gsettings set org.gnome.desktop.privacy remember-recent-files false
				gsettings set org.gnome.desktop.privacy remove-old-temp-files true
				gsettings set org.gnome.desktop.privacy remove-old-trash-files true
				gsettings set org.gnome.desktop.privacy old-files-age 7
				gsettings set org.gnome.desktop.privacy send-software-usage-stats false
			' 2>/dev/null || true
		else
			info "Would apply Budgie gsettings: screen lock, location off, privacy"
		fi
		((DRY_RUN)) || verify_user_setting "Budgie: screen lock, privacy" true \
			"gsettings get org.gnome.desktop.screensaver lock-enabled" || true
		applied_des+=("Budgie")
	fi

	# The microphone switch is the person's choice: off system-wide, calls and
	# meetings stop working until it is turned back on in Settings → Privacy.
	if ((HAS_GNOME || HAS_BUDGIE)) &&
		confirm "Turn the microphone off system-wide (calls stop working until you turn it back on in Settings → Privacy)?" no; then
		if ((DRY_RUN)); then
			info "Would turn the microphone off (org.gnome.desktop.privacy disable-microphone)"
		else
			user_session_run "$TARGET_USER" 'gsettings set org.gnome.desktop.privacy disable-microphone true' 2>/dev/null || true
			ok "Microphone off system-wide (Settings → Privacy turns it back on)."
		fi
	fi

	# ── Cinnamon ──────────────────────────────────────────────────────────────
	if ((HAS_CINNAMON)); then
		info "--- Cinnamon settings ---"
		if ((! DRY_RUN)); then
			log "[RUN]   sudo -u '$TARGET_USER' gsettings batch (Cinnamon privacy)"
			user_session_run "$TARGET_USER" '
				gsettings set org.cinnamon.desktop.screensaver lock-enabled true
				gsettings set org.cinnamon.desktop.screensaver lock-delay 0
				gsettings set org.cinnamon.desktop.session idle-delay 300 2>/dev/null || true
				gsettings set org.gnome.desktop.privacy remember-recent-files false 2>/dev/null || true
				gsettings set org.gnome.desktop.privacy remove-old-temp-files true 2>/dev/null || true
				gsettings set org.gnome.desktop.privacy remove-old-trash-files true 2>/dev/null || true
				gsettings set org.gnome.desktop.privacy old-files-age 7 2>/dev/null || true
				gsettings set org.gnome.system.location enabled false 2>/dev/null || true
			' 2>/dev/null || true
		else
			info "Would apply Cinnamon gsettings: screen lock, privacy, location off"
		fi
		((DRY_RUN)) || verify_user_setting "Cinnamon: screen lock, privacy" true \
			"gsettings get org.cinnamon.desktop.screensaver lock-enabled" || true
		applied_des+=("Cinnamon")
	fi

	# ── MATE ──────────────────────────────────────────────────────────────────
	if ((HAS_MATE)); then
		info "--- MATE settings ---"
		if ((! DRY_RUN)); then
			log "[RUN]   sudo -u '$TARGET_USER' gsettings batch (MATE privacy)"
			user_session_run "$TARGET_USER" '
				gsettings set org.mate.screensaver lock-enabled true 2>/dev/null || true
				gsettings set org.mate.screensaver idle-activation-enabled true 2>/dev/null || true
				gsettings set org.mate.screensaver idle-delay 5 2>/dev/null || true
				gsettings set org.mate.power-manager sleep-display-ac 300 2>/dev/null || true
				gsettings set org.gnome.desktop.privacy remember-recent-files false 2>/dev/null || true
				gsettings set org.gnome.system.location enabled false 2>/dev/null || true
			' 2>/dev/null || true
		else
			info "Would apply MATE gsettings: screensaver lock, idle timeout, privacy"
		fi
		((DRY_RUN)) || verify_user_setting "MATE: screensaver lock, power-manager idle" true \
			"gsettings get org.mate.screensaver lock-enabled" || true
		applied_des+=("MATE")
	fi

	# ── XFCE (XFCE Spin + Vauxite Atomic) ────────────────────────────────────
	if ((HAS_XFCE)); then
		info "--- XFCE settings ---"
		if ! cmd_exists xfconf-query; then
			warn "xfconf-query not found — cannot configure XFCE settings."
			add_action_item 13 MEDIUM "XFCE_SCREENSAVER_MANUAL" \
				"Manually enable screensaver lock in XFCE Settings → Screensaver (lock after 5 min idle)"
		else
			if ((! DRY_RUN)); then
				log "[RUN]   sudo -u '$TARGET_USER' xfconf-query batch (XFCE screensaver/power)"
				# -n creates the property if it does not exist yet; -t gives its type.
				user_session_run "$TARGET_USER" '
					xfconf-query -c xfce4-screensaver -p /saver/enabled -n -t bool -s true
					xfconf-query -c xfce4-screensaver -p /lock/enabled -n -t bool -s true
					xfconf-query -c xfce4-screensaver -p /saver/idle-activation/enabled -n -t bool -s true
					xfconf-query -c xfce4-screensaver -p /saver/idle-activation/delay -n -t int -s 5
					xfconf-query -c xfce4-power-manager -p /xfce4-power-manager/blank-on-ac -n -t int -s 5
					xfconf-query -c xfce4-power-manager -p /xfce4-power-manager/blank-on-battery -n -t int -s 3
					xfconf-query -c xfce4-session -p /general/SaveOnExit -n -t bool -s false
				' 2>/dev/null || true
			else
				info "Would apply xfconf-query: screensaver lock, power manager idle, session save off"
			fi
			((DRY_RUN)) || verify_user_setting "XFCE: screensaver lock, power manager idle" true \
				"xfconf-query -c xfce4-screensaver -p /lock/enabled" || true
			info "XFCE GUI-only: File Manager → Preferences → Privacy (clear recent files on exit)."
		fi
		applied_des+=("XFCE")
	fi

	# ── Sway / wlroots (Sericea Atomic + any Sway session) ───────────────────
	if ((HAS_SWAY)); then
		info "--- Sway/wlroots settings ---"
		cmd_exists swaylock || {
			pkg_install swaylock || true
			unset '_CMD_CACHE[swaylock]'
		}
		cmd_exists swayidle || {
			pkg_install swayidle || true
			unset '_CMD_CACHE[swayidle]'
		}

		local swaylock_cfg="${user_home}/.config/swaylock/config"
		local swayidle_cfg="${user_home}/.config/swayidle/config"

		if ((! DRY_RUN)); then
			run "mkdir -p '${user_home}/.config/swaylock' '${user_home}/.config/swayidle'"
			if [[ ! -f "$swaylock_cfg" ]]; then
				backup_file "${swaylock_cfg}" || return 0
				cat 2>/dev/null >"$swaylock_cfg" <<'SWAYEOF'
# swaylock - privacy-hardened config (fedora-harden.sh)
color=000000
ignore-empty-password
show-failed-attempts
daemonize
SWAYEOF
				run "chown '${TARGET_USER}:${TARGET_USER}' '${swaylock_cfg}'"
				ok "Wrote $swaylock_cfg"
			else
				info "swaylock config already exists — leaving intact."
			fi
			if [[ ! -f "$swayidle_cfg" ]]; then
				backup_file "${swayidle_cfg}" || return 0
				cat 2>/dev/null >"$swayidle_cfg" <<'SWAYEOF'
# swayidle - auto-lock/suspend config (fedora-harden.sh)
timeout 300 'swaylock -f'
timeout 600 'systemctl suspend'
before-sleep 'swaylock -f'
SWAYEOF
				run "chown '${TARGET_USER}:${TARGET_USER}' '${swayidle_cfg}'"
				ok "Wrote $swayidle_cfg"
			else
				info "swayidle config already exists — leaving intact."
			fi
		else
			info "Would write swaylock.conf (black, immediate lock) + swayidle (lock 5 min, suspend 10 min)"
		fi
		add_action_item 13 MEDIUM "SWAY_AUTOSTART_SWAYIDLE" \
			"Add 'exec swayidle -w' to ~/.config/sway/config to autostart idle/lock daemon on login."
		applied_des+=("Sway")
	fi

	# ── Hyprland ──────────────────────────────────────────────────────────────
	if ((HAS_HYPRLAND)); then
		info "--- Hyprland settings ---"
		cmd_exists hypridle || {
			pkg_install hypridle 2>/dev/null || true
			unset '_CMD_CACHE[hypridle]'
		}
		cmd_exists hyprlock || {
			pkg_install hyprlock 2>/dev/null || true
			unset '_CMD_CACHE[hyprlock]'
		}

		local hypridle_cfg="${user_home}/.config/hypr/hypridle.conf"
		if ((! DRY_RUN)); then
			run "mkdir -p '${user_home}/.config/hypr'"
			if [[ ! -f "$hypridle_cfg" ]]; then
				backup_file "${hypridle_cfg}" || return 0
				cat 2>/dev/null >"$hypridle_cfg" <<'HYPREOF'
# hypridle - auto-lock config (fedora-harden.sh)
general {
    lock_cmd = pidof hyprlock || hyprlock
    before_sleep_cmd = loginctl lock-session
}

listener {
    timeout = 300
    on-timeout = loginctl lock-session
}

listener {
    timeout = 600
    on-timeout = systemctl suspend
}
HYPREOF
				run "chown '${TARGET_USER}:${TARGET_USER}' '${hypridle_cfg}'"
				ok "Wrote $hypridle_cfg"
			else
				info "hypridle config already exists — leaving intact."
			fi
		else
			info "Would write hypridle.conf (lock 5 min, suspend 10 min)"
		fi
		add_action_item 13 MEDIUM "HYPRLAND_AUTOSTART_HYPRIDLE" \
			"Add 'exec-once = hypridle' to ~/.config/hypr/hyprland.conf to autostart the idle daemon."
		applied_des+=("Hyprland")
	fi

	# ── i3 ────────────────────────────────────────────────────────────────────
	if ((HAS_I3)); then
		info "--- i3 settings ---"
		cmd_exists xss-lock || {
			pkg_install xss-lock 2>/dev/null || true
			unset '_CMD_CACHE[xss-lock]'
		}
		cmd_exists i3lock || {
			pkg_install i3lock 2>/dev/null || true
			unset '_CMD_CACHE[i3lock]'
		}

		local i3_cfg="${user_home}/.config/i3/config"
		local i3_cfg_d="${user_home}/.config/i3/config.d"
		local i3_lock_frag="${i3_cfg_d}/99-autolock.conf"

		if ((! DRY_RUN)); then
			run "mkdir -p '${i3_cfg_d}'"
			if [[ ! -f "$i3_lock_frag" ]]; then
				backup_file "${i3_lock_frag}" || return 0
				cat 2>/dev/null >"$i3_lock_frag" <<'I3EOF'
# i3 auto-lock via xss-lock + i3lock (fedora-harden.sh)
exec --no-startup-id xss-lock --transfer-sleep-lock -- i3lock --nofork --color=000000
exec --no-startup-id xautolock -time 5 -locker 'i3lock --color=000000'
I3EOF
				run "chown '${TARGET_USER}:${TARGET_USER}' '${i3_lock_frag}'"
				ok "Wrote $i3_lock_frag"
			else
				info "i3 autolock fragment already exists — leaving intact."
			fi
			if [[ -f "$i3_cfg" ]] && ! grep -q "config.d" "$i3_cfg" 2>/dev/null; then
				printf '\n# Auto-included by fedora-harden.sh\ninclude %s/*.conf\n' "${i3_cfg_d}" >>"$i3_cfg" || true
			fi
		else
			info "Would write i3 autolock drop-in (xss-lock + i3lock) in ${i3_cfg_d}/"
		fi
		add_action_item 13 MEDIUM "I3_LOCK_KEYBIND" \
			"Add a manual lock keybind: bindsym \$mod+l exec i3lock --color=000000"
		applied_des+=("i3")
	fi

	# ── LXQt (LXQt Spin + Lazurite Atomic) ───────────────────────────────────
	if ((HAS_LXQT)); then
		info "--- LXQt settings ---"
		local ss_cfg="${user_home}/.config/lxqt/lxqt-screensaver.conf"
		local pm_cfg="${user_home}/.config/lxqt/lxqt-powermanagement.conf"

		if ((! DRY_RUN)); then
			run "mkdir -p '${user_home}/.config/lxqt'"
			if [[ ! -f "$ss_cfg" ]]; then
				backup_file "$ss_cfg" || return 0
				printf '[General]\nlockAfterEnable=true\nlockAfterTimeout=300\nscreensaverTimeout=300\n' >"$ss_cfg"
				run "chown '${TARGET_USER}:${TARGET_USER}' '${ss_cfg}'"
				ok "Wrote LXQt screensaver config"
			else
				backup_file "$ss_cfg" || return 0
				sed -i \
					-e 's|^lockAfterEnable=.*|lockAfterEnable=true|' \
					-e 's|^lockAfterTimeout=.*|lockAfterTimeout=300|' \
					-e 's|^screensaverTimeout=.*|screensaverTimeout=300|' \
					"$ss_cfg" || true
				ok "Patched LXQt screensaver config"
			fi
			if [[ ! -f "$pm_cfg" ]]; then
				backup_file "$pm_cfg" || return 0
				printf '[General]\nenableIdleSuspend=true\nidleSuspendTimeout=600\n' >"$pm_cfg"
				run "chown '${TARGET_USER}:${TARGET_USER}' '${pm_cfg}'"
				ok "Wrote LXQt power management config"
			fi
		else
			info "Would write LXQt screensaver (lock 5 min) + power management (suspend 10 min) configs"
		fi
		info "LXQt GUI-only: verify in LXQt Settings → Screensaver / Power Management."
		applied_des+=("LXQt")
	fi

	# ── Summary ───────────────────────────────────────────────────────────────
	if ((${#applied_des[@]} > 0)); then
		ok "Section 13 complete. Hardened: ${applied_des[*]}"
	else
		warn "Section 13: desktop detected but no DE-specific settings could be applied."
	fi
}
