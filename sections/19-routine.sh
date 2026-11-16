# shellcheck shell=bash
# ============================================================================
#  SECTION 19 — Your routine (use-case automation)
# ============================================================================
# sec_19_routine() - Set up the upkeep this machine's use cases need, as systemd
# timers calling one small helper (fedora-harden-routine). Everyday: monthly cleanup,
# daily free-space check, weekly drift check and weekly summary (with a 90-day
# relevance review), Btrfs scrub, disk health, a journal size cap. Creative and dev
# add box upgrades and build-cache cleanup; laptop adds an optional charge limit.
# Heavy jobs wait for mains power and for a game to end. Desktop notifications only
# when something needs the person. Everything is undone by --rollback.
sec_19_routine() {
	should_run 19 || return 0
	section 19 "Your routine: upkeep for how this machine is used"

	install_routine_helper || return 0

	local detected uses u
	detected="everyday"
	((DRY_RUN)) || detected="$("$ROUTINE_HELPER" detect 2>/dev/null || echo everyday)"
	uses="$PROFILE_ARG"
	if [[ -z "$uses" ]]; then
		info "This machine looks like: $detected"
		uses="$(prompt_input "Use cases to automate for (comma-separated: everyday, gaming, creative, dev, laptop, private)" "${detected// /,}")"
	fi
	local -a chosen=(everyday)
	for u in ${uses//,/ }; do
		case "$u" in
		everyday) ;;
		gaming | creative | dev | laptop | private) chosen+=("$u") ;;
		*) warn "Unknown use case '$u' — ignored." ;;
		esac
	done
	uses="${chosen[*]}"
	info "Routine for: $uses"
	# A re-run with the same use cases keeps the review date: only a change of use
	# cases restarts the 90-day relevance review.
	local reviewed
	reviewed="$(date +%F)"
	if [[ "$(sed -n 's/^USE_CASES=//p' /etc/fedora-harden/profile 2>/dev/null | tr -d '"')" == "$uses" ]]; then
		reviewed="$(sed -n 's/^REVIEWED=//p' /etc/fedora-harden/profile 2>/dev/null)"
		[[ -n "$reviewed" ]] || reviewed="$(date +%F)"
	fi
	write_new_file /etc/fedora-harden/profile 0600 <<EOF || return 0
# Written by fedora-harden.sh (section 19). Re-run section 19 to change it.
USE_CASES="$uses"
REVIEWED=$reviewed
EOF

	write_new_file /etc/systemd/system/fedora-harden-notify@.service 0644 <<EOF || return 0
[Unit]
Description=Tell the desktop that %i needs attention (fedora-harden)

[Service]
Type=oneshot
ExecStart=$ROUTINE_HELPER notify-failed %i
EOF

	# Everyday
	_routine_timer cleanup "Monthly cleanup: unused Flatpak runtimes, Podman images, OSTree data" monthly || return 0
	_routine_timer diskspace "Daily free-space check" daily || return 0
	_routine_timer drift "Weekly check that the hardening is still in effect" weekly || return 0
	_routine_timer summary "Weekly summary and 90-day relevance review" "Mon *-*-* 10:00:00" || return 0
	if findmnt -rn -t btrfs >/dev/null 2>&1; then
		_routine_timer scrub "Monthly Btrfs scrub (finds silent corruption)" monthly || return 0
	fi
	write_new_file /etc/systemd/journald.conf.d/50-fedora-harden.conf 0644 <<'EOF' || return 0
# Written by fedora-harden.sh (section 19): logs never fill the disk.
[Journal]
SystemMaxUse=1G
EOF
	((DRY_RUN)) || run "systemctl restart systemd-journald" || true
	# Disk health: Fedora's smartd already notifies desktop users (smartdnotify).
	pkg_install smartmontools
	if cmd_exists smartctl; then
		run "systemctl enable --now smartd" || info "smartd did not start (no SMART-capable disks here?)."
	fi

	# Use-case additions
	local uupd=0
	[[ -r /usr/share/ublue-os/image-info.json ]] && systemctl list-unit-files uupd.timer >/dev/null 2>&1 && uupd=1
	if [[ " $uses " == *" creative "* || " $uses " == *" dev "* ]] && ((! uupd)); then
		_routine_timer boxes "Weekly upgrade of toolbox and distrobox containers" weekly || return 0
	fi
	if [[ " $uses " == *" dev "* ]]; then
		_routine_timer devclean "Weekly removal of container build cache older than 30 days" weekly || return 0
	fi
	if [[ " $uses " == *" creative "* ]]; then
		if confirm "Watch Flatpak apps for permission changes after updates?" no; then
			_routine_timer flatpak-perms "Weekly Flatpak permission watch" weekly || return 0
		fi
		if cmd_exists ujust && ujust --list 2>/dev/null | grep -q install-resolve; then
			add_action_item 19 LOW "RESOLVE_WITHOUT_LAYERING" \
				"DaVinci Resolve without layering anything: ujust install-resolve (runs it in its own container, davincibox)."
		fi
	fi
	if [[ " $uses " == *" laptop "* ]]; then
		_battery_limit
	fi
	((IS_OSTREE)) && _layer_audit
	_personal_setup "$uses"
	ROUTINE_ACTIVE=1
	ok "Routine in place for: $uses. Weekly summary every Monday; desktop notifications only when something needs you."
}

# install_routine_helper() - Write the helper the routine timers call (sections 19, 20).
install_routine_helper() {
	write_new_file "$ROUTINE_HELPER" 0755 <"$SCRIPT_DIR/libexec/fedora-harden-routine"
}

# _routine_timer <name> <description> <OnCalendar> - service + timer for one helper
# command. Idle CPU and I/O priority; on failure, a desktop notification.
_routine_timer() {
	local name="$1" desc="$2" when="$3"
	write_new_file "/etc/systemd/system/fedora-harden-${name}.service" 0644 <<EOF || return 1
[Unit]
Description=$desc (fedora-harden)
OnFailure=fedora-harden-notify@%n.service

[Service]
Type=oneshot
ExecStart=$ROUTINE_HELPER $name
Nice=19
IOSchedulingClass=idle
TimeoutStartSec=26h
EOF
	write_new_file "/etc/systemd/system/fedora-harden-${name}.timer" 0644 <<EOF || return 1
[Unit]
Description=$desc (fedora-harden)

[Timer]
OnCalendar=$when
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
EOF
	enable_timer "fedora-harden-${name}.timer" || warn "Could not enable fedora-harden-${name}.timer"
	return 0
}

# _battery_limit() - Optional charge limit (80%) where the hardware supports it.
_battery_limit() {
	local f
	for f in /sys/class/power_supply/BAT*/charge_control_end_threshold; do
		[[ -w "$f" ]] || continue
		confirm "Limit battery charging to 80% to slow battery wear?" no || return 0
		local old
		old="$(cat "$f" 2>/dev/null)"
		write_new_file /etc/tmpfiles.d/fedora-harden-battery.conf 0644 <<EOF || return 0
# Written by fedora-harden.sh (section 19): keep the battery at most 80% charged.
w $f - - - - 80
EOF
		if ((! DRY_RUN)) && printf '80' 2>/dev/null >"$f"; then
			record_change SYSFS "$f=$old"
			ok "Battery charge limited to 80% (was $old%)."
		fi
		return 0
	done
	info "This battery has no adjustable charge limit — skipped."
}

# _layer_audit() - Image-based systems: packages layered into the image that have a
# better home (a Flatpak, a container or a box), with how to move them.
_layer_audit() {
	local layered pkg hint n=0
	layered="$(rpm-ostree status --json 2>/dev/null | python3 -c 'import json,sys
d = json.load(sys.stdin)["deployments"]
b = [x for x in d if x.get("booted")] or d[:1]
print(" ".join(b[0].get("requested-packages", []) + b[0].get("requested-local-packages", [])))' 2>/dev/null)"
	for pkg in $layered; do
		case "$pkg" in
		clamav* | clamtk) hint="section 16 scans in a container instead" ;;
		mat2) hint="Metadata Cleaner is a Flatpak" ;;
		buildah | skopeo | podman-compose | setools* | openscap* | scap-security-guide | gcc | make | golang | nodejs* | python3-*) hint="belongs in a toolbox/distrobox box" ;;
		*) continue ;;
		esac
		((++n))
		add_action_item 19 LOW "LAYER_${pkg//[^a-zA-Z0-9]/_}" \
			"$pkg is layered into the image; $hint. Remove the layer: sudo rpm-ostree uninstall $pkg"
	done
	((n)) && info "$n layered package(s) have a better home — see the follow-ups."
	return 0
}

# record_routine_state() - At the end of a run with section 19: checksums of the /etc
# files this run manages and the services it started, for the weekly drift check.
record_routine_state() {
	((ROUTINE_ACTIVE)) || return 0
	((DRY_RUN)) && return 0
	local dir=/var/lib/fedora-harden f u
	install -d -m 700 "$dir" 2>/dev/null || return 0
	local -A files=()
	if [[ -s "$dir/managed.sha256" ]]; then
		while read -r _ f; do files[$f]=1; done <"$dir/managed.sha256"
	fi
	if [[ -n "$ROLLBACK_JOURNAL" && -f "$ROLLBACK_JOURNAL" ]]; then
		while IFS='|' read -r _ ctype f; do
			[[ "$ctype" == FILE_CREATE || "$ctype" == FILE_BACKUP ]] || continue
			[[ "$f" == /etc/* || "$f" == "$ROUTINE_HELPER" ]] && files[$f]=1
		done < <(grep -v '^#' "$ROLLBACK_JOURNAL")
	fi
	backup_file "$dir/managed.sha256" || return 0
	for f in "${!files[@]}"; do
		[[ -f "$f" ]] && sha256sum "$f"
	done 2>/dev/null | sort -k2 >"$dir/managed.sha256"
	backup_file "$dir/managed.units" || return 0
	{
		[[ -f "$dir/managed.units" ]] && cat "$dir/managed.units"
		for u in "${!TOUCHED_UNITS[@]}"; do
			[[ "$u" == *.timer || "$u" == *.socket || "$u" == *.service ]] || continue
			systemctl is-active --quiet "$u" 2>/dev/null && echo "$u"
		done
	} | sort -u >"$dir/managed.units.new" 2>/dev/null && mv -f "$dir/managed.units.new" "$dir/managed.units"
	chmod 600 "$dir"/managed.* 2>/dev/null || true
	info "Recorded ${#files[@]} managed files and their services for the weekly drift check."
}
