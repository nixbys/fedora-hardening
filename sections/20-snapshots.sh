# shellcheck shell=bash
# ============================================================================
#  SECTION 20 — Home snapshots and copies
# ============================================================================
# sec_20_snapshots() - Protect the home folder against deleted or overwritten files,
# with what the system already ships: Snapper where it is installed (Bazzite),
# read-only Btrfs snapshots on other Btrfs systems, and hard-link incremental copies
# (rsync) elsewhere — to a second drive when one is configured. How often follows how
# actively the machine is used; nothing is taken when nothing changed. A home index
# flags large replaceable folders; each is left out only with approval.
sec_20_snapshots() {
	should_run 20 || return 0
	section 20 "Home snapshots and copies"
	install_routine_helper || return 0

	local home backend target="" fstype
	home="$(readlink -f /home)"
	fstype="$(findmnt -no FSTYPE -T "$home" 2>/dev/null)"
	local home_pending=0
	if [[ "$fstype" == btrfs ]]; then
		backend=btrfs
		cmd_exists snapper && backend=snapper
		# Installed with bootc, home is a plain folder on Btrfs: make it its own
		# subvolume at the next boot, before anyone logs in; snapshots start then.
		btrfs subvolume show "$home" >/dev/null 2>&1 || home_pending=1
	else
		backend=rsync
		pkg_install rsync
		if ((! DRY_RUN)) && ! cmd_exists rsync; then
			warn "rsync is not available — home copies not set up."
			return 0
		fi
		target="$(_backup_target "$home")"
	fi
	info "Home folder $home ($fstype): $backend$([[ -n "$target" ]] && echo " → $target")"

	write_new_file /etc/fedora-harden/snapshots 0600 <<EOF || return 0
# Written by fedora-harden.sh (section 20).
BACKEND=$backend
HOME_DIR=$home
TARGET=$target
EXCLUDES=""
EOF
	# The snapshot store is created by the helper on the first snapshot (Snapper's
	# config on Bazzite: it thins to 24 recent, 7 daily, 4 weekly).
	if ((! DRY_RUN)); then
		if [[ "$backend" == rsync ]]; then
			install -d -m 700 "$target" && record_change SNAPSHOT_DATA "$target"
		else
			record_change SNAPSHOT_DATA "$home/.snapshots"
			if ((home_pending)); then
				install -d -m 700 /var/lib/fedora-harden
				grep -qx '\.' /var/lib/fedora-harden/exclude-queue 2>/dev/null ||
					echo . >>/var/lib/fedora-harden/exclude-queue
				add_action_item 20 MEDIUM "HOME_SUBVOLUME_PENDING" \
					"Restart once to finish setting up home snapshots: at the next boot, before anyone logs in, $home becomes its own Btrfs subvolume (contents and permissions kept)."
			fi
		fi
	fi

	_routine_timer snapshot "Home snapshot when due (frequency follows how actively this machine is used)" hourly || return 0
	_routine_timer index "Weekly home index: note what grew, flag new large folders" weekly || return 0
	if [[ "$backend" != rsync ]]; then
		write_new_file /etc/systemd/system/fedora-harden-exclude.service 0644 <<EOF || return 0
[Unit]
Description=Leave approved folders out of home snapshots (fedora-harden), before anyone logs in
Before=systemd-user-sessions.service
ConditionFileNotEmpty=/var/lib/fedora-harden/exclude-queue

[Service]
Type=oneshot
ExecStart=$ROUTINE_HELPER exclude-convert

[Install]
WantedBy=multi-user.target
EOF
		backup_file /etc/systemd/system/multi-user.target.wants/fedora-harden-exclude.service || return 0
		run "systemctl daemon-reload && systemctl enable fedora-harden-exclude.service" || true
	fi

	if ((! DRY_RUN)); then
		info "Indexing the home folder (folders of 5 GB or more)..."
		FH_NO_WAIT=1 "$ROUTINE_HELPER" index >/dev/null 2>&1 || true
		_snapshot_exclusions "$backend"
	fi
	_offsite_options "$home"
	ok "Home protection on: $backend. The first snapshot comes within the hour; how often depends on how much the machine is used."
}

# _backup_target <home> - Where copies go without Btrfs: --backup-target, or a drive
# configured for backups (/backup, /mnt/backup) — only if it is a different device;
# otherwise /var/lib/fedora-harden/home-copies on the same disk.
_backup_target() {
	local home="$1" t
	for t in "$BACKUP_TARGET" /backup /mnt/backup; do
		[[ -n "$t" && -d "$t" ]] || continue
		if [[ "$(stat -c %d "$t")" != "$(stat -c %d "$home")" ]]; then
			echo "$t/fedora-harden-home"
			return 0
		fi
		[[ "$t" == "$BACKUP_TARGET" ]] && warn "$t is on the same drive as $home; using the default location."
	done
	add_action_item 20 MEDIUM "COPIES_SAME_DISK" \
		"Home copies are kept on the same disk ($home): they help with deleted files, not a failed disk. With a second drive: sudo ./fedora-harden.sh --only 20 --backup-target /path/on/that/drive"
	echo /var/lib/fedora-harden/home-copies
}

# _snapshot_exclusions <backend> - Offer to leave each large replaceable folder of
# the index out of snapshots (asked one by one; off under --yes).
_snapshot_exclusions() {
	local backend="$1" index=/var/lib/fedora-harden/home-index.tsv path size class excl=""
	[[ -s "$index" ]] || return 0
	while IFS=$'\t' read -r path size class; do
		[[ "$class" == replaceable ]] || continue
		confirm "Leave $path ($size GB, replaceable) out of home snapshots?" no || continue
		if [[ "$backend" == rsync ]]; then
			excl+="$path "
		else
			printf '%s\n' "$path" >>/var/lib/fedora-harden/exclude-queue
			info "$path will become its own subvolume at the next boot, before anyone logs in."
		fi
	done < <(sort -t$'\t' -k2 -rn "$index")
	[[ -n "$excl" ]] && sed -i "s|^EXCLUDES=.*|EXCLUDES=\"${excl% }\"|" /etc/fedora-harden/snapshots
	return 0
}

# _offsite_options <home> - Snapshots live on the same disk. Rank the ways to keep a
# copy elsewhere by what this machine has, and let the person choose.
_offsite_options() {
	local usb net have_pika=0 have_dejadup=0
	usb="$(lsblk -nrpo MOUNTPOINT,HOTPLUG 2>/dev/null | awk '$2 == 1 && $1 != "" {print $1; exit}' || true)"
	net="$(findmnt -rn -t cifs,nfs,nfs4,smb3 -o TARGET 2>/dev/null | head -1 || true)"
	flatpak info org.gnome.World.PikaBackup >/dev/null 2>&1 && have_pika=1
	flatpak info org.gnome.DejaDup >/dev/null 2>&1 && have_dejadup=1
	local n=1
	if [[ -n "$usb" ]]; then
		add_action_item 20 MEDIUM "OFFSITE_${n}" \
			"Off-machine copy, best fit (external drive at $usb): Pika Backup$( ((have_pika)) && echo ' (installed)' || echo ' — flatpak install flathub org.gnome.World.PikaBackup'). Encrypted, deduplicated, runs on a schedule."
		((++n))
	fi
	if [[ -n "$net" ]]; then
		add_action_item 20 MEDIUM "OFFSITE_${n}" \
			"Off-machine copy to the network share at $net: Pika Backup to that folder, or restic in a box for a server you reach over SSH."
		((++n))
	fi
	add_action_item 20 LOW "OFFSITE_${n}" \
		"Off-machine copy to cloud storage: Déjà Dup$( ((have_dejadup)) && echo ' (installed)' || echo ' — flatpak install flathub org.gnome.DejaDup') (Google Drive, Microsoft OneDrive, a Nextcloud/WebDAV server, or a folder), encrypted."
	((++n))
	[[ -z "$usb" ]] && add_action_item 20 LOW "OFFSITE_${n}" \
		"Off-machine copy to an external drive (plug one in and re-run section 20 for a tailored suggestion): Pika Backup, flatpak install flathub org.gnome.World.PikaBackup"
	return 0
}
