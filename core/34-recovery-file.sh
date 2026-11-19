# shellcheck shell=bash
# ---------- The recovery file -----------------------------------------------
# _recovery_get <key> [file] - Value of KEY=... (last one wins, quotes removed).
_recovery_get() {
	[[ -r "${2:-$RECOVERY_FILE}" ]] || return 0
	sed -n "s/^$1=//p" "${2:-$RECOVERY_FILE}" | tail -n 1 | sed 's/^"\(.*\)"$/\1/'
}

# _union <list> <list> - Space-separated union, first-seen order.
# shellcheck disable=SC2086  # the lists are split on purpose
_union() {
	printf '%s\n' $1 $2 | awk 'NF && !seen[$0]++' | tr '\n' ' ' | sed 's/ $//'
}

# write_recovery_file - Record what this machine was set up with (after a real run).
write_recovery_file() {
	((DRY_RUN)) && return 0
	local f="$RECOVERY_FILE" s sections="" flatpaks="" timers wg="" key copy
	for s in "${SECTIONS[@]}"; do
		[[ -n "$ONLY_LIST" ]] && ! in_list "$s" "$ONLY_LIST" && continue
		[[ -n "$SKIP_LIST" ]] && in_list "$s" "$SKIP_LIST" && continue
		sections+="$s "
	done
	sections="$(_union "$(_recovery_get SECTIONS)" "$sections" | tr ' ' '\n' | sort -n | tr '\n' ' ' | sed 's/ $//')"
	[[ -n "$ROLLBACK_JOURNAL" ]] &&
		flatpaks="$(awk -F'|' '$2 == "FLATPAK_INSTALL" {print $3}' "$ROLLBACK_JOURNAL" 2>/dev/null | tr '\n' ' ')"
	flatpaks="$(_union "$(_recovery_get FLATPAKS)" "$flatpaks")"
	timers="$(systemctl list-unit-files 'fedora-harden-*.timer' --state=enabled --no-legend 2>/dev/null | awk '{print $1}' | tr '\n' ' ' | sed 's/ $//' || true)"
	[[ -e /etc/wireguard/wg0.conf ]] &&
		wg="supply the provider config again with --wireguard-config FILE (it was installed as /etc/wireguard/wg0.conf)"
	copy="${RECOVERY_BACKUP_ARG:-$(_recovery_get BACKUP_COPY)}"
	[[ -n "$copy" ]] || copy=yes
	# Earlier answers are kept unless this run answered the same question.
	local -A all=() text=()
	while IFS='=' read -r key s; do
		all[${key#ANSWER_}]="$s"
	done < <(grep -E '^ANSWER_[0-9a-f]{12}=(yes|no)$' "$f" 2>/dev/null)
	while IFS= read -r s; do
		text[${s%%|*}]="${s#*|}"
	done < <(awk '/^# Q / {q=substr($0, 5); next} /^ANSWER_/ {split($1, a, "[_=]"); print a[2] "|" q}' "$f" 2>/dev/null)
	for key in "${!ANSWERS[@]}"; do
		all[$key]="${ANSWERS[$key]}"
		text[$key]="${ANSWER_TEXT[$key]}"
	done
	local release="${PLATFORM_RELEASE:-unknown}" edition
	# shellcheck source=/dev/null
	edition="$(. /etc/os-release 2>/dev/null && echo "${VARIANT_ID:-${ID:-unknown}}")"
	local new
	new="$(mktemp)" || return 0
	register_tmp "$new"
	cat >"$new" <<EOF || {
# fedora-harden recovery file: what this machine was set up with, kept up to date
# after every run. After a reinstall or a recovery, put things back with:
#   sudo ./fedora-harden.sh --restore $f
# It holds no secrets (no keys, passwords or tunnel configs).
# BACKUP_COPY=no keeps it out of the home snapshots (or: --recovery-backup off).
UPDATED=$(date '+%F %T')
SESSION=$RUN_STAMP
FEDORA_RELEASE=$release
EDITION=$edition
IMAGE_BASED=$( ((IS_OSTREE)) && echo yes || echo no)
TARGET_USER=${TARGET_USER:-$(_recovery_get TARGET_USER)}
SECTIONS="$sections"
USE_CASES="$(sed -n 's/^USE_CASES=//p' /etc/fedora-harden/profile 2>/dev/null | tr -d '"')"
BOXES="$(_union "$(_recovery_get BOXES)" "${BOXES_MADE[*]}")"
FLATPAKS="$flatpaks"
TIMERS="$timers"
SNAPSHOT_BACKEND=$(sed -n 's/^BACKEND=//p' /etc/fedora-harden/snapshots 2>/dev/null)
BACKUP_TARGET=${BACKUP_TARGET:-$(_recovery_get BACKUP_TARGET)}
WIREGUARD="${wg:-$(_recovery_get WIREGUARD)}"
LUKS_UNLOCK=${SETUP_CHOICES[LUKS_UNLOCK]:-$(_recovery_get LUKS_UNLOCK)}
PAM_U2F=${SETUP_CHOICES[PAM_U2F]:-$(_recovery_get PAM_U2F)}
FLATHUB_VERIFIED=${SETUP_CHOICES[FLATHUB_VERIFIED]:-$(_recovery_get FLATHUB_VERIFIED)}
PRIVATE_BROWSING=${SETUP_CHOICES[PRIVATE_BROWSING]:-$(_recovery_get PRIVATE_BROWSING)}
OPENSNITCH=${SETUP_CHOICES[OPENSNITCH]:-$(_recovery_get OPENSNITCH)}
BACKUP_COPY=$copy
# Answers to the questions (Q = the question; --restore gives the same answers).
$(for key in $(printf '%s\n' "${!all[@]}" | sort); do printf '# Q %s\nANSWER_%s=%s\n' "${text[$key]//$'\n'/ }" "$key" "${all[$key]}"; done)
EOF
		warn "Could not write the recovery file (disk full?) — keeping the previous one."
		return 0
	}
	# Rewrite only when something besides the date and session changed, so a
	# repeated run leaves /etc as it was.
	if [[ -f "$f" ]] && diff -q <(grep -vE '^(UPDATED|SESSION)=' "$f") <(grep -vE '^(UPDATED|SESSION)=' "$new") >/dev/null 2>&1; then
		_recovery_backup_copy "$copy"
		return 0
	fi
	write_new_file "$f" 0600 <"$new" || return 0
	_recovery_backup_copy "$copy"
}

# _recovery_backup_copy <yes|no> - Keep a copy inside the home folder's backups
# (section 20 snapshots or copies everything under it), or remove it.
_recovery_backup_copy() {
	local want="$1" home dest
	home="$(sed -n 's/^HOME_DIR=//p' /etc/fedora-harden/snapshots 2>/dev/null || true)"
	[[ -n "$home" && -d "$home" ]] || return 0
	dest="$home/.fedora-harden/machine.conf"
	if [[ "$want" != yes ]]; then
		if [[ -e "$dest" ]] && backup_file "$dest"; then
			rm -f "$dest" && info "Recovery file no longer copied into the home backups."
		fi
		return 0
	fi
	install -d -m 700 "$home/.fedora-harden" 2>/dev/null || return 0
	cmp -s "$RECOVERY_FILE" "$dest" && return 0
	backup_file "$dest" || return 0
	cp -f "$RECOVERY_FILE" "$dest" && chmod 600 "$dest" || return 0
	info "Recovery file copied into the home backups ($dest); turn off with --recovery-backup off."
}

# load_recovery_file <file> - --restore: read a recovery file (never sourced) and
# set this run up to reapply it without questions.
load_recovery_file() {
	local f="$1" v key s
	[[ -r "$f" ]] || {
		err "--restore: cannot read '$f'."
		exit 2
	}
	grep -q '^# fedora-harden recovery file' "$f" || {
		err "--restore: '$f' is not a fedora-harden recovery file."
		exit 2
	}
	v="$(_recovery_get SECTIONS "$f")"
	if [[ -z "$ONLY_LIST" && "$v" =~ ^[0-9\ ]+$ ]]; then
		ONLY_LIST="${v// /,}"
	fi
	v="$(_recovery_get USE_CASES "$f")"
	[[ -z "$PROFILE_ARG" && "$v" =~ ^[a-z\ ]+$ ]] && PROFILE_ARG="${v// /,}"
	v="$(_recovery_get TARGET_USER "$f")"
	[[ -z "$TARGET_USER" && "$v" =~ ^[a-z_][a-z0-9_.-]*$ ]] && getent passwd "$v" >/dev/null && TARGET_USER="$v"
	v="$(_recovery_get BACKUP_TARGET "$f")"
	[[ -z "$BACKUP_TARGET" && -n "$v" && -d "$v" ]] && BACKUP_TARGET="$v"
	v="$(_recovery_get BACKUP_COPY "$f")"
	[[ -z "$RECOVERY_BACKUP_ARG" && "$v" =~ ^(yes|no)$ ]] && RECOVERY_BACKUP_ARG="$v"
	while IFS='=' read -r key s; do
		RESTORE_ANSWERS[${key#ANSWER_}]="$s"
	done < <(grep -E '^ANSWER_[0-9a-f]{12}=(yes|no)$' "$f")
	ASSUME_YES=1
	printf '%s[INFO]%s  Restoring from %s (written %s on Fedora %s %s):\n' "$C_BLU" "$C_RST" "$f" \
		"$(_recovery_get UPDATED "$f")" "$(_recovery_get FEDORA_RELEASE "$f")" "$(_recovery_get EDITION "$f")"
	printf '         sections %s; use cases: %s; boxes: %s\n' "${ONLY_LIST:-all}" \
		"$(_recovery_get USE_CASES "$f")" "$(_recovery_get BOXES "$f")"
	printf '         %d earlier answers reused; everything else takes the default.\n' "${#RESTORE_ANSWERS[@]}"
	v="$(_recovery_get WIREGUARD "$f")"
	[[ -n "$v" && -z "$WG_CONFIG" ]] && printf '         WireGuard: %s\n' "$v"
	v="$(_recovery_get LUKS_UNLOCK "$f")"
	[[ "$v" == tpm2 || "$v" == fido2 ]] && printf '         Disk unlock was %s: re-enroll it when asked (needs the passphrase).\n' "$v"
	return 0
}

# _report_recovery - HTML report: say whether a recovery file exists and when it
# was updated; its contents only with --include-setup.
_report_recovery() {
	if [[ ! -f "$RECOVERY_FILE" ]]; then
		printf '<h2>Recovery file</h2><p>None yet (written after a real run).</p>\n'
		return 0
	fi
	printf '<h2>Recovery file</h2><p>%s, updated %s. Restore with <code>sudo %s --restore %s</code>.</p>\n' \
		"$(_html "$RECOVERY_FILE")" "$(_html "$(_recovery_get UPDATED)")" "$SCRIPT_NAME" "$(_html "$RECOVERY_FILE")"
	((INCLUDE_SETUP)) || {
		printf '<p>Its contents are left out of this report; add <code>--include-setup</code> to include them.</p>\n'
		return 0
	}
	printf '<table>\n'
	local key val
	while IFS='=' read -r key val; do
		printf '<tr><td>%s</td><td>%s</td></tr>\n' "$(_html "$key")" "$(_html "${val//\"/}")"
	done < <(grep -E '^[A-Z_]+=' "$RECOVERY_FILE" | grep -v '^ANSWER_')
	printf '</table>\n'
}
