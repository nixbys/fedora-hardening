# shellcheck shell=bash
# ---------- Rollback session helpers ----------------------------------------

# Print the backup directory of a session ID (RUN_STAMP format); 1 if there is none.
find_session_backup_dir() {
	local stamp="$1"
	local dir="/root/harden-backups-${stamp}"
	if [[ -d "$dir" ]]; then
		printf '%s' "$dir"
		return 0
	fi
	return 1
}

# --list-sessions. Also lists backup directories without a session report (runs from
# before session reports existed).
list_sessions_cmd() {
	printf '\n%s════════ Past Hardening Sessions ════════%s\n' "$C_CYN" "$C_RST"

	local found=0
	local -A seen_stamps=() # track stamps that have session reports

	if [[ -d "$SESSION_DIR" ]]; then
		for f in "$SESSION_DIR"/session-*.txt; do
			[[ -f "$f" ]] || continue
			((++found))
			# Single awk pass extracts both Session and Status fields to avoid reading the file twice.
			local session_id status _awk_out
			_awk_out="$(awk '/^Session:/{sid=$2} /^Status:/{sts=$2} END{print (sid?sid:"unknown"), (sts?sts:"unknown")}' "$f" 2>/dev/null || true)"
			session_id="${_awk_out%% *}"
			status="${_awk_out##* }"
			[[ -z "$session_id" ]] && session_id="unknown"
			[[ -z "$status" ]] && status="unknown"
			seen_stamps["$session_id"]=1
			case "$status" in
			completed) printf '  %s[✓]%s %s  (completed)\n' "$C_GRN" "$C_RST" "$session_id" ;;
			aborted) printf '  %s[✗]%s %s  (aborted)\n' "$C_RED" "$C_RST" "$session_id" ;;
			running) printf '  %s[~]%s %s  (interrupted)\n' "$C_YEL" "$C_RST" "$session_id" ;;
			*) printf '       %s  (%s)\n' "$session_id" "$status" ;;
			esac
			printf '       Report: %s\n' "$f"
		done
	fi

	# Show backup dirs that have no session report (pre-session-feature runs)
	for d in /root/harden-backups-*/; do
		[[ -d "$d" ]] || continue
		local stamp="${d%/}"
		stamp="${stamp##*/harden-backups-}"
		[[ -n "${seen_stamps[$stamp]:-}" ]] && continue
		((++found))
		local journal_note="no journal"
		[[ -f "${d}.rollback-journal" ]] && journal_note="journal present"
		printf '  %s[?]%s %s  (no session report — %s)\n' "$C_YEL" "$C_RST" "$stamp" "$journal_note"
		printf '       Backup dir: %s\n' "$d"
	done

	if ((found == 0)); then
		printf '  No sessions found.\n'
	fi
	printf '%s═════════════════════════════════════════%s\n\n' "$C_CYN" "$C_RST"
	printf 'To roll back a single session:  sudo %s --rollback <session-id>\n' "$SCRIPT_NAME"
	printf 'To roll back ALL sessions:      sudo %s --rollback all\n\n' "$SCRIPT_NAME"
}

# Undo journal entries, newest first. Shared by rollback_session and
# rollback_all_sessions; updates _RBJ_RESTORED and _RBJ_ERRORS (the caller sets them
# up).
# Arguments: <journal_file> <backup_dir> <rb_report>
_apply_rollback_journal() {
	local journal_file="$1" backup_dir="$2" rb_report="$3"

	_rjl() { [[ -n "$rb_report" ]] && printf '%s\n' "$*" >>"$rb_report" 2>/dev/null || true; }

	local -a journal_lines=()
	while IFS= read -r jline; do
		[[ "$jline" == '#'* || -z "$jline" ]] && continue
		journal_lines+=("$jline")
	done <"$journal_file"

	local i n=${#journal_lines[@]}
	local -a touched=() rb_pkgs=()
	for ((i = n - 1; i >= 0; i--)); do
		local ts ctype detail
		IFS='|' read -r ts ctype detail <<<"${journal_lines[$i]}"
		[[ -z "${ctype:-}" ]] && continue

		case "$ctype" in
		FILE_BACKUP)
			local restored_path="/${detail#/}"
			touched+=("$restored_path")
			local backup_copy="${backup_dir}${detail}"
			if [[ -f "$backup_copy" ]]; then
				if ((DRY_RUN)); then
					info "Would restore: $restored_path"
				elif cp -a "$backup_copy" "$restored_path" 2>/dev/null; then
					ok "Restored: $restored_path"
					_rjl "  [OK]   RESTORE  $restored_path"
					((++_RBJ_RESTORED))
				else
					warn "Failed to restore: $restored_path"
					_rjl "  [FAIL] RESTORE  $restored_path"
					((++_RBJ_ERRORS))
				fi
			else
				warn "Backup copy not found: $backup_copy — skipping restore of $detail"
				_rjl "  [SKIP] RESTORE  $detail (backup copy missing)"
			fi
			;;

		FILE_CREATE)
			local created_path="/${detail#/}"
			touched+=("$created_path")
			if [[ ! -e "$created_path" ]]; then
				_rjl "  [SKIP] REMOVE   $created_path (already absent)"
			elif ((DRY_RUN)); then
				info "Would remove created file: $created_path"
			elif rm -f -- "$created_path" 2>/dev/null; then
				ok "Removed created file: $created_path"
				_rjl "  [OK]   REMOVE   $created_path"
				((++_RBJ_RESTORED))
			else
				warn "Failed to remove created file: $created_path"
				_rjl "  [FAIL] REMOVE   $created_path"
				((++_RBJ_ERRORS))
			fi
			;;

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
				rb_pkgs+=("${_rb_more[@]}")
			fi
			;;

		SERVICE_ENABLE)
			if ((DRY_RUN)); then
				info "Would run: systemctl disable $detail"
			elif systemctl disable "$detail" 2>/dev/null; then
				ok "Service disabled: $detail"
				_rjl "  [OK]   SERVICE_DISABLE  $detail"
				((++_RBJ_RESTORED))
			else
				warn "Could not disable service: $detail"
				_rjl "  [WARN] SERVICE_DISABLE  $detail"
				((++_RBJ_ERRORS))
			fi
			;;

		SERVICE_DISABLE)
			if ((DRY_RUN)); then
				info "Would run: systemctl enable $detail"
			elif systemctl enable "$detail" 2>/dev/null; then
				ok "Service re-enabled: $detail"
				_rjl "  [OK]   SERVICE_ENABLE  $detail"
				((++_RBJ_RESTORED))
			else
				warn "Could not re-enable service: $detail"
				_rjl "  [WARN] SERVICE_ENABLE  $detail"
				((++_RBJ_ERRORS))
			fi
			;;

		SNAPSHOT_DATA)
			# Snapshots and copies are the person's data: never deleted by rollback.
			info "Kept home snapshots/copies in $detail — delete them yourself if you no longer want them."
			_rjl "  [KEEP] SNAPSHOT_DATA  $detail"
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

		ROOT_SNAPSHOT)
			# A read-only snapshot of / from before the run: a recovery point, kept.
			info "Kept the pre-run snapshot $detail (delete with: sudo btrfs subvolume delete $detail)."
			_rjl "  [KEEP] ROOT_SNAPSHOT  $detail"
			;;

		SYSFS)
			# path=old value written by the run (e.g. a battery charge limit)
			local sp="${detail%%=*}" sv="${detail#*=}"
			if ((DRY_RUN)); then
				info "Would restore $sp to $sv"
			elif printf '%s' "$sv" 2>/dev/null >"$sp"; then
				ok "Restored $sp"
				((++_RBJ_RESTORED))
			else
				warn "Could not restore $sp"
				((++_RBJ_ERRORS))
			fi
			;;

		WG_TUNNEL)
			if ((DRY_RUN)); then
				info "Would stop and disable wg-quick@$detail"
			elif systemctl disable --now "wg-quick@$detail" 2>/dev/null; then
				ok "Tunnel $detail stopped and disabled"
				_rjl "  [OK]   WG_TUNNEL  $detail"
				((++_RBJ_RESTORED))
			else
				warn "Could not stop wg-quick@$detail"
				_rjl "  [WARN] WG_TUNNEL  $detail"
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

		CHAGE)
			# user:min:max:warn as they were before the run (empty = not set → -1)
			local cu cmin cmax cwarn
			IFS=: read -r cu cmin cmax cwarn <<<"$detail"
			if ((DRY_RUN)); then
				info "Would restore password ageing for $cu"
			elif chage -m "${cmin:--1}" -M "${cmax:--1}" -W "${cwarn:--1}" "$cu" 2>/dev/null; then
				ok "Restored password ageing for $cu"
				_rjl "  [OK]   CHAGE  $cu"
				((++_RBJ_RESTORED))
			else
				warn "Could not restore password ageing for $cu"
				_rjl "  [WARN] CHAGE  $cu"
				((++_RBJ_ERRORS))
			fi
			;;

		FLATPAK_INSTALL)
			if ((DRY_RUN)); then
				info "Would run: flatpak uninstall -y $detail"
			elif have_cmd flatpak && flatpak uninstall -y "$detail" 2>/dev/null; then
				ok "Flatpak removed: $detail"
				_rjl "  [OK]   FLATPAK_REMOVE  $detail"
				((++_RBJ_RESTORED))
			else
				warn "Flatpak uninstall failed for: $detail"
				_rjl "  [WARN] FLATPAK_REMOVE  $detail"
				((++_RBJ_ERRORS))
			fi
			;;

		BOX)
			# user:tool:name — a box section 19 created (its data goes with it)
			local bu bt bn
			IFS=: read -r bu bt bn <<<"$detail"
			if ((DRY_RUN)); then
				info "Would remove the $bt box '$bn' of $bu"
			elif runuser -u "$bu" -- "$bt" rm --force "$bn" >/dev/null 2>&1; then
				ok "Removed the $bt box '$bn' of $bu"
				_rjl "  [OK]   BOX_REMOVE  $detail"
				((++_RBJ_RESTORED))
			else
				warn "Could not remove the $bt box '$bn' of $bu (already gone?)"
				_rjl "  [WARN] BOX_REMOVE  $detail"
			fi
			;;

		GROUP_ADD)
			local gu="${detail%%:*}" gg="${detail#*:}"
			if ((DRY_RUN)); then
				info "Would remove $gu from group $gg"
			elif gpasswd -d "$gu" "$gg" >/dev/null 2>&1; then
				ok "Removed $gu from group $gg"
				((++_RBJ_RESTORED))
			else
				warn "Could not remove $gu from group $gg"
				((++_RBJ_ERRORS))
			fi
			;;

		FLATPAK_SUBSET)
			# remote:previous subset (empty = all apps)
			local fr="${detail%%:*}" fs="${detail#*:}"
			if ((DRY_RUN)); then
				info "Would restore the $fr subset to '${fs:-all apps}'"
			elif flatpak remote-modify --subset="$fs" "$fr" 2>/dev/null; then
				ok "Flatpak remote $fr shows ${fs:-all apps} again"
				((++_RBJ_RESTORED))
			else
				warn "Could not restore the $fr subset"
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

		LUKS_TOKEN)
			# device:tpm2|fido2 — the unlock method section 19 enrolled; the
			# passphrase was never touched
			local ld="${detail%:*}" lk="${detail##*:}"
			if ((DRY_RUN)); then
				info "Would remove the $lk unlock from $ld"
			elif systemd-cryptenroll --wipe-slot="$lk" "$ld" >/dev/null 2>&1; then
				ok "Removed the $lk unlock from $ld (the passphrase still works)"
				((++_RBJ_RESTORED))
			else
				warn "Could not remove the $lk unlock from $ld: sudo systemd-cryptenroll --wipe-slot=$lk $ld"
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

		*)
			warn "Unknown journal entry type '$ctype' — skipping"
			_rjl "  [SKIP] UNKNOWN  $ctype: $detail"
			;;
		esac
	done

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
	_rollback_reload "${touched[@]}"
}

# After restoring files, make the running system use them again. Audit rules are
# loaded from the restored file (auditctl -R), not regenerated.
_rollback_reload() {
	((DRY_RUN)) && return 0
	local p sysctl=0 audit=0 fw=0 ssh=0 units=0 journald=0 svc
	local -a sandboxed=()
	for p in "$@"; do
		case "$p" in
		/etc/systemd/system/*.service.d/50-fedora-harden-sandbox.conf)
			svc="${p#/etc/systemd/system/}"
			sandboxed+=("${svc%.service.d/*}")
			units=1
			;;
		/etc/sysctl.d/* | /etc/sysctl.conf) sysctl=1 ;;
		/etc/audit/*) audit=1 ;;
		/etc/firewalld/*) fw=1 ;;
		/etc/ssh/*) ssh=1 ;;
		/etc/systemd/journald.conf.d/*) units=1 journald=1 ;;
		/etc/systemd/* | /etc/containers/systemd/*) units=1 ;;
		esac
	done
	((units)) && { systemctl daemon-reload 2>/dev/null || true; }
	((journald)) && { systemctl restart systemd-journald 2>/dev/null || true; }
	for svc in "${sandboxed[@]}"; do
		systemctl is-active --quiet "$svc" 2>/dev/null && { systemctl restart "$svc" 2>/dev/null || true; }
	done
	((sysctl)) && { sysctl --system >/dev/null 2>&1 || true; }
	((audit)) && have_cmd auditctl && [[ -f /etc/audit/audit.rules ]] && { auditctl -R /etc/audit/audit.rules >/dev/null 2>&1 || true; }
	((fw)) && systemctl is-active --quiet firewalld 2>/dev/null && { firewall-cmd --reload >/dev/null 2>&1 || true; }
	((ssh)) && systemctl is-active --quiet sshd 2>/dev/null && { systemctl reload sshd 2>/dev/null || true; }
	return 0
}

# Runs from before the rollback journal have only file backups: restore all of them.
# Updates _RBJ_RESTORED and _RBJ_ERRORS. Arguments: <backup_dir> <rb_report>
_restore_backup_dir_files() {
	local backup_dir="$1" rb_report="$2"

	_rbfl() { [[ -n "$rb_report" ]] && printf '%s\n' "$*" >>"$rb_report" 2>/dev/null || true; }

	local found_any=0
	while IFS= read -r bfile; do
		found_any=1
		local rel="${bfile#"${backup_dir}"}"
		local restored_path="/${rel#/}"
		if ((DRY_RUN)); then
			info "Would restore: $restored_path"
		elif cp -a "$bfile" "$restored_path" 2>/dev/null; then
			ok "Restored: $restored_path"
			_rbfl "  [OK]   RESTORE  $restored_path"
			((++_RBJ_RESTORED))
		else
			warn "Failed to restore: $restored_path"
			_rbfl "  [FAIL] RESTORE  $restored_path"
			((++_RBJ_ERRORS))
		fi
	done < <(find "$backup_dir" -type f ! -name '.rollback-journal' 2>/dev/null | sort)

	if ((! found_any)); then
		warn "No backup files found in: $backup_dir"
		_rbfl "  [INFO] No files found in backup dir: $backup_dir"
	fi
}

# Undo one session: restore backed-up files, remove the packages and Flatpaks it
# installed, reverse its service changes; writes a rollback report to sessions/.
# Usage: rollback_session <session-id|last>
rollback_session() {
	local session_id="${1:-last}"
	local backup_dir journal_file

	# Resolve 'last' to the most recent known session stamp
	if [[ "$session_id" == "last" ]]; then
		local latest=""
		if [[ -d "$SESSION_DIR" ]]; then
			for f in "$SESSION_DIR"/session-*.txt; do
				[[ -f "$f" ]] || continue
				local stamp
				stamp="$(basename "$f" .txt)"
				stamp="${stamp#session-}"
				[[ "$stamp" == "$RUN_STAMP" ]] && continue # this rollback run itself
				[[ -z "$latest" || "$stamp" > "$latest" ]] && latest="$stamp"
			done
		fi
		if [[ -z "$latest" ]]; then
			for d in /root/harden-backups-*/; do
				[[ -d "$d" ]] || continue
				local stamp
				stamp="${d%/}"
				stamp="${stamp##*/harden-backups-}"
				[[ "$stamp" == "$RUN_STAMP" ]] && continue
				[[ -z "$latest" || "$stamp" > "$latest" ]] && latest="$stamp"
			done
		fi
		if [[ -z "$latest" ]]; then
			err "No previous sessions found to roll back."
			return 1
		fi
		session_id="$latest"
		info "Most recent session found: $session_id"
	fi

	backup_dir="$(find_session_backup_dir "$session_id")" || {
		err "Backup directory not found for session: $session_id"
		err "Expected location: /root/harden-backups-${session_id}"
		return 1
	}

	journal_file="${backup_dir}/.rollback-journal"
	local has_journal=1
	if [[ ! -f "$journal_file" ]]; then
		has_journal=0
		warn "No rollback journal found in: $backup_dir"
		warn "This appears to be a pre-journal run — backed-up files will be restored."
		warn "Package installs and service state changes cannot be automatically reversed."
	fi

	info "Session:     $session_id"
	info "Backup dir:  $backup_dir"
	if ((has_journal)); then
		info "Journal:     $journal_file"
	else
		info "Journal:     (none)"
	fi

	if ! confirm "Proceed with rollback of session ${session_id}?"; then
		info "Rollback cancelled."
		return 0
	fi

	local rb_stamp
	printf -v rb_stamp '%(%Y%m%d-%H%M%S)T' -1 2>/dev/null || rb_stamp="$(date +%Y%m%d-%H%M%S)"
	local rb_report=""
	if [[ -d "$SESSION_DIR" ]]; then
		rb_report="${SESSION_DIR}/rollback-${session_id}-at-${rb_stamp}.txt"
	fi

	_RBJ_RESTORED=0
	_RBJ_ERRORS=0

	if [[ -n "$rb_report" ]]; then
		{
			printf '=== Fedora Hardening Rollback Report ===\n'
			printf 'Rolling back session:  %s\n' "$session_id"
			printf 'Rollback started:      %s\n' "$(date '+%F %T')"
			printf 'Host:                  %s\n' "$HOST_LABEL"
			printf 'Backup dir:            %s\n' "$backup_dir"
			if ((has_journal)); then
				printf 'Journal:               %s\n' "$journal_file"
			else
				printf 'Journal:               NONE (pre-journal run — file restore only)\n'
				printf '\nNOTE: Package installs and service state changes from this session\n'
				printf '      cannot be automatically reversed. Review manually.\n'
			fi
			printf '\n=== Rollback Actions ===\n'
		} >"$rb_report" 2>/dev/null || rb_report=""
	fi

	if ((has_journal)); then
		_apply_rollback_journal "$journal_file" "$backup_dir" "$rb_report"
	else
		_restore_backup_dir_files "$backup_dir" "$rb_report"
	fi

	if [[ -n "$rb_report" ]]; then
		{
			printf '\n=== Rollback Summary ===\n'
			printf 'Session rolled back:  %s\n' "$session_id"
			printf 'Changes reverted:     %d\n' "$_RBJ_RESTORED"
			printf 'Errors/warnings:      %d\n' "$_RBJ_ERRORS"
			printf 'Completed:            %s\n' "$(date '+%F %T')"
			((IS_OSTREE)) && printf '\nNOTE: rpm-ostree uninstalls require a reboot to take effect.\n'
			printf '\nA reboot is recommended to ensure all rollback changes are applied.\n'
		} >>"$rb_report" 2>/dev/null || true
		chmod 600 "$rb_report" 2>/dev/null || true
		ok "Rollback report saved: $rb_report"
	fi

	if ((_RBJ_ERRORS > 0)); then
		warn "Rollback completed with $_RBJ_ERRORS warning(s) — manual review may be needed."
	else
		ok "Rollback complete: $_RBJ_RESTORED change(s) reversed for session $session_id."
	fi
	((IS_OSTREE)) && warn "A reboot is required for rpm-ostree changes to take effect."
	info "A system reboot is recommended to finalize all rollback changes."
	return 0
}

# Undo every session, newest first, so each one is undone on top of the state it left
# (aborted sessions included). Sessions without a rollback journal have their backed-up
# files restored; their package and service changes cannot be inferred and are
# reported as unknown. Writes a combined report and a log to sessions/.
rollback_all_sessions() {
	printf '\n%s╔══════════════════════════════════════════════╗%s\n' "$C_RED" "$C_RST"
	printf '%s║   FULL SYSTEM ROLLBACK — ALL SESSIONS        ║%s\n' "$C_RED" "$C_RST"
	printf '%s╚══════════════════════════════════════════════╝%s\n\n' "$C_RED" "$C_RST"
	warn "This will attempt to reverse ALL changes from ALL hardening sessions."
	warn "File restores, package removals, and service state reversals will be applied."
	printf '\n'

	# 1. Discover all backup directories
	local -a all_stamps=()
	for d in /root/harden-backups-*/; do
		[[ -d "$d" ]] || continue
		local stamp="${d%/}"
		stamp="${stamp##*/harden-backups-}"
		[[ "$stamp" == "$RUN_STAMP" ]] && continue # this rollback run itself
		all_stamps+=("$stamp")
	done

	if [[ ${#all_stamps[@]} -eq 0 ]]; then
		err "No hardening backup directories found under /root/harden-backups-*."
		warn "If the script was run before backup support existed, no automatic rollback is possible."
		warn "Check /root/ manually for any files that may have been modified."
		return 1
	fi

	# Sort stamps lexicographically — YYYYMMDD-HHMMSS sorts correctly as strings
	local -a sorted_stamps=()
	while IFS= read -r s; do sorted_stamps+=("$s"); done \
		< <(printf '%s\n' "${all_stamps[@]}" | sort)

	local total_sessions=${#sorted_stamps[@]}
	info "Found $total_sessions session(s) to roll back (will process newest first):"
	local i
	for ((i = total_sessions - 1; i >= 0; i--)); do
		local s="${sorted_stamps[$i]}"
		if [[ -f "/root/harden-backups-${s}/.rollback-journal" ]]; then
			printf '  %s[journal]%s  %s\n' "$C_GRN" "$C_RST" "$s"
		else
			printf '  %s[no journal — file restore only]%s  %s\n' "$C_YEL" "$C_RST" "$s"
		fi
	done
	printf '\n'

	if ! confirm "Proceed with FULL rollback of all $total_sessions session(s)?"; then
		info "Full rollback cancelled."
		return 0
	fi

	# 2. Set up combined report and log files
	local rb_stamp
	printf -v rb_stamp '%(%Y%m%d-%H%M%S)T' -1 2>/dev/null || rb_stamp="$(date +%Y%m%d-%H%M%S)"

	# Ensure sessions dir exists — it may not if this is a pre-session-feature environment
	if [[ -z "$SESSION_DIR" ]] || ! install -d -m 700 "$SESSION_DIR" 2>/dev/null; then
		# A private directory, never a world-readable file in /tmp.
		SESSION_DIR="$(mktemp -d /tmp/fedora-harden-rollback.XXXXXX)" || SESSION_DIR=""
		warn "Sessions directory unavailable; writing the rollback report to ${SESSION_DIR:-nowhere}"
	fi

	local rb_report="${SESSION_DIR}/rollback-full-at-${rb_stamp}.txt"
	local rb_log="${SESSION_DIR}/rollback-full-at-${rb_stamp}.log"

	_frblog() {
		local msg="$*"
		printf '[%s] %s\n' "$(date '+%F %T')" "$msg" >>"$rb_log" 2>/dev/null || true
		log "[FULL-ROLLBACK] $msg"
	}

	{
		printf '=== Fedora Hardening — Full System Rollback Report ===\n'
		printf 'Started:        %s\n' "$(date '+%F %T')"
		printf 'Host:           %s\n' "$HOST_LABEL"
		printf 'Sessions found: %d\n' "$total_sessions"
		printf 'Processing:     newest-first (reverse chronological)\n'
		printf '\n'
		printf 'Sessions discovered:\n'
		for ((i = total_sessions - 1; i >= 0; i--)); do
			local s="${sorted_stamps[$i]}"
			if [[ -f "/root/harden-backups-${s}/.rollback-journal" ]]; then
				printf '  %s  [journal present]\n' "$s"
			else
				printf '  %s  [no journal — file restore only]\n' "$s"
			fi
		done
		printf '\n'
		printf 'NOTE: Sessions without a rollback journal (runs predating this feature)\n'
		printf '      will have their backed-up config files restored. Package installs\n'
		printf '      and service state changes from those sessions cannot be automatically\n'
		printf '      reversed and must be reviewed manually.\n'
		printf '\n'
	} >"$rb_report" 2>/dev/null || {
		warn "Could not create rollback report file."
		rb_report=""
	}
	: >"$rb_log" 2>/dev/null || true

	_frblog "Full rollback started. Sessions (${total_sessions}): ${sorted_stamps[*]}"

	# 3. Process sessions newest-first
	local total_restored=0 total_errors=0 sessions_ok=0 sessions_skipped=0
	for ((i = total_sessions - 1; i >= 0; i--)); do
		local s="${sorted_stamps[$i]}"
		local bdir="/root/harden-backups-${s}"
		local jfile="${bdir}/.rollback-journal"

		{
			printf '\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
			printf 'Session:    %s\n' "$s"
			printf 'Backup dir: %s\n' "$bdir"
		} >>"$rb_report" 2>/dev/null || true

		_frblog "Processing session $s"

		if [[ ! -d "$bdir" ]]; then
			warn "Backup directory missing for session $s — skipping."
			printf '  [SKIP] Backup directory not found.\n' >>"$rb_report" 2>/dev/null || true
			_frblog "Session $s skipped: backup dir missing"
			((++sessions_skipped))
			continue
		fi

		_RBJ_RESTORED=0
		_RBJ_ERRORS=0

		if [[ -f "$jfile" ]]; then
			printf 'Journal:    %s\n\nRollback actions:\n' "$jfile" >>"$rb_report" 2>/dev/null || true
			_frblog "Session $s: processing journal"
			_apply_rollback_journal "$jfile" "$bdir" "$rb_report"
		else
			{
				printf 'Journal:    NONE (pre-journal run — restoring files only)\n\n'
				printf 'NOTE: Package installs and service state changes from this session\n'
				printf '      cannot be automatically reversed. Review manually.\n\n'
				printf 'Rollback actions:\n'
			} >>"$rb_report" 2>/dev/null || true
			warn "Session $s: no journal — restoring backed-up files only."
			_frblog "Session $s: no journal found; attempting raw file restore"
			_restore_backup_dir_files "$bdir" "$rb_report"
		fi

		printf '\n  Session result: restored=%d  errors/warnings=%d\n' \
			"$_RBJ_RESTORED" "$_RBJ_ERRORS" >>"$rb_report" 2>/dev/null || true
		_frblog "Session $s done: restored=$_RBJ_RESTORED errors=$_RBJ_ERRORS"

		total_restored=$((total_restored + _RBJ_RESTORED))
		total_errors=$((total_errors + _RBJ_ERRORS))
		((++sessions_ok))
	done

	# 4. Write combined summary to report and log
	{
		printf '\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
		printf '=== Full Rollback Summary ===\n'
		printf 'Sessions found:     %d\n' "$total_sessions"
		printf 'Sessions processed: %d\n' "$sessions_ok"
		printf 'Sessions skipped:   %d\n' "$sessions_skipped"
		printf 'Changes reverted:   %d\n' "$total_restored"
		printf 'Errors/warnings:    %d\n' "$total_errors"
		printf 'Completed:          %s\n' "$(date '+%F %T')"
		printf 'Log file:           %s\n' "$rb_log"
		((IS_OSTREE)) && printf '\nNOTE: rpm-ostree uninstalls require a reboot to take effect.\n'
		printf '\nA reboot is strongly recommended to finalize all rollback changes.\n'
	} >>"$rb_report" 2>/dev/null || true
	chmod 600 "$rb_report" 2>/dev/null || true
	chmod 600 "$rb_log" 2>/dev/null || true

	_frblog "Full rollback complete. Processed=$sessions_ok Skipped=$sessions_skipped Restored=$total_restored Errors=$total_errors"

	printf '\n'
	ok "Full rollback report: $rb_report"
	ok "Full rollback log:    $rb_log"
	if ((total_errors > 0)); then
		warn "Full rollback completed with $total_errors warning(s) — manual review may be needed."
	else
		ok "Full rollback complete: $total_restored change(s) reversed across $sessions_ok session(s)."
	fi
	((IS_OSTREE)) && warn "A reboot is required for rpm-ostree changes to take effect."
	info "A system reboot is strongly recommended to finalize all rollback changes."
	return 0
}
# The target user's XDG Downloads directory (xdg-user-dir, else ~/Downloads). Returns
# 1, printing nothing, when there is no non-root target user.
get_user_downloads_dir() {
	local user="${TARGET_USER:-${SUDO_USER:-}}"
	[[ -z "$user" || "$user" == "root" ]] && return 1
	local home
	home="$(user_home "$user")"
	[[ -z "$home" ]] && return 1
	local dl
	dl="$(sudo -u "$user" xdg-user-dir DOWNLOAD 2>/dev/null || true)"
	[[ -z "$dl" ]] && dl="${home}/Downloads"
	printf '%s' "$dl"
}

# Downloads/<project>/results and logs, owned by the target user.
init_user_report_dirs() {
	local user="${TARGET_USER:-${SUDO_USER:-}}"
	USER_DOWNLOADS_DIR="$(get_user_downloads_dir 2>/dev/null || true)"
	if [[ -z "$USER_DOWNLOADS_DIR" ]]; then
		warn "No target user set — section reports will only appear in the log ($LOG_WHERE)."
		return 0
	fi
	USER_PROJECT_DIR="${USER_DOWNLOADS_DIR}/${PROJECT_NAME}"
	USER_RESULTS_DIR="${USER_PROJECT_DIR}/results"
	USER_LOGS_DIR="${USER_PROJECT_DIR}/logs"
	if ((DRY_RUN)); then
		info "Would create: $USER_PROJECT_DIR"
		info "Would create: $USER_RESULTS_DIR"
		info "Would create: $USER_LOGS_DIR"
		return 0
	fi
	install -d -m 750 -o "$user" -g "$user" "$USER_PROJECT_DIR" 2>/dev/null ||
		{
			warn "Could not create $USER_PROJECT_DIR — reports will only be in the log ($LOG_WHERE)."
			return 0
		}
	install -d -m 750 -o "$user" -g "$user" "$USER_RESULTS_DIR" 2>/dev/null ||
		{
			warn "Could not create $USER_RESULTS_DIR — reports will only be in the log ($LOG_WHERE)."
			return 0
		}
	install -d -m 750 -o "$user" -g "$user" "$USER_LOGS_DIR" 2>/dev/null || true
	ok "Project export dir ready: $USER_PROJECT_DIR"
	ok "Report dir ready: $USER_RESULTS_DIR"
	ok "Log dir ready: $USER_LOGS_DIR"
}

# Write stdin to a file in the user's results directory.
# Usage: { echo content; } | write_user_report <filename>
write_user_report() {
	local filename="$1"
	if [[ -z "$USER_RESULTS_DIR" ]]; then
		cat >/dev/null
		return 0
	fi
	if ((DRY_RUN)); then
		info "Would write report: $USER_RESULTS_DIR/$filename"
		cat >/dev/null
		return 0
	fi
	local user="${TARGET_USER:-${SUDO_USER:-}}"
	local path="${USER_RESULTS_DIR}/${filename}"
	if ! cat 2>/dev/null >"$path"; then
		err "Failed to write report to $path (filesystem may be read-only or full)"
		return 1
	fi
	chown "${user}:${user}" "$path" 2>/dev/null || true
	chmod 640 "$path" 2>/dev/null || true
	ok "Report saved: $path"
}

# Usage: copy_to_user_results <source_path> [dest_filename]
copy_to_user_results() {
	local src="$1" dest_name="${2:-$(basename "$1")}"
	[[ -z "$USER_RESULTS_DIR" || ! -f "$src" ]] && return 0
	((DRY_RUN)) && {
		info "Would copy $src -> $USER_RESULTS_DIR/$dest_name"
		return 0
	}
	local user="${TARGET_USER:-${SUDO_USER:-}}"
	cp -a "$src" "${USER_RESULTS_DIR}/${dest_name}" 2>/dev/null || true
	chown "${user}:${user}" "${USER_RESULTS_DIR}/${dest_name}" 2>/dev/null || true
	chmod 640 "${USER_RESULTS_DIR}/${dest_name}" 2>/dev/null || true
	ok "Copied $src -> $USER_RESULTS_DIR/$dest_name"
}

# Copy the run log and the error log to the user's logs directory.
copy_log_to_user() {
	[[ -n "$USER_LOGS_DIR" ]] || return 0
	((DRY_RUN)) && return 0
	local user="${TARGET_USER:-${SUDO_USER:-}}" dest="${USER_LOGS_DIR}/harden-${RUN_STAMP}.log"
	if ((LOG_JOURNAL)); then
		journalctl -t fedora-harden "FH_SESSION=$RUN_STAMP" -o short-iso --no-pager 2>/dev/null >"$dest" || return 0
	else
		[[ -f "$LOG_FILE" ]] || return 0
		cp -a "$LOG_FILE" "$dest" 2>/dev/null || return 0
	fi
	chown "${user}:${user}" "$dest" 2>/dev/null || true
	chmod 640 "$dest" 2>/dev/null || true
	ok "Log copied: $dest"
}

# Split follow-ups into selected and deferred. Accepts 'all', item numbers, tags, or a
# comma-separated mix of numbers and tags.
select_actionable_items() {
	local selection="${1:-all}"

	# Validate selection input to prevent shell injection
	if [[ ! "$selection" =~ ^[a-zA-Z0-9,[:space:]]*$ ]]; then
		err "Invalid selection format: contains non-alphanumeric characters (only 0-9, a-z, A-Z, commas allowed)"
		return 1
	fi

	local token idx=1
	declare -A picks=()
	SELECTED_ACTIONABLE_ITEMS=()
	DEFERRED_ACTIONABLE_ITEMS=()

	selection="${selection// /}"
	if [[ -z "$selection" || "${selection,,}" == "all" ]]; then
		SELECTED_ACTIONABLE_ITEMS=("${ACTIONABLE_ITEMS[@]}")
		return 0
	fi

	IFS=',' read -r -a tokens <<<"$selection"
	for token in "${tokens[@]}"; do
		[[ -z "$token" ]] && continue
		if [[ "$token" =~ ^[0-9]+$ ]]; then
			picks["index:$token"]=1
		else
			picks["tag:${token^^}"]=1
		fi
	done

	for item in "${ACTIONABLE_ITEMS[@]}"; do
		local section priority tag desc
		IFS='|' read -r section priority tag desc <<<"$item"
		if [[ -v "picks[index:${idx}]" || -v "picks[tag:${tag}]" ]]; then
			SELECTED_ACTIONABLE_ITEMS+=("$item")
		else
			DEFERRED_ACTIONABLE_ITEMS+=("$item")
		fi
		((++idx))
	done

	((${#SELECTED_ACTIONABLE_ITEMS[@]} > 0))
}

# Fix the follow-ups only with approval, all or selected by number and/or tag; declined
# ones stay with the session (--resume, --report).
handle_actionable_follow_up() {
	local summary_path="${1:-}"
	local selection="all"

	show_actionable_items
	((${#ACTIONABLE_ITEMS[@]} > 0)) || return 0

	if ! confirm "Implement the recommended next steps from the final summary now?"; then
		info "Follow-ups kept for later: sudo $SCRIPT_NAME --resume (or --report for a shareable page)."
		return 0
	fi

	if ((${#ACTIONABLE_ITEMS[@]} > 1)); then
		info "You can implement all items, or choose specific item numbers/tags from the actionable list."
		selection="$(prompt_input "Enter 'all' or comma-separated item numbers/tags to implement" "all")"
		if ! select_actionable_items "$selection"; then
			warn "Invalid actionable-item selection '$selection' — defaulting to all items."
			SELECTED_ACTIONABLE_ITEMS=("${ACTIONABLE_ITEMS[@]}")
			DEFERRED_ACTIONABLE_ITEMS=()
		fi
	else
		SELECTED_ACTIONABLE_ITEMS=("${ACTIONABLE_ITEMS[@]}")
		DEFERRED_ACTIONABLE_ITEMS=()
	fi

	ACTIONABLE_ITEMS=("${SELECTED_ACTIONABLE_ITEMS[@]}")
	remediation_loop
	if ((${#DEFERRED_ACTIONABLE_ITEMS[@]} > 0)); then
		info "${#DEFERRED_ACTIONABLE_ITEMS[@]} actionable item(s) were deferred by user choice."
		ACTIONABLE_ITEMS+=("${DEFERRED_ACTIONABLE_ITEMS[@]}")
	fi
	return 0
}
