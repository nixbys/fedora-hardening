# shellcheck shell=bash
# ============================================================================
#  SECTION 17 — OpenSCAP
# ============================================================================
# sec_17_openscap() - Install and run OpenSCAP compliance scanner
# Installs OpenSCAP framework and runs initial compliance scan against security baseline.
sec_17_openscap() {
	should_run 17 || return 0
	section 17 "OpenSCAP compliance scanner"
	if ((IS_OSTREE)); then
		_oscap_in_container
	else
		_oscap_on_host || return 0
	fi
	_oscap_report
}

# _oscap_in_container() - Image-based systems: scan the host read-only from a
# throwaway Fedora container (oscap-chroot) instead of layering OpenSCAP.
_oscap_in_container() {
	local release="${FEDORA_MAJOR:-0}"
	((release > 0)) || release="$(rpm -E %fedora 2>/dev/null || echo 44)"
	local image="registry.fedoraproject.org/fedora:${release}"
	if ! cmd_exists podman; then
		warn "podman is not available — OpenSCAP scan skipped."
		return 0
	fi
	info "Image-based system: OpenSCAP runs in a throwaway $image container and reads the host read-only (nothing is layered)."
	if confirm "Run a baseline scan now (results in /root/scap-report.html)?"; then
		# Host networking: the container only downloads the scanner, and this avoids
		# depending on the container network stack (nested setups, unusual firewalls).
		# Its package cache lives in memory: the container is thrown away anyway.
		# oscap exits 2 when rules fail, so success is judged by the results file.
		((DRY_RUN)) || rm -f /root/scap-results.xml /root/scap-report.html
		run "podman run --rm --network host --tmpfs /var/cache/libdnf5:rw,size=2g --tmpfs /tmp:rw,size=512m --security-opt label=disable -v /:/host:ro -v /root:/out '$image' sh -c 'dnf -y -q install openscap-scanner scap-security-guide >/dev/null && oscap-chroot /host xccdf eval --profile xccdf_org.ssgproject.content_profile_standard --results /out/scap-results.xml --report /out/scap-report.html /usr/share/xml/scap/ssg/content/ssg-fedora-ds.xml' || true"
		if ((DRY_RUN)); then
			return 0
		elif [[ -s /root/scap-results.xml ]]; then
			ok "Report: /root/scap-report.html"
		else
			local why=""
			[[ -s "${ERROR_CAPTURE_FILE:-}" ]] && why="$(tail -n 3 "$ERROR_CAPTURE_FILE" | tr '\n' ' ')"
			warn "The OpenSCAP container produced no results${why:+: $why}"
			add_action_item 17 MEDIUM "SCAP_CONTAINER_FAILED" \
				"The OpenSCAP scan container did not produce results${why:+ ($why)}. Check network access to registry.fedoraproject.org and re-run section 17."
		fi
	fi
}

# _oscap_on_host() - Package-based systems: install OpenSCAP and scan. Returns 1 to skip.
_oscap_on_host() {
	pkg_install openscap-scanner scap-security-guide
	# On rpm-ostree, packages are staged — oscap may not be available until reboot.
	# Use cmd_exists check only; do not hard-fail if missing.
	ensure_command_dep oscap "OpenSCAP compliance scan" openscap-scanner || true
	if ! cmd_exists oscap; then
		warn "oscap command is unavailable after dependency checks — skipping section 17."
		return 1
	fi
	local content="/usr/share/xml/scap/ssg/content/ssg-fedora-ds.xml"
	if [[ ! -f "$content" ]]; then
		warn "SSG content missing at expected path; retrying dependency install and alternate path lookup."
		pkg_install scap-security-guide
		if [[ ! -f "$content" ]]; then
			local alt_content=""
			local candidate
			for candidate in /usr/share/xml/scap/ssg/content/ssg-fedora*-ds.xml; do
				[[ -f "$candidate" ]] || continue
				alt_content="$candidate"
				break
			done
			if [[ -n "$alt_content" ]]; then
				content="$alt_content"
				info "Using alternate SSG content path: $content"
			else
				warn "No Fedora SSG datastream found; skipping OpenSCAP scan."
				return 1
			fi
		fi
	fi
	info "Available profiles:"
	run "oscap info '$content' | grep -E '^(Profile|Title)' | head -20 || true"
	if confirm "Run a baseline scan now (results in /root/scap-report.html)?"; then
		run "oscap xccdf eval \
            --profile xccdf_org.ssgproject.content_profile_standard \
            --results /root/scap-results.xml \
            --report  /root/scap-report.html \
            '$content' || true"
		ok "Report: /root/scap-report.html"
	fi
}

# scap_results() - Parse an XCCDF results file. Prints "<pass> <fail> <notchecked>",
# or with "failing" the IDs of failed rules. Each result is a <rule-result idref=...>
# element with a nested <result>fail</result>, not a result="..." attribute.
# Usage: scap_results <results.xml> [counts|failing]
scap_results() {
	awk -v want="${2:-counts}" '
		/<rule-result[ >]/ {
			id = ""
			if (match($0, /idref="[^"]*"/)) id = substr($0, RSTART + 7, RLENGTH - 8)
		}
		/<result>[a-z]+<\/result>/ {
			r = $0
			sub(/.*<result>/, "", r)
			sub(/<\/result>.*/, "", r)
			n[r]++
			if (want == "failing" && r == "fail" && id != "") print id
		}
		END { if (want == "counts") print n["pass"] + 0, n["fail"] + 0, n["notchecked"] + 0 }
	' "$1"
}

# _oscap_report() - Copy results to the user's results folder and summarise them.
_oscap_report() {
	if ((! DRY_RUN)); then
		copy_to_user_results /root/scap-report.html "section-22-openscap-${REPORT_DATE}.html"
		copy_to_user_results /root/scap-results.xml "section-22-openscap-results-${REPORT_DATE}.xml"
		local pass_count="?" fail_count="?" notchecked_count="?"
		if [[ -f /root/scap-results.xml ]]; then
			read -r pass_count fail_count notchecked_count < <(
				scap_results /root/scap-results.xml 2>/dev/null || printf '? ? ?\n'
			)
			info "OpenSCAP results — pass: $pass_count  fail: $fail_count  not-checked: $notchecked_count"
			{
				printf '=== Section 17: OpenSCAP Compliance Summary ===\n'
				printf 'Generated: %s\n\n' "$RUN_STAMP_HUMAN"
				printf 'Results XML:  /root/scap-results.xml\n'
				printf 'HTML report:  /root/scap-report.html\n\n'
				printf 'Pass:         %s\n' "$pass_count"
				printf 'Fail:         %s\n' "$fail_count"
				printf 'Not checked:  %s\n\n' "$notchecked_count"
				printf -- '--- Top 25 failing rules ---\n'
				scap_results /root/scap-results.xml failing 2>/dev/null |
					head -25 ||
					printf '(no failures found or XML parse error)\n'
			} | write_user_report "section-22-openscap-summary-${REPORT_DATE}.txt" || true
			local fail_n
			fail_n="${fail_count//[^0-9]/}"
			if [[ -n "$fail_n" ]] && ((fail_n > 0)) 2>/dev/null; then
				add_action_item 17 HIGH "SCAP_FAILED_RULES" \
					"OpenSCAP: $fail_count rule(s) failed — review $USER_RESULTS_DIR/section-22-openscap-${REPORT_DATE}.html"
			else
				ok "OpenSCAP scan: $pass_count passing, $fail_count failing."
			fi
		else
			add_action_item 17 MEDIUM "SCAP_NO_SCAN" \
				"OpenSCAP scan was skipped or results not found — rerun section 17 to generate compliance report."
		fi
	fi
}
