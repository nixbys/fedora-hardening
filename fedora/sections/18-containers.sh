# shellcheck shell=bash
# ============================================================================
#  SECTION 18 — Container Security (Podman + Toolbox)
# ============================================================================
# A "containerized mindset": system administration runs natively; development, daily
# work and untrusted software run in containers. Hardens image policy, runtime defaults
# and registry resolution for them.
sec_18_containers() {
	should_run 18 || return 0
	section 18 "Container security (Podman + Toolbox — containerized mindset)"

	local box_tool
	box_tool="$(image_box_tool)"
	if ((IS_OSTREE)); then
		# Atomic images ship podman and their box tool; layer toolbox only where it
		# is the platform's tool and missing (Universal Blue uses distrobox).
		pkg_install podman
		[[ "$box_tool" == toolbox ]] && pkg_install toolbox
	else
		pkg_install podman toolbox
	fi
	ensure_command_dep podman "rootless container engine" podman || true
	if ! cmd_exists podman; then
		warn "podman not available after install attempt — skipping section 18."
		return 0
	fi

	if ((IS_OSTREE)); then
		_tools_box_setup "$box_tool"
	else
		if confirm "Install buildah (OCI image builder) and skopeo (image inspection/transfer)?"; then
			pkg_install buildah skopeo
		fi
		if confirm "Install podman-compose (docker-compose compatibility layer)?"; then
			pkg_install podman-compose
		fi
	fi

	# ── Rootless Podman: subuid/subgid ───────────────────────────────────────
	local run_user="${TARGET_USER:-${SUDO_USER:-}}"
	if [[ -n "$run_user" && "$run_user" != "root" ]]; then
		if ! grep -q "^${run_user}:" /etc/subuid 2>/dev/null; then
			info "Adding subuid range for rootless Podman (user: $run_user)..."
			if ((! DRY_RUN)); then
				backup_file /etc/subuid || return 0
				usermod --add-subuids 100000-165535 "$run_user" 2>/dev/null ||
					warn "usermod --add-subuids failed for $run_user — rootless Podman needs a range in /etc/subuid."
			else
				info "[DRY] Would add subuid 100000-165535 for $run_user"
			fi
		else
			ok "subuid entry already present for $run_user."
		fi
		if ! grep -q "^${run_user}:" /etc/subgid 2>/dev/null; then
			info "Adding subgid range for rootless Podman (user: $run_user)..."
			if ((! DRY_RUN)); then
				backup_file /etc/subgid || return 0
				usermod --add-subgids 100000-165535 "$run_user" 2>/dev/null ||
					warn "usermod --add-subgids failed for $run_user — rootless Podman needs a range in /etc/subgid."
			else
				info "[DRY] Would add subgid 100000-165535 for $run_user"
			fi
		else
			ok "subgid entry already present for $run_user."
		fi

		# ── User-level containers.conf with secure runtime defaults ──────────
		local user_home cont_conf_dir cont_conf
		user_home="$(user_home "$run_user")"
		cont_conf_dir="${user_home}/.config/containers"
		cont_conf="${cont_conf_dir}/containers.conf"
		if [[ -n "$user_home" ]]; then
			if ((! DRY_RUN)); then
				install -d -m 700 "$cont_conf_dir" 2>/dev/null || true
				if [[ ! -f "$cont_conf" ]]; then
					backup_file "$cont_conf" || return 0
					cat 2>/dev/null >"$cont_conf" <<'EOF'
# Rootless Podman hardening defaults — written by fedora-harden.sh
[containers]
# Block privilege escalation inside containers
no_new_privileges = true

# Enforce kernel syscall allowlist (system default seccomp profile)
seccomp_profile = "/usr/share/containers/seccomp.json"

# Minimal capability set — grant only what is explicitly required per workload
default_capabilities = [
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "FSETID",
    "KILL",
    "NET_BIND_SERVICE",
    "SETFCAP",
    "SETGID",
    "SETPCAP",
    "SETUID",
    "SYS_CHROOT",
]

[engine]
# crun is the default OCI runtime on Fedora; preferred over runc for performance + security
# runtime = "crun"
EOF
					run "chown '${run_user}:${run_user}' '${cont_conf}'"
					ok "Wrote rootless containers.conf for $run_user (no-new-privileges + seccomp defaults)."
				else
					ok "containers.conf already exists for $run_user — not overwriting."
				fi
			else
				info "[DRY] Would write ${cont_conf} with no-new-privileges + seccomp + minimal caps."
			fi
		fi
	fi

	# ── System image policy: reject pulls from unregistered registries ────────
	# Default Fedora policy is 'insecureAcceptAnything' for all registries.
	# Hardened policy sets default to 'reject' and explicitly allows trusted sources.
	local policy_file="/etc/containers/policy.json"
	# Merge, never replace: image-based systems sign their own updates in this file
	# (e.g. Universal Blue: sigstoreSigned for ghcr.io/ublue-os); replacing it would
	# drop that check. Only the catch-all for unknown registries becomes "reject",
	# and the trusted registries are added if they are missing.
	if [[ ! -f "$policy_file" ]]; then
		warn "Container image policy file not found at $policy_file — skipping policy hardening."
	elif ! have_cmd python3; then
		add_action_item 18 LOW "CONTAINER_POLICY_REVIEW" \
			"Review /etc/containers/policy.json: unknown registries should be rejected (python3 is needed to edit it safely)."
	else
		local policy_state
		policy_state="$(
			python3 - "$policy_file" <<'PY' 2>/dev/null || echo error
import json, sys
p = json.load(open(sys.argv[1]))
docker = p.get("transports", {}).get("docker", {})
catch = docker.get("", p.get("default", []))
print("open" if any(r.get("type") == "insecureAcceptAnything" for r in catch) else "restricted")
PY
		)"
		case "$policy_state" in
		restricted)
			ok "Container image policy already rejects unknown registries."
			;;
		open)
			if confirm "Harden the container image policy to reject unknown registries? (keeps existing signature rules; allows Fedora, CentOS, Red Hat, quay.io, docker.io)"; then
				backup_file "$policy_file" || return 0
				if ((DRY_RUN)); then
					info "Would merge a reject-by-default rule into $policy_file"
				elif python3 - "$policy_file" <<'PY'
import json, os, sys
path = sys.argv[1]
p = json.load(open(path))
docker = p.setdefault("transports", {}).setdefault("docker", {})
for registry in ("registry.fedoraproject.org", "registry.centos.org",
                 "registry.access.redhat.com", "quay.io", "docker.io"):
    docker.setdefault(registry, [{"type": "insecureAcceptAnything"}])
docker[""] = [{"type": "reject"}]
p["default"] = [{"type": "reject"}]
with open(path, "w") as f:
    json.dump(p, f, indent=4)
    f.write("\n")
PY
				then
					ok "Image policy hardened — pulls from unlisted registries are rejected; existing signature rules kept."
				else
					warn "Could not update $policy_file."
				fi
			else
				add_action_item 18 LOW "CONTAINER_POLICY_PERMISSIVE" \
					"Container image policy accepts images from any registry. Consider rejecting unknown registries in /etc/containers/policy.json."
			fi
			;;
		*)
			warn "Could not read $policy_file as JSON — leaving it unchanged."
			;;
		esac
	fi

	# ── Block unqualified image names resolving silently to docker.io ─────────
	# Without this, 'podman pull nginx' silently resolves to docker.io/library/nginx.
	# Requiring fully-qualified names (registry/org/image:tag) prevents supply-chain
	# confusion and makes registry provenance explicit.
	local reg_conf_d="/etc/containers/registries.conf.d"
	local reg_conf="${reg_conf_d}/99-hardening.conf"
	if [[ ! -f "$reg_conf" ]]; then
		if ((! DRY_RUN)); then
			install -d -m 755 "$reg_conf_d" 2>/dev/null || true
			backup_file "$reg_conf" || return 0
			cat 2>/dev/null >"$reg_conf" <<'EOF'
# Require fully-qualified image names — written by fedora-harden.sh
# An empty list prevents silent docker.io resolution for unqualified names.
# Always use full names: docker.io/library/nginx, quay.io/fedora/fedora, etc.
unqualified-search-registries = []
EOF
			ok "Blocked unqualified image name resolution — explicit registry required for all pulls."
		else
			info "[DRY] Would write ${reg_conf} disabling unqualified registry search."
		fi
	else
		ok "Registry conf.d override already present at $reg_conf."
	fi

	# ── Box tool availability check ───────────────────────────────────────────
	if ! cmd_exists "$box_tool"; then
		warn "$box_tool command not found after install. On rpm-ostree systems a reboot may be required."
	else
		ok "$box_tool is available for development and command-line tools."
	fi

	# ── What a box is (and is not) ────────────────────────────────────────────
	# toolbox and distrobox containers are privileged (rootless), run without SELinux
	# separation, share your home directory and mount the host's / at /run/host. They
	# keep the host clean; they do not contain what runs inside them.
	warn "Toolbox and distrobox are not a security boundary: their containers share your home, see the host at /run/host and run without SELinux separation. Use them to keep the host clean, not to run untrusted software."

	# ── Post-run guidance action items ────────────────────────────────────────
	add_action_item 18 MEDIUM "CONTAINER_WORKFLOW" \
		"Use $box_tool for development and command-line tools so the host stays clean — it does not isolate them (shared home, host access). For untrusted software use a Flatpak with tight permissions, or: podman run --rm --read-only --cap-drop all --security-opt no-new-privileges --network none -v ./dir:/work:ro,Z IMAGE"
	add_action_item 18 LOW "CONTAINER_NETWORK_AUDIT" \
		"Review Podman network isolation: run 'podman network ls' and use 'podman network create --internal' for workloads that must not reach the internet. Verify inter-container traffic is explicitly controlled."

	ok "Section 18 complete — rootless Podman hardened, image policy set, $box_tool ready."
}

# Image-based systems: keep build and audit tools out of the image. Writes a
# distrobox manifest (distrobox) or prints the toolbox commands.
_tools_box_setup() {
	local box_tool="$1" run_user="${TARGET_USER:-${SUDO_USER:-}}"
	local release="${FEDORA_MAJOR:-0}"
	((release > 0)) || release="$(rpm -E %fedora 2>/dev/null || echo 44)"
	info "Image-based system: build and audit tools ($TOOLS_BOX_PKGS) go in the '$TOOLS_BOX' $box_tool box, not the image."
	if [[ "$box_tool" != distrobox ]]; then
		add_action_item 18 LOW "TOOLS_BOX" \
			"Create the tools box: toolbox create --release $release $TOOLS_BOX && toolbox run -c $TOOLS_BOX sudo dnf install -y $TOOLS_BOX_PKGS"
		return 0
	fi
	if [[ -z "$run_user" || "$run_user" == root ]]; then
		info "No desktop user (run with sudo or --user NAME) — distrobox manifest not written."
		return 0
	fi
	local home ini
	home="$(user_home "$run_user")"
	[[ -n "$home" && -d "$home" ]] || return 0
	ini="$home/.config/distrobox/$TOOLS_BOX.ini"
	if [[ -f "$ini" ]]; then
		ok "Distrobox manifest already present: $ini"
	else
		write_new_file "$ini" 0644 <<EOF || return 0
# Build and audit tools kept out of the host image — written by fedora-harden.sh.
# Create or recreate the box:
#   distrobox assemble create --file $ini
#   ujust distrobox-assemble CONTAINER=$TOOLS_BOX FILE=$ini   (Universal Blue)
# Scan the host from inside it:  sudo oscap-chroot /run/host xccdf eval ...
# Like every distrobox, it shares your home and sees the host: it keeps the host
# clean, it does not isolate what runs inside it.
[$TOOLS_BOX]
image=registry.fedoraproject.org/fedora-toolbox:$release
additional_packages="$TOOLS_BOX_PKGS"
pull=true
EOF
		if ((! DRY_RUN)); then
			chown -R "$run_user:" "$home/.config/distrobox" 2>/dev/null || true
			ok "Wrote distrobox manifest $ini"
		fi
	fi
	add_action_item 18 LOW "TOOLS_BOX" \
		"Create the tools box (as $run_user): distrobox assemble create --file $ini — on Universal Blue also: ujust distrobox-assemble CONTAINER=$TOOLS_BOX FILE=$ini"
}
