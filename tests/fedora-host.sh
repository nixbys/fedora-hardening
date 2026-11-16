#!/usr/bin/env bash
# tests/fedora-host.sh - Run test-suite tiers on a real Fedora host (VM), not on the
# machine that starts the test.
#
# GitHub's hosted runners are Ubuntu. Containers there share Ubuntu's kernel and
# AppArmor, so SELinux cannot really enforce, and the host's nftables policy blocks
# wg-quick. This script boots Fedora CoreOS (Fedora kernel, SELinux enforcing,
# firewalld-capable nftables, Podman built in) in QEMU with KVM, copies the repository
# in, runs tests/run-suite.sh there as root and copies the artifacts back.
#
# QEMU runs in a Fedora container (no host packages needed; /dev/kvm required). The
# CoreOS image is checksum-verified against Fedora's stream metadata and cached.
#
# Usage: tests/fedora-host.sh <artifacts-dir> [run-suite.sh arguments...]
#        FAULT_GROUPS is passed through; FH_VM_CACHE=<dir> caches the CoreOS image
#        (default ~/.cache/fedora-harden-vm), FH_VM_RELEASE the Fedora release of the
#        host VM and the QEMU container (default 45).
# Exit code: run-suite.sh's (1 if the VM cannot be prepared).

# Remote command strings expand inside the VM.
# shellcheck disable=SC2016
set -uo pipefail

if [[ "${1:-}" != --inside ]]; then
    OUT="${1:?usage: fedora-host.sh <artifacts-dir> [run-suite args...]}"
    shift
    ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
    CACHE="${FH_VM_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/fedora-harden-vm}"
    mkdir -p "$OUT" "$CACHE"
    if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
        echo "fedora-host: /dev/kvm is not available to this user" >&2
        exit 1
    fi
    exec podman run --rm --device /dev/kvm --security-opt label=disable \
        -v "$ROOT:/src:ro" -v "$OUT:/out" -v "$CACHE:/cache" \
        -e FAULT_GROUPS="${FAULT_GROUPS:-}" -e FH_VM_RELEASE="${FH_VM_RELEASE:-45}" --entrypoint /bin/bash \
        "registry.fedoraproject.org/fedora:${FH_VM_RELEASE:-45}" \
        /src/tests/fedora-host.sh --inside "$@"
fi
shift

# ── Inside the QEMU container ───────────────────────────────────────────────────
OUT=/out
say() { printf 'fedora-host: %s\n' "$*"; }
die() {
    say "$*" >&2
    exit 1
}

dnf install -y -q --setopt=install_weak_deps=False qemu-system-x86-core qemu-img openssh-clients xz jq tar \
    >"$OUT/host-dnf.log" 2>&1 || die "could not install QEMU (see host-dnf.log)"

# Fedora CoreOS on the release under test: the first of stable, testing and next
# that runs it (stable moves to a new Fedora about two weeks after testing). The
# image is verified against the stream metadata's SHA-256 and cached.
want="${FH_VM_RELEASE:-45}" meta="" stream=""
for stream in stable testing next; do
    meta="$(curl -sf --retry 3 "https://builds.coreos.fedoraproject.org/streams/$stream.json")" || continue
    [[ "$(jq -r '.architectures.x86_64.artifacts.qemu.release' <<<"$meta")" == "$want".* ]] && break
    meta=""
done
[[ -n "$meta" ]] || die "no Fedora CoreOS stream runs Fedora $want yet"
url="$(jq -r '.architectures.x86_64.artifacts.qemu.formats["qcow2.xz"].disk.location' <<<"$meta")"
sum="$(jq -r '.architectures.x86_64.artifacts.qemu.formats["qcow2.xz"].disk.sha256' <<<"$meta")"
base="/cache/$(basename "$url" .xz)"
if [[ ! -s "$base" ]]; then
    if ! { curl -sfL --retry 3 -o "$base.xz" "$url" && echo "$sum  $base.xz" | sha256sum -c --quiet && xz -d "$base.xz"; }; then
        rm -f "$base" "$base.xz"
        die "could not download or verify $url"
    fi
fi
say "host: $(basename "$base")"

work="$(mktemp -d)"
ssh-keygen -q -t ed25519 -N "" -f "$work/id"
qemu-img create -q -f qcow2 -b "$base" -F qcow2 "$work/host.qcow2" 60G
# Ignition: SSH key for "core"; Zincati (CoreOS auto-updates) off.
jq -n --arg key "$(cat "$work/id.pub")" '{
  ignition: {version: "3.4.0"},
  passwd: {users: [{name: "core", sshAuthorizedKeys: [$key]}]},
  storage: {files: [{path: "/etc/zincati/config.d/90-disable-auto-updates.toml", mode: 420,
    contents: {source: "data:,%5Bupdates%5D%0Aenabled%20%3D%20false%0A"}}]}
}' >"$work/config.ign"

mem=$(($(awk '/MemTotal/ {print $2}' /proc/meminfo) * 3 / 4 / 1024))
((mem > 12288)) && mem=12288
qemu-system-x86_64 -enable-kvm -cpu host -m "$mem" -smp "$(nproc)" -nographic \
    -drive if=virtio,file="$work/host.qcow2" \
    -fw_cfg name=opt/com.coreos/config,file="$work/config.ign" \
    -nic user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:2222-:22 \
    -serial file:"$OUT/host-console.log" -monitor none >/dev/null 2>&1 &
qemu_pid=$!
trap 'kill "$qemu_pid" 2>/dev/null' EXIT

vm() { # vm <command> — run a command in the VM over SSH
    ssh -q -i "$work/id" -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 -o ServerAliveInterval=30 core@127.0.0.1 "$@"
}
for ((i = 0; i < 300; i += 5)); do
    vm true 2>/dev/null && break
    kill -0 "$qemu_pid" 2>/dev/null || die "the VM stopped while booting (see host-console.log)"
    sleep 5
done
vm true 2>/dev/null || die "the VM did not come up within 5 minutes (see host-console.log)"
vm 'cat /etc/os-release; uname -r; getenforce' >"$OUT/host-info.txt" 2>&1
say "booted: $(sed -n 's/^PRETTY_NAME=//p' "$OUT/host-info.txt" | tr -d '"'), SELinux $(tail -n 1 "$OUT/host-info.txt")"

# Copy the repository in (without git metadata or earlier artifacts) and run.
tar -C /src --exclude=.git --exclude=.test-artifacts -cf - . | vm 'mkdir -p src && tar -C src -xf -' ||
    die "could not copy the repository into the VM"
args=""
for a in "$@"; do args+=" $(printf '%q' "$a")"; done
rc=0
vm "cd src && sudo FAULT_GROUPS='${FAULT_GROUPS:-}' TMPDIR=/var/tmp ./tests/run-suite.sh --artifacts /var/tmp/suite$args" || rc=$?
vm 'sudo tar -C /var/tmp/suite -cf - .' | tar -C "$OUT" -xf - 2>/dev/null ||
    say "could not copy the artifacts back"
vm 'sudo systemctl poweroff' 2>/dev/null
for ((i = 0; i < 60; i++)); do
    kill -0 "$qemu_pid" 2>/dev/null || break
    sleep 1
done
exit "$rc"
