#!/usr/bin/env bash
# tests/atomic-vm.sh - Image-based behaviour on an INSTALLED, BOOTED Fedora Atomic
# system (VM).
#
# The container test (tests/atomic-real.sh) cannot exercise what needs a booted
# OSTree sysroot. This test installs the image under test (Silverblue, Universal
# Blue, ...) onto an empty virtual disk with `bootc install to-disk`, run inside a
# Fedora CoreOS VM (CoreOS's published QEMU image, checksum-verified), boots that
# disk and runs fedora-harden.sh on it. The only change to the image is enabling
# sshd so the test can log in. The root filesystem is Btrfs, as Fedora's installer
# uses for Atomic desktops (Silverblue ships no bootc install configuration).
#
# Checked for real: the image-signature finding (rpm-ostree status), the /etc
# baseline and the weekly report catching a new file (ostree admin config-diff),
# that no tool is requested as a layered package, a ClamAV scan through the
# quadlet, distrobox on Universal Blue, verify-host.sh and --rollback.
#
# QEMU runs in a Fedora container (no host packages needed; /dev/kvm required).
# Prints PASS:/FAIL: lines; exits 1 if any check fails.
#
# Usage: tests/atomic-vm.sh <image> <artifacts-dir> [fedora release for the QEMU container]
#        FH_VM_CACHE=<dir> caches the CoreOS image (default ~/.cache/fedora-harden-vm)

# The single-quoted bash -c / remote commands expand inside the container or VM.
# shellcheck disable=SC2016
set -uo pipefail

if [[ "${1:-}" != --inside ]]; then
    IMG="${1:?usage: atomic-vm.sh <image> <artifacts-dir> [release]}"
    OUT="${2:?usage: atomic-vm.sh <image> <artifacts-dir> [release]}"
    REL="${3:-45}"
    ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
    CACHE="${FH_VM_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/fedora-harden-vm}"
    mkdir -p "$OUT" "$CACHE"
    if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
        echo "FAIL: /dev/kvm is not available to this user"
        exit 1
    fi
    exec podman run --rm --device /dev/kvm --security-opt label=disable \
        -v "$ROOT:/src:ro" -v "$OUT:/out" -v "$CACHE:/cache" \
        -e IMG="$IMG" --entrypoint /bin/bash "registry.fedoraproject.org/fedora:$REL" \
        /src/tests/atomic-vm.sh --inside
fi

# ── Inside the QEMU container ───────────────────────────────────────────────────
OUT=/out
fail=0
check() { # check <description> <command...>
    if "${@:2}"; then
        echo "PASS: $1"
    else
        echo "FAIL: $1"
        fail=1
        return 1
    fi
}

dnf install -y -q --setopt=install_weak_deps=False qemu-system-x86-core qemu-img openssh-clients xz jq \
    >"$OUT/dnf.log" 2>&1 || {
    echo "FAIL: install QEMU (see $OUT/dnf.log)"
    exit 1
}

# Fedora CoreOS stable, verified against the stream metadata's SHA-256, cached.
meta="$(curl -sf https://builds.coreos.fedoraproject.org/streams/stable.json)" || {
    echo "FAIL: fetch Fedora CoreOS stream metadata"
    exit 1
}
url="$(jq -r '.architectures.x86_64.artifacts.qemu.formats["qcow2.xz"].disk.location' <<<"$meta")"
sum="$(jq -r '.architectures.x86_64.artifacts.qemu.formats["qcow2.xz"].disk.sha256' <<<"$meta")"
base="/cache/$(basename "$url" .xz)"
if [[ ! -s "$base" ]]; then
    if ! { curl -sfL -o "$base.xz" "$url" && echo "$sum  $base.xz" | sha256sum -c --quiet && xz -d "$base.xz"; }; then
        echo "FAIL: download/verify $url"
        rm -f "$base" "$base.xz"
        exit 1
    fi
fi
echo "builder: $(basename "$base")"

work="$(mktemp -d)"
ssh-keygen -q -t ed25519 -N "" -f "$work/id"
qemu_pid=""
trap '[[ -n "$qemu_pid" ]] && kill "$qemu_pid" 2>/dev/null' EXIT

boot_vm() { # boot_vm <disk> [extra qemu args...] — start QEMU in the background
    local disk="$1"
    shift
    qemu-system-x86_64 -enable-kvm -cpu host -m 6144 -smp 4 -nographic \
        -drive if=virtio,file="$disk" "$@" \
        -nic user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:2222-:22 \
        -serial file:"$OUT/console-$(basename "$disk" .qcow2).log" -monitor none >/dev/null 2>&1 &
    qemu_pid=$!
}
VM_USER=core
vm() { # vm <command...> — run a command in the VM over SSH
    ssh -q -i "$work/id" -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 -o ServerAliveInterval=15 "$VM_USER@127.0.0.1" "$@"
}
# shellcheck disable=SC2329  # called through check()
wait_ssh() { # wait_ssh <seconds>
    local i
    for ((i = 0; i < $1; i += 5)); do
        vm true 2>/dev/null && return 0
        kill -0 "$qemu_pid" 2>/dev/null || return 1
        sleep 5
    done
    return 1
}
# shellcheck disable=SC2329  # also called by name after poweroff
wait_off() { # wait_off <seconds> — wait for QEMU to exit after a poweroff
    local i
    for ((i = 0; i < $1; i++)); do
        kill -0 "$qemu_pid" 2>/dev/null || return 0
        sleep 1
    done
    kill "$qemu_pid" 2>/dev/null
}

# ── Stage 1: a CoreOS VM installs the image onto an empty disk ─────────────────
qemu-img create -q -f qcow2 -b "$base" -F qcow2 "$work/builder.qcow2" 30G
qemu-img create -q -f qcow2 "$work/target.qcow2" 40G
# Ignition: SSH key for "core"; Zincati (CoreOS auto-updates) off.
jq -n --arg key "$(cat "$work/id.pub")" '{
  ignition: {version: "3.4.0"},
  passwd: {users: [{name: "core", sshAuthorizedKeys: [$key]}]},
  storage: {files: [{path: "/etc/zincati/config.d/90-disable-auto-updates.toml", mode: 420,
    contents: {source: "data:,%5Bupdates%5D%0Aenabled%20%3D%20false%0A"}}]}
}' >"$work/config.ign"
boot_vm "$work/builder.qcow2" -drive if=virtio,file="$work/target.qcow2" \
    -fw_cfg name=opt/com.coreos/config,file="$work/config.ign"
check "Fedora CoreOS builder VM boots" wait_ssh 300 || exit 1
vm 'cat >authorized_keys' <"$work/id.pub"
vm "sudo IMG='$IMG' bash -s" >"$OUT/install.log" 2>&1 <<'EOF'
set -euo pipefail
printf 'FROM %s\nRUN systemctl enable sshd\n' "$IMG" | podman build -q -t localhost/fh-target -f - .
podman run --rm --privileged --pid=host --security-opt label=type:unconfined_t \
    -v /dev:/dev -v /var/lib/containers:/var/lib/containers -v /var/home/core/authorized_keys:/keys:ro \
    localhost/fh-target bootc install to-disk --wipe --generic-image --filesystem btrfs \
    --karg console=ttyS0,115200 --root-ssh-authorized-keys /keys --target-imgref "$IMG" /dev/vdb
echo "INSTALL-OK"
EOF
check "bootc install to-disk of $IMG" grep -q "INSTALL-OK" "$OUT/install.log" || exit 1
vm sudo systemctl poweroff >/dev/null 2>&1
wait_off 120

# ── Stage 2: boot the installed disk ───────────────────────────────────────────
boot_vm "$work/target.qcow2"
VM_USER=root
check "installed $IMG boots and accepts SSH" wait_ssh 600 || exit 1
# Some images reboot once on first boot (Bazzite applies kernel arguments): wait
# until boot finishes and the boot ID stays the same before testing anything.
settled=0
for _ in 1 2 3 4 5; do
    boot_id="$(vm cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
    vm timeout 300 systemctl is-system-running --wait >/dev/null 2>&1
    sleep 30
    wait_ssh 600 || break
    if [[ -n "$boot_id" && "$(vm cat /proc/sys/kernel/random/boot_id 2>/dev/null)" == "$boot_id" ]]; then
        settled=1
        break
    fi
    echo "note: the VM rebooted during first boot; waiting again"
done
check "installed system finished booting" test "$settled" -eq 1 || exit 1
vm rpm-ostree status --booted >"$OUT/booted.txt" 2>&1
check "booted deployment is $IMG" grep -q -- "$IMG" "$OUT/booted.txt" || exit 1
vm 'id tester >/dev/null 2>&1 || useradd -m tester'
ublue=0
vm test -r /usr/share/ublue-os/image-info.json && ublue=1

# ── Run the script on the booted image ─────────────────────────────────────────
scp -q -i "$work/id" -P 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    /src/fedora-harden.sh /src/tests/verify-host.sh root@127.0.0.1:
rc=0
vm "TERM=dumb ./fedora-harden.sh --yes --only 2,3,4,12,13,21,22,23 --user tester </dev/null" \
    >"$OUT/run.log" 2>&1 || rc=$?
check "run exits 0 (got $rc)" test "$rc" -eq 0
check "no [FAIL] lines in the run" bash -c '! grep -q "^\[FAIL\]" "$1"' _ "$OUT/run.log"

# Packages the run asked rpm-ostree to layer (request lists of all deployments).
vm rpm-ostree status --json >"$OUT/status.json" 2>&1
jq -r '[.deployments[] | .["requested-packages"][]?] | unique | .[]' "$OUT/status.json" >"$OUT/requested.txt" 2>/dev/null
echo "requested layers: $(tr '\n' ' ' <"$OUT/requested.txt")"
for pkg in clamav clamd clamav-update aide rkhunter openscap-scanner scap-security-guide \
    setools-console buildah skopeo podman-compose mat2 yubikey-manager yubico-piv-tool toolbox; do
    check "$pkg is not layered" bash -c '! grep -qx -- "$1" "$2"' _ "$pkg" "$OUT/requested.txt"
done

# ── Section 12 on a real sysroot ───────────────────────────────────────────────
# Installed from a local build, the image boots from an unverified reference; some
# images (Universal Blue) rebase themselves to their signed reference on first boot.
# The script must report whichever is true.
vm rpm-ostree status --booted >"$OUT/booted-after.txt" 2>&1
if grep -q 'ostree-image-signed:' "$OUT/booted-after.txt"; then
    check "signed image reference is reported as verified" \
        grep -q 'Booted image is signature-verified: docker://' "$OUT/run.log"
else
    check "unsigned image reference is reported (IMAGE_UNSIGNED)" \
        grep -q 'Booted image is not signature-verified: ostree-unverified-' "$OUT/run.log"
fi
check "/etc baseline recorded from ostree admin config-diff" vm test -s /var/lib/fedora-harden/etc-baseline.txt
check "weekly /etc check is clean right after the run" vm systemctl start fedora-harden-etc-check.service
vm touch /etc/fh-vm-test-change
if vm systemctl start fedora-harden-etc-check.service >/dev/null 2>&1; then
    check "weekly /etc check fails after a new /etc file" false
else
    check "weekly /etc check fails after a new /etc file" true
fi
vm journalctl -t fedora-harden-etc --no-pager -o cat >"$OUT/etc-journal.txt" 2>&1
check "the new file is logged (journalctl -t fedora-harden-etc)" grep -q fh-vm-test-change "$OUT/etc-journal.txt"
vm rm -f /etc/fh-vm-test-change

# ── ClamAV through the quadlet on the booted host ─────────────────────────────
# EICAR: the standard antivirus test string (harmless by design), in a 0600 file.
vm 'f=/var/home/tester/eicar.com; printf "%s" "X5O!P%@AP[4\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*" >$f && chown tester: $f && chmod 600 $f'
scan_rc=0
vm timeout 900 systemctl start fedora-harden-clamscan.service >/dev/null 2>&1 || scan_rc=$?
vm journalctl -u fedora-harden-clamscan --no-pager -o cat >"$OUT/clamscan.journal" 2>&1
check "real scan finds the planted test file (unit exit $scan_rc)" \
    grep -q 'eicar.com: Eicar-Test-Signature FOUND' "$OUT/clamscan.journal"

# ── Box tool and verify-host ───────────────────────────────────────────────────
if ((ublue)); then
    check "Universal Blue: distrobox manifest accepted" \
        vm runuser -u tester -- distrobox assemble create --dry-run \
        --file /var/home/tester/.config/distrobox/fedora-harden-tools.ini
    check "Universal Blue: uupd stays the only updater" grep -q 'handled by uupd.timer' "$OUT/run.log"
else
    check "toolbox path: tools-box commands offered" grep -q "toolbox create --release" "$OUT/run.log"
fi
for grp in CLAM INT; do
    vm ./verify-host.sh --only "$grp" >"$OUT/verify-$grp.log" 2>&1
    check "verify-host $grp passes" bash -c 'grep -q " PASS" "$1" && ! grep -q " FAIL" "$1"' _ "$OUT/verify-$grp.log"
done

# ── Rollback ────────────────────────────────────────────────────────────────────
rc=0
vm "./fedora-harden.sh --yes --rollback all </dev/null" >"$OUT/rollback.log" 2>&1 || rc=$?
check "--rollback all exits 0 (got $rc)" test "$rc" -eq 0
for f in /etc/containers/systemd/fedora-harden-clamscan.container /etc/systemd/system/fedora-harden-etc-check.timer \
    /var/lib/fedora-harden/etc-baseline.txt; do
    check "rollback removed $f" vm test ! -e "$f"
done

vm systemctl poweroff >/dev/null 2>&1 || true
wait_off 60
exit "$fail"
