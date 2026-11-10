#!/usr/bin/env bash
# tests/atomic-real.sh - Image-based (rpm-ostree) behaviour on a REAL Fedora Atomic
# image, booted with systemd in a privileged container. Called by the "atomic" tier
# of tests/run-suite.sh; prints PASS:/FAIL: lines and exits 1 if any check fails.
#
# Real in this test: the image's rpm-ostree (container mode: an install changes the
# container's package set, so layering shows up in `rpm -qa`), systemd and the
# Podman quadlet generator, Flatpak installs from Flathub, nested Podman (the
# OpenSCAP scan and a real ClamAV scan of a planted test file), distrobox, toolbox,
# verify-host.sh and --rollback.
#
# Not testable in a container: commands that need a booted OSTree sysroot
# (rpm-ostree status, ostree admin config-diff). The test only checks that
# section 12 handles their absence; the image signature and /etc report need a VM.
#
# Usage: tests/atomic-real.sh <image> <artifacts-dir>

# The single-quoted bash -c / remote commands expand inside the container or VM.
# shellcheck disable=SC2016
set -uo pipefail

IMG="${1:?usage: atomic-real.sh <image> <artifacts-dir>}"
OUT="${2:?usage: atomic-real.sh <image> <artifacts-dir>}"
ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
name="fh-atomic-$$"
mkdir -p "$OUT"

# shellcheck disable=SC2329  # called by the EXIT trap
cleanup() {
    podman rm -f -t 5 "$name" >/dev/null 2>&1
    podman volume rm -f "$name-containers" "$name-flatpak" >/dev/null 2>&1
}
trap cleanup EXIT

fail=0
check() { # check <description> <command...>
    if "${@:2}"; then
        echo "PASS: $1"
    else
        echo "FAIL: $1"
        fail=1
    fi
}
in_box() { podman exec "$name" "$@"; }

# ── Boot the image ─────────────────────────────────────────────────────────────
# Podman storage and Flatpak installs get their own volumes: nested overlay on the
# container's overlay root is not reliable, and they are large.
if ! podman run -d --name "$name" --privileged --systemd=always \
    -v "$name-containers:/var/lib/containers" -v "$name-flatpak:/var/lib/flatpak" \
    -v "$ROOT/fedora-harden.sh:/fh/fedora-harden.sh:ro,z" \
    -v "$ROOT/tests/verify-host.sh:/fh/verify-host.sh:ro,z" \
    "$IMG" /sbin/init >"$OUT/boot.log" 2>&1; then
    echo "FAIL: boot $IMG (see $OUT/boot.log)"
    exit 1
fi
state=""
for _ in $(seq 1 90); do
    state="$(in_box systemctl is-system-running 2>/dev/null || true)"
    [[ "$state" == running || "$state" == degraded ]] && break
    sleep 1
done
check "image boots with systemd ($state)" bash -c '[[ "$1" == running || "$1" == degraded ]]' _ "$state"

# A real Atomic host has /run/ostree-booted (the script's detection) and a user.
# Container-only adjustments, neither of which applies to a booted host:
#  - var.mount bind-mounts the (empty) OSTree deployment /var over the container's
#    /var when a dependency pulls it in (enabling rpm-ostreed-automatic.timer does,
#    via network-online.target), hiding everything under /var. Bind-mounting /var
#    onto itself makes systemd see var.mount as already mounted, as on a booted
#    host, so units that require it (quadlet volumes under /var/home) still start.
#  - systemd-resolved has no upstream DNS: give it the container's servers.
#  - boot-time tmpfiles may not all have run (Bazzite: /var/roothome, the target of
#    /root, was missing); run them as a real boot does.
in_box bash -c '
    mount --rbind /var /var
    systemd-tmpfiles --create --boot >/dev/null 2>&1
    test -d /var/roothome || { echo "setup: /var/roothome missing after tmpfiles"; exit 1; }
    touch /run/ostree-booted
    mkdir -p /etc/systemd/resolved.conf.d
    printf "[Resolve]\nDNS=%s\n" "$(awk "/^nameserver/{print \$2}" /run/systemd/resolve/stub-resolv.conf | tr "\n" " ")" \
        >/etc/systemd/resolved.conf.d/90-test-upstream.conf
    systemctl restart systemd-resolved
    id testuser >/dev/null 2>&1 || useradd -m testuser
    rpm -qa --qf "%{NAME}\n" | sort -u >/tmp/rpm-before' >"$OUT/setup.log" 2>&1
check "container can resolve and reach Flathub" in_box curl -sfI -o /dev/null https://dl.flathub.org/repo/summary.idx

ublue=0
in_box test -r /usr/share/ublue-os/image-info.json && ublue=1
in_box bash -c 'grep -m1 "^AutomaticUpdatePolicy" /etc/rpm-ostreed.conf 2>/dev/null || true' >"$OUT/policy-before.txt"

# ── Run the sections that used to layer packages ──────────────────────────────
rc=0
in_box env TERM=dumb /fh/fedora-harden.sh --yes --only 2,3,4,12,13,21,22,23 --user testuser \
    </dev/null >"$OUT/run.log" 2>&1 || rc=$?
check "run exits 0 (got $rc)" test "$rc" -eq 0
check "no [FAIL] lines in the run" bash -c '! grep -q "^\[FAIL\]" "$1"' _ "$OUT/run.log"

# ── Nothing from the list is layered (real rpm-ostree, container mode) ─────────
in_box bash -c 'rpm -qa --qf "%{NAME}\n" | sort -u | comm -13 /tmp/rpm-before -' >"$OUT/layered.txt"
echo "layered by the run: $(tr '\n' ' ' <"$OUT/layered.txt")"
for pkg in clamav clamd clamav-update aide rkhunter openscap-scanner scap-security-guide \
    setools-console buildah skopeo podman-compose mat2 yubikey-manager yubico-piv-tool toolbox; do
    check "$pkg is not layered" bash -c '! grep -qx -- "$1" "$2"' _ "$pkg" "$OUT/layered.txt"
done

# ── Flatpaks really installed from Flathub ────────────────────────────────────
in_box flatpak list --app --columns=application >"$OUT/flatpaks.txt" 2>&1
check "Yubico Authenticator Flatpak installed" grep -qx com.yubico.yubioath "$OUT/flatpaks.txt"
check "Metadata Cleaner Flatpak installed" grep -qx io.gitlab.metadatacleaner.metadatacleaner "$OUT/flatpaks.txt"

# ── ClamAV: the quadlet generates a locked-down unit, and a real scan finds a
#    planted test file ────────────────────────────────────────────────────────────
in_box systemctl cat fedora-harden-clamscan.service >"$OUT/clamscan.service" 2>&1
check "quadlet generator produced fedora-harden-clamscan.service" grep -q '^ExecStart=.*podman run' "$OUT/clamscan.service"
for opt in "--read-only" "--network none" "--cap-drop all" "--security-opt=no-new-privileges" ":/scan:ro"; do
    check "scan container runs with $opt" grep -q -- "$opt" "$OUT/clamscan.service"
done
check "ClamAV timer enabled" in_box systemctl is-enabled --quiet fedora-harden-clamscan.timer
# EICAR: the standard antivirus test string (harmless by design).
in_box bash -c 'printf "%s" "X5O!P%@AP[4\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*" >/home/testuser/eicar.com
    chown testuser: /home/testuser/eicar.com; chmod 600 /home/testuser/eicar.com
    echo "harmless" >/home/testuser/notes.txt; chown testuser: /home/testuser/notes.txt'
# Test-only drop-in: also write the scan's output to a file (journald does not
# keep logs in some image containers, e.g. Bazzite's).
in_box bash -c 'mkdir -p /run/systemd/system/fedora-harden-clamscan.service.d
    printf "[Service]\nStandardOutput=append:/run/clamscan.out\nStandardError=append:/run/clamscan.out\n" \
        >/run/systemd/system/fedora-harden-clamscan.service.d/test-output.conf
    systemctl daemon-reload'
scan_rc=0
in_box timeout 900 systemctl start fedora-harden-clamscan.service >"$OUT/clamscan-start.log" 2>&1 || scan_rc=$?
in_box cat /run/clamscan.out >"$OUT/clamscan.out" 2>&1
check "real scan finds the planted test file in a 0600 file under /home" \
    grep -q 'eicar.com: Eicar-Test-Signature FOUND' "$OUT/clamscan.out"
check "the unit fails when a file is found (exit $scan_rc)" test "$scan_rc" -ne 0
check "the scan does not report the clean file" bash -c '! grep -q "notes.txt" "$1"' _ "$OUT/clamscan.out"

# ── OpenSCAP ran in a throwaway container and the summary reads real results ───
check "OpenSCAP results written by the container scan" in_box test -s /root/scap-results.xml
check "OpenSCAP summary counts real results (pass > 0)" \
    grep -qE 'OpenSCAP results — pass: [1-9][0-9]*  fail: [0-9]+' "$OUT/run.log"

# ── Section 12 without a booted sysroot: no abort, timers in place ────────────
check "/etc change report timer enabled" in_box systemctl is-enabled --quiet fedora-harden-etc-check.timer
check "/etc check script installed" in_box test -x /usr/local/sbin/fedora-harden-etc-check

# ── Box tool: distrobox on Universal Blue, toolbox elsewhere ──────────────────
ini=/home/testuser/.config/distrobox/fedora-harden-tools.ini
if ((ublue)); then
    check "distrobox manifest written for the user" in_box test -f "$ini"
    check "real distrobox accepts the manifest" \
        in_box runuser -u testuser -- distrobox assemble create --dry-run --file "$ini"
    check "Universal Blue: uupd stays the only updater" grep -q 'handled by uupd.timer' "$OUT/run.log"
    in_box bash -c 'grep -m1 "^AutomaticUpdatePolicy" /etc/rpm-ostreed.conf 2>/dev/null || true' >"$OUT/policy-after.txt"
    check "Universal Blue: rpm-ostreed policy unchanged" cmp -s "$OUT/policy-before.txt" "$OUT/policy-after.txt"
else
    check "toolbox path: tools-box commands offered" grep -q "toolbox create --release" "$OUT/run.log"
    check "toolbox path: no distrobox manifest" in_box test ! -e "$ini"
fi
check "box tool is not called a security boundary" grep -q 'not a security boundary' "$OUT/run.log"

# ── verify-host.sh on the hardened image ──────────────────────────────────────
for grp in CLAM INT; do
    in_box /fh/verify-host.sh --only "$grp" >"$OUT/verify-$grp.log" 2>&1
    check "verify-host $grp passes" bash -c 'grep -q " PASS" "$1" && ! grep -q " FAIL" "$1"' _ "$OUT/verify-$grp.log"
done

# ── Rollback removes what the run created ─────────────────────────────────────
rc=0
in_box /fh/fedora-harden.sh --yes --rollback all </dev/null >"$OUT/rollback.log" 2>&1 || rc=$?
check "--rollback all exits 0 (got $rc)" test "$rc" -eq 0
for f in /etc/containers/systemd/fedora-harden-clamscan.container /etc/systemd/system/fedora-harden-clamscan.timer \
    /etc/systemd/system/fedora-harden-etc-check.timer /usr/local/sbin/fedora-harden-etc-check; do
    check "rollback removed $f" in_box test ! -e "$f"
done
in_box flatpak list --app --columns=application >"$OUT/flatpaks-after-rollback.txt" 2>&1
check "rollback removed the Flatpaks it installed" \
    bash -c '! grep -qE "^(com.yubico.yubioath|io.gitlab.metadatacleaner.metadatacleaner)$" "$1"' _ "$OUT/flatpaks-after-rollback.txt"

exit "$fail"
