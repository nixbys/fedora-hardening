#!/usr/bin/env bash
# tests/fault-matrix.sh - Fault injection: break the script's surroundings one fault
# at a time and check that every run ends cleanly (finishes, or refuses with a clear
# message), never shows a raw bash error, never hangs, and that --rollback still
# returns /etc to its original state.
#
# Runs in the suite's Fedora images (test-only = no systemd, test = systemd), built
# by tests/run-suite.sh for the release under test. Prints PASS:/FAIL: lines.
#
# Usage: tests/fault-matrix.sh <fedora-release> <artifacts-dir> [group ...]
#   groups: args env net pkg fs interrupt   (default: all)

# Single-quoted bash -c bodies expand inside the containers.
# shellcheck disable=SC2016
# Verdicts use "cond && echo 1 || echo 0" on purpose (echo cannot fail here).
# shellcheck disable=SC2015
set -uo pipefail

REL="${1:?usage: fault-matrix.sh <release> <artifacts-dir> [group ...]}"
OUT="${2:?usage: fault-matrix.sh <release> <artifacts-dir> [group ...]}"
shift 2
GROUPS_WANTED=("$@")
((${#GROUPS_WANTED[@]})) || GROUPS_WANTED=(args env net pkg fs interrupt)
ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
SCRIPT="$ROOT/fedora-harden.sh"
IMG_QUICK="localhost/fedora-harden:test-only-f$REL"
IMG_FULL="localhost/fedora-harden:test-f$REL"
RUN_TIMEOUT="${FAULT_RUN_TIMEOUT:-1800}" # a run longer than this counts as a hang
mkdir -p "$OUT"

CONTAINERS=()
# shellcheck disable=SC2329  # called by the EXIT trap
cleanup() {
    local c
    for c in "${CONTAINERS[@]}"; do podman rm -f -t 3 "$c" >/dev/null 2>&1; done
}
trap cleanup EXIT

fail=0
pass() { echo "PASS: $1"; }
flunk() {
    echo "FAIL: $1${2:+ — $2}"
    fail=1
}
verdict() { # verdict <name> <0|1 ok> [detail]
    if (($2)); then pass "$1"; else flunk "$1" "${3:-}"; fi
}
want() { [[ " ${GROUPS_WANTED[*]} " == *" $1 "* ]]; }

# clean_log <log> — no raw bash errors from the script, no unexpected abort.
# "fedora-harden.sh: line N:" is bash reporting an error inside the script.
clean_log() {
    ! grep -qE 'fedora-harden\.sh: line [0-9]+:|unbound variable|syntax error near|bad substitution|Aborted at line' "$1"
}
bash_errors() { grep -E 'fedora-harden\.sh: line [0-9]+:|unbound variable|Aborted at line' "$1" | head -3 | tr '\n' ' '; }

# quick <log> [podman args...] -- <script args...> — run in a throwaway no-systemd container
# (script at /opt/fh, readable by any user)
quick() {
    local log="$1" pargs=() rc=0
    shift
    while (($#)) && [[ "$1" != -- ]]; do
        pargs+=("$1")
        shift
    done
    shift
    timeout "$RUN_TIMEOUT" podman run --rm -v "$SCRIPT:/opt/fh/fedora-harden.sh:ro,z" "${pargs[@]}" \
        --entrypoint /opt/fh/fedora-harden.sh "$IMG_QUICK" "$@" </dev/null >"$log" 2>&1 || rc=$?
    return "$rc"
}
# quick_sh <log> [podman args...] -- <bash script> — run a bash script in the quick image
quick_sh() {
    local log="$1" pargs=() rc=0
    shift
    while (($#)) && [[ "$1" != -- ]]; do
        pargs+=("$1")
        shift
    done
    shift
    timeout "$RUN_TIMEOUT" podman run --rm -v "$SCRIPT:/opt/fh/fedora-harden.sh:ro,z" "${pargs[@]}" \
        --entrypoint /bin/bash "$IMG_QUICK" -c "$1" </dev/null >"$log" 2>&1 || rc=$?
    return "$rc"
}

# boot <name> [podman args...] — systemd container from the full image, script at
# /opt/fh/fedora-harden.sh (so /root can be replaced in filesystem faults)
boot() {
    local name="$1" state=""
    shift
    CONTAINERS+=("$name")
    podman run -d --systemd=always --cap-add NET_ADMIN,NET_RAW --name "$name" --hostname fault-test \
        --memory 3g --memory-swap 3g -v "$SCRIPT:/opt/fh/fedora-harden.sh:ro,z" "$@" \
        "$IMG_FULL" >/dev/null 2>"$OUT/$name.boot.log" || return 1
    for _ in $(seq 1 60); do
        state="$(podman exec "$name" systemctl is-system-running 2>/dev/null || true)"
        [[ "$state" == running || "$state" == degraded ]] && break
        sleep 1
    done
    [[ "$state" == running || "$state" == degraded ]] || return 1
    # As in the full tier: testuser needs an SSH key before section 7 disables passwords.
    podman exec "$name" bash -c '
        ssh-keygen -A >/dev/null
        install -d -m 700 -o testuser -g testuser /home/testuser/.ssh
        su - testuser -c "ssh-keygen -q -t ed25519 -N \"\" -f ~/.ssh/id_ed25519"
        install -m 600 -o testuser -g testuser /home/testuser/.ssh/id_ed25519.pub /home/testuser/.ssh/authorized_keys' \
        >/dev/null 2>&1
}
sx() { # sx <name> <command...>
    local name="$1"
    shift
    podman exec "$name" "$@" </dev/null
}
# harden <name> <log> [script args...] — real run inside a booted container; returns its exit code
harden() {
    local name="$1" log="$2" rc=0
    shift 2
    timeout "$RUN_TIMEOUT" podman exec "$name" /opt/fh/fedora-harden.sh "$@" </dev/null >"$log" 2>&1 || rc=$?
    return "$rc"
}
etc_snap() { # etc_snap <name> <outfile> — as tests/run-suite.sh etc_snapshot
    sx "$1" bash -c 'find /etc -xdev -type f ! -path "/etc/hosts" ! -path "/etc/hostname" \
        ! -path "/etc/resolv.conf" ! -path "/etc/machine-id" ! -name "*.cache" \
        ! -path "/etc/shadow-" ! -path "/etc/gshadow-" ! -path "/etc/passwd-" ! -path "/etc/group-" \
        -exec sha256sum {} + 2>/dev/null | sort -k2' >"$2"
}
etc_diff() { # etc_diff <snapA> <snapB> — changed paths
    diff <(awk '{print $2" "$1}' "$1") <(awk '{print $2" "$1}' "$2") | awk '/^[<>]/{print $2}' | sort -u || true
}
# unexplained <container> <paths> — rollback residue that is not documented state.
# Rollback cannot (and should not) undo: system users and groups that packages
# created, the rebuilt SELinux policy and udev hardware database, audit.rules
# (auditd regenerates it from the restored rules.d), and files of protected
# packages (systemd-udev, ...) a minimal system pulled in, which dnf never removes,
# and packages those still need.
unexplained() {
    local n="$1" p owner protected
    protected="$(sx "$n" bash -c 'cat /etc/dnf/protected.d/*.conf 2>/dev/null')"
    while IFS= read -r p; do
        [[ -n "$p" ]] || continue
        case "$p" in
            /etc/passwd | /etc/group | /etc/shadow | /etc/gshadow) continue ;;
            /etc/selinux/*/policy/policy.* | /etc/udev/hwdb.bin | /etc/audit/audit.rules) continue ;;
        esac
        owner="$(sx "$n" rpm -qf --qf '%{NAME}' "$p" 2>/dev/null | head -1)"
        [[ -n "$owner" ]] && grep -qx -- "$owner" <<<"$protected" && continue
        # A package kept because an installed (protected) package needs it, e.g.
        # kbd for systemd-udev on Fedora 44: rpm confirms it cannot be removed.
        [[ -n "$owner" ]] && ! sx "$n" rpm -e --test "$owner" >/dev/null 2>&1 && continue
        echo "$p"
    done <<<"$2"
}

# ═════════════════════════════════════════════════════════════════════════════
# args — invalid or unusual command lines must be refused clearly (exit 2), not
# crash or silently do nothing.
# ═════════════════════════════════════════════════════════════════════════════
if want args; then
    l="$OUT/args"
    mkdir -p "$l"
    rc=0
    quick "$l/nonroot.log" --user testuser -- --yes --dry-run || rc=$?
    verdict "args: non-root run is refused with a clear message (exit $rc)" \
        "$( ((rc != 0)) && grep -q 'must be run as root' "$l/nonroot.log" && clean_log "$l/nonroot.log" && echo 1 || echo 0)"
    rc=0
    quick "$l/unknown.log" -- --frobnicate || rc=$?
    verdict "args: unknown option exits 2 (got $rc)" "$( ((rc == 2)) && echo 1 || echo 0)"
    for spec in "only 99" "only abc" "only 3,,5" "skip x" "skip 99"; do
        rc=0
        quick "$l/${spec// /-}.log" -- --yes --dry-run "--${spec%% *}" "${spec#* }" || rc=$?
        verdict "args: --$spec is refused (exit 2, got $rc)" \
            "$( ((rc == 2)) && grep -qi 'section' "$l/${spec// /-}.log" && echo 1 || echo 0)" "$(tail -1 "$l/${spec// /-}.log")"
    done
    rc=0
    quick "$l/user-missing.log" -- --yes --dry-run --user nosuchuser || rc=$?
    verdict "args: --user for a missing account is refused (exit 2, got $rc)" \
        "$( ((rc == 2)) && grep -qi 'nosuchuser' "$l/user-missing.log" && echo 1 || echo 0)"
    rc=0
    quick_sh "$l/user-nohome.log" -- 'useradd -M nohome && /opt/fh/fedora-harden.sh --yes --dry-run --user nohome' || rc=$?
    verdict "args: --user without a home directory runs cleanly (exit $rc)" \
        "$( ((rc == 0)) && clean_log "$l/user-nohome.log" && echo 1 || echo 0)" "$(bash_errors "$l/user-nohome.log")"
    rc=0
    quick "$l/user-root.log" -- --yes --dry-run --user root || rc=$?
    verdict "args: --user root runs cleanly (exit $rc)" \
        "$( ((rc == 0)) && clean_log "$l/user-root.log" && echo 1 || echo 0)" "$(bash_errors "$l/user-root.log")"
    rc=0
    quick "$l/rollback-unknown.log" -- --yes --rollback 19990101-000000 || rc=$?
    verdict "args: --rollback of an unknown session fails clearly (exit $rc)" \
        "$( ((rc != 0)) && clean_log "$l/rollback-unknown.log" && echo 1 || echo 0)" "$(tail -1 "$l/rollback-unknown.log")"
    rc=0
    quick "$l/rollback-none.log" -- --yes --rollback || rc=$?
    verdict "args: --rollback with no sessions ends cleanly (exit $rc)" \
        "$(clean_log "$l/rollback-none.log" && echo 1 || echo 0)" "$(bash_errors "$l/rollback-none.log")"
    rc=0
    quick "$l/list-sessions-none.log" -- --list-sessions || rc=$?
    verdict "args: --list-sessions with no sessions exits 0 (got $rc)" \
        "$( ((rc == 0)) && clean_log "$l/list-sessions-none.log" && echo 1 || echo 0)"
    rc=0
    quick "$l/dry-rollback.log" -- --dry-run --rollback || rc=$?
    verdict "args: --dry-run --rollback ends cleanly (exit $rc)" \
        "$(clean_log "$l/dry-rollback.log" && echo 1 || echo 0)" "$(bash_errors "$l/dry-rollback.log")"
fi

# ═════════════════════════════════════════════════════════════════════════════
# env — locales, terminals, closed output, odd paths and invocations
# ═════════════════════════════════════════════════════════════════════════════
if want env; then
    l="$OUT/env"
    mkdir -p "$l"
    for loc in C POSIX tr_TR.UTF-8 de_DE.UTF-8; do
        rc=0
        quick "$l/locale-$loc.log" -e LC_ALL="$loc" -e LANG="$loc" -- --yes --dry-run || rc=$?
        verdict "env: dry run under LC_ALL=$loc (exit $rc)" \
            "$( ((rc == 0)) && clean_log "$l/locale-$loc.log" && echo 1 || echo 0)" "$(bash_errors "$l/locale-$loc.log")"
    done
    rc=0
    quick_sh "$l/no-term.log" -- 'env -u TERM -u LANG -u HOME PATH=/usr/bin /opt/fh/fedora-harden.sh --yes --dry-run' || rc=$?
    verdict "env: no TERM, LANG or HOME; PATH=/usr/bin (exit $rc)" \
        "$( ((rc == 0)) && clean_log "$l/no-term.log" && echo 1 || echo 0)" "$(bash_errors "$l/no-term.log")"
    rc=0
    quick_sh "$l/closed-stdout.log" -- '/opt/fh/fedora-harden.sh --yes --dry-run >&- 2>/tmp/err; rc=$?
        cat /tmp/err; ls /var/log/fedora-harden/harden-*.log >/dev/null && echo LOG-WRITTEN; exit $rc' || rc=$?
    verdict "env: closed stdout does not break the run (exit $rc)" \
        "$( ((rc == 0)) && grep -q LOG-WRITTEN "$l/closed-stdout.log" && echo 1 || echo 0)" "$(tail -2 "$l/closed-stdout.log" | tr '\n' ' ')"
    rc=0
    quick_sh "$l/paths.log" -- 'set -e
        mkdir -p "/opt/my scripts" && cp /opt/fh/fedora-harden.sh "/opt/my scripts/" && chmod +x "/opt/my scripts/fedora-harden.sh"
        ln -s "/opt/my scripts/fedora-harden.sh" /usr/local/bin/harden
        "/opt/my scripts/fedora-harden.sh" --yes --dry-run --only 19 >/tmp/a 2>&1
        harden --yes --dry-run --only 19 >/tmp/b 2>&1
        bash /opt/fh/fedora-harden.sh --yes --dry-run --only 19 >/tmp/c 2>&1
        cat /tmp/a /tmp/b /tmp/c' || rc=$?
    verdict "env: path with spaces, symlink and 'bash script' invocations (exit $rc)" \
        "$( ((rc == 0)) && clean_log "$l/paths.log" && echo 1 || echo 0)" "$(bash_errors "$l/paths.log")"
    rc=0
    quick_sh "$l/sh.log" -- 'sh /opt/fh/fedora-harden.sh --yes --dry-run --only 19' || rc=$?
    verdict "env: 'sh script' either works or refuses clearly (exit $rc)" \
        "$(clean_log "$l/sh.log" && echo 1 || echo 0)" "$(tail -2 "$l/sh.log" | tr '\n' ' ')"
    # A permissive umask must not leave world-writable files behind.
    rc=0
    quick_sh "$l/umask.log" -- 'umask 000; touch /tmp/marker; sleep 1
        /opt/fh/fedora-harden.sh --yes --only 9,20 --user testuser >/tmp/run 2>&1; rc=$?
        cat /tmp/run; echo "--- world-writable files created by the run:"
        find /etc /root /var/log/fedora-harden -xdev -newer /tmp/marker -type f -perm -o+w
        exit $rc' || rc=$?
    ww="$(sed -n '/^--- world-writable/,$p' "$l/umask.log" | tail -n +2)"
    verdict "env: umask 000 leaves no world-writable files (exit $rc)" \
        "$( ((rc == 0)) && [[ -z "$ww" ]] && clean_log "$l/umask.log" && echo 1 || echo 0)" "$ww"
fi

# ═════════════════════════════════════════════════════════════════════════════
# net — no network and broken DNS: the run must finish (no hang) and report what
# it could not do
# ═════════════════════════════════════════════════════════════════════════════
if want net; then
    l="$OUT/net"
    mkdir -p "$l"
    for spec in "none:--network=none" "dead-dns:--dns=192.0.2.53"; do
        n="fault-net-${spec%%:*}-$$"
        if ! boot "$n" "${spec#*:}"; then
            flunk "net: ${spec%%:*}: container boots"
            continue
        fi
        start=$SECONDS rc=0
        harden "$n" "$l/${spec%%:*}.log" --yes --user testuser || rc=$?
        took=$((SECONDS - start))
        verdict "net: ${spec%%:*}: full run finishes (exit $rc, ${took}s)" \
            "$( ((rc == 0)) && echo 1 || echo 0)" "$( ((rc == 124)) && echo "hung (timeout ${RUN_TIMEOUT}s)" || bash_errors "$l/${spec%%:*}.log")"
        verdict "net: ${spec%%:*}: no raw bash errors" "$(clean_log "$l/${spec%%:*}.log" && echo 1 || echo 0)" "$(bash_errors "$l/${spec%%:*}.log")"
        podman rm -f -t 3 "$n" >/dev/null 2>&1
    done
fi

# ═════════════════════════════════════════════════════════════════════════════
# pkg — package manager failures
# ═════════════════════════════════════════════════════════════════════════════
if want pkg; then
    l="$OUT/pkg"
    mkdir -p "$l"
    # A broken, mandatory repository makes every dnf transaction fail.
    n="fault-pkg-repo-$$"
    if boot "$n"; then
        sx "$n" bash -c 'printf "[broken]\nname=broken\nbaseurl=http://192.0.2.1/repo\nenabled=1\ngpgcheck=0\nskip_if_unavailable=False\n" \
            >/etc/yum.repos.d/broken.repo'
        rc=0
        harden "$n" "$l/broken-repo.log" --yes --user testuser || rc=$?
        verdict "pkg: broken repository: full run finishes (exit $rc)" "$( ((rc == 0)) && echo 1 || echo 0)" \
            "$( ((rc == 124)) && echo hung || bash_errors "$l/broken-repo.log")"
        verdict "pkg: broken repository: reported once, package work skipped" \
            "$(grep -q 'repositories did not answer' "$l/broken-repo.log" && clean_log "$l/broken-repo.log" && echo 1 || echo 0)" \
            "$(bash_errors "$l/broken-repo.log")"
    else
        flunk "pkg: broken repository: container boots"
    fi
    podman rm -f -t 3 "$n" >/dev/null 2>&1
    # The RPM database lock held by another process (a stuck dnf).
    n="fault-pkg-lock-$$"
    if boot "$n"; then
        sx "$n" bash -c 'nohup python3 -c "
import fcntl, time
f = open(\"/var/lib/rpm/.rpm.lock\", \"a\")
fcntl.lockf(f, fcntl.LOCK_EX)
time.sleep(3600)" >/dev/null 2>&1 &'
        sleep 2
        start=$SECONDS rc=0
        # Section 17 installs wireguard-tools, which the image does not have.
        FAULT_RUN_TIMEOUT=900 harden "$n" "$l/rpm-lock.log" --yes --only 17 || rc=$?
        took=$((SECONDS - start))
        verdict "pkg: RPM lock held elsewhere: run does not hang (exit $rc, ${took}s)" \
            "$( ((rc != 124)) && clean_log "$l/rpm-lock.log" && echo 1 || echo 0)" \
            "$( ((rc == 124)) && echo "hung ${took}s" || bash_errors "$l/rpm-lock.log")"
    else
        flunk "pkg: RPM lock: container boots"
    fi
    podman rm -f -t 3 "$n" >/dev/null 2>&1
    # A tool the script configures is not installed at all.
    n="fault-pkg-missing-$$"
    if boot "$n" --network=none; then
        sx "$n" bash -c 'rpm -e --nodeps openssh-server firewalld audit >/dev/null 2>&1'
        rc=0
        harden "$n" "$l/missing-tools.log" --yes --only 5,7,11 --user testuser || rc=$?
        verdict "pkg: sshd, firewalld and auditd absent (offline): sections 5/7/11 end cleanly (exit $rc)" \
            "$( ((rc == 0)) && clean_log "$l/missing-tools.log" && echo 1 || echo 0)" "$(bash_errors "$l/missing-tools.log")"
    else
        flunk "pkg: missing tools: container boots"
    fi
    podman rm -f -t 3 "$n" >/dev/null 2>&1
fi

# ═════════════════════════════════════════════════════════════════════════════
# fs — read-only and full filesystems, malformed and symlinked configs
# ═════════════════════════════════════════════════════════════════════════════
if want fs; then
    l="$OUT/fs"
    mkdir -p "$l"
    # Read-only drop-in directories: the section must report it, not abort.
    for spec in "7:/etc/ssh/sshd_config.d" "10:/etc/sysctl.d" "9:/etc/security"; do
        sec="${spec%%:*}" dir="${spec#*:}" n="fault-fs-ro$sec-$$"
        if boot "$n" --mount "type=tmpfs,destination=$dir,ro=true"; then
            rc=0
            harden "$n" "$l/ro-$sec.log" --yes --only "$sec" --user testuser || rc=$?
            verdict "fs: read-only $dir: section $sec ends cleanly (exit $rc)" \
                "$( ((rc == 0)) && clean_log "$l/ro-$sec.log" && echo 1 || echo 0)" "$(bash_errors "$l/ro-$sec.log")"
            if [[ "$sec" == 7 ]]; then
                verdict "fs: read-only $dir: sshd config still valid" "$(sx "$n" sshd -t >/dev/null 2>&1 && echo 1 || echo 0)"
            fi
        else
            flunk "fs: read-only $dir: container boots"
        fi
        podman rm -f -t 3 "$n" >/dev/null 2>&1
    done
    # Full log and backup filesystems. With no room for a backup, a file must not be
    # changed (a change that cannot be rolled back is worse than no change).
    # notmpcopyup: start empty instead of copying the image's directory into the tmpfs.
    for spec in "log:/var/log/fedora-harden:8k" "backup:/root:64k" "tmp:/tmp:16k"; do
        what="${spec%%:*}" rest="${spec#*:}"
        dir="${rest%:*}" size="${rest##*:}" n="fault-fs-full-$what-$$"
        if boot "$n" --mount "type=tmpfs,destination=$dir,tmpfs-size=$size,notmpcopyup"; then
            sx "$n" bash -c "dd if=/dev/zero of=$dir/.filler bs=1k count=$((${size%k} - 1)) 2>/dev/null; true"
            sx "$n" cp /etc/security/pwquality.conf /etc/security/pwquality.conf.orig-test
            rc=0
            harden "$n" "$l/full-$what.log" --yes --only 9,10,20 --user testuser || rc=$?
            # Without room for backups the run must refuse before changing anything.
            if [[ "$what" == backup ]]; then
                verdict "fs: full $dir: run refuses before any change (exit $rc)" \
                    "$( ((rc == 1)) && grep -q 'Nothing was changed' "$l/full-$what.log" && clean_log "$l/full-$what.log" && echo 1 || echo 0)" \
                    "$(bash_errors "$l/full-$what.log")"
            else
                verdict "fs: full $dir: run ends cleanly (exit $rc)" \
                    "$( ((rc == 0)) && clean_log "$l/full-$what.log" && echo 1 || echo 0)" "$(bash_errors "$l/full-$what.log")"
            fi
            if [[ "$what" == backup ]]; then
                changed=0
                sx "$n" cmp -s /etc/security/pwquality.conf /etc/security/pwquality.conf.orig-test || changed=1
                backed=0
                sx "$n" bash -c 'ls /root/harden-backups-*/etc/security/pwquality.conf' >/dev/null 2>&1 && backed=1
                verdict "fs: full backup filesystem: no file changed without a backup" \
                    "$( ((changed == 0 || backed == 1)) && echo 1 || echo 0)" "pwquality.conf changed=$changed backed-up=$backed"
            fi
        else
            flunk "fs: full $dir: container boots"
        fi
        podman rm -f -t 3 "$n" >/dev/null 2>&1
    done
    # Malformed and symlinked configuration files.
    n="fault-fs-malformed-$$"
    if boot "$n"; then
        sx "$n" bash -c '
            printf "# CRLF file\r\nminlen = 8\r\n" >/etc/security/pwquality.conf
            printf "deny = 3\ndeny = 7\nunlock_time = 60\n" >/etc/security/faillock.conf
            printf "%s" "$(cat /etc/login.defs)" >/etc/login.defs.tmp && mv /etc/login.defs.tmp /etc/login.defs
            mv /etc/sysctl.conf /etc/sysctl-real.conf 2>/dev/null; touch /etc/sysctl-real.conf
            ln -s sysctl-real.conf /etc/sysctl.conf'
        etc_snap "$n" "$l/malformed.etc0"
        rc=0
        harden "$n" "$l/malformed.log" --yes --only 9,10 --user testuser || rc=$?
        verdict "fs: CRLF, duplicate keys, no final newline, symlinked config: run ends cleanly (exit $rc)" \
            "$( ((rc == 0)) && clean_log "$l/malformed.log" && echo 1 || echo 0)" "$(bash_errors "$l/malformed.log")"
        sx "$n" bash -c 'grep -cE "^\s*minlen\s*=\s*14\s*$" /etc/security/pwquality.conf' >"$l/minlen.count" 2>&1
        # A CR left in an untouched comment is harmless; setting lines must be clean.
        verdict "fs: CRLF pwquality.conf ends with exactly one clean minlen = 14" \
            "$([[ "$(cat "$l/minlen.count")" == 1 ]] && ! sx "$n" grep -qE $'^[^#].*\r' /etc/security/pwquality.conf && echo 1 || echo 0)" \
            "$(sx "$n" cat -A /etc/security/pwquality.conf | tr '\n' ' ')"
        verdict "fs: duplicate deny keys collapse to one effective deny = 5" \
            "$([[ "$(sx "$n" bash -c 'grep -E "^\s*deny\s*=" /etc/security/faillock.conf' | tr -d ' ')" == "deny=5" ]] && echo 1 || echo 0)" \
            "$(sx "$n" grep -E '^\s*deny' /etc/security/faillock.conf | tr '\n' ' ')"
        verdict "fs: login.defs without final newline keeps PASS_MAX_DAYS on its own line" \
            "$(sx "$n" grep -qE '^PASS_MAX_DAYS\s+90$' /etc/login.defs && echo 1 || echo 0)"
        verdict "fs: symlinked /etc/sysctl.conf stays a symlink" "$(sx "$n" test -L /etc/sysctl.conf && echo 1 || echo 0)"
        rc=0
        harden "$n" "$l/malformed-rollback.log" --yes --rollback all || rc=$?
        etc_snap "$n" "$l/malformed.etc1"
        d="$(etc_diff "$l/malformed.etc0" "$l/malformed.etc1")"
        verdict "fs: rollback restores the malformed files exactly (exit $rc)" \
            "$( ((rc == 0)) && [[ -z "$d" ]] && echo 1 || echo 0)" "$(echo "$d" | head -5 | tr '\n' ' ')"
    else
        flunk "fs: malformed configs: container boots"
    fi
    podman rm -f -t 3 "$n" >/dev/null 2>&1
fi

# ═════════════════════════════════════════════════════════════════════════════
# interrupt — killed runs, concurrent runs, idempotency, rollback integrity
# ═════════════════════════════════════════════════════════════════════════════
if want interrupt; then
    l="$OUT/interrupt"
    mkdir -p "$l"
    for spec in "INT:45" "TERM:90" "KILL:60"; do
        sig="${spec%%:*}" after="${spec#*:}" n="fault-int-$sig-$$"
        if ! boot "$n"; then
            flunk "interrupt: SIG$sig: container boots"
            continue
        fi
        etc_snap "$n" "$l/$sig.etc0"
        podman exec "$n" /opt/fh/fedora-harden.sh --yes --user testuser </dev/null >"$l/$sig-run1.log" 2>&1 &
        sleep "$after"
        sx "$n" pkill "-$sig" -f '/opt/fh/fedora-harden.sh' >/dev/null 2>&1
        wait
        # SIGKILL cannot be trapped: a dnf transaction already running finishes on
        # its own. Allow that, but nothing may keep running after it.
        for _ in $(seq 1 120); do
            left="$(sx "$n" pgrep -f -a 'fedora-harden.sh|dnf|rpm' 2>/dev/null | grep -v pgrep || true)"
            [[ -z "$left" ]] && break
            sleep 5
        done
        verdict "interrupt: SIG$sig after ${after}s leaves no stray processes" "$([[ -z "$left" ]] && echo 1 || echo 0)" "$left"
        verdict "interrupt: SIG$sig: no raw bash errors" "$(clean_log "$l/$sig-run1.log" && echo 1 || echo 0)" "$(bash_errors "$l/$sig-run1.log")"
        rc=0
        harden "$n" "$l/$sig-run2.log" --yes --user testuser || rc=$?
        verdict "interrupt: SIG$sig: a new run afterwards completes (exit $rc)" \
            "$( ((rc == 0)) && clean_log "$l/$sig-run2.log" && ! grep -q '^\[FAIL\]' "$l/$sig-run2.log" && echo 1 || echo 0)" \
            "$(grep '^\[FAIL\]' "$l/$sig-run2.log" | head -2 | tr '\n' ' ')$(bash_errors "$l/$sig-run2.log")"
        rc=0
        harden "$n" "$l/$sig-rollback.log" --yes --rollback all || rc=$?
        etc_snap "$n" "$l/$sig.etc1"
        d="$(etc_diff "$l/$sig.etc0" "$l/$sig.etc1")"
        printf '%s\n' "$d" >"$l/$sig.residual"
        d="$(unexplained "$n" "$d")"
        verdict "interrupt: SIG$sig: --rollback all restores /etc (exit $rc, $(grep -c . <<<"$d") files differ)" \
            "$( ((rc == 0)) && [[ -z "$d" ]] && echo 1 || echo 0)" "$(echo "$d" | head -6 | tr '\n' ' ')"
        podman rm -f -t 3 "$n" >/dev/null 2>&1
    done

    # Two runs at once: the second must refuse (or wait), never interleave edits.
    n="fault-int-concurrent-$$"
    if boot "$n"; then
        etc_snap "$n" "$l/concurrent.etc0"
        # A is a full run (several minutes); B starts while A is still working.
        podman exec "$n" /opt/fh/fedora-harden.sh --yes --user testuser </dev/null >"$l/concurrent-a.log" 2>&1 &
        sleep 15
        rc_b=0
        harden "$n" "$l/concurrent-b.log" --yes --only 9,10,20 --user testuser || rc_b=$?
        wait
        verdict "interrupt: a second concurrent run refuses clearly (exit $rc_b)" \
            "$( ((rc_b != 0)) && grep -qiE 'already running|another .*run' "$l/concurrent-b.log" && echo 1 || echo 0)" \
            "$(tail -2 "$l/concurrent-b.log" | tr '\n' ' ')"
        harden "$n" "$l/concurrent-rollback.log" --yes --rollback all || true
        etc_snap "$n" "$l/concurrent.etc1"
        d="$(unexplained "$n" "$(etc_diff "$l/concurrent.etc0" "$l/concurrent.etc1")")"
        verdict "interrupt: after concurrent runs, rollback restores /etc" "$([[ -z "$d" ]] && echo 1 || echo 0)" \
            "$(echo "$d" | head -6 | tr '\n' ' ')"
    else
        flunk "interrupt: concurrent: container boots"
    fi
    podman rm -f -t 3 "$n" >/dev/null 2>&1

    # Idempotency and complete rollback of a full run.
    n="fault-int-idem-$$"
    if boot "$n"; then
        etc_snap "$n" "$l/idem.etc0"
        harden "$n" "$l/idem-run1.log" --yes --user testuser || true
        etc_snap "$n" "$l/idem.etc1"
        harden "$n" "$l/idem-run2.log" --yes --user testuser || true
        etc_snap "$n" "$l/idem.etc2"
        d="$(etc_diff "$l/idem.etc1" "$l/idem.etc2")"
        printf '%s\n' "$d" >"$l/idem.run2-changes"
        verdict "interrupt: a second full run changes nothing ($(grep -c . <<<"$d") files differ)" \
            "$([[ -z "$d" ]] && echo 1 || echo 0)" "$(echo "$d" | head -6 | tr '\n' ' ')"
        dup="$(sx "$n" bash -c 'for f in /etc/sysctl.d/99-hardening.conf /etc/security/pwquality.conf /etc/security/faillock.conf /etc/ssh/sshd_config.d/10-hardening.conf; do
            [ -f "$f" ] && grep -vE "^\s*(#|$)" "$f" | sed -E "s/\s*=.*//; s/\s+.*//" | sort | uniq -d | sed "s|^|$f: |"; done')"
        verdict "interrupt: no duplicated keys after two runs" "$([[ -z "$dup" ]] && echo 1 || echo 0)" "$dup"
        rc=0
        harden "$n" "$l/idem-rollback.log" --yes --rollback all || rc=$?
        etc_snap "$n" "$l/idem.etc3"
        d="$(etc_diff "$l/idem.etc0" "$l/idem.etc3")"
        printf '%s\n' "$d" >"$l/idem.residual"
        d="$(unexplained "$n" "$d")"
        verdict "interrupt: --rollback all after two runs restores /etc ($(grep -c . <<<"$d") files differ)" \
            "$( ((rc == 0)) && [[ -z "$d" ]] && echo 1 || echo 0)" "$(echo "$d" | head -8 | tr '\n' ' ')"
    else
        flunk "interrupt: idempotency: container boots"
    fi
    podman rm -f -t 3 "$n" >/dev/null 2>&1
fi

exit "$fail"
