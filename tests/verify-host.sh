#!/usr/bin/env bash
# tests/verify-host.sh - Read-only check that fedora-harden.sh's hardening is in effect.
#
# Run on the real machine AFTER a hardening run (it changes nothing):
#   sudo ./tests/verify-host.sh            # all checks
#   sudo ./tests/verify-host.sh --only SSH # one group (AUTO SEL FW SSH PAM SYS AUD DNS CLAM DESK PERM ROLL)
#
# Each line carries an ID (e.g. SSH-1) that matches the "Hardening Field Check"
# page, so results can be ticked off there. Exit status: 0 when nothing failed,
# 1 when at least one check failed.

# shellcheck disable=SC2016  # single-quoted bash -c bodies are intentional
set -uo pipefail

ONLY=""
case "${1:-}" in
    --only) ONLY="${2:-}" ;;
    -h | --help)
        sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    "") ;;
    *)
        echo "Unknown option: $1 (try --help)" >&2
        exit 2
        ;;
esac

if [[ -t 1 ]]; then
    G=$'\033[0;32m' R=$'\033[0;31m' Y=$'\033[0;33m' D=$'\033[2m' B=$'\033[1m' N=$'\033[0m'
else
    G="" R="" Y="" D="" B="" N=""
fi

PASS=0 FAIL=0 SKIP=0
TARGET_USER="${SUDO_USER:-}"
[[ "$TARGET_USER" == root ]] && TARGET_USER=""
IS_OSTREE=0
[[ -e /run/ostree-booted ]] && IS_OSTREE=1

want() { [[ -z "$ONLY" || "${1%%-*}" == "${ONLY^^}" ]]; }
pass() {
    printf '  %s%-7s PASS%s  %s %s%s%s\n' "$G" "$1" "$N" "$2" "$D" "${3:-}" "$N"
    ((++PASS))
}
fail() {
    printf '  %s%-7s FAIL%s  %s %s%s%s\n' "$R" "$1" "$N" "$2" "$Y" "${3:-}" "$N"
    ((++FAIL))
}
skip() {
    printf '  %s%-7s SKIP%s  %s %s%s%s\n' "$Y" "$1" "$N" "$2" "$D" "${3:-}" "$N"
    ((++SKIP))
}
# verdict <id> <description> <0|1 = passed> [detail shown on failure]
verdict() {
    if (($3)); then pass "$1" "$2"; else fail "$1" "$2" "${4:-}"; fi
}
# check <id> <description> <expected-shown-on-fail> <command...>
check() {
    local id="$1" desc="$2" expected="$3"
    shift 3
    want "$id" || return 0
    if "$@" >/dev/null 2>&1; then pass "$id" "$desc"; else fail "$id" "$desc" "(expected: $expected)"; fi
}
have() { command -v "$1" >/dev/null 2>&1; }
group() { [[ -z "$ONLY" || "$1" == "${ONLY^^}" ]] && printf '\n%s%s%s\n' "$B" "$2" "$N"; }

if ((EUID != 0)); then
    echo "${Y}Run with sudo: several checks read root-only files (sshd -T, auditctl, shadow).${N}" >&2
fi
# shellcheck source=/dev/null
printf '%sfedora-harden verification%s — %s, %s\n' "$B" "$N" \
    "$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}")" "$(date '+%F %T')"

# --- Automatic updates (section 3) -----------------------------------------------
group AUTO "Automatic security updates"
if ((IS_OSTREE)); then
    check AUTO-1 "rpm-ostreed stages updates automatically" "AutomaticUpdatePolicy=stage" \
        grep -qE '^\s*AutomaticUpdatePolicy\s*=\s*stage' /etc/rpm-ostreed.conf
else
    check AUTO-1 "dnf5-automatic timer is enabled" "enabled" \
        systemctl is-enabled --quiet dnf5-automatic.timer
    check AUTO-2 "security-only updates are applied" "upgrade_type = security, apply_updates = yes" \
        bash -c "grep -qE '^\s*upgrade_type\s*=\s*security' /etc/dnf/automatic.conf &&
                 grep -qE '^\s*apply_updates\s*=\s*yes' /etc/dnf/automatic.conf"
fi

# --- SELinux (4) -------------------------------------------------------------------
group SEL "SELinux"
if want SEL-1; then
    mode="$(getenforce 2>/dev/null || echo unknown)"
    cfg="$(awk -F= '/^SELINUX=/{print $2}' /etc/selinux/config 2>/dev/null)"
    if [[ "$mode" == Enforcing ]]; then
        pass SEL-1 "SELinux is enforcing"
    elif [[ "$mode" == Permissive && "$cfg" == permissive ]] && [[ -e /.autorelabel ]]; then
        skip SEL-1 "SELinux permissive, relabel scheduled" "(reboot, then switch to enforcing — see follow-up items)"
    else
        fail SEL-1 "SELinux is enforcing" "(now: $mode, configured: ${cfg:-?})"
    fi
fi

# --- Firewall (5) ------------------------------------------------------------------
group FW "Firewall"
check FW-1 "firewalld is running" "running" firewall-cmd --state
if want FW-2; then
    zone="$(firewall-cmd --get-default-zone 2>/dev/null)"
    ok=0
    [[ "$zone" == drop ]] && ok=1
    verdict FW-2 "default zone is drop" "$ok" "(now: ${zone:-?})"
fi

# --- SSH (7) -----------------------------------------------------------------------
group SSH "SSH"
if have sshd && { want SSH-1 || want SSH-2; }; then
    # Lowercase keywords: OpenSSH 10.5+ prints them in config-file case.
    eff="$(sshd -T 2>/dev/null | awk '{ $1 = tolower($1); print }')"
    if [[ -z "$eff" ]]; then
        skip SSH-1 "effective sshd configuration" "(sshd -T needs root)"
    else
        if grep -qx 'passwordauthentication no' <<<"$eff" && grep -qx 'permitrootlogin no' <<<"$eff" &&
            grep -qx 'x11forwarding no' <<<"$eff"; then
            pass SSH-1 "passwords, root login and X11 forwarding are off"
        else
            fail SSH-1 "passwords, root login and X11 forwarding are off" \
                "($(grep -E '^(passwordauthentication|permitrootlogin|x11forwarding) ' <<<"$eff" | tr '\n' ' '))"
        fi
        want SSH-2 && if grep -qx 'ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com' <<<"$eff"; then
            pass SSH-2 "hardened cipher list is in effect"
        else
            fail SSH-2 "hardened cipher list is in effect" "($(grep '^ciphers ' <<<"$eff"))"
        fi
    fi
elif want SSH-1; then
    skip SSH-1 "effective sshd configuration" "(openssh-server not installed)"
fi

# --- Passwords and lockout (9) -----------------------------------------------------
group PAM "Passwords and lockout"
check PAM-1 "password minimum length 14, 3 character classes" "minlen = 14, minclass = 3" \
    bash -c "grep -qE '^minlen = 14$' /etc/security/pwquality.conf && grep -qE '^minclass = 3$' /etc/security/pwquality.conf"
check PAM-2 "lockout after 5 failures for 15 minutes" "deny = 5, unlock_time = 900" \
    bash -c "grep -qE '^deny = 5$' /etc/security/faillock.conf && grep -qE '^unlock_time = 900$' /etc/security/faillock.conf"
check PAM-3 "new accounts expire passwords after 90 days" "PASS_MAX_DAYS 90" \
    grep -qE '^PASS_MAX_DAYS[[:space:]]+90$' /etc/login.defs

# --- Kernel (10) ------------------------------------------------------------------
group SYS "Kernel settings"
if want SYS-1; then
    bad=""
    for kv in kernel.kptr_restrict=2 kernel.dmesg_restrict=1 kernel.yama.ptrace_scope=1 \
        kernel.unprivileged_bpf_disabled=1 kernel.randomize_va_space=2 net.ipv4.tcp_syncookies=1 \
        net.ipv4.conf.all.rp_filter=1 fs.protected_symlinks=1; do
        k="${kv%=*}" v="${kv#*=}"
        now="$(sysctl -n "$k" 2>/dev/null || echo '?')"
        [[ "$now" == "$v" ]] || bad+="$k=$now "
    done
    ok=0
    [[ -z "$bad" ]] && ok=1
    verdict SYS-1 "kernel and network sysctl values are active" "$ok" "(differs: $bad)"
fi

# --- Audit (11) -------------------------------------------------------------------
group AUD "Audit"
check AUD-1 "audit rules for identity files are loaded" "-w /etc/passwd ... -k identity" \
    bash -c "auditctl -l 2>/dev/null | grep -q 'identity'"

# --- DNS (14) ---------------------------------------------------------------------
group DNS "Encrypted DNS"
check DNS-1 "systemd-resolved is running with DNS-over-TLS" "active, +DNSOverTLS" \
    bash -c "systemctl is-active --quiet systemd-resolved && resolvectl status 2>/dev/null | grep -q '+DNSOverTLS'"
if want DNS-2; then
    target="$(readlink -f /etc/resolv.conf 2>/dev/null)"
    ok=0
    [[ "$target" == /run/systemd/resolve/* ]] && ok=1
    verdict DNS-2 "all lookups go through systemd-resolved" "$ok" "(/etc/resolv.conf -> ${target:-missing})"
fi

# --- ClamAV (21) ------------------------------------------------------------------
group CLAM "Antivirus"
check CLAM-1 "ClamAV scanner daemon is running" "clamd@scan active" systemctl is-active --quiet clamd@scan
check CLAM-2 "on-access scanning of /home is running" "clamav-clamonacc active" \
    systemctl is-active --quiet clamav-clamonacc

# --- Desktop (15) -----------------------------------------------------------------
group DESK "Desktop privacy"
if want DESK-1; then
    if [[ -z "$TARGET_USER" ]]; then
        skip DESK-1 "screen lock enabled for your user" "(run with sudo from your own account)"
    elif ! have gsettings; then
        skip DESK-1 "screen lock enabled for your user" "(no GNOME-family desktop)"
    else
        uid="$(id -u "$TARGET_USER")"
        val="$(sudo -u "$TARGET_USER" env DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
            gsettings get org.gnome.desktop.screensaver lock-enabled 2>/dev/null)"
        ok=0
        [[ "$val" == true ]] && ok=1
        verdict DESK-1 "screen lock enabled for $TARGET_USER" "$ok" "(lock-enabled: ${val:-unknown})"
    fi
fi

# --- Permissions (20) -------------------------------------------------------------
group PERM "File permissions"
check PERM-1 "/etc/shadow is mode 000" "000" bash -c '[[ "$(stat -c %a /etc/shadow)" == 0 ]]'
check PERM-2 "new files are private (umask 077)" "umask 077 in /etc/profile.d/99-umask.sh" \
    grep -q 'umask 077' /etc/profile.d/99-umask.sh

# --- Rollback (journal) -----------------------------------------------------------
group ROLL "Rollback readiness"
check ROLL-1 "a backup + change journal exists for the last run" "/root/harden-backups-*/" \
    bash -c 'compgen -G "/root/harden-backups-*" >/dev/null'

printf '\n%sResult:%s %s%d passed%s, %s%d failed%s, %s%d skipped%s\n' "$B" "$N" \
    "$G" "$PASS" "$N" "$R" "$FAIL" "$N" "$Y" "$SKIP" "$N"
((FAIL == 0)) || echo "Fix or roll back: sudo ./fedora-harden.sh --rollback   (see the Field Check page)"
((FAIL == 0))
