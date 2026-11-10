#!/usr/bin/env bash
# tests/desktop-settings.sh - Section 15 end-to-end check (runs INSIDE a Fedora 44 container).
#
# Verifies that GNOME (gsettings/dconf) and XFCE (xfconf) settings written by
# fedora-harden.sh really persist for the target user. Plain `sudo -u user gsettings`
# without a D-Bus session exits 0 but discards every change, so this reads the values
# back through a fresh session bus.
#
# Usage (from tests/run-suite.sh):
#   podman run --rm -v fedora-harden.sh:/root/fedora-harden.sh:ro \
#     -v tests/desktop-settings.sh:/root/desktop-settings.sh:ro IMAGE /root/desktop-settings.sh

set -uo pipefail

dnf install -y -q --setopt=install_weak_deps=False glib2 gsettings-desktop-schemas dconf \
    dbus-daemon sudo xfconf >/dev/null 2>&1 || {
    echo "FAIL: could not install desktop test dependencies"
    exit 1
}
systemd-machine-id-setup >/dev/null 2>&1 || true
id u1 >/dev/null 2>&1 || useradd -m u1

export XDG_CURRENT_DESKTOP="GNOME:XFCE" DESKTOP_SESSION=gnome
rc=0
/root/fedora-harden.sh --yes --only 15 --user u1 >/tmp/section15.log 2>&1 || rc=$?
grep -E '^\[(OK|WARN|FAIL)' /tmp/section15.log | grep -iE 'gnome|xfce|section 15'

fail=0
expect() { # expect <description> <expected> <command run as u1>
    local got
    got="$(sudo -u u1 -H dbus-run-session -- bash -c "$3" 2>/dev/null | tail -n 1)"
    if [[ "$got" == "$2" ]]; then
        echo "ok:   $1 = $got"
    else
        echo "FAIL: $1 = '${got}' (expected '$2')"
        fail=1
    fi
}
expect "script exit code" 0 "echo $rc"
expect "GNOME lock-enabled" true 'gsettings get org.gnome.desktop.screensaver lock-enabled'
expect "GNOME idle-delay" "uint32 300" 'gsettings get org.gnome.desktop.session idle-delay'
expect "GNOME location" false 'gsettings get org.gnome.system.location enabled'
expect "GNOME remember-recent-files" false 'gsettings get org.gnome.desktop.privacy remember-recent-files'
expect "XFCE lock" true 'xfconf-query -c xfce4-screensaver -p /lock/enabled'
expect "XFCE idle delay" 5 'xfconf-query -c xfce4-screensaver -p /saver/idle-activation/delay'
exit "$fail"
