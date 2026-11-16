#!/usr/bin/env bash
# tests/gui-screenshots.sh - Regenerate docs/screenshots/*.png (runs INSIDE the "gui" image).
#
# Starts the --gui window app (libexec/fedora-harden-gui.py) and plays a sample run
# into it, so the README images always match what the script ships:
#   running.png   sections, progress, a notice and the activity log mid-run
#   question.png  a question answered inside the window
#   stop.png      Stop asks before ending the run
#   summary.png   the summary page with follow-up items
#
# Usage:
#   podman build -f Dockerfile.test --target gui -t localhost/fedora-harden:gui .
#   podman run --rm -v .:/opt/fedora-hardening:ro,z \
#     -v ./tests/gui-screenshots.sh:/root/gui-screenshots.sh:ro,z \
#     -v ./docs/screenshots:/out:z --entrypoint /root/gui-screenshots.sh \
#     localhost/fedora-harden:gui

set -uo pipefail
[[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]] || exec dbus-run-session -- "$0" "$@"

OUT="${OUT:-/out}"
APP=/opt/fedora-hardening/libexec/fedora-harden-gui.py
mkdir -p "$OUT"
[[ -s "$APP" ]] || {
    echo "$APP not found: mount the project at /opt/fedora-hardening" >&2
    exit 1
}
export LC_ALL=C.UTF-8 GTK_A11Y=none
Xvfb :99 -screen 0 1180x800x24 >/dev/null 2>&1 &
export DISPLAY=:99
sleep 1

capture() { # capture <name> — crop the window plus a margin
    local wid X Y WIDTH HEIGHT
    sleep 1.5
    wid="$(xdotool search --onlyvisible --name '^Fedora Hardening$' | head -n 1)"
    eval "$(xdotool getwindowgeometry --shell "$wid")"
    import -window root -crop "$((WIDTH + 24))x$((HEIGHT + 24))+$((X > 12 ? X - 12 : 0))+$((Y > 12 ? Y - 12 : 0))" \
        +repage "$OUT/$1.png"
    echo "wrote $OUT/$1.png"
}

coproc WIN { exec python3 "$APP" 2>/dev/null; }
exec {TX}>&"${WIN[1]}" {RX}<&"${WIN[0]}"
read -r -t 30 -u "$RX" _ready
ev() { # ev <tab-separated event> [pause]
    printf '%s\n' "$1" >&"$TX"
    sleep "${2:-0.05}"
}

ev $'MODE\tApplying changes'
while read -r n title; do
    ev "PLAN	$n	$title" 0
done <<'PLAN'
2 System updates
3 Automatic security updates
6 Secure Boot verification
13 Flatpak + Flathub
4 SELinux (verify enforcing + install tools)
5 firewalld — drop-by-default
7 SSH hardening
17 WireGuard tunnel with kill switch
24 Your routine
25 Home snapshots
PLAN
ev $'SECTION\t2\tSystem updates'
ev $'LOG\tinfo\tChecking for updates'
ev $'LOG\trun\tdnf -y upgrade --refresh'
for p in "Updating and loading repositories:" " Fedora 44 - x86_64 - Updates   100% |  41.3 KiB/s |  21.6 KiB" "Nothing to do."; do ev "LOG	out	$p"; done
ev $'LOG\tok\tSystem is up to date.' 0.4
ev $'SECTION\t3\tAutomatic security updates'
ev $'LOG\trun\tsystemctl enable --now dnf5-automatic.timer'
ev $'LOG\tok\tAutomatic security updates: applied daily at 06:00.' 0.4
ev $'SECTION\t6\tSecure Boot verification'
ev $'LOG\twarn\tSecure Boot is disabled in the firmware. Enable it in the UEFI setup.' 0.4
ev $'SECTION\t13\tFlatpak + Flathub'
ev $'LOG\trun\tflatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo'
ev $'LOG\tok\tFlathub enabled; global Flatpak restrictions applied.' 0.4
ev $'SECTION\t4\tSELinux (verify enforcing + install tools)'
ev $'LOG\tok\tSELinux is enforcing (targeted policy).' 0.4
ev $'SECTION\t5\tfirewalld — drop-by-default'
ev $'LOG\tinfo\tDefault zone: drop. Allowing DHCPv6 client only.'
ev $'LOG\trun\tfirewall-cmd --permanent --set-default-zone=drop'
ev $'NOTICE\twarning\tUSBGuard can block unapproved USB devices, including keyboard and mouse.\\nConnect every device you need before section 23 runs.' 0.6
capture running

ev $'ASK\t1\tconfirm\tno\tAllow SSH logins on this machine?\\nNo keeps the SSH server off; you can turn it on later.' 0.6
capture question
xdotool key Return
read -r -t 5 -u "$RX" _answer

ev $'SECTION\t7\tSSH hardening'
ev $'LOG\tok\tsshd stays off.'
xdotool key ctrl+w
capture stop
xdotool key Escape
sleep 0.5

ev $'SECTION\t17\tWireGuard tunnel with kill switch'
ev $'LOG\terror\tWireGuard tunnel wg0 did not start: journalctl -u wg-quick@wg0'
ev $'SECTION\t24\tYour routine'
ev $'LOG\tok\tUpkeep timers set for: gaming, dev.'
ev $'SECTION\t25\tHome snapshots'
ev $'LOG\tok\tHome snapshots: hourly while this machine is in active use.'
ev $'SUMMARY\tFedora hardening finished.\t3 items need follow-up. A reboot is recommended.\\n\\nLog: journalctl -t fedora-harden FH_SESSION=20261115-101500\\nBackups: /root/harden-backups-20261115-101500'
ev $'ITEMS'
ev $'ITEM\tHIGH\tS17\tWireGuard tunnel wg0 did not start. Check: journalctl -u wg-quick@wg0'
ev $'ITEM\tMEDIUM\tS6\tSecure Boot is disabled. Enable it in the UEFI firmware setup, then check: mokutil --sb-state'
ev $'ITEM\tLOW\tS16\tReview the arkenfox defaults and add local exceptions in user-overrides.js.'
ev $'END\t0\tFinished. A reboot is recommended to apply kernel, sysctl and PAM changes.' 0.6
capture summary

exec {TX}>&-
kill "$WIN_PID" 2>/dev/null
