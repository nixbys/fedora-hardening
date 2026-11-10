#!/usr/bin/env bash
# tests/gui-screenshots.sh - Regenerate docs/screenshots/*.png (runs INSIDE the "gui" image).
#
# Renders each dialog type fedora-harden.sh uses with the Material-dark theme
# embedded in the script itself (extracted between the GTKCSS markers), so the
# README images always match what the script ships.
#
# Usage:
#   podman build -f Dockerfile.test --target gui -t localhost/fedora-harden:gui .
#   podman run --rm -v ./fedora-harden.sh:/root/fedora-harden.sh:ro,z \
#     -v ./tests/gui-screenshots.sh:/root/gui-screenshots.sh:ro,z \
#     -v ./docs/screenshots:/out:z --entrypoint /root/gui-screenshots.sh \
#     localhost/fedora-harden:gui

set -uo pipefail
[[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]] || exec dbus-run-session -- "$0" "$@"

OUT="${OUT:-/out}"
THEME="$(mktemp -d)"
mkdir -p "$OUT" "$THEME/gtk-4.0"
awk '/<<.GTKCSS.$/{f=1; next} /^GTKCSS$/{f=0} f' /root/fedora-harden.sh >"$THEME/gtk-4.0/gtk.css"
[[ -s "$THEME/gtk-4.0/gtk.css" ]] || {
    echo "could not extract theme from fedora-harden.sh" >&2
    exit 1
}
export XDG_CONFIG_HOME="$THEME" ADW_DEBUG_COLOR_SCHEME=prefer-dark LC_ALL=C.UTF-8
Xvfb :99 -screen 0 1100x760x24 >/dev/null 2>&1 &
export DISPLAY=:99
sleep 1
# Neutral backdrop so the window edge is visible in the crop
magick -size 1100x760 xc:'#0B0A0D' /tmp/bg.png 2>/dev/null

capture() { # capture <name> — crop the single visible dialog plus a margin
    local wid X Y WIDTH HEIGHT
    sleep 3
    wid="$(xdotool search --onlyvisible --name . 2>/dev/null | tail -n 1)"
    [[ -n "$wid" ]] || {
        echo "no window for $1" >&2
        return 1
    }
    eval "$(xdotool getwindowgeometry --shell "$wid")"
    import -window root /tmp/full.png 2>/dev/null
    magick /tmp/full.png -crop "${WIDTH}x${HEIGHT}+${X}+${Y}" +repage \
        -bordercolor '#0B0A0D' -border 24 "$OUT/$1.png"
    pkill -x zenity 2>/dev/null
    sleep 1
    echo "wrote $OUT/$1.png (${WIDTH}x${HEIGHT})"
}

(
    printf '45\n# Section 10: Kernel &amp; network sysctl hardening\n'
    sleep 30
) | zenity --progress --title=fedora-harden.sh --text="Preparing..." --percentage=0 --width=640 2>/dev/null &
capture progress

zenity --question --title=fedora-harden.sh --width=480 \
    --text="Allow 'ssh' through the firewall? (you'll harden sshd in section 7)" 2>/dev/null &
capture question

zenity --entry --title=fedora-harden.sh --width=520 --entry-text="alice" \
    --text="Enter the primary username to harden (blank to skip user-specific tweaks):" 2>/dev/null &
capture entry

cat >/tmp/summary.txt <<'EOF'
Fedora hardening finished.

3 item(s) need follow-up (listed below).
A reboot is recommended.

Log: /var/log/fedora-harden/harden-20261110-120000.log
Backups: /root/harden-backups-20261110-120000

──────────── Follow-up items ────────────

HIGH
  • §7   Install a public key for alice in /home/alice/.ssh/authorized_keys
         (ssh-copy-id from your client), then re-run: sudo ./fedora-harden.sh --only 7

MEDIUM
  • §13  Review Flatpak app permissions with Flatseal (com.github.tchx84.Flatseal).
  • §17  Configure WireGuard tunnel: install provider config to /etc/wireguard/wg0.conf
         (chmod 600) then run: sudo systemctl enable --now wg-quick@wg0
EOF
zenity --text-info --title=fedora-harden.sh --filename=/tmp/summary.txt \
    --width=900 --height=560 --ok-label=Done 2>/dev/null &
capture summary
