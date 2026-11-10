#!/usr/bin/env bash
# tests/gui-test.sh - GUI (--gui-full) checks; runs INSIDE the Fedora 44 "gui" image.
#
# Drives fedora-harden.sh on a virtual X display (Xvfb) with zenity and checks:
#   - a --gui-full --dry-run --yes run exits 0 and does not hang on any dialog
#   - the progress window is closed (not orphaned) when the script exits
#   - exactly one end-of-run window remains, rendered with the Material-dark theme
#     (pixel-sampled), even though the root locale here is NOT UTF-8
#   - pressing Cancel on the progress window stops the run with exit 130
#
# Usage (from tests/run-suite.sh):
#   podman run --rm -v fedora-harden.sh:/root/fedora-harden.sh:ro \
#     -v tests/gui-test.sh:/root/gui-test.sh:ro -v ARTIFACTS:/out IMAGE /root/gui-test.sh

set -uo pipefail
[[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]] || exec dbus-run-session -- "$0" "$@"

OUT="${OUT:-/out}"
mkdir -p "$OUT"
unset LANG LC_ALL LC_CTYPE # root under sudo -i/pkexec often has no UTF-8 locale
Xvfb :99 -screen 0 1000x640x24 >/dev/null 2>&1 &
export DISPLAY=:99
sleep 1
mv /usr/bin/kdialog /usr/bin/kdialog.off 2>/dev/null || true # exercise the zenity path

fail=0
pass() { echo "ok:   $*"; }
bad() {
    echo "FAIL: $*"
    fail=1
}
windows() { xdotool search --onlyvisible --name . 2>/dev/null | wc -l; }
progress_pids() { pgrep -f 'zenity --progress' || true; }

# --- 1. dry run: completes, no hang, progress closed, one themed summary window ----
rc=0
timeout 180 /root/fedora-harden.sh --gui-full --dry-run --yes >"$OUT/gui-dryrun.log" 2>&1 || rc=$?
if ((rc == 0)); then pass "--gui-full --dry-run --yes exits 0"; else bad "--gui-full --dry-run exit $rc (124 = hung)"; fi
sleep 3
import -window root "$OUT/gui-summary.png" 2>/dev/null
if [[ -z "$(progress_pids)" ]]; then pass "progress window closed on exit"; else bad "progress window orphaned: $(progress_pids)"; fi
n="$(windows)"
if ((n == 1)); then pass "exactly one end-of-run window"; else bad "expected 1 end-of-run window, found $n"; fi

# Theme: the summary window's surface must be M3 surface-container-high (#2B2930),
# not Adwaita light (#FAFAFA-ish). Sample a point inside the window body.
wid="$(xdotool search --onlyvisible --name . 2>/dev/null | head -n 1)"
if [[ -n "$wid" ]]; then
    eval "$(xdotool getwindowgeometry --shell "$wid")"
    px="$(magick "$OUT/gui-summary.png" -format "%[hex:p{$((X + 20)),$((Y + 20))}]" info: 2>/dev/null)"
    if [[ "${px^^}" == 2B2930* ]]; then
        pass "Material dark theme applied (surface #$px)"
    else
        bad "theme not applied: surface pixel #${px:-?} (expected #2B2930)"
    fi
else
    bad "no end-of-run window to inspect"
fi
pkill -x zenity 2>/dev/null
sleep 1

# --- 2. Cancel on the progress window stops the run with exit 130 ----------------
# A real (non-dry) run of section 13 is slow enough (package + Flathub work) to cancel.
/root/fedora-harden.sh --gui-full --yes --only 13 >"$OUT/gui-cancel.log" 2>&1 &
pid=$!
for _ in $(seq 1 60); do
    [[ -n "$(progress_pids)" ]] && break
    sleep 0.5
done
sleep 2
import -window root "$OUT/gui-progress.png" 2>/dev/null
pkill -f 'zenity --progress' # same effect as the user pressing Cancel / closing it
rc=0
timeout 120 tail --pid="$pid" -f /dev/null || true
wait "$pid" || rc=$?
if ((rc == 130)); then pass "Cancel stops the run with exit 130"; else bad "Cancel: expected exit 130, got $rc"; fi
if grep -q 'cancelled by user' /var/log/fedora-harden/harden-*.log 2>/dev/null; then
    pass "cancellation is logged"
else
    bad "cancellation not logged"
fi

cp /var/log/fedora-harden/*.log "$OUT/" 2>/dev/null || true
exit "$fail"
