#!/usr/bin/env bash
# tests/gui-test.sh - --gui checks; runs INSIDE the "gui" image (Fedora N).
#
# Drives fedora-harden.sh on a virtual X display (Xvfb) and checks the one window
# that --gui opens (GTK4/libadwaita):
#   - a --gui --dry-run --yes run exits 0 without hanging, the window shows every
#     planned section as done and the summary, and stays open after the script exits
#     (the only window), rendered with the Material-dark theme (pixel-sampled), even
#     though the root locale here is NOT UTF-8; Ctrl+W then closes it
#   - questions are answered inside the window (typed text and Yes/No by keyboard)
#   - Stop (Ctrl+W, then "Stop" in the confirmation) ends the run with exit 130 and
#     the cancellation is logged; a window that disappears also stops the run
#
# The app writes what it shows to $FH_GUI_STATE (a test hook) when it asks something
# and when the run ends.
#
# Usage (from tests/run-suite.sh):
#   podman run --rm -v fedora-harden.sh:/root/fedora-harden.sh:ro \
#     -v tests/gui-test.sh:/root/gui-test.sh:ro -v ARTIFACTS:/out IMAGE /root/gui-test.sh

set -uo pipefail
[[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]] || exec dbus-run-session -- "$0" "$@"

OUT="${OUT:-/out}"
mkdir -p "$OUT"
unset LANG LC_ALL LC_CTYPE # root under sudo -i/pkexec often has no UTF-8 locale
Xvfb :99 -screen 0 1180x800x24 >/dev/null 2>&1 &
export DISPLAY=:99 GTK_A11Y=none
export FH_GUI_STATE="$OUT/window-state.txt"
sleep 1

fail=0
pass() { echo "ok:   $*"; }
bad() {
    echo "FAIL: $*"
    fail=1
}
window() { xdotool search --onlyvisible --name '^Fedora Hardening$' 2>/dev/null | head -n 1; }
app_pids() { pgrep -f 'fedora-harden-gui\.py' || true; }
state() { sed -n "s/^$1=//p" "$FH_GUI_STATE" 2>/dev/null; }
wait_for() { # wait_for <seconds> <command...>
    local i
    for ((i = 0; i < $1 * 2; i++)); do
        "${@:2}" && return 0
        sleep 0.5
    done
    return 1
}
keys() { # keys <key...> — send keys to the window
    local wid
    wid="$(window)"
    [[ -n "$wid" ]] || return 1
    xdotool windowfocus --sync "$wid" 2>/dev/null
    xdotool key --clearmodifiers "$@"
}
close_app() {
    pkill -f 'fedora-harden-gui\.py' 2>/dev/null
    wait_for 10 test -z "$(app_pids)"
    rm -f "$FH_GUI_STATE"
}

# --- 1. dry run: completes, one window with every section done and the summary ----
rc=0
timeout 300 /root/fedora-harden.sh --gui --dry-run --yes >"$OUT/gui-dryrun.log" 2>&1 || rc=$?
if ((rc == 0)); then pass "--gui --dry-run --yes exits 0"; else bad "--gui --dry-run exit $rc (124 = hung)"; fi
wait_for 10 test -n "$(state exit)"
sleep 2
import -window root "$OUT/gui-summary.png" 2>/dev/null
cp "$FH_GUI_STATE" "$OUT/window-state-dryrun.txt" 2>/dev/null
if [[ -n "$(app_pids)" ]]; then pass "window stays open after the script exits"; else bad "window closed with the script"; fi
n="$(xdotool search --onlyvisible --name . 2>/dev/null | wc -l)"
if ((n == 1)); then pass "exactly one window"; else bad "expected 1 window, found $n"; fi
if [[ "$(state exit)" == 0 ]]; then pass "window shows the run finished (exit 0)"; else bad "window end state: '$(state exit)'"; fi
read -r planned done_n < <(state sections | sed 's/[a-z_]*=//g')
if [[ -n "$planned" ]] && ((planned >= 20 && done_n == planned)); then
    pass "every planned section shown as done ($done_n of $planned)"
else
    bad "sections in the window: '$(state sections)'"
fi
if [[ "$(state headline)" == "Dry run finished"* ]]; then pass "summary page shows the outcome"; else bad "summary headline: '$(state headline)'"; fi
lines="$(state ok | sed 's/.*lines=//')"
if ((${lines:-0} > 50)); then pass "activity log filled ($lines lines)"; else bad "activity log has ${lines:-0} lines"; fi

# Theme: the sidebar must be Material dark surface-container-low (#1D1B20), not
# Adwaita light. Sample the empty sidebar to the right of its "Sections" heading.
wid="$(window)"
if [[ -n "$wid" ]]; then
    eval "$(xdotool getwindowgeometry --shell "$wid")"
    px="$(magick "$OUT/gui-summary.png" -format "%[hex:p{$((X + 220)),$((Y + 60))}]" info: 2>/dev/null)"
    if [[ "${px^^}" == 1D1B20* ]]; then
        pass "Material dark theme applied (sidebar #$px)"
    else
        bad "theme not applied: sidebar pixel #${px:-?} (expected #1D1B20)"
    fi
    keys ctrl+w
    if wait_for 10 test -z "$(app_pids)"; then pass "Ctrl+W closes the finished window"; else bad "window did not close on Ctrl+W"; fi
else
    bad "no window to inspect"
fi
close_app

# --- 2. questions are answered in the window ---------------------------------------
# Without --yes, section 24 asks for use cases (typed) and the run ends with a Yes/No
# question about follow-ups; the user name prompt may come first.
/root/fedora-harden.sh --gui --dry-run --only 24 >"$OUT/gui-questions.log" 2>&1 &
pid=$!
asked=0 typed=0
for _ in $(seq 1 240); do
    kill -0 "$pid" 2>/dev/null || break
    a="$(state asks)"
    if [[ -n "$(state asking)" && "${a:-0}" -gt "$asked" ]]; then
        asked="$a"
        q="$(state asking)"
        sleep 0.5
        ((asked == 1)) && import -window root "$OUT/gui-question.png" 2>/dev/null
        case "$q" in
            input\|*"Use cases"*)
                keys ctrl+a && xdotool type --delay 40 "gaming,dev" && keys Return && typed=1
                ;;
            input\|*username*) keys ctrl+a && xdotool type --delay 40 "testuser" && keys Return ;;
            *) keys Return ;;
        esac
    fi
    sleep 0.5
done
rc=0
if kill -0 "$pid" 2>/dev/null; then
    kill "$pid"
    rc=124
fi
wait "$pid" || rc=$?
if ((rc == 0)); then pass "run with questions answered in the window exits 0"; else bad "question run exit $rc (124 = stuck on a question)"; fi
if ((asked >= 1)); then pass "questions shown in the window ($asked)"; else bad "no question appeared in the window"; fi
if ((typed)) && grep -rqs 'gaming' /var/log/fedora-harden/ "$OUT/gui-questions.log"; then
    pass "typed answer reached the script (use cases: gaming,dev)"
else
    bad "typed answer not seen by the script (typed=$typed)"
fi
close_app

# --- 3. Stop in the window ends the run with exit 130 ------------------------------
# A real (non-dry) run of section 13 is slow enough (package + Flathub work) to stop.
rm -f /var/log/fedora-harden/harden-*.log
/root/fedora-harden.sh --gui --yes --only 13 >"$OUT/gui-cancel.log" 2>&1 &
pid=$!
wait_for 60 test -n "$(window)"
sleep 3
import -window root "$OUT/gui-progress.png" 2>/dev/null
keys ctrl+w
sleep 1
import -window root "$OUT/gui-stop-confirm.png" 2>/dev/null
keys alt+s
rc=0
timeout 180 tail --pid="$pid" -f /dev/null || true
if kill -0 "$pid" 2>/dev/null; then
    kill "$pid"
    rc=124
fi
wait "$pid" || rc=$?
if ((rc == 130)); then pass "Stop ends the run with exit 130"; else bad "Stop: expected exit 130, got $rc"; fi
if grep -qs 'cancelled by user' /var/log/fedora-harden/harden-*.log; then
    pass "cancellation is logged"
else
    bad "cancellation not logged"
fi
wait_for 10 test "$(state exit)" = 130
if [[ "$(state exit)" == 130 ]]; then pass "window shows the run stopped"; else bad "window end state after Stop: '$(state exit)'"; fi
close_app

# --- 4. a window that disappears stops the run -------------------------------------
/root/fedora-harden.sh --gui --yes --only 13 >"$OUT/gui-killed.log" 2>&1 &
pid=$!
wait_for 60 test -n "$(window)"
sleep 3
pkill -f 'fedora-harden-gui\.py'
rc=0
timeout 180 tail --pid="$pid" -f /dev/null || true
if kill -0 "$pid" 2>/dev/null; then
    kill "$pid"
    rc=124
fi
wait "$pid" || rc=$?
if ((rc == 130)); then pass "closed window stops the run (exit 130)"; else bad "window gone: expected exit 130, got $rc"; fi

cp /var/log/fedora-harden/*.log /run/fedora-harden/gui/window.log "$OUT/" 2>/dev/null || true
exit "$fail"
