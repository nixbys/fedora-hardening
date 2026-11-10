#!/usr/bin/env bash
# tests/run-suite.sh - Full test suite for fedora-harden.sh
#
# Platform: every tier runs on the Fedora release under test (default 44, --fedora N).
#   static  runs natively when the host is that release (e.g. the CI job container),
#           otherwise inside the matching "lint" image built from Dockerfile.test
#   quick   runs in the fedora-minimal:N "test-only" image
#   full    runs in the fedora-minimal:N systemd "base" image
#   gui     runs in the fedora:N "gui" image (Xvfb + zenity + kdialog)
#   atomic  runs on real Fedora Atomic images of release N (Silverblue, Universal
#           Blue), booted with systemd in privileged containers
#   vm      installs those images on a virtual disk (bootc, in a Fedora CoreOS VM)
#           and boots them with KVM
#   fault   runs in the quick and full images of release N
#
# Tiers (run in order; each includes only its own tests):
#   static  - syntax, shellcheck, shfmt, yamllint, ruff, hadolint, MCP server smoke
#             test, regression greps (RPM toolchain of the release under test)
#   quick   - CLI contract + full dry-run in the no-systemd container, with a check
#             that dry-run left the container filesystem untouched
#   full    - systemd container: dry-run no-change check, REAL run, verification of
#             applied hardening, idempotent re-run, --list-sessions, --rollback all,
#             journal logging, --report/--resume, and section 17 against a real
#             WireGuard peer (tests/wireguard-test.sh: kill switch, DNS, rollback)
#   gui     - --gui-full on a virtual display: no hang, progress window closed,
#             one Material-dark end-of-run window, Cancel exits 130
#   atomic  - image-based behaviour with the images' own rpm-ostree, Flatpak, Podman
#             quadlets, distrobox/toolbox: nothing layered, real Flathub installs, a
#             real ClamAV container scan, OpenSCAP from a container, rollback
#             (tests/atomic-real.sh). Not in "all": pulls ~3 GB per image.
#   vm      - the same on an installed, booted system, plus what needs an OSTree
#             sysroot: image-signature finding, /etc baseline and weekly report
#             (tests/atomic-vm.sh). Not in "all": needs /dev/kvm, ~15 min per image.
#   fault   - fault injection (tests/fault-matrix.sh): bad arguments, odd locales and
#             paths, no network, dead DNS, broken repositories, RPM lock held,
#             missing tools, read-only and full filesystems, malformed configs,
#             SIGINT/SIGTERM/SIGKILL mid-run, concurrent runs, idempotency, and
#             rollback restoring /etc. Not in "all": about an hour.
#
# Usage:
#   tests/run-suite.sh                      # "all": static, quick, full, gui
#   tests/run-suite.sh --tier static        # one tier (repeatable: --tier static --tier quick)
#   tests/run-suite.sh --artifacts DIR      # where logs go (default: mktemp)
#   tests/run-suite.sh --no-build           # reuse existing images
#   tests/run-suite.sh --native             # run static tier on this host as-is
#   tests/run-suite.sh --fedora 45          # test on another Fedora release (default 44)
#   tests/run-suite.sh --tier fault         # fault injection (about an hour)
#   tests/run-suite.sh --tier atomic --image quay.io/fedora/fedora-kinoite:45
#                                           # atomic/vm tiers on other images (repeatable)
#
# Everything that changes system state happens inside throwaway rootless podman
# containers; the host is never modified.

# shellcheck disable=SC2016  # single-quoted bash -c bodies are intentional
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
SCRIPT="$ROOT/fedora-harden.sh"
TARGET_FEDORA="${TARGET_FEDORA:-44}"
NATIVE=0
TIERS=()
ATOMIC_IMAGES=() # --image; default: Silverblue + Universal Blue base for the release
ARTIFACTS=""
NO_BUILD=0
FULL_MEMORY="${FULL_MEMORY:-3g}"
CONTAINERS=()

PASS=0 FAIL=0 SKIP=0
RESULTS=()

if [[ -t 1 ]]; then
    C_RED=$'\033[0;31m' C_GRN=$'\033[0;32m' C_YEL=$'\033[0;33m' C_BLU=$'\033[0;34m' C_RST=$'\033[0m'
else
    C_RED="" C_GRN="" C_YEL="" C_BLU="" C_RST=""
fi

usage() {
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while (($# > 0)); do
    case "$1" in
        --tier)
            [[ "${2:-}" =~ ^(static|quick|full|gui|atomic|vm|fault|all)$ ]] || {
                echo "--tier needs static|quick|full|gui|atomic|vm|fault|all" >&2
                exit 2
            }
            TIERS+=("$2")
            shift 2
            ;;
        --image)
            [[ -n "${2:-}" ]] || usage 2
            ATOMIC_IMAGES+=("$2")
            shift 2
            ;;
        --artifacts)
            [[ -n "${2:-}" ]] || usage 2
            ARTIFACTS="$2"
            shift 2
            ;;
        --no-build)
            NO_BUILD=1
            shift
            ;;
        --native)
            NATIVE=1
            shift
            ;;
        --fedora)
            [[ "${2:-}" =~ ^[0-9]+$ ]] || {
                echo "--fedora needs a release number (e.g. 45)" >&2
                exit 2
            }
            TARGET_FEDORA="$2"
            shift 2
            ;;
        -h | --help) usage 0 ;;
        *)
            echo "Unknown option: $1" >&2
            usage 2
            ;;
    esac
done
# Per-release image tags, so 44 and 45 images can coexist
IMG_QUICK="localhost/fedora-harden:test-only-f${TARGET_FEDORA}"
IMG_FULL="localhost/fedora-harden:test-f${TARGET_FEDORA}"
IMG_LINT="localhost/fedora-harden:lint-f${TARGET_FEDORA}"
IMG_GUI="localhost/fedora-harden:gui-f${TARGET_FEDORA}"
# Universal Blue desktop image (uupd, distrobox, image-info.json) for the release:
# Bluefin and Aurora are on Fedora 44, Bazzite on 45. Override with --image.
ublue_desktop_image() {
    case "$1" in
        44) echo "ghcr.io/ublue-os/bluefin:44" ;;
        *) echo "ghcr.io/ublue-os/bazzite:stable" ;;
    esac
}
((${#ATOMIC_IMAGES[@]})) || ATOMIC_IMAGES=(
    "quay.io/fedora/fedora-silverblue:${TARGET_FEDORA}"
    "$(ublue_desktop_image "$TARGET_FEDORA")"
)
((${#TIERS[@]})) || TIERS=(all)
[[ " ${TIERS[*]} " == *" all "* ]] && TIERS=(static quick full gui)

[[ -n "$ARTIFACTS" ]] || ARTIFACTS="$(mktemp -d "${TMPDIR:-/tmp}/fedora-harden-suite.XXXXXX")"
mkdir -p "$ARTIFACTS"
ARTIFACTS="$(cd -- "$ARTIFACTS" && pwd -P)"

# shellcheck disable=SC2329  # invoked via trap
cleanup() {
    local c
    for c in "${CONTAINERS[@]}"; do
        podman rm -f -t 5 "$c" >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------
record() { # record <PASS|FAIL|SKIP> <name> [detail]
    local status="$1" name="$2" detail="${3:-}"
    case "$status" in
        PASS)
            ((++PASS))
            printf '  %sPASS%s  %s\n' "$C_GRN" "$C_RST" "$name"
            ;;
        FAIL)
            ((++FAIL))
            printf '  %sFAIL%s  %s%s\n' "$C_RED" "$C_RST" "$name" "${detail:+ — $detail}"
            ;;
        SKIP)
            ((++SKIP))
            printf '  %sSKIP%s  %s%s\n' "$C_YEL" "$C_RST" "$name" "${detail:+ — $detail}"
            ;;
    esac
    RESULTS+=("$status|$name|$detail")
}

# check <name> <command...> — PASS when the command exits 0; output saved to a log.
check() {
    local name="$1"
    shift
    local log="$ARTIFACTS/${name//[^A-Za-z0-9_.-]/_}.log"
    if "$@" >"$log" 2>&1; then
        record PASS "$name"
    else
        record FAIL "$name" "exit $?, see $log"
    fi
}

# expect_rc <name> <expected-rc> <command...>
expect_rc() {
    local name="$1" want="$2"
    shift 2
    local log="$ARTIFACTS/${name//[^A-Za-z0-9_.-]/_}.log" rc=0
    "$@" >"$log" 2>&1 || rc=$?
    if ((rc == want)); then
        record PASS "$name"
    else
        record FAIL "$name" "expected exit $want, got $rc (see $log)"
    fi
}

have() { command -v "$1" >/dev/null 2>&1; }
tier_header() { printf '\n%s== Tier: %s ==%s\n' "$C_BLU" "$1" "$C_RST"; }

# ---------------------------------------------------------------------------
# Container helpers
# ---------------------------------------------------------------------------
build_image() { # build_image <target> <tag>
    ((NO_BUILD)) && podman image exists "$2" && return 0
    # Buildah (Fedora 45+) overlays the build context from $TMPDIR (default /var/tmp).
    # Inside a container /var/tmp is often overlayfs itself, and overlay-on-overlay
    # fails ("invalid argument"); use a directory under the artifacts instead.
    local tmp="${TMPDIR:-}"
    if [[ -z "$tmp" && "$(stat -f -c %T /var/tmp 2>/dev/null)" == overlayfs ]]; then
        tmp="$ARTIFACTS/.buildtmp"
        mkdir -p "$tmp"
    fi
    TMPDIR="${tmp:-/var/tmp}" podman build -f "$ROOT/Dockerfile.test" \
        --build-arg "FEDORA_VERSION=$TARGET_FEDORA" --target "$1" -t "$2" "$ROOT"
}

# Leaf entries of `podman diff` that are not expected side effects of a dry run.
# Allowed: package-manager metadata caches/locks, our own logs/session reports, and
# directories podman itself touches when bind-mounting /etc/hosts etc.
unexpected_changes() { # unexpected_changes <diff-file>
    awk '{print $2}' "$1" | sort -u >"$1.paths"
    awk 'NR==FNR{all[$0]=1; next}
        {
            p=$0; parent=0
            for (q in all) if (index(q, p "/") == 1) { parent=1; break }
            if (!parent) print p
        }' "$1.paths" "$1.paths" |
        grep -Ev '^(/etc|/root|/tmp|/run|/var/tmp|/var/log)$' |
        grep -Ev '^(/var/cache/|/var/lib/dnf/|/usr/lib/sysimage/(rpm|libdnf5)/|/var/log/dnf5|/root/sessions|/var/log/fedora-harden|/tmp/|/run/|/var/log/journal|/var/lib/systemd/|/var/lib/rpm-state|/root/\.cache)' ||
        true
}

# ---------------------------------------------------------------------------
# Tier: static
# ---------------------------------------------------------------------------
# on_target_platform — true when this host is the Fedora release the script targets.
on_target_platform() {
    (
        # shellcheck source=/dev/null
        . /etc/os-release 2>/dev/null || exit 1
        [[ "${ID:-}" == fedora && "${VERSION_ID:-}" == "$TARGET_FEDORA" ]]
    )
}

# need_tool <tool> <test-name> — FAIL (not skip) when a toolchain binary is missing:
# the Fedora 44 lint image ships all of them, so a gap means a broken environment.
need_tool() {
    have "$1" && return 0
    record FAIL "$2" "$1 not installed (install the Fedora 44 toolchain: ./setup-dev.sh)"
    return 1
}

tier_static() {
    if ((!NATIVE)) && ! on_target_platform; then
        tier_header "static (re-running inside Fedora $TARGET_FEDORA lint image)"
        if ! have podman; then
            record FAIL "static: Fedora $TARGET_FEDORA platform" "host is not Fedora $TARGET_FEDORA and podman is unavailable"
            return 0
        fi
        if ! build_image lint "$IMG_LINT" >"$ARTIFACTS/build-lint.log" 2>&1; then
            record FAIL "static: build Fedora $TARGET_FEDORA lint image" "see $ARTIFACTS/build-lint.log"
            return 0
        fi
        mkdir -p "$ARTIFACTS/static"
        podman run --rm -v "$ROOT:/src:ro,z" -v "$ARTIFACTS/static:/artifacts:z" "$IMG_LINT" \
            /src/tests/run-suite.sh --tier static --native --fedora "$TARGET_FEDORA" --artifacts /artifacts || true
        local line status name detail
        while IFS= read -r line; do
            IFS='|' read -r status name detail <<<"$line"
            case "$status" in
                PASS) ((++PASS)) ;;
                FAIL) ((++FAIL)) ;;
                SKIP) ((++SKIP)) ;;
            esac
            RESULTS+=("$status|$name|$detail")
        done <"$ARTIFACTS/static/results.txt"
        return 0
    fi

    local platform
    # shellcheck source=/dev/null
    platform="$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}")"
    tier_header "static (platform: $platform)"
    on_target_platform || record SKIP "static: platform is Fedora $TARGET_FEDORA" "running natively on $platform (--native)"

    local scripts=("$ROOT"/*.sh "$ROOT"/tests/*.sh)
    local rel=("${scripts[@]#"$ROOT"/}")

    check "static: bash -n (all scripts)" bash -c 'for f; do bash -n "$f" || exit 1; done' _ "${scripts[@]}"

    if need_tool shellcheck "static: shellcheck"; then
        check "static: shellcheck --severity=warning" shellcheck --severity=warning "${scripts[@]}"
        check "static: shellcheck strict (.shellcheckrc, all checks)" \
            shellcheck --rcfile "$ROOT/.shellcheckrc" "${scripts[@]}"
    fi

    # Style comes from .editorconfig (tabs for the main script, 4 spaces elsewhere).
    if need_tool shfmt "static: shfmt"; then
        check "static: shfmt -d (Fedora $TARGET_FEDORA shfmt, .editorconfig style)" \
            bash -c 'cd "$1" && shift && shfmt -d "$@"' _ "$ROOT" "${rel[@]}"
    fi

    if need_tool yamllint "static: yamllint"; then
        check "static: yamllint --strict" bash -c 'cd "$1" && yamllint --strict .' _ "$ROOT"
    fi

    if need_tool hadolint "static: hadolint"; then
        check "static: hadolint Dockerfile.test" hadolint "$ROOT/Dockerfile.test"
    fi

    check "static: python compiles" python3 -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' \
        "$ROOT/mcp_server_fedora_harden.py" "$ROOT/tests/mcp_smoke.py"
    if need_tool ruff "static: ruff"; then
        check "static: ruff check" ruff check --no-cache "$ROOT/mcp_server_fedora_harden.py" "$ROOT/tests/mcp_smoke.py" "$ROOT/tests/check-references.py"
    fi

    if python3 -c 'import mcp' 2>/dev/null; then
        check "static: MCP server starts and serves tools" \
            python3 -I "$ROOT/tests/mcp_smoke.py" "$ROOT/mcp_server_fedora_harden.py"
    else
        record FAIL "static: MCP server smoke test" "python3-mcp not installed"
    fi

    # The pinned arkenfox release must still match its checksum (catches re-tagging).
    local ark_ver ark_sum
    ark_ver="$(sed -n 's/^ARKENFOX_VERSION="\(.*\)"$/\1/p' "$SCRIPT")"
    ark_sum="$(sed -n 's/^ARKENFOX_SHA256="\(.*\)"$/\1/p' "$SCRIPT")"
    if have curl; then
        check "static: pinned arkenfox $ark_ver matches its checksum" bash -c \
            'curl -fsSL "https://raw.githubusercontent.com/arkenfox/user.js/$1/user.js" | sha256sum | grep -q "^$2 "' _ "$ark_ver" "$ark_sum"
    else
        record SKIP "static: pinned arkenfox checksum" "curl not installed"
    fi

    # Section 22 summary: real XCCDF results nest <result> inside <rule-result>; the
    # old parser looked for a result="..." attribute and always reported 0 / 0.
    check "static: OpenSCAP results parser reads real oscap output" bash -c '
        source <(sed -n "/^scap_results() {/,/^}/p" "$1")
        [[ "$(scap_results "$2")" == "1 1 0" ]] &&
            [[ "$(scap_results "$2" failing)" == xccdf_org.ssgproject.content_rule_aide_build_database ]]' \
        _ "$SCRIPT" "$ROOT/tests/fixtures/scap-results-sample.xml"

    # Regression guard: under `set -e` a post-increment of a zero counter inside (( ))
    # evaluates to 0, returns status 1 and aborts the script.
    check "static: no set -e unsafe post-increments" \
        bash -c '! grep -nE "\(\([A-Za-z_][A-Za-z0-9_]*(\+\+|--)\)\)" "$@"' _ "${scripts[@]}"
}

# ---------------------------------------------------------------------------
# Tier: quick (no systemd)
# ---------------------------------------------------------------------------
quick_run() { # quick_run <args...> — run the script in a throwaway no-systemd container
    podman run --rm -v "$SCRIPT:/root/fedora-harden.sh:ro,z" \
        --entrypoint /root/fedora-harden.sh "$IMG_QUICK" "$@" </dev/null
}

tier_quick() {
    tier_header quick
    if ! have podman; then
        record SKIP "quick tier" "podman not installed"
        return 0
    fi
    if ! build_image test-only "$IMG_QUICK" >"$ARTIFACTS/build-quick.log" 2>&1; then
        record FAIL "quick: build image" "see $ARTIFACTS/build-quick.log"
        return 0
    fi
    record PASS "quick: build image"

    expect_rc "quick: --help exits 0" 0 quick_run --help
    expect_rc "quick: --list exits 0" 0 quick_run --list
    expect_rc "quick: unknown option exits 2" 2 quick_run --bogus
    expect_rc "quick: --only without value exits 2" 2 quick_run --only
    expect_rc "quick: --user without value exits 2" 2 quick_run --user

    # Non-root must be refused before anything happens.
    local log="$ARTIFACTS/quick_nonroot.log" rc=0
    podman run --rm --user testuser -v "$SCRIPT:/opt/fedora-harden.sh:ro,z" \
        --entrypoint /opt/fedora-harden.sh "$IMG_QUICK" --yes --dry-run </dev/null >"$log" 2>&1 || rc=$?
    if ((rc != 0)) && grep -q 'must be run as root' "$log"; then
        record PASS "quick: non-root is refused"
    else
        record FAIL "quick: non-root is refused" "exit $rc (see $log)"
    fi

    # Running from a read-only location (no writable sessions/ dir) must still exit 0.
    expect_rc "quick: dry-run from a read-only directory exits 0" 0 \
        podman run --rm -v "$SCRIPT:/opt/ro/fedora-harden.sh:ro,z" --read-only-tmpfs \
        --entrypoint /opt/ro/fedora-harden.sh "$IMG_QUICK" --yes --dry-run --only 4
    # --only filtering
    log="$ARTIFACTS/quick_only.log"
    rc=0
    quick_run --yes --dry-run --only 5,10 >"$log" 2>&1 || rc=$?
    if ((rc == 0)) && grep -q 'Section 5:' "$log" && grep -q 'Section 10:' "$log" &&
        ! grep -qE 'Section (2|7|20):' "$log"; then
        record PASS "quick: --only 5,10 runs exactly those sections"
    else
        record FAIL "quick: --only 5,10 runs exactly those sections" "exit $rc (see $log)"
    fi

    # A swap file whose mount is not visible (CI runners, containers) must be
    # reported, not abort the run: findmnt fails for it under the ERR trap.
    local swaps="$ARTIFACTS/fake-proc-swaps" log="$ARTIFACTS/quick_swap_report.log" rc=0
    printf 'Filename\tType\tSize\tUsed\tPriority\n/mnt/swapfile file 4194300 0 -2\n' >"$swaps"
    podman run --rm -v "$SCRIPT:/root/fedora-harden.sh:ro,z" -v "$swaps:/proc/swaps:ro,z" --entrypoint /root/fedora-harden.sh \
        "$IMG_QUICK" --dry-run --yes --only 20 >"$log" 2>&1 || rc=$?
    if ((rc == 0)) && grep -q "Unencrypted swap in use: /mnt/swapfile" "$log"; then
        record PASS "quick: unencrypted swap file is reported without aborting (section 20)"
    else
        record FAIL "quick: unencrypted swap file is reported without aborting (section 20)" "exit $rc (see $log)"
    fi

    # Back-to-back runs must get separate sessions: the session ID has one-second
    # resolution, and a shared one truncated the previous run's rollback journal.
    check "quick: back-to-back runs get separate sessions" \
        podman run --rm -v "$SCRIPT:/root/fedora-harden.sh:ro,z" --entrypoint /bin/bash "$IMG_QUICK" -c '
            /root/fedora-harden.sh --yes --dry-run --only 19 >/dev/null 2>&1
            /root/fedora-harden.sh --yes --dry-run --only 19 >/dev/null 2>&1
            logs=(/var/log/fedora-harden/harden-????????-??????.log)
            echo "${#logs[@]} session logs: ${logs[*]}"
            ((${#logs[@]} == 2))'

    # Desktop settings must really persist for the user (gsettings/xfconf need a D-Bus session)
    check "quick: GNOME + XFCE settings persist for the user (section 15)" \
        podman run --rm -v "$SCRIPT:/root/fedora-harden.sh:ro,z" \
        -v "$ROOT/tests/desktop-settings.sh:/root/desktop-settings.sh:ro,z" \
        --entrypoint /root/desktop-settings.sh "$IMG_QUICK"

    # Full dry run + filesystem no-change assertion
    local name="fh-suite-quick-$$"
    CONTAINERS+=("$name")
    log="$ARTIFACTS/quick_dryrun.log"
    rc=0
    podman run --name "$name" -v "$SCRIPT:/root/fedora-harden.sh:ro,z" \
        --entrypoint /root/fedora-harden.sh "$IMG_QUICK" --yes --dry-run </dev/null >"$log" 2>&1 || rc=$?
    if ((rc == 0)); then
        record PASS "quick: full --dry-run exits 0"
    else
        record FAIL "quick: full --dry-run exits 0" "exit $rc (see $log)"
    fi
    if grep -q '^\[FAIL\]' "$log"; then
        record FAIL "quick: dry-run has no [FAIL] lines" "$(grep -c '^\[FAIL\]' "$log") found"
    else
        record PASS "quick: dry-run has no [FAIL] lines"
    fi
    podman diff "$name" >"$ARTIFACTS/quick_dryrun.fsdiff" 2>&1 || true
    local unexpected
    unexpected="$(unexpected_changes "$ARTIFACTS/quick_dryrun.fsdiff")"
    if [[ -z "$unexpected" ]]; then
        record PASS "quick: dry-run made no filesystem changes"
    else
        printf '%s\n' "$unexpected" >"$ARTIFACTS/quick_dryrun.unexpected"
        record FAIL "quick: dry-run made no filesystem changes" \
            "$(wc -l <<<"$unexpected") path(s), see $ARTIFACTS/quick_dryrun.unexpected"
    fi
    podman rm -f "$name" >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# Tier: full (systemd)
# ---------------------------------------------------------------------------
FULL_CT=""
fx() { podman exec "$FULL_CT" "$@" </dev/null; }

# etc_snapshot <outfile> — checksums of every regular file under /etc. Excluded: files
# podman manages, and the shadow-utils "-" backups (rewritten whenever shadow-utils
# saves its database, even with identical content).
etc_snapshot() {
    fx bash -c 'find /etc -xdev -type f ! -path "/etc/hosts" ! -path "/etc/hostname" \
        ! -path "/etc/resolv.conf" ! -path "/etc/machine-id" ! -name "*.cache" \
        ! -path "/etc/shadow-" ! -path "/etc/gshadow-" ! -path "/etc/passwd-" ! -path "/etc/group-" \
        -exec sha256sum {} + 2>/dev/null | sort -k2' >"$1"
}

changed_files() { # changed_files <snapA> <snapB> — paths added/removed/modified
    diff <(awk '{print $2" "$1}' "$1") <(awk '{print $2" "$1}' "$2") |
        awk '/^[<>]/{print $2}' | sort -u || true
}

tier_full() {
    tier_header full
    if ! have podman; then
        record SKIP "full tier" "podman not installed"
        return 0
    fi
    if ! build_image base "$IMG_FULL" >"$ARTIFACTS/build-full.log" 2>&1; then
        record FAIL "full: build image" "see $ARTIFACTS/build-full.log"
        return 0
    fi
    record PASS "full: build image"

    FULL_CT="fh-suite-full-$$"
    CONTAINERS+=("$FULL_CT")
    mkdir -p "$ARTIFACTS/full-logs" "$ARTIFACTS/full-sessions"
    # NET_ADMIN: firewalld needs nftables in the container netns (no host effect when rootless)
    podman run -d --systemd=always --cap-add NET_ADMIN,NET_RAW --name "$FULL_CT" --hostname fedora-harden-test \
        --memory "$FULL_MEMORY" --memory-swap "$FULL_MEMORY" \
        -v "$SCRIPT:/root/fedora-harden.sh:ro,z" \
        -v "$ARTIFACTS/full-logs:/var/log/fedora-harden:z" \
        -v "$ARTIFACTS/full-sessions:/root/sessions:z" \
        "$IMG_FULL" >/dev/null

    local state="" i
    for i in $(seq 1 60); do
        state="$(fx systemctl is-system-running 2>/dev/null || true)"
        [[ "$state" == running || "$state" == degraded ]] && break
        sleep 1
    done
    if [[ "$state" == running || "$state" == degraded ]]; then
        record PASS "full: systemd booted ($state after ${i}s)"
    else
        record FAIL "full: systemd booted" "state=${state:-none}"
        return 0
    fi

    # --- dry-run under systemd changes nothing in /etc -----------------------
    etc_snapshot "$ARTIFACTS/etc.0"
    expect_rc "full: --dry-run exits 0" 0 fx /root/fedora-harden.sh --yes --dry-run
    etc_snapshot "$ARTIFACTS/etc.dry"
    local changed
    changed="$(changed_files "$ARTIFACTS/etc.0" "$ARTIFACTS/etc.dry")"
    if [[ -z "$changed" ]]; then
        record PASS "full: dry-run left /etc untouched"
    else
        printf '%s\n' "$changed" >"$ARTIFACTS/full_dryrun.etc-changes"
        record FAIL "full: dry-run left /etc untouched" "$(wc -l <<<"$changed") file(s) changed"
    fi

    # --- real run -------------------------------------------------------------
    # The SSH section refuses (in --yes mode) to disable password logins unless the
    # target user has a public key, so give testuser one first.
    check "full: install SSH key for testuser" fx bash -c '
        ssh-keygen -A >/dev/null &&
        install -d -m 700 -o testuser -g testuser /home/testuser/.ssh &&
        su - testuser -c "ssh-keygen -q -t ed25519 -N \"\" -f ~/.ssh/id_ed25519" &&
        install -m 600 -o testuser -g testuser /home/testuser/.ssh/id_ed25519.pub /home/testuser/.ssh/authorized_keys'
    local log="$ARTIFACTS/full_real1.log" rc=0
    fx /root/fedora-harden.sh --yes --user testuser >"$log" 2>&1 || rc=$?
    if ((rc == 0)); then
        record PASS "full: real run exits 0"
    else
        record FAIL "full: real run exits 0" "exit $rc (see $log)"
    fi
    if grep -q '^\[FAIL\]' "$log"; then
        grep '^\[FAIL\]' "$log" >"$ARTIFACTS/full_real1.fail-lines"
        record FAIL "full: real run has no [FAIL] lines" \
            "$(wc -l <"$ARTIFACTS/full_real1.fail-lines") found, see $ARTIFACTS/full_real1.fail-lines"
    else
        record PASS "full: real run has no [FAIL] lines"
    fi
    etc_snapshot "$ARTIFACTS/etc.1"

    # --- logging goes to the journal ------------------------------------------
    local session
    session="$(grep -oE 'FH_SESSION=[0-9]{8}-[0-9]{6}' "$log" | head -1)"
    check "full: the run logs to the journal under its session (${session:-none})" \
        bash -c '[[ -n "$2" ]] && (($(podman exec "$1" journalctl -t fedora-harden "$2" -o cat --no-pager | wc -l) > 50))' \
        _ "$FULL_CT" "$session"
    check "full: no log file is written when journald is running" \
        bash -c '! ls "$1"/harden-*.log >/dev/null 2>&1' _ "$ARTIFACTS/full-logs"

    # --- hardening actually applied -------------------------------------------
    check "full: sysctl drop-in written" fx test -s /etc/sysctl.d/99-hardening.conf
    check "full: firewalld default zone is drop" \
        bash -c '[[ "$(podman exec "$1" firewall-cmd --get-default-zone)" == drop ]]' _ "$FULL_CT"
    check "full: pwquality minlen=14" fx grep -Eq '^\s*minlen\s*=\s*14' /etc/security/pwquality.conf
    check "full: pwquality minclass=3" fx grep -Eq '^\s*minclass\s*=\s*3' /etc/security/pwquality.conf
    check "full: faillock deny=5 + unlock_time=900" fx bash -c \
        'grep -Eq "^deny = 5$" /etc/security/faillock.conf && grep -Eq "^unlock_time = 900$" /etc/security/faillock.conf'
    check "full: login.defs PASS_MAX_DAYS 90" fx grep -Eq '^PASS_MAX_DAYS\s+90$' /etc/login.defs
    check "full: auditd rules written" fx test -s /etc/audit/rules.d/hardening.rules
    check "full: umask profile written" fx grep -q 'umask 077' /etc/profile.d/99-umask.sh
    check "full: core dumps disabled" fx test -s /etc/security/limits.d/99-coredump.conf
    check "full: sshd config valid after hardening" fx sshd -t
    # sshd uses the first value it reads, so check the EFFECTIVE config (sshd -T), not the file.
    # Keywords are lowercased: OpenSSH 10.5 (Fedora 45) prints them in config-file case.
    check "full: sshd effective config is hardened (sshd -T)" bash -c '
        out="$(podman exec "$1" sshd -T | awk "{ \$1 = tolower(\$1); print }")" &&
        grep -qx "x11forwarding no" <<<"$out" &&
        grep -qx "passwordauthentication no" <<<"$out" &&
        grep -qx "permitrootlogin no" <<<"$out" &&
        grep -qx "maxauthtries 3" <<<"$out" &&
        grep -qx "allowusers testuser" <<<"$out" &&
        grep -qx "ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com" <<<"$out"' _ "$FULL_CT"
    check "full: clamd@scan running (socket configured before start)" fx systemctl is-active --quiet clamd@scan
    # systemd-resolved cannot START in a rootless container (its unit must keep
    # CAP_SYS_ADMIN while switching user: "Failed at step USER"), so check it was
    # installed, enabled and configured for DNS-over-TLS.
    check "full: systemd-resolved installed + enabled with DNS-over-TLS drop-in" fx bash -c \
        'rpm -q systemd-resolved >/dev/null && systemctl is-enabled --quiet systemd-resolved &&
         grep -qx "DNSOverTLS=yes" /etc/systemd/resolved.conf.d/99-hardening.conf'
    # Current guidance (privacyguides.org / inteltechniques.com), see docs/REFERENCES.md
    check "full: --yes does not install Firejail (opt-in only)" \
        bash -c '! podman exec "$1" rpm -q firejail >/dev/null 2>&1' _ "$FULL_CT"
    check "full: mat2 installed" fx rpm -q mat2
    check "full: Flatpak apps blocked from host filesystem" \
        fx grep -q '!host;' /var/lib/flatpak/overrides/global
    check "full: /etc/shadow mode 000" bash -c '[[ "$(podman exec "$1" stat -c %a /etc/shadow)" == 0 ]]' _ "$FULL_CT"

    # --- the user-facing verifier agrees ------------------------------------------
    # tests/verify-host.sh is what users run on real machines; check it reports PASS
    # for everything a container can provide. SEL/AUD/DNS/CLAM-2/SYS need the host
    # kernel (SELinux, audit, resolved's capabilities, fanotify, writable sysctls).
    log="$ARTIFACTS/full_verify_host.log"
    podman cp "$ROOT/tests/verify-host.sh" "$FULL_CT:/root/verify-host.sh" >/dev/null 2>&1
    fx /root/verify-host.sh >"$log" 2>&1 || true
    local id missing=""
    for id in AUTO-1 AUTO-2 FW-1 FW-2 SSH-1 SSH-2 PAM-1 PAM-2 PAM-3 FLAT-1 FLAT-2 PERM-1 PERM-2 CLAM-1 INT-1 ROLL-1; do
        grep -qE "^[[:space:]]+${id}[[:space:]]+PASS" "$log" || missing+="$id "
    done
    if [[ -z "$missing" ]]; then
        record PASS "full: verify-host.sh reports PASS for all container-checkable items"
    else
        record FAIL "full: verify-host.sh reports PASS for all container-checkable items" "not passing: $missing(see $log)"
    fi

    # --- idempotency ------------------------------------------------------------
    log="$ARTIFACTS/full_real2.log"
    rc=0
    fx /root/fedora-harden.sh --yes --user testuser >"$log" 2>&1 || rc=$?
    if ((rc == 0)); then
        record PASS "full: second run exits 0"
    else
        record FAIL "full: second run exits 0" "exit $rc (see $log)"
    fi
    etc_snapshot "$ARTIFACTS/etc.2"
    changed="$(changed_files "$ARTIFACTS/etc.1" "$ARTIFACTS/etc.2")"
    if [[ -z "$changed" ]]; then
        record PASS "full: second run is idempotent (/etc unchanged)"
    else
        printf '%s\n' "$changed" >"$ARTIFACTS/full_idempotency.etc-changes"
        record FAIL "full: second run is idempotent (/etc unchanged)" \
            "$(wc -l <<<"$changed") file(s) changed, see $ARTIFACTS/full_idempotency.etc-changes"
    fi

    # --- report and resume --------------------------------------------------------
    check "full: --report writes one HTML page with changes, follow-ups and live checks" \
        fx bash -c '/root/fedora-harden.sh --report /tmp/report.html >/dev/null 2>&1 &&
            grep -q "<h2>Changes</h2>" /tmp/report.html && grep -q "<h2>Open follow-ups</h2>" /tmp/report.html &&
            grep -q "FILE_BACKUP" /tmp/report.html'
    log="$ARTIFACTS/full_resume.log"
    rc=0
    fx /root/fedora-harden.sh --resume >"$log" 2>&1 || rc=$?
    if ((rc == 0)) && grep -q "Open follow-ups from session" "$log"; then
        record PASS "full: --resume shows the last session's open follow-ups"
    else
        record FAIL "full: --resume shows the last session's open follow-ups" "exit $rc (see $log)"
    fi

    # --- sessions + rollback ------------------------------------------------------
    log="$ARTIFACTS/full_list_sessions.log"
    rc=0
    fx /root/fedora-harden.sh --list-sessions >"$log" 2>&1 || rc=$?
    if ((rc == 0)) && (($(grep -cE 'session|Session' "$log") >= 2)); then
        record PASS "full: --list-sessions exits 0 and lists sessions"
    else
        record FAIL "full: --list-sessions exits 0 and lists sessions" "exit $rc (see $log)"
    fi

    log="$ARTIFACTS/full_rollback_all.log"
    rc=0
    fx /root/fedora-harden.sh --yes --rollback all >"$log" 2>&1 || rc=$?
    if ((rc == 0)); then
        record PASS "full: --rollback all exits 0"
    else
        record FAIL "full: --rollback all exits 0" "exit $rc (see $log)"
    fi
    etc_snapshot "$ARTIFACTS/etc.rb"
    changed="$(changed_files "$ARTIFACTS/etc.0" "$ARTIFACTS/etc.rb")"
    printf '%s\n' "$changed" >"$ARTIFACTS/full_rollback.residual"
    local hardened_left=0 f
    for f in /etc/sysctl.d/99-hardening.conf /etc/audit/rules.d/hardening.rules /etc/ssh/sshd_config.d/10-hardening.conf \
        /etc/profile.d/99-umask.sh /etc/security/limits.d/99-coredump.conf \
        /var/lib/flatpak/overrides/global; do
        fx test -e "$f" && ((++hardened_left))
    done
    if ((hardened_left == 0)) && cmp -s <(grep pwquality.conf "$ARTIFACTS/etc.0") \
        <(grep pwquality.conf "$ARTIFACTS/etc.rb"); then
        record PASS "full: rollback removed drop-ins and restored pwquality.conf"
    else
        record FAIL "full: rollback removed drop-ins and restored pwquality.conf" \
            "$hardened_left drop-in(s) remain; residual diff in $ARTIFACTS/full_rollback.residual"
    fi

    fx journalctl --no-pager -b >"$ARTIFACTS/full_journal.log" 2>&1 || true
    fx systemctl --failed --no-pager >"$ARTIFACTS/full_failed_units.txt" 2>&1 || true

    # --- section 17: WireGuard with a real peer, kill switch, DNS, rollback ---------
    local wg_out="$ARTIFACTS/wireguard" line
    mkdir -p "$wg_out"
    "$ROOT/tests/wireguard-test.sh" "$TARGET_FEDORA" "$wg_out" >"$wg_out/results.txt" 2>&1 || true
    while IFS= read -r line; do
        case "$line" in
            "PASS: "*) record PASS "full: wireguard: ${line#PASS: }" ;;
            "FAIL: "*) record FAIL "full: wireguard: ${line#FAIL: }" "logs in $wg_out" ;;
        esac
    done <"$wg_out/results.txt"
    grep -qE '^(PASS|FAIL):' "$wg_out/results.txt" || record FAIL "full: wireguard test ran" "no results, see $wg_out/results.txt"
}

# ---------------------------------------------------------------------------
# Tier: gui (Xvfb + zenity)
# ---------------------------------------------------------------------------
tier_gui() {
    tier_header gui
    if ! have podman; then
        record SKIP "gui tier" "podman not installed"
        return 0
    fi
    if ! build_image gui "$IMG_GUI" >"$ARTIFACTS/build-gui.log" 2>&1; then
        record FAIL "gui: build image" "see $ARTIFACTS/build-gui.log"
        return 0
    fi
    record PASS "gui: build image"
    mkdir -p "$ARTIFACTS/gui"
    local log="$ARTIFACTS/gui/gui-test.out" line
    podman run --rm -v "$SCRIPT:/root/fedora-harden.sh:ro,z" \
        -v "$ROOT/tests/gui-test.sh:/root/gui-test.sh:ro,z" -v "$ARTIFACTS/gui:/out:z" \
        --entrypoint /root/gui-test.sh "$IMG_GUI" >"$log" 2>&1 || true
    # One suite result per check reported by the in-container test
    while IFS= read -r line; do
        case "$line" in
            "ok:   "*) record PASS "gui: ${line#ok:   }" ;;
            "FAIL: "*) record FAIL "gui: ${line#FAIL: }" "screenshots + logs in $ARTIFACTS/gui" ;;
        esac
    done <"$log"
    grep -qE '^(ok|FAIL):' "$log" || record FAIL "gui: test ran" "no results, see $log"
}

# ---------------------------------------------------------------------------
# Tiers: atomic and vm (real Fedora Atomic images)
# ---------------------------------------------------------------------------
# run_image_test <tier> <driver> <image> [driver args...] — one suite result per
# PASS:/FAIL: line the driver prints.
run_image_test() {
    local tier="$1" driver="$2" img="$3"
    shift 3
    local slug="${img##*/}" out line
    slug="${slug//[^A-Za-z0-9_.-]/_}"
    out="$ARTIFACTS/$tier/$slug"
    mkdir -p "$out"
    "$ROOT/tests/$driver" "$img" "$out" "$@" >"$out/results.txt" 2>&1 || true
    while IFS= read -r line; do
        case "$line" in
            "PASS: "*) record PASS "$tier $slug: ${line#PASS: }" ;;
            "FAIL: "*) record FAIL "$tier $slug: ${line#FAIL: }" "logs in $out" ;;
        esac
    done <"$out/results.txt"
    grep -qE '^(PASS|FAIL):' "$out/results.txt" || record FAIL "$tier $slug: test ran" "no results, see $out/results.txt"
}

tier_atomic() {
    tier_header "atomic (real Fedora Atomic images, Fedora $TARGET_FEDORA)"
    if ! have podman; then
        record SKIP "atomic tier" "podman not installed"
        return 0
    fi
    local img
    for img in "${ATOMIC_IMAGES[@]}"; do
        run_image_test atomic atomic-real.sh "$img"
    done
}

tier_vm() {
    tier_header "vm (installed Fedora Atomic images, Fedora $TARGET_FEDORA)"
    if ! have podman; then
        record SKIP "vm tier" "podman not installed"
        return 0
    fi
    if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
        record SKIP "vm tier" "/dev/kvm not available"
        return 0
    fi
    local img
    for img in "${ATOMIC_IMAGES[@]}"; do
        run_image_test vm atomic-vm.sh "$img" "$TARGET_FEDORA"
    done
}

# ---------------------------------------------------------------------------
# Tier: fault (fault injection)
# ---------------------------------------------------------------------------
tier_fault() {
    tier_header "fault (fault injection, Fedora $TARGET_FEDORA)"
    if ! have podman; then
        record SKIP "fault tier" "podman not installed"
        return 0
    fi
    # The fault scenarios run in the quick and full images.
    if ! build_image test-only "$IMG_QUICK" >"$ARTIFACTS/build-quick.log" 2>&1 ||
        ! build_image base "$IMG_FULL" >"$ARTIFACTS/build-full.log" 2>&1; then
        record FAIL "fault: build images" "see $ARTIFACTS/build-*.log"
        return 0
    fi
    local out="$ARTIFACTS/fault" line
    mkdir -p "$out"
    "$ROOT/tests/fault-matrix.sh" "$TARGET_FEDORA" "$out" >"$out/results.txt" 2>&1 || true
    while IFS= read -r line; do
        case "$line" in
            "PASS: "*) record PASS "fault ${line#PASS: }" ;;
            "FAIL: "*) record FAIL "fault ${line#FAIL: }" "logs in $out" ;;
        esac
    done <"$out/results.txt"
    grep -qE '^(PASS|FAIL):' "$out/results.txt" || record FAIL "fault: matrix ran" "no results, see $out/results.txt"
}

# ---------------------------------------------------------------------------
printf 'fedora-harden test suite — tiers: %s\nArtifacts: %s\n' "${TIERS[*]}" "$ARTIFACTS"
for t in "${TIERS[@]}"; do
    "tier_$t"
done

printf '\n%s== Summary ==%s  %s%d passed%s, %s%d failed%s, %s%d skipped%s\n' \
    "$C_BLU" "$C_RST" "$C_GRN" "$PASS" "$C_RST" "$C_RED" "$FAIL" "$C_RST" "$C_YEL" "$SKIP" "$C_RST"
printf '%s\n' "${RESULTS[@]}" >"$ARTIFACTS/results.txt"
printf 'Artifacts: %s\n' "$ARTIFACTS"
((FAIL == 0))
