#!/usr/bin/env bash
# =============================================================================
#  Fedora 44+ Security Hardening Script (multi-release + multi-desktop aware)
#  Aligned with privacyguides.org and inteltechniques.com recommendations;
#  sources and review dates: docs/references.json (checked weekly in CI)
#  Tested on Fedora 44 and 45 (tests/run-suite.sh); version: --version
#  License: GPL-3.0-or-later (LICENSE)
#
#  FEATURES:
#    • 24 hardening sections (plus subsections 3b, 11b and 14b) with automatic
#      release/profile detection
#    • Dual-mode support: mutable (dnf) and immutable (rpm-ostree) systems
#    • Fedora release detection: Workstation, Server, IoT, Cloud, CoreOS,
#      Kinoite, Silverblue, Onyx, Sericea, Lazurite, Vauxite, Bazzite, Aurora,
#      and all Atomic desktop variants
#    • Full desktop environment support: KDE Plasma, GNOME, Budgie, Cinnamon,
#      MATE, XFCE, LXQt, Sway, Hyprland, i3 — with per-DE privacy/screen-lock
#      settings configured from the CLI
#    • Firefox Flatpak hardening with arkenfox + 3 security extensions (uBlock, LocalCDN, Containers)
#    • VPN detection (WireGuard, NetworkManager, Mullvad, ProtonVPN) with
#      recommendations when absent (Mullvad/ProtonVPN/IVPN per privacyguides.org)
#    • Firmware and CPU microcode updates via fwupd (privacyguides.org)
#    • NetworkManager MAC address randomization (privacyguides.org network privacy)
#    • IPv6 privacy extensions (RFC 4941 temporary addresses)
#    • Rootless Podman + Toolbox containerized-mindset setup (image policy, seccomp,
#      no-new-privileges, subuid/subgid, unqualified-registry block)
#    • Comprehensive error handling (EXIT/ERR traps + resource cleanup)
#    • Performance optimized: 4 caching layers, batched operations, smart waits
#    • Session-level memoization: command, package, user home, and rpm-ostree pending layer
#    • Automatic feature gating based on system capabilities
#    • Dependency self-healing for required commands/packages (best effort)
#    • Idempotent Flatpak installs: skip if latest, update if stale, soft-fail
#    • Idempotent rpm-ostree layering: skips already-requested staged packages
#    • Safe firewalld service registration: auto-creates missing custom service XML
#    • Graceful startup privilege confirmation (sudo/root context)
#    • Approval-gated remediation with selective item implementation
#    • Logs to the system journal (journalctl -t fedora-harden FH_SESSION=<id>);
#      a log file only where there is no journald
#    • After the run: services it touched that failed, with their own log lines
#    • --report: one HTML page per session; --resume: review open follow-ups later
#    • rpm-ostree-aware Fail2Ban setup (defers activation safely until reboot)
#    • Deterministic command exit-code capture (set -e safe for rpm-ostree and firewall-cmd)
#    • Comprehensive file operation error handling (chmod, chown, cp, install, sed safe)
#    • Full rollback support: per-session change journal + --rollback to undo any run
#    • Full-reset failsafe: --rollback all reverses every session from the very first run
#    • Pre-journal session support: raw file restore for runs predating the journal feature
#    • Session reports: written to ./sessions/ on every exit (success or abort)
#
#  USAGE:
#    sudo ./fedora-harden.sh [options]
#
#  OPTIONS:
#    -u, --user <name>      Target username for SSH and home-folder hardening
#    -y, --yes              Assume "yes" to all prompts (non-interactive)
#    -n, --dry-run          Print what would run; make no changes
#        --gui              Run in one window: sections, progress, live activity,
#                           questions and summary (GTK4/libadwaita, Material dark)
#        --report [file]    Write an HTML report of the last session and exit; host
#                           name, user names, home paths and addresses are replaced
#                           with placeholders unless --full is given
#        --resume           Review the last session's open follow-ups and exit
#        --score            Show what protects this machine now (read-only) and exit
#        --json             With --score: print it as JSON, for scripts and monitoring
#        --kernel-hardening Add the kernel boot hardening options (section 9; opt-in,
#                           about 1-5% slower in some workloads)
#        --wireguard-config <f> Install this WireGuard config with a kill switch (section 15)
#        --profile <list>   Use cases for section 19: everyday,gaming,creative,dev,laptop,private
#        --backup-target <dir> Second drive for home copies without Btrfs (section 20)
#        --restore <file>   Reapply a recovery file (/etc/fedora-harden/machine.conf)
#                           without questions, e.g. after a reinstall
#        --include-setup    With --report: include the recovery file's contents
#        --recovery-backup on|off  Copy the recovery file into the home backups
#                           (default on; the choice is remembered)
#        --skip <list>      Comma-separated sections to skip (e.g. 7,8,17)
#        --only <list>      Comma-separated sections to run exclusively
#        --list             List all section numbers & names and exit
#        --list-sessions    List all past hardening sessions with their status
#        --rollback [id|all] Roll back changes from the last session (or session <id>)
#                           Use 'all' to perform a full-reset rollback of every session
#                           from the very first run (failsafe complete reversal).
#                           Sessions without a journal have backed-up files restored;
#                           use --list-sessions first to view available session IDs.
#    -V, --version          Show the version and exit
#    -h, --help             Show this help and exit
#
#  SECTIONS (run in numeric order; the numbers follow the dependency flow):
#     1  System updates (dnf upgrade + fwupd firmware/microcode install
#        + optional hardware security key support: YubiKey/FIDO2/PIV/pam-u2f)
#     2  Automatic security updates (dnf5-plugin-automatic or rpm-ostreed)
#     3  Secure Boot verification (GRUB password is manual — printed as a note)
#     4  Flatpak / Flathub + global Flatpak filesystem restrictions + mat2
#        (Firejail opt-in only)
#     5  SELinux verification + tools
#     6  firewalld hardening (drop-default policy)
#     7  SSH hardening (key-based auth, hardened cipher suite)
#     8  Password & PAM policy (pwquality length, faillock)
#     9  Kernel sysctl hardening (network, VM, filesystem, IPv6 privacy extensions)
#    10  auditd rules (identity, privilege escalation, module tracking,
#        time/network-config/mount syscalls, deletes under /etc)
#    11  DNS over TLS (systemd-resolved with Quad9), LLMNR/mDNS off, NTS time
#   11b  NetworkManager MAC address randomization (network-layer privacy)
#    12  Fail2Ban (intrusion detection + auto-ban)
#    13  Desktop environment settings — auto-dispatches by detected DE:
#            KDE Plasma (kwriteconfig6/5: screen lock, recent-docs, BT)
#            GNOME/Onyx (gsettings: lock, location, privacy; mic if asked)
#            Budgie     (gsettings GNOME backend)
#            Cinnamon   (org.cinnamon.desktop.screensaver + GNOME privacy)
#            MATE       (org.mate.screensaver + power-manager)
#            XFCE/Vauxite (xfconf-query: screensaver, power manager)
#            Sway/Sericea (swaylock.conf + swayidle.conf)
#            Hyprland   (hypridle.conf)
#            i3         (xss-lock + i3lock drop-in via config.d/)
#            LXQt/Lazurite (lxqt-screensaver.conf + lxqt-powermanagement.conf)
#    14  Firefox Flatpak + arkenfox + extensions (uBlock Origin, LocalCDN,
#        Multi-Account Containers) + VPN detection + recommendations
#    15  WireGuard tunnel from a provider config (--wireguard-config), with a kill
#        switch and DNS through the tunnel; does nothing without a config
#    16  ClamAV + freshclam + weekly scan of /home (on-access opt-in);
#        image-based: weekly scan in a locked-down container (Podman quadlet)
#    17  OpenSCAP compliance scan (image-based: from a throwaway container)
#    18  Container security — rootless Podman + toolbox/distrobox (containerized-mindset
#        setup: image policy hardening, no-new-privileges, seccomp, subuid/subgid,
#        unqualified-registry block, optional buildah/skopeo/podman-compose; on
#        image-based systems those go in a tools box instead of the image)
#    19  Your routine: timers for cleanup, disk health, Btrfs scrub, free space, a
#        weekly check that the hardening is still in effect, a weekly summary and a
#        90-day relevance review — only what the machine's use cases need (--profile)
#    20  Home snapshots: Snapper on Bazzite, read-only Btrfs snapshots elsewhere, or
#        incremental copies without Btrfs; as often as the machine is used
#    21  Unused services: offers avahi, cups, bluetooth, modemmanager (default No)
#    22  File permission hardening (shadow files, /tmp, compiler access,
#        umask 077 for regular users, core dump limits, hostname privacy check)
#    23  USBGuard (interactive — can lock out input devices if misconfigured)
#    24  AIDE file integrity baseline (weekly check by a timer);
#        image-based: image signature status + weekly /etc change report
#
#  IMAGE-BASED SYSTEMS (Silverblue, Kinoite, Bazzite, Aurora, ...): tools are kept
#  out of the image — Flatpaks, containers and a tools box instead of layered
#  packages. Toolbox and distrobox are not a security boundary (shared home,
#  host access, no SELinux separation); they keep the host clean.
#
#  SECTIONS NOT AUTOMATED (by design):
#     —  LUKS — must be chosen during Anaconda install
#    3b  GRUB password — requires interactive grub2-mkpasswd-pbkdf2
#    13  KDE GUI-only screens (Privacy, KWallet master password, Activity tracking)
#    13  GNOME GUI-only screens (Online Accounts, Sharing, Bluetooth)
#    13  Sway compositor: add 'exec swayidle -w' to sway config (action item)
#    13  Hyprland: add 'exec-once = hypridle' to hyprland.conf (action item)
#    13  i3: add lock keybind (action item)
#    15  WireGuard: the provider config file itself (pass it with --wireguard-config)
#    18  Ongoing maintenance checklist (scheduled human task)
#
#  PLATFORM SUPPORT:
#    ✓ Fedora Workstation (mutable, dnf)
#    ✓ Fedora Server (mutable, dnf)
#    ✓ Fedora IoT (immutable, rpm-ostree)
#    ✓ Fedora Cloud (mutable images/variants)
#    ✓ Fedora CoreOS (immutable, rpm-ostree)
#    ✓ Fedora Kinoite (immutable, rpm-ostree + KDE)
#    ✓ Fedora Silverblue (immutable, rpm-ostree + GNOME)
#    ✓ Fedora Onyx (immutable, rpm-ostree + GNOME Atomic)
#    ✓ Fedora Sericea (immutable, rpm-ostree + Sway Atomic)
#    ✓ Fedora Lazurite (immutable, rpm-ostree + LXQt Atomic)
#    ✓ Fedora Vauxite (immutable, rpm-ostree + XFCE Atomic)
#    ✓ Bazzite (gaming remix, rpm-ostree + KDE or GNOME)
#    ✓ Aurora / Universal Blue (rpm-ostree + KDE)
#    ✓ Fedora XFCE Spin (mutable, dnf + XFCE)
#    ✓ Fedora LXQt Spin (mutable, dnf + LXQt)
#    ✓ Fedora Cinnamon Spin (mutable, dnf + Cinnamon)
#    ✓ Fedora MATE-Compiz Spin (mutable, dnf + MATE)
#    ✓ Fedora Budgie Spin (mutable, dnf + Budgie)
#    Auto-detection: Reads /etc/os-release metadata + /run/ostree-booted
#    Desktop detection: XDG_CURRENT_DESKTOP + installed tooling/packages
#
#  PERFORMANCE OPTIMIZATIONS:
#    • Caching layers: command availability, package status, user home dirs
#    • Batched I/O: multi-pattern sed in single pass
#    • Smart waits: firewalld readiness backoff instead of fixed sleeps
#    • Package pre-checks: avoid redundant package status queries
#    • Flatpak update-state check (flatpak resolver, no download): skip already-current apps
#    • Safe arithmetic counters: pre-increment (++ x) avoids set -e false exits
#    • Resource cleanup: EXIT trap guarantees /tmp cleanup
#    • Session run stamp reuse for report/log/backup naming
#
#  ERROR HANDLING:
#    • EXIT trap: Cleans up all temporary files on script exit
#    • ERR trap: Logs file and line number + failing command context + exit code
#    • Resource safety: Guaranteed cleanup of /tmp operations
#    • Fallback strategies: curl → wget, plus best-effort dependency install
#    • Follow-ups: kept with the session; --resume and --report show them later
#
# =============================================================================

set -Eeuo pipefail

# A closed stdout or stderr (e.g. `cmd >&-` from a wrapper) would make the first
# status line fail and abort the run; the run log still records everything.
[[ -e /dev/fd/1 ]] || exec 1>/dev/null
[[ -e /dev/fd/2 ]] || exec 2>/dev/null
# Files the script creates are readable but never writable by other users,
# whatever umask it was started with (configs in /etc must stay world-readable).
umask 022

# The program lives in core/, fedora/ and libexec/ next to this file (install it
# with git clone; see README). A symlink to this file (e.g. /usr/local/bin/harden)
# is followed to find them.
SCRIPT_DIR="$(readlink -f -- "${BASH_SOURCE[0]}")"
SCRIPT_DIR="${SCRIPT_DIR%/*}"
if [[ ! -f "$SCRIPT_DIR/core/01-globals.sh" || ! -d "$SCRIPT_DIR/fedora/sections" ]]; then
	printf '%s: core/ and fedora/ are missing next to it in %s.\n' "${0##*/}" "$SCRIPT_DIR" >&2
	printf 'Run it from a full copy of the project: git clone https://github.com/nixbys/fedora-hardening\n' >&2
	exit 1
fi

# Load order matters: files run top-level statements (globals, traps) as they load.
# core/ is the distribution-neutral framework (logging, rollback, recovery file,
# scorecard, summary, main); fedora/ is everything Fedora-specific: the platform
# file (packages, detection, section list), helpers and the sections.
# shellcheck source=core/01-globals.sh
source "$SCRIPT_DIR/core/01-globals.sh"
# shellcheck source=core/02-gui.sh
source "$SCRIPT_DIR/core/02-gui.sh"
# shellcheck source=core/03-logging.sh
source "$SCRIPT_DIR/core/03-logging.sh"
# shellcheck source=core/04-report.sh
source "$SCRIPT_DIR/core/04-report.sh"
# shellcheck source=core/05-rollback-journal.sh
source "$SCRIPT_DIR/core/05-rollback-journal.sh"
# shellcheck source=core/06-rollback-sessions.sh
source "$SCRIPT_DIR/core/06-rollback-sessions.sh"
# shellcheck source=core/07-preflight.sh
source "$SCRIPT_DIR/core/07-preflight.sh"
# shellcheck source=core/30-scorecard.sh
source "$SCRIPT_DIR/core/30-scorecard.sh"
# shellcheck source=core/34-recovery-file.sh
source "$SCRIPT_DIR/core/34-recovery-file.sh"
# shellcheck source=core/35-actionable-items.sh
source "$SCRIPT_DIR/core/35-actionable-items.sh"
# shellcheck source=core/36-summary.sh
source "$SCRIPT_DIR/core/36-summary.sh"
# shellcheck source=core/38-main.sh
source "$SCRIPT_DIR/core/38-main.sh"

# Fedora: platform file and section helpers
# shellcheck source=fedora/lib/00-platform.sh
source "$SCRIPT_DIR/fedora/lib/00-platform.sh"
# shellcheck source=fedora/lib/31-kernel-boot.sh
source "$SCRIPT_DIR/fedora/lib/31-kernel-boot.sh"
# shellcheck source=fedora/lib/32-service-sandboxing.sh
source "$SCRIPT_DIR/fedora/lib/32-service-sandboxing.sh"
# shellcheck source=fedora/lib/33-personal-setup.sh
source "$SCRIPT_DIR/fedora/lib/33-personal-setup.sh"
# shellcheck source=fedora/lib/37-safety-point.sh
source "$SCRIPT_DIR/fedora/lib/37-safety-point.sh"

# Fedora sections, in run order
# shellcheck source=fedora/sections/01-updates.sh
source "$SCRIPT_DIR/fedora/sections/01-updates.sh"
# shellcheck source=fedora/sections/02-dnf-automatic.sh
source "$SCRIPT_DIR/fedora/sections/02-dnf-automatic.sh"
# shellcheck source=fedora/sections/03-secureboot.sh
source "$SCRIPT_DIR/fedora/sections/03-secureboot.sh"
# shellcheck source=fedora/sections/04-flatpak.sh
source "$SCRIPT_DIR/fedora/sections/04-flatpak.sh"
# shellcheck source=fedora/sections/05-selinux.sh
source "$SCRIPT_DIR/fedora/sections/05-selinux.sh"
# shellcheck source=fedora/sections/06-firewalld.sh
source "$SCRIPT_DIR/fedora/sections/06-firewalld.sh"
# shellcheck source=fedora/sections/07-ssh.sh
source "$SCRIPT_DIR/fedora/sections/07-ssh.sh"
# shellcheck source=fedora/sections/08-pam.sh
source "$SCRIPT_DIR/fedora/sections/08-pam.sh"
# shellcheck source=fedora/sections/09-sysctl.sh
source "$SCRIPT_DIR/fedora/sections/09-sysctl.sh"
# shellcheck source=fedora/sections/10-auditd.sh
source "$SCRIPT_DIR/fedora/sections/10-auditd.sh"
# shellcheck source=fedora/sections/11-dot.sh
source "$SCRIPT_DIR/fedora/sections/11-dot.sh"
# shellcheck source=fedora/sections/12-fail2ban.sh
source "$SCRIPT_DIR/fedora/sections/12-fail2ban.sh"
# shellcheck source=fedora/sections/13-desktop.sh
source "$SCRIPT_DIR/fedora/sections/13-desktop.sh"
# shellcheck source=fedora/sections/14-browsers.sh
source "$SCRIPT_DIR/fedora/sections/14-browsers.sh"
# shellcheck source=fedora/sections/15-wireguard.sh
source "$SCRIPT_DIR/fedora/sections/15-wireguard.sh"
# shellcheck source=fedora/sections/16-clamav.sh
source "$SCRIPT_DIR/fedora/sections/16-clamav.sh"
# shellcheck source=fedora/sections/17-openscap.sh
source "$SCRIPT_DIR/fedora/sections/17-openscap.sh"
# shellcheck source=fedora/sections/18-containers.sh
source "$SCRIPT_DIR/fedora/sections/18-containers.sh"
# shellcheck source=fedora/sections/19-routine.sh
source "$SCRIPT_DIR/fedora/sections/19-routine.sh"
# shellcheck source=fedora/sections/20-snapshots.sh
source "$SCRIPT_DIR/fedora/sections/20-snapshots.sh"
# shellcheck source=fedora/sections/21-services.sh
source "$SCRIPT_DIR/fedora/sections/21-services.sh"
# shellcheck source=fedora/sections/22-perms.sh
source "$SCRIPT_DIR/fedora/sections/22-perms.sh"
# shellcheck source=fedora/sections/23-usbguard.sh
source "$SCRIPT_DIR/fedora/sections/23-usbguard.sh"
# shellcheck source=fedora/sections/24-ids.sh
source "$SCRIPT_DIR/fedora/sections/24-ids.sh"

main "$@"
