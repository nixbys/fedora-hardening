# fedora-hardening

A Bash script that hardens Fedora Workstation and the Fedora Atomic desktops
(Silverblue, Kinoite, Bazzite, Bluefin and the rest) in one run, following
[Privacy Guides](https://www.privacyguides.org) and
[IntelTechniques](https://inteltechniques.com).

It works out the release, the package manager (`dnf` or `rpm-ostree`) and the
desktop, then applies 24 sections in dependency order. Every change is journaled, so
`--rollback` can undo a run, and a second run changes nothing. It runs as root and
touches SSH, PAM, the kernel and the firewall: read the `--dry-run` output first.

## Sections at a Glance

| # | Section | Notes |
|---|---------|-------|
| [1](sections/01-updates.sh) | System updates | `dnf upgrade` + fwupd firmware/microcode + optional HW security key |
| [2](sections/02-dnf-automatic.sh) | Automatic updates | `dnf5-plugin-automatic` (security-only) or `rpm-ostreed` |
| [3](sections/03-secureboot.sh) | Secure Boot | Verification (GRUB password is manual — printed as an action item) |
| [4](sections/04-flatpak.sh) | Flatpak / Flathub | Blocks Flatpak apps from the host filesystem; mat2 (image-based: Metadata Cleaner Flatpak); Firejail opt-in only |
| [5](sections/05-selinux.sh) | SELinux | Enforcing; a disabled system goes permissive + full relabel first (safe path) |
| [6](sections/06-firewalld.sh) | firewalld | Drop-default zone policy (OpenSnitch suggested for outbound control) |
| [7](sections/07-ssh.sh) | SSH hardening | Key-based auth, hardened ciphers via `sshd_config.d/10-hardening.conf` (takes precedence over Fedora's defaults); never restarts sshd on an invalid config |
| [8](sections/08-pam.sh) | Password & PAM | pwquality: at least 15 characters, no composition rules or forced expiry (NIST SP 800-63B); faillock (5 tries, 15 min) |
| [9](sections/09-sysctl.sh) | Kernel sysctl | Network, VM, filesystem, IPv6 privacy extensions (RFC 4941) |
| [10](sections/10-auditd.sh) | auditd | Identity, privilege escalation, module, time/network/mount syscalls, deletes under /etc |
| [11](sections/11-dot.sh) | DNS over TLS | systemd-resolved with Quad9 only (installed if missing; warns if DNS bypasses it); LLMNR off, mDNS only for gaming/creative; NTS time (11c) |
| [11b](sections/11-dot.sh) | MAC randomization | Random MAC for Wi-Fi, stable per-network MAC for Ethernet (home DHCP reservations keep working) |
| [12](sections/12-fail2ban.sh) | Fail2Ban | Intrusion detection + auto-ban |
| [13](sections/13-desktop.sh) | Desktop settings | Screen lock, recent docs, Bluetooth, location — per DE, verified after applying; microphone off only if you choose |
| [14](sections/14-browsers.sh) | Browsers | Firefox Flatpak + pinned arkenfox + extensions; Brave/Chromium/Chrome privacy policies when installed; VPN detection; Tor Browser + Mullvad Browser (opt-in, locked down) |
| [15](sections/15-wireguard.sh) | WireGuard | With `--wireguard-config FILE`: the tunnel, a kill switch and DNS through the tunnel; nothing otherwise |
| [16](sections/16-clamav.sh) | ClamAV | freshclam + a weekly idle-priority scan of /home (on-access scanning if you choose it); image-based: weekly scan in a locked-down container |
| [17](sections/17-openscap.sh) | OpenSCAP | Compliance scan (image-based: from a throwaway container, nothing layered) |
| [18](sections/18-containers.sh) | Container security | Rootless Podman, image policy, seccomp, registry hardening; toolbox or distrobox for tools |
| [19](sections/19-routine.sh) | Your routine | Timers for the upkeep this machine's use cases need, a weekly drift check and summary, desktop notifications |
| [20](sections/20-snapshots.sh) | Home snapshots | Btrfs snapshots (Snapper on Bazzite) or incremental copies of home, as often as the machine is used |
| [21](sections/21-services.sh) | Service cleanup | Offers to disable avahi, cups, bluetooth, ModemManager (default No); unencrypted telnet/rsh/rlogin sockets off |
| [22](sections/22-perms.sh) | File permissions | shadow, /tmp, compilers, umask 077 for regular users, core dumps, hostname privacy, unencrypted-swap check |
| [23](sections/23-usbguard.sh) | USBGuard | Opt-in (never turned on by `--yes`) — plug in devices before this section runs |
| [24](sections/24-ids.sh) | File integrity | AIDE baseline (recorded in the background) + weekly check by a timer; image-based: image signature status + weekly report of `/etc` changes |

**Sections not automated by design:** LUKS (Anaconda install-time), GRUB password (interactive key derivation), WireGuard tunnel config (requires peer keys).

## Requirements

- **Fedora 44+** (or a compatible Atomic/Universal Blue variant) — tested on the latest Fedora (45) and kept compatible with 44 (see [TESTING.md](TESTING.md))
- `bash` 5.x
- `sudo` / root access
- Internet connection (for package installs and firmware updates)
- For `--gui`: a graphical session. GTK4, libadwaita and their Python bindings ship
  with Fedora Workstation and the Atomic desktops; `--gui` installs them elsewhere

## Quick Start

```bash
git clone https://github.com/nixbys/fedora-hardening.git
cd fedora-hardening
sudo ./fedora-harden.sh --dry-run           # preview what would change (no modifications made)
sudo ./fedora-harden.sh                     # run all sections interactively
sudo ./fedora-harden.sh --user yourusername # target a specific user for SSH/home-dir hardening
sudo ./fedora-harden.sh --only 6,7,9        # run only specific sections
sudo ./fedora-harden.sh --skip 16,23        # skip sections you don't want
```

Run it from the clone: `fedora-harden.sh` loads its parts from the folders next to it
(a symlink to it, e.g. in `/usr/local/bin`, works too).

| Folder | What's in it |
|---|---|
| `sections/` | One file per section, numbered in run order (the numbers in the table above link to them) |
| `lib/` | Shared code: options, logging, rollback, the GUI bridge, the scorecard, the summary |
| `libexec/` | The `--gui` window and the routine helper, installed by the script |
| `tests/` | The test suite and `verify-host.sh` |

> **Non-interactive runs (`--yes`)** accept every recommendation, with one safety
> exception: SSH hardening is skipped (and reported as a HIGH follow-up item) when
> the target user has no public key in `~/.ssh/authorized_keys`, because disabling
> password logins would lock you out.

## All Options

```
sudo ./fedora-harden.sh [options]

  -u, --user <name>       Target username for SSH and home-folder hardening
  -y, --yes               Assume "yes" to all prompts (non-interactive)
  -n, --dry-run           Print what would run; make no changes
      --gui               Run in one window: sections, progress, live activity,
                          questions and summary (GTK4/libadwaita)
      --report [file]     Write an HTML report of the last session and exit
                          (host, user names, home paths and addresses replaced
                          with placeholders; add --full to keep them)
      --resume            Review the last session's open follow-ups and exit
      --score             Show what protects this machine now (read-only) and exit
      --kernel-hardening  Add the kernel boot hardening options (section 9; opt-in)
      --wireguard-config <file>  Install this WireGuard config with a kill switch (section 15)
      --profile <list>    Use cases for section 19: everyday,gaming,creative,dev,laptop,private
      --backup-target <dir>  Second drive for home copies on systems without Btrfs (section 20)
      --restore <file>    Reapply a recovery file (/etc/fedora-harden/machine.conf) without questions
      --include-setup     With --report: include the recovery file's contents
      --recovery-backup on|off  Copy the recovery file into the home backups (default on, remembered)
      --skip <list>       Comma-separated sections to skip  (e.g. 7,8,17)
      --only <list>       Comma-separated sections to run exclusively
      --list              List all section numbers & names and exit
      --list-sessions     List all past hardening sessions with their status
      --rollback [id|all] Roll back changes from the last session (or session <id>)
                          Use 'all' for a full-reset rollback of every session
  -h, --help              Show this help and exit
```

The GUI, image-based systems, the routine, personal setup, the recovery file, home
snapshots, WireGuard, hardware keys and container security are described in
[docs/guide.md](docs/guide.md).

## Privacy

The script hardens privacy and security. It does not make you anonymous: a VPN or DNS
provider still sees your traffic, and browser fingerprinting and account logins still
identify you. For anonymity, use Tor Browser, Tails or Whonix.

**What it stores, and who can read it.** Everything stays on this machine.

| What | Where | Readable by |
|---|---|---|
| Backups of changed files and the change journal | `/root/harden-backups-<timestamp>/` | root |
| Session and rollback reports | `/var/lib/fedora-harden/sessions/` | root |
| Your use cases and snapshot settings | `/etc/fedora-harden/` | root |
| Routine state and checksums | `/var/lib/fedora-harden/` | root |
| Log | the journal (`journalctl -t fedora-harden`) | root and members of `wheel`, `adm`, `systemd-journal` |
| Reports you ask for (`--report`) and section reports | your `Downloads/fedora-hardening/` | you |

The `--report` page is meant to be shared, so the host name, user names, home paths
and IP/MAC addresses in it are replaced with placeholders; `--report --full` keeps
them for your own use. Log messages never contain keys or passwords.

**What it contacts.** Only what the work needs: Fedora's package repositories,
Flathub, addons.mozilla.org (Firefox extensions), GitHub for one pinned,
checksum-verified file (arkenfox), the ClamAV signature servers, and the container
registries of the images it uses. There is no telemetry. After a run the system
itself contacts less: DNS goes only to Quad9 over TLS, the host name is no longer
announced on the local network (LLMNR off; mDNS off unless you game or create),
Fedora's countme, ABRT crash reports and fwupd report uploads stay off, and
NetworkManager's connectivity check can be turned off (it is asked).

## Rollback

Every file the script modifies is backed up before the change, and every file it creates is journaled, so a rollback restores modified files **and removes created ones** (drop-ins, rules, timers). A session journal is written to `/root/harden-backups-<timestamp>/`.

Before changing anything, a run also sets a **safety point**: on image-based systems the booted deployment is pinned (it stays in the boot menu whatever updates follow); on traditional Fedora with Btrfs a read-only snapshot of `/` is kept in `/var/lib/fedora-harden/root-snapshots/` (the three newest). Rollback keeps that snapshot; it is the way back if something outside the script's own changes goes wrong.

```bash
sudo ./fedora-harden.sh --rollback          # undo the most recent run
sudo ./fedora-harden.sh --list-sessions     # list past sessions
sudo ./fedora-harden.sh --rollback 20260601-143022   # undo one of them
sudo ./fedora-harden.sh --rollback all      # reverse every session, back to before the first run
```

## After Running

Check that the hardening is really in effect. This only reads state and changes nothing:

```bash
sudo ./tests/verify-host.sh            # every check, with PASS / FAIL / SKIP
sudo ./tests/verify-host.sh --only SSH # one area: AUTO SEL FW SSH PAM SYS AUD DNS CLAM INT DESK FLAT PERM ROLL
```

The script prints a prioritized list of **follow-ups** at the end (HIGH / MEDIUM / LOW), each with the command to run. If a service it enabled or restarted failed, the follow-up quotes that service's own log lines. Everything the run did is in the system journal:

```bash
journalctl -t fedora-harden                         # every run
journalctl -t fedora-harden FH_SESSION=20261110-213440 -p warning   # one run, problems only
sudo ./fedora-harden.sh --resume                    # the last run's open follow-ups, fixes offered again
sudo ./fedora-harden.sh --report                    # one HTML page: changes, follow-ups, warnings, live checks
sudo ./fedora-harden.sh --score                     # what protects this machine now, and how to fix the rest
```

## More

- [docs/guide.md](docs/guide.md): the features in detail, with screenshots
- [DEVELOPMENT.md](DEVELOPMENT.md): layout, conventions, CI; [TESTING.md](TESTING.md): the test tiers
- [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md): reporting issues, trust assumptions
- [CHANGELOG.md](CHANGELOG.md): what changed and why
- Sources: every recommendation cites its source in the code (`# Source:`); the list,
  with review dates, is [docs/references.json](docs/references.json), checked weekly
  in CI

## License

Provided as-is for personal use, without warranty. Read the sections you plan to run
(`sections/NN-*.sh`, or `--dry-run`) before using it on a machine you cannot easily
reinstall.
