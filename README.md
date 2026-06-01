# fedora-hardening

> **A comprehensive, idempotent security hardening script for Fedora and all Atomic Desktop variants.**  
> Aligned with [privacyguides.org](https://www.privacyguides.org) and [inteltechniques.com](https://inteltechniques.com) recommendations.

---

## Overview

`fedora-harden.sh` is a single-file Bash script that applies 23 hardening sections to a Fedora system in one pass. It auto-detects your release variant (Workstation, Silverblue, Kinoite, Bazzite, etc.), package manager (`dnf` vs. `rpm-ostree`), and desktop environment, then applies the appropriate hardening steps automatically.

Every change is journaled for full rollback support. The script is safe to run multiple times — all operations are idempotent.

---

## Features

- **23 hardening sections** covering the full security surface of a Fedora desktop or server
- **Dual package-manager support** — mutable (`dnf`) and immutable (`rpm-ostree`) systems handled transparently
- **Full Atomic Desktop support** — Silverblue, Kinoite, Onyx, Sericea, Lazurite, Vauxite, Bazzite, Aurora, CoreOS, and more
- **Per-desktop-environment hardening** — KDE Plasma, GNOME, Budgie, Cinnamon, MATE, XFCE, LXQt, Sway, Hyprland, i3
- **Firefox Flatpak hardening** — arkenfox user.js + uBlock Origin, LocalCDN, Multi-Account Containers
- **Containerized-mindset setup** — rootless Podman + Toolbox with image policy hardening, no-new-privileges, seccomp, and unqualified-registry blocking
- **Hardware security key support** — YubiKey/FIDO2/PIV/pam-u2f packages + USBGuard integration
- **VPN detection** — WireGuard, Mullvad, ProtonVPN, IVPN detection with recommendations when absent
- **Full rollback** — per-session change journal; `--rollback` or `--rollback all` to undo any or every run
- **Audit export** — PDF/TXT audit report for deferred remediation via `--import-audit`
- **Dry-run mode** — preview all changes without touching the system
- **GUI frontend** — optional kdialog/zenity prompts and progress window via `--gui` / `--gui-full`
- **4-layer caching** — memoized command checks, package status, user home dirs, and rpm-ostree pending layers

---

## Sections at a Glance

| # | Section | Notes |
|---|---------|-------|
| 2 | System updates | `dnf upgrade` + fwupd firmware/microcode + optional HW security key |
| 3 | Automatic updates | `dnf5-automatic` or `rpm-ostreed` |
| 4 | SELinux | Verification + tools |
| 5 | firewalld | Drop-default zone policy |
| 6 | Secure Boot | Verification (GRUB password is manual — printed as an action item) |
| 7 | SSH hardening | Key-based auth, hardened cipher suite |
| 8 | USBGuard | Interactive — plug in devices before this section runs |
| 9 | Password & PAM | pwquality, faillock, account aging |
| 10 | Kernel sysctl | Network, VM, filesystem, IPv6 privacy extensions (RFC 4941) |
| 11 | auditd | Identity, privilege escalation, module, time/network/mount/delete syscalls |
| 12 | rkhunter + AIDE | Rootkit detection + file integrity monitoring |
| 13 | Flatpak / Flathub | App sandboxing + optional Firejail |
| 14 | DNS over TLS | systemd-resolved with Quad9 + Cloudflare |
| 14b | MAC randomization | NetworkManager network-layer privacy |
| 15 | Desktop settings | Screen lock, recent docs, Bluetooth, location, mic — per DE |
| 16 | Firefox | Flatpak + arkenfox + extensions + VPN detection |
| 17 | WireGuard | Tool install (tunnel config is manual) |
| 18 | Fail2Ban | Intrusion detection + auto-ban |
| 19 | Service cleanup | Disable avahi, cups, bluetooth, modemmanager |
| 20 | File permissions | shadow, /tmp, compilers, umask 077, core dumps, hostname privacy |
| 21 | ClamAV | Install + freshclam + on-access scanning for /home |
| 22 | OpenSCAP | Scanner install + initial compliance scan |
| 23 | Container security | Rootless Podman + Toolbox, image policy, seccomp, registry hardening |

**Sections not automated by design:** LUKS (Anaconda install-time), GRUB password (interactive key derivation), WireGuard tunnel config (requires peer keys).

---

## Requirements

- **Fedora 44+** (or a compatible Atomic/Universal Blue variant)
- `bash` 5.x
- `sudo` / root access
- Internet connection (for package installs and firmware updates)

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/nixbys/fedora-hardening.git
cd fedora-hardening

# Preview what would change (no modifications made)
sudo ./fedora-harden.sh --dry-run

# Run all sections interactively
sudo ./fedora-harden.sh

# Target a specific user for SSH/home-dir hardening
sudo ./fedora-harden.sh --user yourusername

# Run only specific sections
sudo ./fedora-harden.sh --only 5,7,10

# Skip sections you don't want
sudo ./fedora-harden.sh --skip 8,21
```

---

## All Options

```
sudo ./fedora-harden.sh [options]

  -u, --user <name>       Target username for SSH/chage/home-dir hardening
  -y, --yes               Assume "yes" to all prompts (non-interactive)
  -n, --dry-run           Print what would run; make no changes
      --gui               Enable graphical prompts (kdialog/zenity) when available
      --gui-full          Full windowed frontend: GUI progress + GUI status output
      --import-audit <p>  Import a generated audit PDF/TXT and choose items later
      --skip <list>       Comma-separated sections to skip  (e.g. 7,8,17)
      --only <list>       Comma-separated sections to run exclusively
      --list              List all section numbers & names and exit
      --list-sessions     List all past hardening sessions with their status
      --rollback [id|all] Roll back changes from the last session (or session <id>)
                          Use 'all' for a full-reset rollback of every session
  -h, --help              Show this help and exit
```

---

## Platform Support

| Variant | Package Manager | Desktop |
|---------|----------------|---------|
| Fedora Workstation | `dnf` | GNOME |
| Fedora Server | `dnf` | — |
| Fedora Spins (XFCE, LXQt, Cinnamon, MATE, Budgie) | `dnf` | various |
| Fedora Silverblue | `rpm-ostree` | GNOME |
| Fedora Kinoite | `rpm-ostree` | KDE Plasma |
| Fedora Onyx | `rpm-ostree` | GNOME Atomic |
| Fedora Sericea | `rpm-ostree` | Sway Atomic |
| Fedora Lazurite | `rpm-ostree` | LXQt Atomic |
| Fedora Vauxite | `rpm-ostree` | XFCE Atomic |
| Fedora IoT / Cloud / CoreOS | `rpm-ostree` | headless |
| Bazzite | `rpm-ostree` | KDE or GNOME |
| Aurora / Universal Blue | `rpm-ostree` | KDE |

Auto-detection reads `/etc/os-release` + `/run/ostree-booted`. Desktop detection uses `$XDG_CURRENT_DESKTOP` + installed tooling.

---

## Rollback

Every file the script modifies is backed up before the change. A session journal is written to `/root/harden-backups-<timestamp>/`.

```bash
# Undo the most recent run
sudo ./fedora-harden.sh --rollback

# Undo a specific past session
sudo ./fedora-harden.sh --list-sessions
sudo ./fedora-harden.sh --rollback 20260601-143022

# Full-reset: reverse every session from the very first run
sudo ./fedora-harden.sh --rollback all
```

---

## Hardware Security Keys

During **Section 2**, the script will ask if you use a hardware security key (YubiKey, FIDO2, PIV, etc.). If yes, it installs `pcsc-lite`, `opensc`, `libfido2`, `yubico-piv-tool`, and `yubikey-manager`, and optionally sets up `pam-u2f`.

> ⚠️ **Important:** If you use a hardware key, plug it in **before Section 8 (USBGuard) runs** so it is automatically added to the allowlist. If you miss it, run:
> ```bash
> sudo usbguard generate-policy >> /etc/usbguard/rules.conf
> ```

---

## Container Security (Section 23)

Section 23 sets up a **containerized-mindset** environment using rootless Podman and Toolbox:

- Configures `~/.config/containers/containers.conf` with `no-new-privileges`, hardened seccomp, and minimal capabilities
- Writes `/etc/containers/policy.json` to require image signature verification (confirm-gated)
- Blocks unqualified image searches via `/etc/containers/registries.conf.d/99-hardening.conf`
- Configures `subuid`/`subgid` for rootless container operation
- Optionally installs `buildah`, `skopeo`, and `podman-compose`

---

## After Running

The script generates a session report in `./sessions/` and prints a prioritized **actionable items** list at the end (HIGH / MEDIUM / LOW). Items that require manual steps (GRUB password, WireGuard tunnel config, etc.) are called out explicitly with instructions.

You can export the audit to PDF/TXT for later review:
```bash
# Items declined during the run are exported automatically.
# Re-import them later:
sudo ./fedora-harden.sh --import-audit ./sessions/audit-20260601-143022.txt
```

---

## CI

| Check | Tool | Status |
|-------|------|--------|
| Shell syntax | `bash -n` | [![CI](https://github.com/nixbys/fedora-hardening/actions/workflows/actions.yml/badge.svg)](https://github.com/nixbys/fedora-hardening/actions/workflows/actions.yml) |
| Static analysis | ShellCheck 0.11.0 (`--enable=all`) | ↑ same |
| Formatting | shfmt v3.6.0 | ↑ same |

---

## References

- [privacyguides.org — Linux hardening](https://www.privacyguides.org/en/os/linux-overview/)
- [inteltechniques.com — Linux privacy](https://inteltechniques.com/blog/2022/04/15/the-linux-privacy-guide/)
- [Fedora Security Guide](https://docs.fedoraproject.org/en-US/fedora/latest/system-administrators-guide/security/)
- [CIS Fedora Benchmark](https://www.cisecurity.org/benchmark/red_hat_linux)
- [arkenfox user.js](https://github.com/arkenfox/user.js)

---

## License

This project is provided as-is for personal use. Review every section before running on a production system. No warranty is expressed or implied.
