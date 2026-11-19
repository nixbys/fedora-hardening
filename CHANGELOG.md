# Changelog

## Unreleased — core and Fedora parts

- The code is split into `core/` (logging, rollback, recovery file, scorecard,
  summary, `main`) and `fedora/` (package handling, detection, the section list,
  section helpers and `fedora/sections/`). Behaviour is unchanged.
- `core/` reaches dnf, rpm-ostree, grubby, SELinux and firewalld only through
  `fedora/lib/00-platform.sh`; the static tier checks that, and that the platform
  file provides everything `core/` expects. DEVELOPMENT.md describes how another
  distribution family would be added (its own entry script and folder); only Fedora
  is supported.

## 1.0.0 — 2026-11-19

The first versioned release. It collects all changes made before releases began, newest first.

### Kernel and sudo

- Section 9 asks to limit io_uring, a frequently exploited kernel interface, to
  root (`kernel.io_uring_disabled = 1`); off by default for the dev use case.
- Section 8 adds a sudo drop-in with `Defaults use_pty`, validated with visudo
  before it is installed.
- The scorecard shows whether kernel lockdown is on (Fedora enables it under
  Secure Boot).

### Releases

- Versioned releases: pushing a tag `vX.Y.Z` publishes a tarball, its SHA-256
  checksum and a signed build attestation (`.github/workflows/release.yml`). The
  tag must match `FH_VERSION`, and the changelog section becomes the notes.
- `--version` (`-V`) prints the release.

### Browsers

- Section 14 is now "Browsers". Besides Firefox and the VPN check, it applies a
  managed privacy policy to Brave, Chromium and Chrome when they are installed
  (native or Flatpak): telemetry, Privacy Sandbox, autofill and Brave's Rewards,
  Wallet, VPN, AI chat and Tor windows off; third-party cookies blocked, HTTPS only,
  Global Privacy Control, de-AMP, debouncing and query-parameter stripping on. DNS
  stays with the system's DNS over TLS. Asked once; undone by --rollback.
- Brave's Flatpak gets /etc read-only when section 4 blocks host-etc, since that is
  how it loads the policy.
- Tor Browser and Mullvad Browser are offered in section 14 (opt-in) as well as
  through the `private` use case. Mullvad Browser loses access to cameras, smart
  cards, the keyring and NetworkManager; both are left otherwise as shipped.

### Rawhide early warning

- A weekly workflow (`.github/workflows/rawhide.yml`) runs the quick and full tiers
  against Fedora Rawhide, the next release, on the usual Fedora CoreOS test host.
  It never blocks a pull request; a failure opens or updates one tracking issue.
- `tests/run-suite.sh --fedora rawhide` tests against Rawhide locally too.

### Privacy and review fixes

Project layout:
- `fedora-harden.sh` is now a short entry point that loads `lib/NN-*.sh` (shared code)
  and `sections/NN-*.sh` (one file per section) in a fixed order. The `--gui` window
  and the routine helper are files in `libexec/` instead of heredocs; they are
  installed to the same places as before. Run the script from a clone (it says so
  when its parts are missing); a symlink to it works.
- Error reports name the file as well as the line (`Aborted at line 42 of
  sections/05-selinux.sh`).

Privacy:
- Session and rollback reports moved out of the script's folder to
  `/var/lib/fedora-harden/sessions` (root-only). `/etc/fedora-harden/profile` and
  `/etc/fedora-harden/snapshots` are root-only (600).
- `--report` replaces the host name, user names, home paths and IP/MAC addresses with
  placeholders, since the page is meant to be shared; `--report --full` keeps them.
- DNS over TLS goes to Quad9 only (Cloudflare removed), `DNSSEC=allow-downgrade` so
  captive portals and odd networks still resolve; LLMNR off; mDNS off unless the
  routine's use cases include gaming or creative work.
- README: a Privacy section (what is stored, where, who can read it, what is
  contacted; privacy and security, not anonymity).

Review fixes (nothing here makes the system worse any more):
- Passwords: at least 15 characters, no composition rules, no forced expiry (NIST SP
  800-63B). `login.defs` and account ageing are left as Fedora ships them.
- sysctl: `kernel.pid_max = 65536` and `kernel.core_pattern = |/bin/false` removed
  (they broke heavy workloads and crash reports for no security gain).
  `ptrace_scope` stays at Fedora's default for the dev use case.
- auditd logs deletes and renames under `/etc` only, not every file everywhere.
- GNOME/Budgie: the microphone is turned off only when you choose it.
- Service trim (21): printing, discovery, Bluetooth, modems and network storage are
  only disabled when you say so (default No, also under `--yes`); unencrypted
  telnet/rsh/rlogin sockets are still switched off.
- `umask 077` applies to regular users only; root keeps the default so services can
  read what root creates.
- SSH (7) is skipped when no SSH server is installed instead of installing one;
  Fail2Ban (12) only runs when sshd is enabled.
- rkhunter is dropped (false alarms after updates; AIDE covers file integrity).
  AIDE's weekly check is a systemd timer instead of a cron job (image-based Fedora
  has no cron) and the baseline is recorded in the background at the end of the run.
- USBGuard (23) and ClamAV on-access scanning (16) are opt-in: never turned on by
  `--yes`. Without on-access scanning, a weekly idle-priority scan of `/home` runs.
- MAC randomization: random for Wi-Fi, stable per network for Ethernet.
- Subordinate IDs for rootless Podman are added with `usermod` only, and backed up.

New:
- A safety point before the run: the booted deployment is pinned on image-based
  systems; a read-only snapshot of `/` is taken on traditional Fedora with Btrfs.
- Time sync prefers NTS (authenticated) servers (11c).
- Unused kernel modules (dccp, sctp, rds, tipc, cramfs, freevxfs, jffs2, hfs) are
  blocked unless loaded right now (9b).
- Firmware security (fwupd Host Security ID) is reported, with what only the owner
  can fix in the firmware setup.
- fwupd report uploads and ABRT automatic crash reporting stay off;
  NetworkManager's connectivity check can be turned off (asked; default keep).
- The weekly summary says when a reboot is waiting for installed updates.

### Scorecard and deep hardening

- **Protection scorecard:** at the end of a run, on the `--gui` summary page, in
  `--report`, and with the new read-only `--score`, the script checks the live
  system (disk encryption, Secure Boot, firewall, automatic updates, SELinux, SSH,
  DNS over TLS, home snapshots, screen lock, Flatpak restrictions, firmware HSI
  level, admin rights as advice) and says how to fix what is not protected.
- **Kernel boot hardening (opt-in, section 9):** `init_on_free=1`, `slab_nomerge`,
  `page_alloc.shuffle=1`, `randomize_kstack_offset=on` via grubby or `rpm-ostree
  kargs`; asked for, or `--kernel-hardening`; not offered for gaming (1–5% cost);
  `--rollback` removes exactly what was added.
- **Service sandboxing (section 21):** running CUPS and Avahi get a conservative
  systemd sandbox drop-in, kept only if the service restarts cleanly; exposure
  before and after is reported. sshd is left alone (its sandbox would apply to
  every login session). `--rollback` removes the drop-ins and restarts the service.

### Personal setup

- **Section 19 also sets up what your use cases need, once each:** a `dev` box with
  build tools and the `davincibox` container for DaVinci Resolve (created for you,
  nothing layered), a `private` use case with Tor Browser and Mullvad Browser,
  Flathub limited to verified apps, your security key as a second factor for sudo
  and login, unlocking an encrypted disk with the TPM plus a PIN or a FIDO2 key (the
  passphrase keeps working), and a pointer to OpenSnitch. Each is a question; with
  `--yes` only what a chosen use case implies happens. `--rollback` undoes all of it.
- **Recovery file:** `/etc/fedora-harden/machine.conf` (root-only, no secrets) records
  what the machine was set up with, including every answer, and is copied into the
  home backups (`--recovery-backup off` to stop). `--restore FILE` reapplies it
  without questions. `--report` names it without its contents; `--include-setup`
  adds them.
- The use-case profile (`/etc/fedora-harden/profile`) is now readable by root only.

### Sections numbered in the order they run

- **Sections are renumbered 1–24 in execution order.** The order was already chosen
  for dependencies; now the numbers match it, in `--list`, the README and the code.
  **`--only` and `--skip` numbers change.** Old → new:

  | Old | New | Section | | Old | New | Section |
  |---|---|---|---|---|---|---|
  | 2 | 1 | System updates | | 17 | 15 | WireGuard |
  | 3 | 2 | Automatic updates | | 21 | 16 | ClamAV |
  | 6 | 3 | Secure Boot (6b → 3b GRUB note) | | 22 | 17 | OpenSCAP |
  | 13 | 4 | Flatpak / Flathub | | 23 | 18 | Container security |
  | 4 | 5 | SELinux | | 24 | 19 | Your routine |
  | 5 | 6 | firewalld | | 25 | 20 | Home snapshots |
  | 7 | 7 | SSH | | 19 | 21 | Service trim |
  | 9 | 8 | Passwords and PAM | | 20 | 22 | File permissions |
  | 10 | 9 | Kernel sysctl | | 8 | 23 | USBGuard |
  | 11 | 10 | auditd | | 12 | 24 | rkhunter + AIDE |
  | 14 | 11 | DNS over TLS (14b → 11b MAC randomization) | | | | |
  | 18 | 12 | Fail2Ban | | | | |
  | 15 | 13 | Desktop settings | | | | |
  | 16 | 14 | Firefox (16b → 14b VPN check) | | | | |

- **The file-integrity baseline (AIDE) now runs last.** Before, it was recorded
  before the service trim, the file permissions and USBGuard (which installs a
  package), so the first check reported changes the run itself had made.
- Follow-up items and session reports from earlier runs keep their old numbers.

### One GUI mode

- **`--gui` runs the whole session in one window.** The script no longer opens a
  progress window, separate question dialogs and a separate summary. One GTK4/libadwaita
  window shows:
  - the planned sections with their status: running, done, warnings, errors, or
    skipped when a section does not apply;
  - a progress bar with elapsed time and an estimate of the time left;
  - a live activity log with every message, command and command output. It can be
    filtered (done, warnings, errors, commands), searched, and copied;
  - questions answered inside the window. Yes/No and text entry work from the
    keyboard;
  - notices to read (USBGuard, GRUB password, VPN), which stay until dismissed;
  - a summary page with the follow-up items grouped by priority, each with a copy
    button.

  The window stays open after the run so you can read the results. Closing it during
  a run, or pressing **Stop**, asks first, then stops after the current step
  (exit 130). If the window disappears, the run stops instead of going on unseen.
  Narrow windows fold the section list away (F9 toggles it).
- GTK4, libadwaita and their Python bindings ship with Fedora Workstation and every
  Atomic desktop (Silverblue, Kinoite, Bazzite, Bluefin), so nothing is layered for
  the GUI. On other package-based systems `--gui` installs them.
- zenity and kdialog are no longer used. `--gui-full` is removed: use `--gui`.

### Home snapshots (section 20)

- **New section 20:** snapshots of the home folder on every supported system:
  Snapper on Bazzite, read-only Btrfs snapshots on other Btrfs systems (home is made
  its own subvolume at boot where needed), and hard-link incremental copies with
  `rsync` without Btrfs — to a second drive when one is configured.
- Frequency follows how actively the machine is used; nothing is taken when nothing
  changed; 24 recent, 7 daily and 4 weekly are kept; 15% of the disk always stays free.
- A home index notes growth and flags large replaceable folders, which are left out
  only with approval; each snapshot keeps a note of what changed.
- Off-machine backup options are ranked for the machine as follow-ups.
- Rollback never deletes snapshots or copies.

### Your routine (section 19)

- **New section 19:** detects how the machine is used (everyday, gaming, creative,
  development, laptop), asks once or takes `--profile`, and adds only the timers those
  use cases need: monthly cleanup, daily free-space check, monthly Btrfs scrub, weekly
  drift check of the hardening, weekly summary, box upgrades, build-cache cleanup and
  an optional Flatpak permission watch; plus a journal size cap, `smartd`, an optional
  battery charge limit and a layer audit on image-based systems.
- **Notifications and summary:** a desktop notification only when something needs the
  person; a weekly summary of what was done and what is still open.
- **Relevance review:** every 90 days the summary compares the saved use cases with
  what the machine shows now and points out automations that had no effect.
- Heavy jobs wait for mains power and for a game to end. Everything is undone by
  `--rollback`.

### Journal logging, honest diagnosis, WireGuard kill switch

- **Logs in the system journal:** every message goes to the journal with the session
  and section as fields (`journalctl -t fedora-harden FH_SESSION=<id>`); a log file is
  written only where there is no journald. The separate error log is gone.
- **Diagnosis instead of "auto-remediation":** the old loop re-read its own error log
  and could not fix anything. After the sections, the script now checks the services
  it enabled or restarted and reports each failed one with its own journal lines.
- **`--report` and `--resume` replace the PDF export and `--import-audit`:** one
  self-contained HTML page per session (changes, open follow-ups, warnings, and live
  checks when `tests/verify-host.sh` is present), and the open follow-ups of the last
  session, with the fixes offered again. No `enscript`/`ps2pdf` dependency.
- **Section 15 rebuilt:** with `--wireguard-config FILE` it installs the tunnel, a
  firewalld kill switch (nothing leaves outside the tunnel, also while it is down)
  and DNS routing through the tunnel; refuses incomplete and split-tunnel configs;
  all of it is undone by `--rollback`. Without a config it does nothing (it used to
  install `wireguard-tools` and print a guide).

### Production hardening from fault injection

A new `fault` test tier breaks the script's surroundings one fault at a time. Every
failure it found is fixed and covered by the tier.

- **Safer changes:** a file that is read-only, immutable or cannot be backed up is
  left unchanged and its section stops with a follow-up item (the rest of the run
  continues). A run that cannot write its backup folder stops before changing
  anything.
- **Rollback restores /etc:** the countme setting, the countme timer mask, firewalld's
  configuration and zones, and the audit rules are now backed up and restored;
  everything a package install added (including dependencies) is recorded and
  removed in one transaction; restored settings are reloaded (sysctl, audit,
  firewalld, sshd, systemd). `--rollback` no longer picks the rollback run itself as
  the session to undo, and an unknown session exits cleanly.
- **No hangs:** repositories are checked once with a time limit, and package work is
  skipped with one follow-up item when they do not answer (a repository that drops
  packets stalled a run for over half an hour). Downloads, firmware and Flatpak
  refreshes have time limits.
- **One run at a time:** a second run while one is in progress is refused.
- **Clear input errors:** invalid `--only`/`--skip` lists and a `--user` that does
  not exist are refused (exit 2) instead of running nothing or everything.
- **Robust output:** a closed stdout, a write error to the log, or a permissive
  `umask` no longer break the run or leave world-writable files; `printf` format
  strings starting with `---` no longer print bash errors in every run.
- **Fixed:** with `set -E`, the error handler also ran in subshells and could clean
  up (lock, temporary files, session report) in the middle of a run.
- **Fixed:** duplicate keys in a config file collapse to one; section 10 says
  plainly when the audit tools are missing; section 16 no longer tries to scan
  without ClamAV; section 18 merges into an existing image policy instead of
  replacing it, keeping signature rules such as Universal Blue's.

### Image-based systems keep tools out of the image

On Silverblue, Kinoite, Bazzite, Aurora and other Atomic variants the script no
longer layers tools into the image; package-based Fedora behaves as before.

- **Flatpaks instead of layers:** Yubico Authenticator replaces `yubikey-manager`
  and `yubico-piv-tool` (only the smart-card drivers and `pam-u2f` stay on the host);
  Metadata Cleaner replaces `mat2`.
- **ClamAV in a container:** a weekly Podman quadlet scans `/home` read-only, with no
  network, a read-only root and one capability (reading files). The signatures ship
  in the official image, refreshed before each scan. If ClamAV is already layered,
  a follow-up item explains how to remove it.
- **OpenSCAP from a throwaway container** that scans the host read-only with
  `oscap-chroot`.
- **File integrity:** instead of AIDE and rkhunter (the image already guarantees
  `/usr`), section 24 checks that the booted image is signature-verified and adds a
  weekly report of `/etc` changes since the end of the hardening run.
- **Tools box:** `buildah`, `skopeo`, `podman-compose`, `setools` and OpenSCAP go in a
  `fedora-harden-tools` box; with distrobox (Universal Blue) the script writes a
  manifest usable with `distrobox assemble` and `ujust distrobox-assemble`. Toolbox
  is no longer layered on Universal Blue.
- **Docs:** section 18 and the README say plainly that toolbox and distrobox are not
  a security boundary. The README no longer claims the image policy requires
  signature verification (it rejects unknown registries).
- **Fixed:** the OpenSCAP summary always reported 0 passed / 0 failed and never
  listed failing rules (it looked for an attribute oscap does not write), so the
  failed-rules follow-up item never appeared.
- **Fixed:** two runs started in the same second shared a session, and the second
  truncated the first one's rollback journal.
- **Fixed:** a failed write to the run log could abort the run (rpm-ostree output).
  Section 24 recognises images verified through an OSTree remote (Fedora CoreOS).
- **Tested on the real images:** new `atomic` tier (real Silverblue and Universal Blue
  desktop images booted with systemd: real rpm-ostree, Flathub installs, quadlets, a
  real ClamAV scan of a test file) and `vm` tier (the images installed with
  `bootc install to-disk` and booted with KVM: image signature, `/etc` baseline and
  weekly report on a real OSTree sysroot). They replace a simulation with stub
  commands. Both run in CI for Fedora 44 and 45.

### Current guidance (Privacy Guides, IntelTechniques)

Reviewed against Privacy Guides (Linux Overview updated October 2026, Desktop,
Linux Application Sandboxing) and IntelTechniques (Extreme Privacy 5th ed., 2026
OS Telemetry Guide):

- **Firejail is no longer installed by `--yes`.** Privacy Guides cautions that it is
  a large setuid binary with a large attack surface; it stays available as opt-in.
- **Flatpak apps are blocked from the host filesystem** (`host`, `host-os`,
  `host-etc`) with a global override; home-directory access can be blocked too
  (opt-in). Apps use file portals. `--rollback` restores the previous overrides.
- **Firefox:** arkenfox is pinned to a release (144.0) and checksum-verified instead
  of following its `master` branch; your previous `user.js` is backed up. Adds
  Global Privacy Control, Do Not Track and DNS-over-HTTPS (Quad9, with fallback) so
  Encrypted Client Hello can work.
- **New checks:** unencrypted disk swap (prefer ZRAM) and X11 sessions (prefer
  Wayland) are reported with follow-up items. `mat2` is offered for removing file
  metadata. OpenSnitch is suggested for outbound connection control.
- **Universal Blue (Bazzite, Bluefin, Aurora):** section 2 no longer enables
  rpm-ostreed's automatic updates next to `uupd`, which already updates the image,
  Flatpaks and distroboxes; it confirms `uupd.timer` is on and points to `ujust update`.
- **Fixed:** the countme opt-out never ran on rpm-ostree systems (section 2 returned
  before reaching it).
- **Housekeeping:** `TOOLCHAIN.md` merged into an up-to-date `DEVELOPMENT.md`; the
  unused Trunk configuration removed (its `.shellcheckrc` now lives at the repository
  root, where shellcheck finds it); dead reference links replaced.
- **Automation:** `docs/references.json` + `tests/check-references.py` + a weekly
  **Reference watch** workflow open an issue when a source changes or arkenfox
  releases a new version. The static tests also verify the pinned arkenfox checksum.

### Fedora 45

- Tested on **Fedora 45** alongside 44: every test tier runs on both releases in CI.
  The hardening needed no changes for 45; the effective SSH, password and firewall
  settings match 44.
- `tests/verify-host.sh`: a read-only check you run on a hardened machine. Each
  result has an ID matching the Hardening Field Check page.
- Fixed: packages the script knows by a provided name (`clamav-update`, `wget`,
  `dnf-automatic`, `clamav-scanner-systemd`) were re-installed on every run.
- Tooling: shfmt is no longer packaged in Fedora 45, so the same pinned version is
  built with Fedora's Go; OpenSSH 10.5 prints `sshd -T` keywords in mixed case and
  the tests now allow for it. Dependabot no longer tries to track the Fedora
  images, which it cannot query.

### Fedora 44 test suite, hardening fixes, Material-dark GUI

#### If you ran an earlier version: re-run these sections

Earlier versions reported some hardening as applied when it was not. Re-run them
after updating (preview first with `--dry-run`):

```bash
sudo ./fedora-harden.sh --only 2,7,8,13,16
```

| Section | What was wrong | Now |
|---|---|---|
| 7 SSH | The drop-in was `99-hardening.conf`, but sshd keeps the first value it reads and Fedora's `40-redhat-crypto-policies.conf`/`50-redhat.conf` load first: the cipher/MAC/KEX lists and `X11Forwarding no` were ignored. | `10-hardening.conf` (the old file is migrated). Verified with `sshd -T`. |
| 9 Password & PAM | Patterns were basic regex, where `#?` and `\s+` are literal, so pwquality, faillock and `login.defs` were never changed. | Values are set reliably (replace, uncomment, or append). |
| 3 Automatic updates | Looked for a `dnf5-automatic` package that does not exist and an empty config file, then skipped the section. | Installs `dnf5-plugin-automatic`, configures security-only updates, enables the timer. |
| 15 Desktop settings | `gsettings`/`xfconf-query` ran without a D-Bus session and silently discarded every change. | Runs on the user's session bus and reads the values back. |
| 21 ClamAV | `clamd@scan` was started before its socket was configured and never ran; on-access scanning was configured but not started. | Socket configured first; `clamonacc` enabled. |

#### Safety

- sshd is never restarted on a configuration that `sshd -t` rejects.
- `--yes` no longer disables password logins when the target user has no public
  key; it skips SSH hardening and reports a HIGH follow-up item.
- SELinux: a disabled system is moved to permissive with a full relabel on the next
  boot instead of straight to enforcing (which can leave it unbootable). Dry runs no
  longer edit `/etc/selinux/config`.
- `--rollback` now also removes files the script created.

#### Reliability

The script used to abort — skipping every later section — on:
`((counter++))` when the counter was 0 (36 places, including rollback),
firewalld not running (now configured offline with `firewall-offline-cmd`), one
unsupported sysctl key, auditd/resolved/rkhunter/AIDE/Flatpak failures, a failed
package install, or a failed config write. All now warn and add a follow-up item.
A successful run from a read-only directory no longer exits 1.

#### GUI (`--gui`, `--gui-full`)

- Material Design 3 dark theme for all dialogs, titlebar included (zenity draws its
  own); private to the script, no desktop settings changed. zenity is preferred,
  kdialog is the fallback (themed colours, KWin titlebar).
- Fixed: `--gui-full` aborted on its first warning and at startup; the progress
  window auto-closed at 100% so successful runs ended as "cancelled" (exit 130);
  the window could be orphaned; text containing `&` vanished; `--yes` still waited
  on a text prompt; kdialog progress/cancel never worked; no dialog appeared at all
  under a non-UTF-8 root locale.
- One non-blocking end-of-run window with the summary and follow-up items
  (selectable, so commands can be copied). Dialog errors fall back to terminal
  prompts instead of answering "No".

#### Testing, CI and tooling

- `tests/run-suite.sh`: static, quick, full (real run, idempotency, rollback) and
  gui tiers, all on Fedora 44 images. The old harness pulled the wrong image and
  its "dry run" in full mode was a real run.
- CI runs every job in `fedora:44` containers with Fedora RPM tools; actions are
  SHA-pinned; workflows are audited by actionlint + zizmor; gitleaks scans the full
  history. Fixes the nightly failures (nonexistent base image, trufflehog,
  hadolint, yamllint).
- `setup-dev.sh` installs the Fedora 44 toolchain (it previously crashed on
  `--help`); pre-commit hooks use it.
- The MCP development server now starts (it could not import its SDK) and reports
  real results.
- `SECURITY.md` and `THREAT_MODEL.md` (from #12).
