# Changelog

## Unreleased — journal logging, honest diagnosis, WireGuard kill switch

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
- **Section 17 rebuilt:** with `--wireguard-config FILE` it installs the tunnel, a
  firewalld kill switch (nothing leaves outside the tunnel, also while it is down)
  and DNS routing through the tunnel; refuses incomplete and split-tunnel configs;
  all of it is undone by `--rollback`. Without a config it does nothing (it used to
  install `wireguard-tools` and print a guide).

## Unreleased — production hardening from fault injection

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
- **Fixed:** duplicate keys in a config file collapse to one; section 11 says
  plainly when the audit tools are missing; section 21 no longer tries to scan
  without ClamAV; section 23 merges into an existing image policy instead of
  replacing it, keeping signature rules such as Universal Blue's.

## Unreleased — image-based systems keep tools out of the image

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
  `/usr`), section 12 checks that the booted image is signature-verified and adds a
  weekly report of `/etc` changes since the end of the hardening run.
- **Tools box:** `buildah`, `skopeo`, `podman-compose`, `setools` and OpenSCAP go in a
  `fedora-harden-tools` box; with distrobox (Universal Blue) the script writes a
  manifest usable with `distrobox assemble` and `ujust distrobox-assemble`. Toolbox
  is no longer layered on Universal Blue.
- **Docs:** section 23 and the README say plainly that toolbox and distrobox are not
  a security boundary. The README no longer claims the image policy requires
  signature verification (it rejects unknown registries).
- **Fixed:** the OpenSCAP summary always reported 0 passed / 0 failed and never
  listed failing rules (it looked for an attribute oscap does not write), so the
  failed-rules follow-up item never appeared.
- **Fixed:** two runs started in the same second shared a session, and the second
  truncated the first one's rollback journal.
- **Fixed:** a failed write to the run log could abort the run (rpm-ostree output).
  Section 12 recognises images verified through an OSTree remote (Fedora CoreOS).
- **Tested on the real images:** new `atomic` tier (real Silverblue and Universal Blue
  desktop images booted with systemd: real rpm-ostree, Flathub installs, quadlets, a
  real ClamAV scan of a test file) and `vm` tier (the images installed with
  `bootc install to-disk` and booted with KVM: image signature, `/etc` baseline and
  weekly report on a real OSTree sysroot). They replace a simulation with stub
  commands. Both run in CI for Fedora 44 and 45.

## Unreleased — current guidance (Privacy Guides, IntelTechniques)

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
- **Universal Blue (Bazzite, Bluefin, Aurora):** section 3 no longer enables
  rpm-ostreed's automatic updates next to `uupd`, which already updates the image,
  Flatpaks and distroboxes; it confirms `uupd.timer` is on and points to `ujust update`.
- **Fixed:** the countme opt-out never ran on rpm-ostree systems (section 3 returned
  before reaching it).
- **Housekeeping:** `TOOLCHAIN.md` merged into an up-to-date `DEVELOPMENT.md`; the
  unused Trunk configuration removed (its `.shellcheckrc` now lives at the repository
  root, where shellcheck finds it); dead reference links replaced.
- **Automation:** `docs/references.json` + `tests/check-references.py` + a weekly
  **Reference watch** workflow open an issue when a source changes or arkenfox
  releases a new version. The static tests also verify the pinned arkenfox checksum.

## Unreleased — Fedora 45

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

## Unreleased — Fedora 44 test suite, hardening fixes, Material-dark GUI

### If you ran an earlier version: re-run these sections

Earlier versions reported some hardening as applied when it was not. Re-run them
after updating (preview first with `--dry-run`):

```bash
sudo ./fedora-harden.sh --only 3,7,9,15,21
```

| Section | What was wrong | Now |
|---|---|---|
| 7 SSH | The drop-in was `99-hardening.conf`, but sshd keeps the first value it reads and Fedora's `40-redhat-crypto-policies.conf`/`50-redhat.conf` load first: the cipher/MAC/KEX lists and `X11Forwarding no` were ignored. | `10-hardening.conf` (the old file is migrated). Verified with `sshd -T`. |
| 9 Password & PAM | Patterns were basic regex, where `#?` and `\s+` are literal, so pwquality, faillock and `login.defs` were never changed. | Values are set reliably (replace, uncomment, or append). |
| 3 Automatic updates | Looked for a `dnf5-automatic` package that does not exist and an empty config file, then skipped the section. | Installs `dnf5-plugin-automatic`, configures security-only updates, enables the timer. |
| 15 Desktop settings | `gsettings`/`xfconf-query` ran without a D-Bus session and silently discarded every change. | Runs on the user's session bus and reads the values back. |
| 21 ClamAV | `clamd@scan` was started before its socket was configured and never ran; on-access scanning was configured but not started. | Socket configured first; `clamonacc` enabled. |

### Safety

- sshd is never restarted on a configuration that `sshd -t` rejects.
- `--yes` no longer disables password logins when the target user has no public
  key; it skips SSH hardening and reports a HIGH follow-up item.
- SELinux: a disabled system is moved to permissive with a full relabel on the next
  boot instead of straight to enforcing (which can leave it unbootable). Dry runs no
  longer edit `/etc/selinux/config`.
- `--rollback` now also removes files the script created.

### Reliability

The script used to abort — skipping every later section — on:
`((counter++))` when the counter was 0 (36 places, including rollback),
firewalld not running (now configured offline with `firewall-offline-cmd`), one
unsupported sysctl key, auditd/resolved/rkhunter/AIDE/Flatpak failures, a failed
package install, or a failed config write. All now warn and add a follow-up item.
A successful run from a read-only directory no longer exits 1.

### GUI (`--gui`, `--gui-full`)

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

### Testing, CI and tooling

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
