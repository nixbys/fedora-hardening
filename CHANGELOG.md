# Changelog

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
