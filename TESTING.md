# Testing fedora-harden.sh

## Platform policy

`fedora-harden.sh` supports **Fedora 44 and 45**. Tests run on the latest release
only (45, the default of `--fedora`); the script stays compatible with the previous
release, so code must not rely on commands or options that exist only in the newest
one. `--fedora 44` is still available when a change needs checking there. Every test
runs on the release it tests:

| What | Runs on |
|------|---------|
| Static tier (lint, formatting, MCP smoke test) | `registry.fedoraproject.org/fedora:45` — the `lint` image from `Dockerfile.test`, or natively when the host is Fedora 45 |
| Quick tier | `registry.fedoraproject.org/fedora-minimal:45` (`test-only` image, no systemd) |
| Full tier | `registry.fedoraproject.org/fedora-minimal:45` with systemd as PID 1 (`base` image) |
| GUI tier | `registry.fedoraproject.org/fedora:45` + Xvfb, GTK4/libadwaita for Python (`gui` image) |
| VM tier | the real image-based systems: `quay.io/fedora/fedora-silverblue:45` and a Universal Blue desktop (`ghcr.io/ublue-os/bazzite:stable`), installed with bootc and booted |
| VM tier | the same images installed on a virtual disk with `bootc install to-disk` and booted with KVM |
| CI (`.github/workflows/ci.yml`) | static jobs run in a `fedora:45` container; container tests run on a Fedora CoreOS 45 VM (`tests/fedora-host.sh`); repository scans use `fedora:44` as a tool host |
| Developer tooling (`setup-dev.sh`, pre-commit) | Fedora RPMs (`ShellCheck yamllint ruff hadolint gitleaks pre-commit python3-mcp`); shfmt is an RPM on 44 and built at the same pinned version with Fedora's Go on 45 (`tests/install-shfmt.sh`) |

On an rpm-ostree host (Silverblue, Kinoite, Bazzite, …) do development inside a
Fedora 44 toolbox:

```bash
toolbox create --image registry.fedoraproject.org/fedora-toolbox:44 fh-dev
toolbox enter fh-dev
./setup-dev.sh
```

All tests that change system state run in throwaway **rootless** podman containers;
the host is never modified.

## Test suite

```bash
./tests/run-suite.sh                    # "all": static, quick, full, gui
./tests/run-suite.sh --tier vm          # installed + booted images (needs /dev/kvm)
./tests/run-suite.sh --tier fault       # fault injection (about an hour)
./tests/run-suite.sh --tier vm --image quay.io/fedora/fedora-kinoite:45   # other images
./tests/run-suite.sh --tier static      # one tier (repeatable)
./tests/run-suite.sh --artifacts ./out  # keep logs somewhere specific
./tests/run-suite.sh --no-build         # reuse already-built images
./tests/run-suite.sh --fedora 45        # run on Fedora 45 images
```

Results are written to `<artifacts>/results.txt`, with one log per check.

### static

`bash -n`, ShellCheck (warning level and the strict `.shellcheckrc`
profile), `shfmt -d` (style from `.editorconfig`), `yamllint --strict`, `hadolint`,
`ruff`, an MCP server smoke test over stdio, and a regression guard against
`((x++))`-style increments that abort under `set -e` when `x` is 0.

### quick (no systemd)

- CLI contract: `--help`/`--list` exit 0; unknown options and missing option values exit 2
- an unencrypted swap file whose mount the script cannot see is reported, not fatal
- two back-to-back runs get separate sessions (a shared session truncated the first
  run's rollback journal)
- non-root invocation is refused
- `--only 6,9` runs exactly those sections
- running from a read-only directory (no writable `sessions/`) still exits 0
- section 13 end-to-end (`tests/desktop-settings.sh`): GNOME (gsettings/dconf) and XFCE
  (xfconf) settings are read back as the user to prove they persisted
- a full `--dry-run --yes` exits 0 with no `[FAIL]` lines
- **dry-run changes nothing**: `podman diff` of the container may only show package
  metadata caches and the script's own logs

### full (systemd)

1. `--dry-run` under systemd leaves `/etc` byte-for-byte unchanged
2. a **real run** (`--yes --user testuser`) exits 0 with no `[FAIL]` lines
3. hardening is actually applied: sysctl drop-in, firewalld default zone `drop`,
   pwquality (`minlen=14`, `minclass=3`), faillock, `login.defs` ageing, audit rules,
   umask profile, core-dump limits, clamd running, systemd-resolved with DNS-over-TLS,
   valid `sshd -t` **and** the effective sshd config (`sshd -T`: X11 forwarding off,
   password auth off, hardened ciphers), `/etc/shadow` mode 000
4. a second real run is **idempotent** (no file under `/etc` changes)
5. `--list-sessions` lists both sessions
6. `--rollback all` exits 0, removes the drop-ins the script created and restores
   `pwquality.conf`

The full tier's container gets 3 GB of memory (`FULL_MEMORY` to override) because it
does a real run, and ClamAV loads its signature database into memory.

The systemd container gets `--cap-add NET_ADMIN,NET_RAW` so firewalld can manage
nftables. Under rootless podman this applies only to the container's own network
namespace.

The full tier also checks that the run logs to the journal under its session (and
writes no log file), that `--report` writes a page with the changes, follow-ups and
live checks, and that `--resume` brings back the last session's follow-ups. `--score`
reads the live system (the firewall is reported on) and creates no session, and the
report includes the scorecard. A running Avahi gets the section 21 sandbox drop-in
and keeps running; `--rollback all` removes the drop-in and Avahi still runs.

Section 19 runs with `--profile everyday,dev`: the profile is saved, the timers are
enabled, the helper's drift check is clean after the run and catches a changed managed
file, and the weekly summary is written. The static tier extracts the helper embedded
in the script and lints it with ShellCheck.

Section 20 runs in the full tier without Btrfs (the rsync path): the first copy
holds the home folder, nothing is copied when nothing changed, a changed file gives a
new copy with a change note, unchanged files are hard links, the index and the
off-machine options exist, and rollback keeps the copies. The vm tier covers Btrfs on
installed systems: home is made its own subvolume (owner and SELinux label kept),
read-only snapshots with change notes (Silverblue), Snapper snapshots (Bazzite), and
an approved folder becoming its own subvolume with its contents intact.

Section 15 is tested against a real WireGuard peer (`tests/wireguard-test.sh`, two
containers on a private network): invalid and split-tunnel configs are refused; the
handshake happens and traffic flows through the tunnel; DNS is routed through it;
with the tunnel stopped the peer is unreachable outside the tunnel while the endpoint
stays allowed; `--rollback` removes the tunnel and the kill switch and direct traffic
works again.

### gui

Runs `tests/gui-test.sh` on a virtual X display, as root with no UTF-8 locale (as
under `sudo -i`/`pkexec`):

- `--gui --dry-run --yes` exits 0 and never hangs; the one window shows every
  planned section finished (done or skipped), a filled activity log and the summary
- the window stays open after the script exits and is the only window; a sampled
  pixel proves the Material-dark theme was applied (`#1D1B20` sidebar); Ctrl+W
  closes it
- without `--yes`, questions appear in the window and are answered from the
  keyboard: a typed answer (use cases for section 19) reaches the script, and
  Return picks the default of a Yes/No question
- Stop (Ctrl+W, then Stop in the confirmation) ends a real run with exit 130, the
  cancellation is logged and the window shows the run stopped
- a window that disappears mid-run stops the run (exit 130)

The window reports what it shows to `$FH_GUI_STATE` (a test-only hook) when it asks
something and when the run ends. Screenshots (`gui-summary.png`, `gui-question.png`,
`gui-progress.png`, `gui-stop-confirm.png`) are saved in `<artifacts>/gui/`.

### vm (installed and booted)

`tests/atomic-vm.sh` boots Fedora CoreOS's published QEMU image (checksum-verified,
cached in `~/.cache/fedora-harden-vm`), installs the image under test onto an empty
virtual disk with `bootc install to-disk` (Btrfs, as Fedora's installer uses), boots
that disk and runs the script over SSH. The only change to the image is enabling
sshd. It is the one test of the image-based systems:

- the run requests no tool as a layered package (`rpm-ostree status --json`)
  (none of ClamAV, AIDE, OpenSCAP, setools, buildah, skopeo,
  podman-compose, mat2, the YubiKey CLI tools or toolbox)
- Yubico Authenticator and Metadata Cleaner are installed from Flathub instead
- OpenSCAP runs from a throwaway container and the summary counts real results
- the image-signature finding: the locally installed image is an unverified
  reference, and the script reports it
- the `/etc` baseline from `ostree admin config-diff`; the weekly check is clean
  after the run, fails after a new file appears in `/etc`, and logs it
- the ClamAV scan through the quadlet: read-only, offline, capabilities dropped,
  finds the EICAR test file planted in a `0600` file and does not report a clean one
- Universal Blue: the distrobox manifest is accepted and uupd stays the only
  updater (the rpm-ostreed policy is unchanged); elsewhere the toolbox commands
  are offered
- `verify-host.sh` passes, and `--rollback all` removes the units and Flatpaks

QEMU runs in a Fedora container, so the host only needs Podman and access to
`/dev/kvm`. One image takes about 10–15 minutes.

### fault (fault injection)

`tests/fault-matrix.sh` breaks one thing at a time around a run and checks that the
run ends cleanly (it finishes, or refuses with a clear message), that no raw bash
error appears, that nothing hangs, and that `--rollback all` returns `/etc` to its
original state:

| Group | Faults |
|-------|--------|
| args | non-root, unknown option, invalid `--only`/`--skip`, missing `--user` account, user without a home, rollback of an unknown or missing session |
| env | `C`/`POSIX`/Turkish/German locales, no `TERM`/`LANG`/`HOME`, minimal `PATH`, closed stdout, paths with spaces, symlinks, `bash`/`sh` invocation, `umask 000` |
| net | no network, a DNS server that never answers |
| pkg | a repository that drops packets, the RPM database lock held, sshd/firewalld/auditd uninstalled |
| fs | read-only `/etc/ssh/sshd_config.d`, `/etc/sysctl.d`, `/etc/security`; full log, backup and `/tmp` filesystems; CRLF files, duplicate keys, no final newline, a symlinked config |
| interrupt | SIGINT, SIGTERM and SIGKILL mid-run (then a new run and a rollback), two runs at once, a second full run changing nothing, rollback after two runs |

Rollback restores every file the script changed. What it cannot undo is documented
state: system users and groups that packages created, the rebuilt SELinux policy and
udev hardware database, `audit.rules` (regenerated by auditd from the restored
`rules.d`), and protected packages such as `systemd-udev` that a minimal system pulled
in as dependencies, which dnf never removes.

## Ad-hoc runs with test-in-podman.sh

```bash
./test-in-podman.sh --quick --dry-run          # no systemd, fastest
./test-in-podman.sh --dry-run --only 6,7,9    # systemd, selected sections
./test-in-podman.sh                            # REAL run inside the container
./test-in-podman.sh --quick -it                # interactive shell
./test-in-podman.sh --keep --artifacts ./out   # keep container + logs for inspection
```

Without `--dry-run` the script makes real changes, but only inside the throwaway
container. Artifacts are kept after the run (the path is printed): `output.log`,
`logs/harden-*.log` (no journald in the quick container), `sessions/`, `fs-diff.txt` and, for the
systemd variant, `journal.log` and `failed-units.txt`.

| Option | Default |
|--------|---------|
| `--memory` | 1g (systemd), 256m (`--quick`) — enough for dry runs; use `--memory 3g` for real runs (ClamAV loads its signatures into memory) |
| `--cpus` | 2 (systemd), 1 (`--quick`) |
| PID limit | 2048 |

## Container images

`Dockerfile.test` has three stages:

| Target | Base | Purpose |
|--------|------|---------|
| `base` | `fedora-minimal:44` + systemd and the services the script manages | full tier |
| `test-only` | `fedora-minimal:44`, no systemd | quick tier |
| `lint` | `fedora:44` + the lint toolchain RPMs | static tier |
| `gui` | `fedora:45` + Xvfb, python3-gobject, gtk4, libadwaita, xdotool, ImageMagick | gui tier |

```bash
podman build -f Dockerfile.test --target base      -t localhost/fedora-harden:test .
podman build -f Dockerfile.test --target test-only -t localhost/fedora-harden:test-only .
podman build -f Dockerfile.test --target lint      -t localhost/fedora-harden:lint .
```

## CI

`.github/workflows/ci.yml` runs on push, pull request, nightly and on demand. The
static, scan and container jobs run inside a `registry.fedoraproject.org/fedora`
container of the release under test (45). The atomic-images jobs run on the
runner itself, so they can free disk space and use KVM; the runner only starts
containers and VMs, and every check runs on the Fedora Atomic image under test:

| Job | What it does |
|-----|--------------|
| static | static tier with Fedora 45 RPM tools |
| secrets | `gitleaks git` over the full history (Fedora `gitleaks` RPM) |
| vulnerabilities | `trivy fs` (Fedora `trivy` RPM), SARIF uploaded to code scanning |
| container-tests | quick, full, gui and the six fault groups (one job each), on a Fedora CoreOS VM booted with KVM: Fedora kernel, SELinux enforcing, real nftables |
| atomic-images | atomic and vm tiers for Silverblue 45 and Bazzite |

### Running tiers on a Fedora host

GitHub's runners are Ubuntu: a container there shares Ubuntu's kernel and AppArmor,
so SELinux cannot enforce and the host's policy blocks `wg-quick` from running
`nft`. `tests/fedora-host.sh` boots Fedora CoreOS for the release under test (the
first of the stable, testing and next streams that runs it; checksum-verified,
cached) with KVM, copies the repository in and runs `run-suite.sh` there:

```bash
tests/fedora-host.sh <artifacts-dir> --tier full          # any run-suite.sh arguments
FAULT_GROUPS="net pkg" tests/fedora-host.sh out --tier fault
```

On a Fedora host the WireGuard tunnel checks run instead of being skipped.

## Troubleshooting

- **`podman: command not found`** — `sudo dnf install podman` (or use the toolbox above).
- **Static tier says the lint image failed to build** — see `<artifacts>/build-lint.log`.
- **A full-tier check failed** — the container is removed afterwards, but every log
  is in the artifacts directory: `full_real1.log`, `full_journal.log` (the container's journal,
  including the run's own entries), `full_failed_units.txt`, and `etc.*` checksum snapshots.
- **SELinux denials on bind mounts** — mounts use the shared `:z` label. Avoid
  mounting the repository with `:Z` (private label) from other containers while
  tests run: it relabels the files and locks running test containers out.
