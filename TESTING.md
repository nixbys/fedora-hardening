# Testing fedora-harden.sh

## Platform policy

`fedora-harden.sh` targets **Fedora 44 and 45**. Every test runs on the release it
tests (`--fedora 44` is the default, `--fedora 45` the other):

| What | Runs on |
|------|---------|
| Static tier (lint, formatting, MCP smoke test) | `registry.fedoraproject.org/fedora:44` — the `lint` image from `Dockerfile.test`, or natively when the host is Fedora 44 |
| Quick tier | `registry.fedoraproject.org/fedora-minimal:44` (`test-only` image, no systemd) |
| Full tier | `registry.fedoraproject.org/fedora-minimal:44` with systemd as PID 1 (`base` image) |
| GUI tier | `registry.fedoraproject.org/fedora:44` + Xvfb, zenity, kdialog (`gui` image) |
| Atomic tier | the real image-based systems: `quay.io/fedora/fedora-silverblue:N` and a Universal Blue desktop (`ghcr.io/ublue-os/bluefin:44`, `ghcr.io/ublue-os/bazzite:stable` for 45), booted with systemd |
| VM tier | the same images installed on a virtual disk with `bootc install to-disk` and booted with KVM |
| CI (`.github/workflows/ci.yml`) | static and container jobs run as a 44/45 matrix in a container of that release; repository scans run on `fedora:44` |
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
./tests/run-suite.sh --tier atomic      # real Fedora Atomic images (pulls ~3-4 GB each)
./tests/run-suite.sh --tier vm          # installed + booted images (needs /dev/kvm)
./tests/run-suite.sh --tier fault       # fault injection (about an hour)
./tests/run-suite.sh --tier atomic --image quay.io/fedora/fedora-kinoite:45   # other images
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
- `--only 5,10` runs exactly those sections
- running from a read-only directory (no writable `sessions/`) still exits 0
- section 15 end-to-end (`tests/desktop-settings.sh`): GNOME (gsettings/dconf) and XFCE
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

### gui

Runs `tests/gui-test.sh` on a virtual X display, as root with no UTF-8 locale (as
under `sudo -i`/`pkexec`):

- `--gui-full --dry-run --yes` exits 0 and never waits on a dialog
- the progress window is closed, not orphaned, when the script exits
- exactly one end-of-run window remains, and a sampled pixel proves the
  Material-dark theme was applied (`#2B2930` surface)
- killing the progress window (= the user pressing Cancel) stops a real run with
  exit 130, and the cancellation is logged

Screenshots (`gui-summary.png`, `gui-progress.png`) are saved in `<artifacts>/gui/`.

### atomic (real image-based systems)

`tests/atomic-real.sh` boots each image under test — real Fedora Silverblue and a
real Universal Blue desktop for the release — with systemd as PID 1 in a privileged
container, and runs sections 2, 3, 4, 12, 13, 21, 22 and 23 with nothing stubbed:

- the image's own `rpm-ostree` works in container mode, so anything the run layers
  shows up in `rpm -qa`; none of ClamAV, AIDE, rkhunter, OpenSCAP, setools, buildah,
  skopeo, podman-compose, mat2, the YubiKey CLI tools or toolbox may appear
- Yubico Authenticator and Metadata Cleaner are installed from Flathub
- the ClamAV quadlet is turned into a unit by Podman's generator, runs read-only,
  offline and with capabilities dropped, and a **real scan finds the EICAR test file**
  planted in a `0600` file under `/home`
- OpenSCAP runs from a throwaway container and the summary counts real results
- Universal Blue: the distrobox manifest is accepted by `distrobox assemble`, uupd
  stays the only updater; elsewhere the toolbox commands are offered
- `verify-host.sh` passes, and `--rollback all` removes the units and Flatpaks

Two container-only adjustments, neither of which applies to a booted system: the
container's `/var` is bind-mounted onto itself, so systemd sees the image's
`var.mount` as already mounted (otherwise it would mount the empty OSTree deployment
`/var` over the real one); boot-time tmpfiles are run as a real boot does; and
systemd-resolved is given the container's DNS servers. A booted OSTree sysroot cannot exist in a container, which is what the
vm tier is for.

### vm (installed and booted)

`tests/atomic-vm.sh` boots Fedora CoreOS's published QEMU image (checksum-verified,
cached in `~/.cache/fedora-harden-vm`), installs the image under test onto an empty
virtual disk with `bootc install to-disk` (Btrfs, as Fedora's installer uses), boots
that disk and runs the script over SSH. The only change to the image is enabling
sshd. On top of the atomic checks it covers what needs a real sysroot:

- the run requests no tool as a layered package (`rpm-ostree status --json`)
- the image-signature finding: the locally installed image is an unverified
  reference, and the script reports it
- the `/etc` baseline from `ostree admin config-diff`; the weekly check is clean
  after the run, fails after a new file appears in `/etc`, and logs it
- the ClamAV scan through the quadlet on the booted host

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
./test-in-podman.sh --dry-run --only 5,7,10    # systemd, selected sections
./test-in-podman.sh                            # REAL run inside the container
./test-in-podman.sh --quick -it                # interactive shell
./test-in-podman.sh --keep --artifacts ./out   # keep container + logs for inspection
```

Without `--dry-run` the script makes real changes, but only inside the throwaway
container. Artifacts are kept after the run (the path is printed): `output.log`,
`logs/harden-*.log`, `logs/*-errors.log`, `sessions/`, `fs-diff.txt` and, for the
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
| `gui` | `fedora:44` + Xvfb, zenity, kdialog, qdbus, xdotool, ImageMagick | gui tier |

```bash
podman build -f Dockerfile.test --target base      -t localhost/fedora-harden:test .
podman build -f Dockerfile.test --target test-only -t localhost/fedora-harden:test-only .
podman build -f Dockerfile.test --target lint      -t localhost/fedora-harden:lint .
```

## CI

`.github/workflows/ci.yml` runs on push, pull request, nightly and on demand. The
static, scan and container jobs run inside a `registry.fedoraproject.org/fedora`
container of the release under test (44 and 45). The atomic-images jobs run on the
runner itself, so they can free disk space and use KVM; the runner only starts
containers and VMs, and every check runs on the Fedora Atomic image under test:

| Job | What it does |
|-----|--------------|
| static | static tier with Fedora 44 RPM tools |
| secrets | `gitleaks git` over the full history (Fedora `gitleaks` RPM) |
| vulnerabilities | `trivy fs` (Fedora `trivy` RPM), SARIF uploaded to code scanning |
| container-tests | quick, full, gui and fault tiers; podman runs nested in a privileged Fedora job container |
| atomic-images | atomic and vm tiers for Silverblue and a Universal Blue desktop, Fedora 44 and 45 |

## Troubleshooting

- **`podman: command not found`** — `sudo dnf install podman` (or use the toolbox above).
- **Static tier says the lint image failed to build** — see `<artifacts>/build-lint.log`.
- **A full-tier check failed** — the container is removed afterwards, but every log
  is in the artifacts directory: `full_real1.log`, `full-logs/*-errors.log`,
  `full_journal.log`, `full_failed_units.txt`, and `etc.*` checksum snapshots.
- **SELinux denials on bind mounts** — mounts use the shared `:z` label. Avoid
  mounting the repository with `:Z` (private label) from other containers while
  tests run: it relabels the files and locks running test containers out.
