# Testing fedora-harden.sh

## Platform policy

`fedora-harden.sh` targets **Fedora 44**, so every test and check runs on Fedora 44:

| What | Runs on |
|------|---------|
| Static tier (lint, formatting, MCP smoke test) | `registry.fedoraproject.org/fedora:44` — the `lint` image from `Dockerfile.test`, or natively when the host is Fedora 44 |
| Quick tier | `registry.fedoraproject.org/fedora-minimal:44` (`test-only` image, no systemd) |
| Full tier | `registry.fedoraproject.org/fedora-minimal:44` with systemd as PID 1 (`base` image) |
| CI (`.github/workflows/ci.yml`) | every job runs in a `fedora:44` job container; tools are Fedora 44 RPMs |
| Developer tooling (`setup-dev.sh`, pre-commit) | Fedora 44 RPMs (`ShellCheck shfmt yamllint ruff hadolint gitleaks pre-commit python3-mcp`) |

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
./tests/run-suite.sh                    # all tiers
./tests/run-suite.sh --tier static      # one tier (repeatable)
./tests/run-suite.sh --artifacts ./out  # keep logs somewhere specific
./tests/run-suite.sh --no-build         # reuse already-built images
```

Results are written to `<artifacts>/results.txt`, with one log per check.

### static

`bash -n`, ShellCheck (warning level and the strict `.trunk/configs/.shellcheckrc`
profile), `shfmt -d` (style from `.editorconfig`), `yamllint --strict`, `hadolint`,
`ruff`, an MCP server smoke test over stdio, and a regression guard against
`((x++))`-style increments that abort under `set -e` when `x` is 0.

### quick (no systemd)

- CLI contract: `--help`/`--list` exit 0; unknown options and missing option values exit 2
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

The systemd container gets `--cap-add NET_ADMIN,NET_RAW` so firewalld can manage
nftables. Under rootless podman this applies only to the container's own network
namespace.

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
| `--memory` | 1g (systemd), 256m (`--quick`) |
| `--cpus` | 2 (systemd), 1 (`--quick`) |
| PID limit | 2048 |

## Container images

`Dockerfile.test` has three stages:

| Target | Base | Purpose |
|--------|------|---------|
| `base` | `fedora-minimal:44` + systemd and the services the script manages | full tier |
| `test-only` | `fedora-minimal:44`, no systemd | quick tier |
| `lint` | `fedora:44` + the lint toolchain RPMs | static tier |

```bash
podman build -f Dockerfile.test --target base      -t localhost/fedora-harden:test .
podman build -f Dockerfile.test --target test-only -t localhost/fedora-harden:test-only .
podman build -f Dockerfile.test --target lint      -t localhost/fedora-harden:lint .
```

## CI

`.github/workflows/ci.yml` runs on push, pull request, nightly and on demand. Every
job runs inside a `registry.fedoraproject.org/fedora:44` container:

| Job | What it does |
|-----|--------------|
| static | static tier with Fedora 44 RPM tools |
| secrets | `gitleaks git` over the full history (Fedora `gitleaks` RPM) |
| vulnerabilities | `trivy fs` (Fedora `trivy` RPM), SARIF uploaded to code scanning |
| container-tests | quick and full tiers; podman runs nested in a privileged Fedora 44 job container |

## Troubleshooting

- **`podman: command not found`** — `sudo dnf install podman` (or use the toolbox above).
- **Static tier says the lint image failed to build** — see `<artifacts>/build-lint.log`.
- **A full-tier check failed** — the container is removed afterwards, but every log
  is in the artifacts directory: `full_real1.log`, `full-logs/*-errors.log`,
  `full_journal.log`, `full_failed_units.txt`, and `etc.*` checksum snapshots.
- **SELinux denials on bind mounts** — mounts use the shared `:z` label. Avoid
  mounting the repository with `:Z` (private label) from other containers while
  tests run: it relabels the files and locks running test containers out.
