# Quickstart: Testing fedora-harden.sh

All tests run on Fedora 44 images in rootless podman containers — the host is never
modified. See [TESTING.md](TESTING.md) for details.

## One-time setup (Fedora 44)

```bash
./setup-dev.sh          # installs podman + lint toolchain RPMs, git hooks
```

On Silverblue/Kinoite/Bazzite, run it inside a Fedora 44 toolbox:

```bash
toolbox create --image registry.fedoraproject.org/fedora-toolbox:44 fh-dev
toolbox enter fh-dev
```

## Run the tests

```bash
./tests/run-suite.sh                   # everything (static, quick, full)
./tests/run-suite.sh --tier static     # lint only (Fedora 44 lint image)
./tests/run-suite.sh --tier quick      # CLI + dry-run, no systemd
```

## Ad-hoc runs

```bash
./test-in-podman.sh --quick --dry-run         # fastest, no systemd (256 MB)
./test-in-podman.sh --dry-run --only 5,10     # systemd container, selected sections
./test-in-podman.sh                           # REAL run inside the throwaway container
./test-in-podman.sh --quick -it               # interactive shell
```

| Flag | Effect |
|------|--------|
| `--quick` | no-systemd image (fastest) |
| `--dry-run` | pass `--dry-run` to the script |
| `--only` / `--skip` | select sections |
| `--memory` / `--cpus` | resource limits (default 1g/2, quick 256m/1) |
| `--artifacts DIR` | where logs go (kept after the run) |
| `--keep` | keep the container for inspection |
| `-it` | interactive shell |

## Results

The artifact directory printed at the end contains `output.log`,
`logs/harden-*.log`, `logs/*-errors.log`, `sessions/` and `fs-diff.txt`
(files changed inside the container).
