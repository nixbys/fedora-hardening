# Developing fedora-harden.sh

## Platform

Development, tests and CI all run on **Fedora 44 and 45**, the releases the script
targets. On a Fedora 44 machine, set up once:

```bash
git clone https://github.com/nixbys/fedora-hardening.git
cd fedora-hardening
./setup-dev.sh        # Fedora RPM toolchain + git hooks
```

On Silverblue, Kinoite, Bazzite or another rpm-ostree system, work inside a toolbox:

```bash
toolbox create --image registry.fedoraproject.org/fedora-toolbox:44 fh-dev
toolbox enter fh-dev
./setup-dev.sh
```

`setup-dev.sh` installs `ShellCheck yamllint ruff hadolint gitleaks pre-commit
python3-mcp podman` from Fedora's repositories. shfmt is an RPM on Fedora 44; on 45 it
is built at the same pinned version with Fedora's Go (`tests/install-shfmt.sh`).

## Workflow

1. Branch from `main` (`main` only accepts pull requests).
2. Edit `fedora-harden.sh`; `bash -n fedora-harden.sh` for a quick syntax check.
3. Commit. pre-commit runs shellcheck, shfmt, yamllint, ruff, hadolint, gitleaks and
   the generic file checks; the commit-msg hook enforces conventional commits
   (`fix:`, `feat:`, `docs:`, ...).
4. Test: `./tests/run-suite.sh` (all tiers) or one tier, see [TESTING.md](TESTING.md).
5. Push and open a pull request. CI runs every tier on Fedora 44 and 45.

## Conventions in fedora-harden.sh

These rules exist because breaking them caused real bugs:

- **`set -Eeuo pipefail` is on.** Never write `((x++))` (it fails when `x` is 0); use
  `((++x))`. Never end a function or a `case` branch with `[[ test ]] && cmd`: when
  the test is false, the function returns 1 and the caller aborts. Use `if`.
- **Dry run must change nothing.** Route changes through `run "..."`, or guard them
  with `if ((!DRY_RUN))`. The quick and full tiers check that a dry run leaves the
  filesystem untouched.
- **Everything must be reversible.** Call `backup_file <path>` before writing a file.
  It backs up an existing file or journals a new one, so `--rollback` restores or
  removes it.
- **Failures warn, they don't abort.** Commands that depend on the machine (services,
  network, package installs) use `run ... || warn ...` plus
  `add_action_item <section> <HIGH|MEDIUM|LOW> <TAG> "<what the user should do>"`.
- **Check the effect, not just the file.** sshd keeps the first value it reads, so
  drop-ins sort before Fedora's (`10-hardening.conf`). gsettings needs the user's
  D-Bus session (`user_session_run`). Settings are edited with `set_conf_key`, never
  with basic-regex `sed`.
- **`confirm "question"`** answers yes under `--yes`; `confirm "question" no` answers
  no, for options current guidance does not recommend enabling automatically.
- **Cite sources.** Each recommendation carries a `# Source:` comment naming the
  Privacy Guides or IntelTechniques page it comes from (listed in
  `docs/references.json`).
- **Formatting** comes from `.editorconfig` (tabs in the script, 4 spaces in helper
  scripts); run `shfmt -w`.

## Keeping up with the guidance

The weekly **Reference watch** workflow opens an issue when a source in
`docs/references.json` changes or arkenfox publishes a new release. To act on it:

1. Read the changed page and update the script where the advice changed.
2. For a new arkenfox release, update `ARKENFOX_VERSION` and `ARKENFOX_SHA256`
   (`curl -fsSL https://raw.githubusercontent.com/arkenfox/user.js/<tag>/user.js | sha256sum`).
3. Run the tests, then record the review:
   `python3 tests/check-references.py --update`, and commit `docs/references.json`.

## CI

| Workflow | Runs | What it does |
|---|---|---|
| `ci.yml` | push, PR, nightly | static tier and quick/full/gui tiers on Fedora 44 and 45; gitleaks; trivy |
| `workflow-security.yml` | push, PR | actionlint and zizmor audit of every workflow |
| `reference-watch.yml` | weekly | checks the guidance sources and the pinned arkenfox release |

Every job runs in a `registry.fedoraproject.org/fedora` container. Actions are pinned
to commit SHAs; Dependabot proposes grouped updates weekly.

## MCP server (optional)

`mcp_server_fedora_harden.py` exposes lint, test and docs checks as MCP tools for
Claude while you work on the script. It is not used by `fedora-harden.sh`.

```bash
sudo dnf install python3-mcp
claude mcp add fedora-harden-dev -- python3 "$PWD/mcp_server_fedora_harden.py"
```

Tools: `verify-script`, `lint-script`, `test-script`, `check-security`,
`validate-docs`, `analyze-performance`, `generate-changelog`, `quality-report`,
`setup-dev-environment`.

## Releasing

Changes land through pull requests with green CI. Before a large change, tag the
current `main` so users can return to it (for example `pre-fedora44-overhaul`), and
record user-visible changes in [CHANGELOG.md](CHANGELOG.md).

## Troubleshooting

- **A hook fails with "command not found"**: re-run `./setup-dev.sh`; on an rpm-ostree
  host, make sure you are inside the toolbox.
- **Container builds fail with "mounting an overlay over build context"**: you are
  running podman inside a container on Fedora 45+; the suite handles this, for manual
  builds set `TMPDIR` to a directory on a real filesystem.
- **SELinux denials on bind mounts**: use `:z`, not `:Z`, when mounting the repository
  into containers while tests run.
