# Contributing

Thanks for helping. Before you start:

- **A bug:** open an issue with the bug form. It asks for the version, your Fedora
  edition and a `--report`, which hides host name, user names, home paths and
  addresses; don't paste a `--report --full`.
- **A security problem:** never in a public issue; see [SECURITY.md](SECURITY.md).
- **A new section or a changed recommendation:** open an issue with the guidance form
  first, with the source it comes from. The project is complete for its scope (README,
  "Status"), so changes follow the guidance it cites rather than new ideas.
- Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

The rest of this file is the developer guide: setup, layout, conventions, releasing.

## Platform

Development, tests and CI run on **Fedora 45**, the latest release the script targets
(it stays compatible with 44). On a Fedora 45 machine, set up once:

```bash
git clone https://github.com/nixbys/linux-hardening.git
cd linux-hardening
./setup-dev.sh        # Fedora RPM toolchain + git hooks
```

On Silverblue, Kinoite, Bazzite or another rpm-ostree system, work inside a toolbox:

```bash
toolbox create --image registry.fedoraproject.org/fedora-toolbox:44 fh-dev
toolbox enter fh-dev
./setup-dev.sh
```

`setup-dev.sh` installs `ShellCheck yamllint ruff hadolint gitleaks pre-commit
podman` from Fedora's repositories. shfmt is an RPM on Fedora 44; on 45 it
is built at the same pinned version with Fedora's Go (`tests/install-shfmt.sh`).

## Workflow

1. Branch from `main` (`main` only accepts pull requests).
2. Edit the script (see [Layout](#layout)); `bash -n <file>` for a quick syntax check,
   `shellcheck -x -a fedora-harden.sh` to check it with all its parts.
3. Commit. pre-commit runs shellcheck, shfmt, yamllint, ruff, hadolint, gitleaks and
   the generic file checks; the commit-msg hook enforces conventional commits
   (`fix:`, `feat:`, `docs:`, ...).
4. Test: `./tests/run-suite.sh` (all tiers) or one tier, see [TESTING.md](TESTING.md).
5. Push and open a pull request. CI runs every tier on Fedora 45.

## Layout

`fedora-harden.sh` holds the usage text (`--help` prints its header comment) and
loads the rest with one `source` line per file, in this order:

- `core/NN-*.sh`: the framework, shared by any distribution family: globals, the
  GUI bridge, logging, rollback, preflight and option parsing, the scorecard, the
  recovery file, follow-ups, the summary and `main`.
- `fedora/lib/00-platform.sh`: what core needs from Fedora (see below).
- `fedora/lib/NN-*.sh`: helpers shared by Fedora sections (kernel boot options,
  service sandboxing, personal setup, the safety point).
- `fedora/sections/NN-*.sh`: one file per section, with the helpers only that
  section uses.

The order matters: files run their top-level statements (globals, traps) as they
load. A new file needs its own `source` line (with a `# shellcheck source=` directive)
in `fedora-harden.sh`; the static tier fails when a file in `core/` or `fedora/` is
not loaded. Bash's own error messages and the ERR trap name the file and line
(`fedora/sections/05-selinux.sh line 42`).

`libexec/` holds programs the script installs rather than runs inline: the `--gui`
window (`fedora-harden-gui.py`) and the routine helper (`fedora-harden-routine`). Short
config files stay as heredocs next to the code that writes them.

## Core and distribution families

`core/` never calls a distribution's own tools (package managers, boot loaders,
SELinux, the firewall); the static tier fails if it does. It reaches them through
the family's platform file, `fedora/lib/00-platform.sh`, whose header lists the
contract: the section list and run order, detection, the package backend, the
safety point, the scorecard rows for the firewall, updates and SELinux, and the
`--rollback` steps for entries only that family writes (packages, kernel options,
ostree pins).

Only Fedora is supported. Another family (the RHEL rebuilds, Debian) would get its
own entry script and folder, reusing `core/`:

1. Add `<family>/lib/00-platform.sh` providing every function and variable in the
   contract (the static tier checks Fedora's; add the same check for the new one),
   and `<family>/sections/`.
2. Add `<family>-harden.sh`, loading `core/` and `<family>/` like `fedora-harden.sh`.
3. Give it its own test tier on real images of that family in CI. Until that tier
   passes, it is not supported, and the README does not say otherwise.

Don't add distribution checks (`if debian; then ...`) to `core/` or to Fedora's
sections: a family that needs different behaviour gets it in its own files.

## Framework mappings

`fedora/mappings/NN-name.yaml` maps a section to NIST CSF 2.0 subcategories, NIST
SP 800-53 Rev. 5 controls and MITRE ATT&CK Enterprise techniques and mitigations; the
edition is part of each key, so a new edition means new keys, not silently stale
ones. The files are references only: they never feed the script. When a section's
behaviour changes, update its mapping and `reviewed` date, then regenerate the table:
`python3 tests/check-mappings.py --write` (the static tier fails if `docs/MAPPING.md`
is stale or an ID is malformed). Use only ATT&CK mitigations ATT&CK itself links to
the listed techniques. A benchmark entry needs item numbers from the benchmark itself,
and CIS Red Hat Enterprise Linux is always marked `authoritative: false` for Fedora.

## Conventions in the script

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
- **Formatting** comes from `.editorconfig` (tabs in the script and its `core/` and
  `fedora/` files, 4 spaces in the routine helper and the test scripts); run `shfmt -w`.
- **Comments say why.** No header that restates the function name; document
  arguments (`# Usage: name <arg> ...`), caveats and the reason for non-obvious code.

## Keeping up with the guidance

The weekly **Reference watch** workflow opens an issue when a source in
`docs/references.json` changes or arkenfox publishes a new release. To act on it:

1. Read the changed page and update the script where the advice changed.
2. For a new arkenfox release, update `ARKENFOX_VERSION` and `ARKENFOX_SHA256` in
   `core/01-globals.sh`
   (`curl -fsSL https://raw.githubusercontent.com/arkenfox/user.js/<tag>/user.js | sha256sum`).
3. Run the tests, then record the review:
   `python3 tests/check-references.py --update`, and commit `docs/references.json`.

The same workflow runs `tests/check-overlap.py`, which reports any run of 12 or more
words in the README, the docs or a code comment that repeats a source word for word,
and opens its own issue. Write the guidance in the project's own words; a quotation
(quotation marks or a `>` block, with the citation) is fine. Run it locally before a
release: `python3 tests/check-overlap.py`.

## Releasing

Changes land through pull requests with green CI. Before a large change, tag the
current `main` so users can return to it (for example `pre-fedora44-overhaul`), and
record user-visible changes in [CHANGELOG.md](CHANGELOG.md).

CI, the test tiers and troubleshooting are in [TESTING.md](TESTING.md).
