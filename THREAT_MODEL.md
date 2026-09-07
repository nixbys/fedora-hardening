# Threat Model

This document states the trust assumptions behind `fedora-harden.sh` so
contributors and reviewers can reason about changes without re-deriving them
from scratch. See [SECURITY.md](SECURITY.md) for how to report a problem.

## What This Project Actually Does

`fedora-harden.sh` is invoked as `sudo ./fedora-harden.sh` (per the README
Quick Start) against a real Fedora or Atomic-Desktop system — a developer's
laptop, a home server, or a workstation someone is using right now. It is not
a container init script or a CI fixture: its 23 sections rewrite `sshd_config`,
firewalld zones, sysctl values, PAM stacks, and systemd unit state on a
machine with an existing user, existing sessions, and existing expectations
about what still works after the script exits.

That framing drives every decision below: the two things that matter most are
(1) **what a malicious change to this repository could make root do on
someone else's machine**, and (2) **what the script itself could break even
when behaving exactly as written**, because "it ran with no errors" and "the
system is still usable and no less secure than before" are not the same
guarantee.

## Trust Boundaries

| Boundary | Trusted | Not trusted / must be defended against |
|---|---|---|
| The script's own logic | Runs as root; a passing run is trusted to have applied what it claims | A crafted or unexpected `/etc/os-release`, desktop-environment signal, or package-manager state causing the wrong hardening path to run silently |
| The repository's source | The commit you reviewed on `main` | Any other way the bytes reached the machine (stale clone, third-party mirror, a copy pasted from a forum/chat) — see SECURITY.md |
| Contributors / pull requests | Reviewed diffs merged by a maintainer | An unreviewed PR from a fork; CI running attacker-supplied `run:` content with repository-token access |
| The target system | A Fedora release the script's detection logic recognizes (see README "Platform Support") | An unsupported/future release, a heavily pre-modified system, or a system mid-way through a `rpm-ostree` staged deployment |
| Runtime dependencies | Fedora's own signed `dnf`/`rpm-ostree` packages | Anything the script would need to fetch from the network unauthenticated to do its job (it does not do this today — keep it that way; see SECURITY.md) |

## Threat: A Malicious or Careless Pull Request (Supply-Chain Risk)

This is the risk most specific to a "clone it and run it as root" project.
Unlike a library that gets audited transitively through a dependency tree,
this script is meant to be trusted directly and immediately. Concretely:

- **A PR that quietly changes what a section *does* is the highest-value
  target.** A one-line change inside `sec_07_ssh()` or `sec_05_firewalld()`
  that weakens a setting instead of hardening it (e.g. flips a `no` to `yes`,
  widens a firewalld zone, or drops a sysctl entry) is easy to miss in a large
  diff and would ship the *opposite* of what every user of this project
  believes they are getting. Review diffs to `fedora-harden.sh` by reading the
  actual `dnf`/`sed`/`sysctl`/config-write lines, not just the surrounding
  comments — comments describe intent, they don't enforce it.
- **A PR that adds a new fetch-and-execute path is the second-highest.** The
  script currently gets everything it installs through Fedora's own signed
  package repositories (`dnf`/`rpm-ostree`), which carries Fedora's own
  package-signing guarantees. A change that introduces an unauthenticated
  `curl ... | bash`, an unpinned `git clone` of a third-party tool, or a
  dynamically constructed command from user input would reintroduce, inside a
  *hardening* tool, exactly the class of risk this project exists to close on
  the target system. New external tool installs should go through `dnf`/
  Flathub/verified upstream signing wherever the tool already ships that way.
- **CI itself is an attack surface.** A workflow that checks out a fork's PR
  and runs untrusted `run:` steps with write access to repository secrets (or
  a floating `@master`/`@latest` action reference that could change behavior
  after review) could compromise the pipeline without ever touching
  `fedora-harden.sh` directly. This is why every workflow here pins actions to
  an exact commit SHA and declares an explicit least-privilege `permissions:`
  block, and why `.github/workflows/workflow-security.yml` (actionlint +
  zizmor) audits every workflow file — including itself — on every push and
  PR.

## Threat: Running on an Unsupported Fedora Version

The script auto-detects variant, package manager, and desktop environment
from `/etc/os-release` and `/run/ostree-booted` (README "Platform Support").
On a release the detection logic doesn't recognize:

- The most likely failure mode is a section **silently no-op'ing or
  misapplying** rather than crashing loudly — e.g. a systemd unit name, PAM
  module path, or config file location that moved between releases, so a
  `sed`/`grep` pattern matches nothing and the section reports success without
  having changed anything.
- The second failure mode is a **partial application**: a section correctly
  handles the package-manager branch (dnf vs. rpm-ostree) but assumes a config
  file layout from the tested release that differs on an untested one,
  leaving the system in a state no combination of "hardened" or "default"
  actually describes.
- **Mitigation already in place:** `--dry-run` shows every command before it
  runs, sections are independently selectable (`--only`/`--skip`) so an
  unfamiliar system can be tested section-by-section, and every file the
  script touches is backed up before modification so `--rollback` can undo a
  bad application. None of this replaces testing new releases before they're
  added to the supported list — a mismatch between "the script believes it
  succeeded" and "the config now says what the script thinks it says" is a
  correctness bug worth its own test case, not just a rollback safety net.

## Threat: Hardening Changes Breaking a Production System

Every one of these is a *known, accepted* operational risk of what this
category of tool does — not a bug — but each is exactly the kind of mistake
that turns "hardened" into "locked out":

- **SSH hardening (Section 7)** disables password authentication. Applied
  without a working key already installed for the target `--user`, this is a
  remote lockout on a headless/remote box with no physical console fallback.
- **firewalld drop-default (Section 5)** can cut off a service (a dev server,
  a file share, a remote-access tool) that was working a moment before, with
  no prompt distinguishing "you forgot this is exposed" from "this was
  intentionally exposed."
- **USBGuard (Section 8)** allowlists only devices plugged in when the section
  runs — a hardware security key inserted afterward is blocked until manually
  added (the README calls this out, but it's easy to run sections out of
  order via `--only`).
- **Full rollback (`--rollback all`)** reverses every session from the first
  run. On a system that has had unrelated manual changes layered on top of
  hardening changes since then, rollback restoring an old backup can also
  discard or conflict with those unrelated changes — rollback restores what
  the script backed up, not a full system snapshot.

None of this argues for weakening what the script does; it argues for the
`--dry-run` default, per-section `--only`/`--skip` control, and rollback
journal it already has to stay load-bearing as sections are added, and for new
sections to fail loudly (and skip cleanly) rather than partially applying when
a precondition isn't met.

## Known Gaps

These are open and acknowledged:

1. **No cryptographic verification of the script itself at run time.** Nothing
   stops a tampered copy from running with a valid-looking `--dry-run` output;
   the only defense is verifying the source before running it (SECURITY.md).
   Signed releases/tags are a reasonable future improvement.
2. **No automated test asserts a hardening section's *effect*, only that the
   script parses and runs without error.** CI (`ci.yml`) validates syntax and
   builds a Fedora container image; it does not currently assert "after
   Section 7 runs, `sshd -T` reports `passwordauthentication no`" for every
   section. Contributions adding effect-level assertions inside the podman
   test harness (`test-in-podman.sh`, `TESTING.md`) are welcome.
3. **`mcp_server_fedora_harden.py` shells out to run lint/test/security
   commands** as a local development convenience. It is not part of the
   hardening script's runtime path and is not invoked by `fedora-harden.sh`,
   but it runs with whatever privileges the developer invoking it has —
   treat it as regular local tooling, not as a hardened component.
