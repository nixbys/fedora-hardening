# Security Policy

`fedora-harden.sh` is a single Bash script that you download, then run as
**root** (via `sudo`) against a real, in-use Fedora system. That combination —
untrusted-until-reviewed shell code, executed with full privileges, against a
machine someone actually uses — is the thing this policy exists to protect.

## Supported Versions

Security fixes are handled on the default branch (`main`) until formal
releases are tagged. There is no long-term-support branch; always pull the
latest `main` before running the script.

## Before You Run It

- **Read the script, or at minimum the section list, before running it with
  `sudo`.** This project has no build step and no package registry between
  the source you can read and the code that executes — `git clone` +
  `sudo ./fedora-harden.sh` runs exactly the bytes in the repository. Verifying
  what you're about to run is not optional caution here; it's the only review
  step that exists between "someone pushed a commit" and "this runs as root
  on your machine."
- **Verify the commit you're running.** If you pull the script by any means
  other than `git clone` immediately before running it (a cached copy, a
  mirror, a `curl`'d raw-file URL saved from a chat or forum post), confirm it
  matches the current `main` branch of `github.com/nixbys/fedora-hardening`
  before trusting it.
- **Use `--dry-run` first.** Every run prints exactly what it would change
  before you commit to applying it for real.
- **Don't run it unattended on a production or single-point-of-failure
  system.** Several sections (SSH hardening, firewalld default-drop, USBGuard)
  can lock out access if misconfigured for your environment — see "Operational
  Risk" below.
- **Keep the session journal.** Every run writes a backup/journal under
  `/root/harden-backups-<timestamp>/`; don't delete it until you're confident
  you won't need `--rollback`.

## Reporting a Vulnerability

Please report security issues privately via [GitHub Security
Advisories](https://github.com/nixbys/fedora-hardening/security/advisories/new)
rather than a public issue. This includes:

- A hardening section that silently fails to apply the protection it claims to
  (a false sense of security is worse than no claim at all).
- A way for the script's own logic to be tricked into weakening a system
  instead of hardening it (e.g. a crafted `/etc/os-release` or environment
  causing the wrong branch of the dnf/rpm-ostree detection to run).
- Any code-execution or privilege-escalation path in the script or in
  `mcp_server_fedora_harden.py` that isn't already covered by "this script
  runs as root by design."

If you're unsure whether something rises to that level, open it privately
first — it's easy to downgrade a private report to a public issue, much harder
to do the reverse.

## Supply-Chain Guidance for Contributors and Reviewers

Because this script runs with root privileges on real systems, a malicious or
careless pull request here is a meaningfully different risk than in most
projects. See [THREAT_MODEL.md](THREAT_MODEL.md) for the full reasoning; in
short:

- Every GitHub Actions workflow in this repo pins third-party actions to an
  exact commit SHA (not a floating tag like `@v3` or `@master`) — see
  `.github/workflows/workflow-security.yml`, which audits this automatically.
  If you add a workflow step, pin it the same way.
  Dependabot (`.github/dependabot.yml`) proposes the version bumps as
  small, reviewable PRs so this doesn't need manual upkeep.
- Any new external command the script downloads and executes (the pattern
  already used for `dnf`/`rpm-ostree` packages, which are cryptographically
  signed by Fedora) should go through Fedora's own package repositories
  wherever possible, rather than an unauthenticated `curl | bash`-style
  fetch — the whole point of this project is to reduce that class of exposure
  on the systems it's run against, not add it to the codebase itself.
- Review diffs to `fedora-harden.sh` for anything that changes *what gets
  executed* (new `curl`, `wget`, `eval`, or dynamically constructed commands)
  with more scrutiny than a diff that only changes strings, comments, or
  section wording.

## Reporting Issues in the MCP Server

`mcp_server_fedora_harden.py` is a local developer-tooling helper (invoked via
`mcp install`, not part of the hardening script's runtime path) that shells
out to run linting/testing commands. Treat vulnerability reports about it the
same way as the shell script — via a private security advisory.
