# Fedora Hardening - Development Toolchain

Comprehensive guide to the integrated development and deployment tools.

## Overview

The fedora-hardening project uses a modern, automated development pipeline optimized for:
- **Efficiency**: One-command workflows with automated verification
- **Privacy**: All tools run locally, no cloud dependencies
- **Security**: Automated scanning and validation at every step
- **Quality**: Continuous testing and metrics collection

```
Development Flow:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  1. Code → 2. Commit → 3. Pre-commit Hooks → 4. CI/CD → 5. Release
  ─────────────────────────────────────────────────────────────────
  ✓ Edit      ✓ Stage    ✓ Lint            ✓ Test    ✓ Tag
  ✓ Test      ✓ Commit   ✓ Format          ✓ Scan    ✓ Release
  ✓ Format    ✓ Validate ✓ Secrets         ✓ Build   ✓ Publish
                ✓ Message ✓ Conventions    ✓ Quality

  Interactive: MCP Server ↔ Claude for real-time assistance
```

## Toolchain Components

### 1. Pre-commit Hooks (Local Validation)

**File**: `.pre-commit-config.yaml`

Automatically validates every commit before it happens.

```bash
# Install (one-time)
pip install pre-commit
pre-commit install

# Or use setup script
./setup-dev.sh
```

**Tools included**:
- **shellcheck** - Shell script linting
- **shfmt** - Shell script formatting
- **trufflehog** - Secrets detection
- **markdownlint** - Markdown validation
- **yamllint** - YAML validation
- **hadolint** - Dockerfile linting
- **commitizen** - Commit message validation (conventional commits)

**What it prevents**:
```bash
# ✗ Commit blocked: Syntax error
git commit ...
shellcheck: SC2086 Double quote to prevent globbing

# ✗ Commit blocked: Secret detected
git commit ...
trufflehog: Found AWS key pattern

# ✗ Commit blocked: Bad commit message
git commit -m "fixed stuff"  # Not conventional
commitizen: Invalid commit message format
```

### 2. GitHub Actions CI/CD

**File**: `.github/workflows/ci.yml`

Automated testing and validation on every push.

```yaml
Jobs:
  1. Lint         - shellcheck, hadolint, yamllint
  2. Syntax       - bash -n validation
  3. Test Suite   - podman container testing
  4. Security     - trufflehog, trivy, gitleaks
  5. Quality      - Metrics, complexity, docs verification
  6. Docker Build - Test image builds
```

**Triggers**:
- Every push to main/develop
- Every pull request
- Nightly scheduled runs

**View results**: GitHub → Actions tab → CI workflow

### 3. MCP Server (Claude Integration)

**File**: `mcp_server_fedora_harden.py`

Interactive development assistant integrated with Claude.

```python
# Tools provided:
- verify-script          # One-command full verification
- lint-script           # Linting check
- test-script           # Run tests
- check-security        # Security scanning
- validate-docs         # Documentation verification
- analyze-performance   # Complexity metrics
- update-version        # Semantic versioning
- generate-changelog    # Changelog from commits
- create-release        # Automated release
- quality-report        # Comprehensive metrics
- setup-dev-environment # Dev tools setup
```

**Usage in Claude**:
```
/mcp fedora-harden verify-script
→ Full syntax, lint, test, security, docs check

/mcp fedora-harden test-script --mode quick
→ Quick test in container

/mcp fedora-harden quality-report
→ Comprehensive quality metrics
```

### 4. Container Testing

**Files**: `Dockerfile.test`, `test-in-podman.sh`

Isolated testing environment with minimal resource usage.

```bash
# Quick test (1-2 min, 256 MB)
./test-in-podman.sh --quick --dry-run

# Full test (3-5 min, 512 MB)
./test-in-podman.sh --dry-run

# Specific section
./test-in-podman.sh --only 5 --dry-run

# Interactive debugging
./test-in-podman.sh -it
```

### 5. Development Setup Script

**File**: `setup-dev.sh`

Automated environment initialization.

```bash
# Full setup
./setup-dev.sh

# Dry-run preview
./setup-dev.sh --dry-run

# Skip optional tools
./setup-dev.sh --skip-optional
```

**Installs**:
- Python 3.8+
- Git, Podman, Bash
- pre-commit, shellcheck, shfmt
- yamllint, hadolint, commitizen
- MCP SDK (optional)

## Workflow Examples

### Development (Make Changes)

```bash
# 1. Setup environment (one-time)
./setup-dev.sh

# 2. Make changes
nano fedora-harden.sh

# 3. Verify syntax
bash -n fedora-harden.sh

# 4. Test changes
./test-in-podman.sh --quick --dry-run

# 5. Commit (pre-commit hooks validate automatically)
git add fedora-harden.sh
git commit -m "fix: improve error handling in section 5"
# Pre-commit checks:
# ✓ Syntax valid
# ✓ No linting issues
# ✓ Formatting correct
# ✓ No secrets
# ✓ Commit message format valid

# 6. Push
git push origin feature-branch
```

### CI/CD Pipeline (GitHub)

```bash
# 1. Create PR on GitHub
# (Automatically triggers CI/CD)

# 2. GitHub Actions runs:
#    ✓ Lint checks
#    ✓ Syntax validation
#    ✓ Container tests
#    ✓ Security scans
#    ✓ Quality metrics

# 3. Review results in GitHub Actions tab
#    Green checkmark = All tests pass
#    Red X = Fix issues before merging

# 4. Merge when all tests pass
```

### Interactive Claude Development

```python
# In Claude with MCP Server running:

/mcp fedora-harden verify-script
→ Full verification: syntax, lint, test, security, docs
→ Single command covers all checks

/mcp fedora-harden check-security
→ Scan for secrets, suspicious patterns
→ Real-time feedback on security

/mcp fedora-harden quality-report
→ Comprehensive metrics report
→ Complexity, documentation, test coverage
```

### Release Management

```bash
# 1. Create release with MCP
/mcp fedora-harden update-version --bump minor
→ Updates version in script

# 2. Generate changelog
/mcp fedora-harden generate-changelog
→ Creates changelog from commits

# 3. Create release
/mcp fedora-harden create-release --version 2.1.0
→ Tags commit, creates GitHub release

# 4. Publish
git push origin --tags
→ Triggers release automation
```

## Quality Gates

Automated checks that must pass before code is merged:

### Pre-commit (Local)
- ✓ Syntax validity
- ✓ Linting (shellcheck)
- ✓ Formatting (shfmt)
- ✓ Secret detection
- ✓ Trailing whitespace
- ✓ Commit message format

### CI/CD (GitHub)
- ✓ Full syntax check
- ✓ Container build
- ✓ Test suite execution
- ✓ Security vulnerability scan
- ✓ Secret detection (gitleaks)
- ✓ Docker image linting
- ✓ Documentation completeness

### Manual Review
- ✓ Code review by maintainers
- ✓ Design review for major changes
- ✓ Documentation review

## Privacy & Security

### Privacy
- **Local-first**: All tools run on your machine
- **No cloud**: No data sent to external services
- **No telemetry**: Optional metrics only (user-controlled)
- **Self-hosted**: CI/CD runs on GitHub (can be self-hosted)

### Security
- **Secret scanning**: Automated detection of credentials
- **Vulnerability scanning**: Container and dependency checks
- **Code quality**: Prevents unsafe patterns
- **Input validation**: Conventional commits ensure consistency
- **Access control**: GitHub branch protection on main

## Performance Metrics

### Development Cycle Time
- Syntax check: ~100ms
- Pre-commit validation: ~2-5 seconds
- Container test (quick): 1-2 minutes
- Container test (full): 3-5 minutes
- CI/CD pipeline: ~10-15 minutes

### Resource Usage
- Quick container: 256 MB memory, 1 CPU
- Full container: 512 MB memory, 2 CPUs
- Disk usage per container: ~5 GB max
- No persistent overhead between runs

### Build Artifacts
- Quick image: ~150 MB
- Full image: ~400 MB
- Cached layers: Subsequent builds <10 seconds

## Troubleshooting

### Pre-commit hooks not running
```bash
# Reinstall
pre-commit uninstall
pre-commit install
pre-commit install --hook-type commit-msg
```

### CI/CD failing
```bash
# View GitHub Actions output
# GitHub → Actions tab → CI workflow → Click job

# Run locally to debug
./test-in-podman.sh --quick --dry-run
```

### MCP Server connection issues
```bash
# Check if running
python3 mcp_server_fedora_harden.py

# Verify Claude has MCP enabled
# In Claude: /help (check MCP section)
```

### Container issues
```bash
# Check podman
podman --version
podman ps

# Rebuild images
podman image rm fedora-harden:*
./test-in-podman.sh --quick
```

## Integration Guide

### VS Code
```json
// .vscode/settings.json
{
  "[shell]": {
    "editor.defaultFormatter": "shellformat.shellformat",
    "editor.formatOnSave": true
  }
}
```

### Pre-commit Local Run
```bash
# Run on all files
pre-commit run --all-files

# Run specific hook
pre-commit run shellcheck --all-files

# Run on changed files only
pre-commit run
```

### Docker/Podman Build
```bash
# Build test image
podman build -f Dockerfile.test -t fedora-harden:test .

# Run with custom settings
podman run --rm \
  --memory 1g \
  --cpus 4 \
  fedora-harden:test /bin/bash
```

## Maintenance

### Update Pre-commit Hooks
```bash
pre-commit autoupdate
git add .pre-commit-config.yaml
git commit -m "chore: update pre-commit hook versions"
```

### Update GitHub Actions
```bash
# GitHub will notify of outdated actions
# Review and merge automated updates
```

### Update MCP Server
```bash
pip install --upgrade mcp
```

## Next Steps

1. **Quick Start**: `./setup-dev.sh`
2. **Development**: Read `DEVELOPMENT.md`
3. **Testing**: Read `TESTING.md` and `QUICKSTART-TESTING.md`
4. **Contributing**: Make changes and submit PR

## Resources

- **Setup**: `./setup-dev.sh` or `DEVELOPMENT.md`
- **Testing**: `TESTING.md`, `QUICKSTART-TESTING.md`
- **Workflow**: `DEVELOPMENT.md`
- **MCP Server**: `mcp_server_fedora_harden.py`
- **CI/CD**: `.github/workflows/ci.yml`
- **Pre-commit**: `.pre-commit-config.yaml`
- **Container**: `Dockerfile.test`, `test-in-podman.sh`

---

**Goal**: Maximize efficiency, privacy, and security while creating the best developer experience.
