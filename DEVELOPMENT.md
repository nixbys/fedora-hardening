# Fedora Hardening Script - Development Guide

Complete guide for contributing to and developing fedora-harden.sh with integrated tooling.

## Quick Start

```bash
# Clone repository
git clone https://github.com/fedora-hardening/fedora-hardening.git
cd fedora-hardening

# Setup development environment
pip install pre-commit
pre-commit install
pre-commit install --hook-type commit-msg

# Install optional dev tools
pip install shellcheck-py yamllint hadolint commitizen

# Test your changes
./test-in-podman.sh --quick --dry-run

# Commit (will auto-check syntax, lint, format)
git add fedora-harden.sh
git commit -m "fix: clear description of what changed"
```

## Development Workflow

### 1. Make Changes
```bash
# Edit script
nano fedora-harden.sh

# Verify syntax
bash -n fedora-harden.sh
```

### 2. Automated Checks (Pre-commit)
```bash
# Your changes are automatically checked when you commit:
# - Syntax validation (bash -n)
# - Linting (shellcheck)
# - Formatting (shfmt)
# - Trailing whitespace removal
# - Secret detection
# - Conventional commit message format
# - YAML/JSON validation

git commit -m "fix: improve error handling in section 5"
# Pre-commit hooks run automatically
```

### 3. Test Changes
```bash
# Quick test (fast, no systemd)
./test-in-podman.sh --quick --dry-run

# Full test (realistic, with systemd)
./test-in-podman.sh --dry-run

# Test specific section
./test-in-podman.sh --only 5 --dry-run

# Interactive debugging
./test-in-podman.sh --quick -it
```

### 4. Verify Documentation
```bash
# Check all sections documented
grep -c "^sec_" fedora-harden.sh

# Check global variables documented
grep -c "^# ----------" fedora-harden.sh

# Verify function docstrings
grep "^# [a-z_]*() -" fedora-harden.sh
```

### 5. Push & Create PR
```bash
# Push to your fork
git push origin feature-branch

# Create pull request on GitHub
# CI/CD automatically runs full test suite
```

## MCP Server Development Integration

The MCP Server provides Claude-integrated development tools for maximum efficiency.

### Setup MCP Server

```bash
# Install MCP (when available in Claude Code)
# Or use Python directly:
pip install mcp

# Run server
python3 mcp_server_fedora_harden.py
```

### Using in Claude

```
# One-command verification
/mcp fedora-harden verify-script

# Run tests
/mcp fedora-harden test-script --mode quick

# Check security
/mcp fedora-harden check-security

# Generate report
/mcp fedora-harden quality-report

# Update version
/mcp fedora-harden update-version --bump patch

# Setup environment
/mcp fedora-harden setup-dev-environment --dry-run false
```

### MCP Tools Available

1. **verify-script** - Comprehensive syntax, lint, test, security, docs check
2. **lint-script** - Run shellcheck and shfmt
3. **test-script** - Run test suite (quick/full, specific sections)
4. **check-security** - Detect secrets, suspicious patterns
5. **validate-docs** - Check documentation completeness
6. **analyze-performance** - Complexity and performance metrics
7. **update-version** - Semantic versioning (major/minor/patch)
8. **generate-changelog** - Create changelog from commits
9. **create-release** - Automated release creation
10. **quality-report** - Comprehensive quality metrics
11. **setup-dev-environment** - Initialize dev tools

## Commit Message Format

Uses conventional commits for automatic changelog generation:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types:
- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation changes
- **style**: Code style (formatting, missing semicolons)
- **refactor**: Code refactoring without feature changes
- **perf**: Performance improvements
- **test**: Test additions/changes
- **chore**: Build, dependencies, etc.

Examples:
```bash
# Good
git commit -m "fix(sec_05): improve firewalld error handling"
git commit -m "feat: add GUI-full single-window mode"
git commit -m "docs: update testing guide with MCP examples"

# Bad
git commit -m "updated stuff"
git commit -m "fix bugs"
```

## Testing Strategies

### Unit Testing (Syntax)
```bash
bash -n fedora-harden.sh  # Validates syntax, no execution
```

### Integration Testing (Container)
```bash
# Quick variant (fast, for rapid iteration)
./test-in-podman.sh --quick --dry-run

# Full variant (realistic, with systemd)
./test-in-podman.sh --dry-run
```

### Specific Section Testing
```bash
# Test one section
./test-in-podman.sh --quick --only 5 --dry-run

# Test multiple sections
./test-in-podman.sh --quick --only 5,7,10 --dry-run
```

### Performance Testing
```bash
# Measure complexity
grep -c "^[a-z_]*() {" fedora-harden.sh  # Function count
wc -l fedora-harden.sh  # Line count

# Time execution
time ./test-in-podman.sh --quick --dry-run
```

### Security Testing
```bash
# Check for hardcoded secrets
trufflehog filesystem . --only-verified

# Scan for suspicious patterns
grep -E "eval |rm -rf /|dd if=" fedora-harden.sh
```

## CI/CD Pipeline

Automated on every push:

1. **Syntax Check** - Validate script can be parsed
2. **Linting** - shellcheck for issues
3. **Format Check** - shfmt for consistency
4. **Container Build** - Build test images
5. **Test Suite** - Run in isolated containers
6. **Security Scan** - Secret and vulnerability detection
7. **Quality Metrics** - Complexity, documentation coverage
8. **Docker Linting** - hadolint for Dockerfile quality

View results: GitHub Actions tab → CI workflow

## Documentation Standards

### Script Header
```bash
#!/usr/bin/env bash
# =============================================================================
#  Fedora 44+ Security Hardening Script (multi-release + desktop aware)
#  Based on: [Reference document]
#
#  FEATURES:
#    • Feature description
#    • Another feature
#
#  USAGE:
#    sudo ./fedora-harden.sh [options]
#
#  OPTIONS:
#    -u, --user <name>      Description
#
#  SECTIONS:
#     2  Section name
#     3  Another section
# =============================================================================
```

### Function Documentation
```bash
# function_name() - Brief description of what it does
# Longer explanation if needed: side effects, return values, etc.
# Usage: function_name <param1> <param2>
function_name() {
    # Implementation
}
```

### Global Variable Documentation
```bash
# ---------- Logical group name -------------------------------------------
VARIABLE_NAME=""  # What this variable tracks/stores
ANOTHER_VAR=0     # When it's set to 1, what it means
```

## Performance Optimization

### Profiling
```bash
# Bash execution tracing
bash -x fedora-harden.sh --dry-run 2>&1 | tee profile.log

# Time specific sections
time ./fedora-harden.sh --dry-run --only 5
```

### Optimization Patterns
- **Batch operations**: Multiple sed patterns in one pass
- **Caching**: Store command results, reuse
- **Avoid loops**: Use built-in bash operations
- **Minimize forks**: Reduce external command calls

## Security Considerations

### When Developing
1. **Never hardcode secrets** - Use environment variables
2. **Validate input** - Check user-provided values
3. **Escape variables** - Quote ${var} in most contexts
4. **Avoid eval** - Never use eval with user input
5. **Check permissions** - Don't run as root unnecessarily

### Pre-commit Secrets Detection
```bash
# Automatically scans for:
# - AWS keys, API tokens
# - Private keys
# - Database credentials
# - Other sensitive patterns

# If detected, commit is blocked:
git commit ...
# trufflehog: Detected secret patterns
# Commit aborted
```

## Troubleshooting

### Pre-commit hooks not running
```bash
# Reinstall hooks
pre-commit uninstall
pre-commit install
pre-commit install --hook-type commit-msg
```

### shellcheck not found
```bash
# Install
pip install shellcheck-py
# Or: sudo apt-get install shellcheck
```

### Test container won't start
```bash
# Check podman
podman --version
podman ps

# Rebuild images
podman image rm fedora-harden:* 2>/dev/null || true
./test-in-podman.sh --quick --dry-run
```

### Commit message rejected
```bash
# Check format (must follow conventional commits)
git commit -m "fix: brief description"  # Good
git commit -m "updated stuff"           # Bad - rejected

# View rules
cat .pre-commit-config.yaml | grep -A5 commitizen
```

## Release Process

### Manual Release
```bash
# 1. Update version (in script header)
# 2. Update CHANGELOG.md
# 3. Create tag
git tag -a v2.0.0 -m "Release version 2.0.0"
git push origin v2.0.0

# GitHub automatically creates release
```

### Automated Release (Future)
```bash
# MCP server can automate:
/mcp fedora-harden update-version --bump minor
/mcp fedora-harden generate-changelog
/mcp fedora-harden create-release --version 2.1.0
```

## Resources

- **Script Help**: `./fedora-harden.sh --help`
- **Testing Guide**: `TESTING.md`
- **Quick Start**: `QUICKSTART-TESTING.md`
- **Container Config**: `Dockerfile.test`
- **Pre-commit**: `.pre-commit-config.yaml`
- **CI/CD**: `.github/workflows/ci.yml`

## Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/my-feature`
3. Make changes with tests
4. Pre-commit hooks validate automatically
5. Push and create pull request
6. CI/CD pipeline runs automatically
7. Review and merge!

## Code of Conduct

- Be respectful and inclusive
- Focus on code quality and security
- Write clear commit messages
- Test your changes thoroughly
- Document new features
- Review others' contributions constructively
