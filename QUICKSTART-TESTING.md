# Quickstart: Testing fedora-harden.sh in Podman

## Installation (One-Time)

```bash
# Install podman (container runtime)
sudo dnf install podman

# Make test script executable
chmod +x test-in-podman.sh
```

## Run Tests

### Fastest Option (Recommended for CI/Development)
```bash
# Ultra-minimal test: 1-2 minutes, 256 MB memory, 1 CPU
./test-in-podman.sh --quick --dry-run
```

### Full System Test
```bash
# Complete test with systemd: 3-5 minutes, 512 MB memory, 2 CPUs
./test-in-podman.sh --dry-run
```

### Interactive Testing
```bash
# Open shell in container for manual testing
./test-in-podman.sh --quick -it

# Inside container:
root@container:/# ./fedora-harden.sh --help
root@container:/# ./fedora-harden.sh --list
root@container:/# ./fedora-harden.sh --dry-run --only 5
```

## Common Workflows

### Test Before Commit
```bash
# Quick syntax check + logic test
./test-in-podman.sh --quick --dry-run

# Then test with real systemd
./test-in-podman.sh --dry-run

# If all pass, commit
git add . && git commit -m "..."
```

### Test Specific Section
```bash
# Test firewalld section (section 5)
./test-in-podman.sh --quick --only 5 --dry-run

# Test multiple sections
./test-in-podman.sh --quick --only 5,7,10 --dry-run
```

### Low-Resource Environments
```bash
# Minimal memory (256 MB), 1 CPU
./test-in-podman.sh --quick --memory 256m --cpus 1 --dry-run
```

## What Each Flag Does

| Flag | Effect | Best For |
|------|--------|----------|
| `--quick` | Skip systemd, ultra-minimal | CI, rapid iteration |
| `--dry-run` | No changes made | Safe testing |
| `-it` | Interactive shell | Debugging |
| `--only 5` | Test section 5 only | Targeted testing |
| `--memory 512m` | Set memory limit | Resource testing |
| `--cpus 2` | Set CPU limit | Performance testing |

## Understanding Results

### Success
```
[ℹ] Using quick (no-systemd) variant for faster testing
[ℹ] Building container image...
[✓] Container image built successfully
[ℹ] Starting container...
[✓] Test completed successfully
```

### Dry-Run (No Changes)
```
[ℹ] Running fedora-harden.sh (--quick mode)
Would run: systemctl enable firewalld
Would run: sed -i ... /etc/ssh/sshd_config
[✓] Test completed successfully  ← No actual changes made!
```

## Files Generated

Test artifacts are automatically created and cleaned up:

```
/tmp/fedora-harden-test-PID.log       # Main test output
/tmp/fedora-harden-test-PID/           # Test directory (auto-cleaned)
  ├── harden-*.log                    # Hardening logs
  └── sessions/session-*.txt          # Session reports
```

## Troubleshooting

### "podman: command not found"
```bash
sudo dnf install podman
```

### "Cannot connect to Podman"
```bash
# On first run, podman initializes storage
podman version
./test-in-podman.sh --quick --dry-run
```

### "Out of memory"
```bash
# Increase memory limit
./test-in-podman.sh --quick --memory 512m --dry-run
```

### "Permission denied"
```bash
# Add user to podman group
usermod -aG podman $USER
newgrp podman
```

## Performance

Typical times on modern hardware (2 GHz+ CPU, 8 GB+ RAM):

```
Quick variant (no systemd):  1-2 minutes ✓ Fast
Full variant (systemd):      3-5 minutes
First run (build included):  Add 1-2 minutes
Cached run:                  No build time
```

## Next Steps

- Read [`TESTING.md`](TESTING.md) for advanced options
- Check [`fedora-harden.sh --help`](fedora-harden.sh) for script options
- View [`Dockerfile.test`](Dockerfile.test) for container configuration
- See [CI/CD examples](TESTING.md#continuous-integration--gitlab-ci) for automation

---

**Made for efficiency.** Quick testing, minimal resources, maximum safety. 🚀
