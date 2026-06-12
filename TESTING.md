# Fedora Hardening Script - Testing Guide

## Quick Container Testing (Recommended)

The easiest way to test `fedora-harden.sh` safely in an isolated environment is using the provided podman test script.

### Prerequisites

```bash
# Install podman (replaces docker for most use cases)
sudo dnf install podman

# Optional: Install podman-compose for multi-container testing
sudo dnf install podman-compose
```

### Quick Start - Fast Testing Mode (Recommended for CI)

```bash
# Fastest test: ultra-minimal container without systemd (~1-2 minutes)
./test-in-podman.sh --quick --dry-run

# Test with auto-cleanup and interactive output
./test-in-podman.sh --quick -it
```

### Full System Testing

```bash
# Full test with systemd (more realistic, slower, ~3-5 minutes)
./test-in-podman.sh --dry-run

# Run only specific hardening section (e.g., section 5 = firewalld)
./test-in-podman.sh --quick --only 5

# Skip specific sections
./test-in-podman.sh --quick --skip 12,19 --dry-run
```

### Resource-Constrained Testing

Useful for testing on minimal systems or CI with limited resources:

```bash
# Ultra-minimal: 256 MB memory, 1 CPU
./test-in-podman.sh --quick --memory 256m --cpus 1 --dry-run

# Standard: 512 MB memory, 2 CPUs (default)
./test-in-podman.sh --quick --dry-run

# Generous: 1 GB memory, 4 CPUs
./test-in-podman.sh --memory 1g --cpus 4 --dry-run
```

### Interactive Container Shell

For manual testing or debugging:

```bash
# Open interactive shell in quick test container
./test-in-podman.sh --quick -it

# Inside container, run the script manually
root@container:/root# bash -n fedora-harden.sh  # Syntax check
root@container:/root# ./fedora-harden.sh --list  # Show sections
root@container:/root# ./fedora-harden.sh --dry-run --only 5  # Test section 5
```

## Container Architecture

### Two Testing Variants

#### 1. **Quick Variant** (Recommended)
- **Size**: ~150 MB
- **Startup**: <5 seconds
- **Memory**: 256 MB (configurable)
- **CPU**: 1 core (configurable)
- **Best for**: CI/CD, rapid iteration, syntax checking

```bash
./test-in-podman.sh --quick --dry-run
```

Runs the script directly without systemd overhead.

#### 2. **Full Variant** (Realistic)
- **Size**: ~400 MB
- **Startup**: ~10 seconds
- **Memory**: 512 MB (configurable)
- **CPU**: 2 cores (configurable)
- **Best for**: Integration testing, service behavior verification

```bash
./test-in-podman.sh --dry-run
```

Includes systemd for testing service installation/enabling.

## Resource Optimization

The test containers are optimized for minimal resource usage:

### Memory Management
- **Swap disabled**: Prevents thrashing, ensures predictable performance
- **Memory limit**: Strictly enforced, container exits on OOM
- **Default**: 256-512 MB (adjustable with `--memory` flag)

### CPU Management
- **CPU limit**: Prevents container from monopolizing host resources
- **Default**: 1-2 cores (adjustable with `--cpus` flag)

### Storage
- **No persistent layers**: All test state in `/tmp`, auto-cleaned
- **Size limit**: 5 GB per container to prevent disk exhaustion
- **No swap**: Consistent performance across systems

### Process Limits
- **PID limit**: 1024 to prevent fork bomb attacks during testing

## Usage Examples

### Continuous Integration / GitLab CI

```yaml
test:fedora-harden:
  image: fedora:44-minimal
  before_script:
    - dnf install -y podman
  script:
    - cd fedora-hardening
    - ./test-in-podman.sh --quick --dry-run
  artifacts:
    paths:
      - /tmp/fedora-harden-test-*.log
    when: always
```

### GitHub Actions

```yaml
name: Test Fedora Hardening

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install podman
        run: sudo apt-get install -y podman
      - name: Run tests
        run: cd fedora-hardening && ./test-in-podman.sh --quick --dry-run
      - name: Upload logs
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: test-logs
          path: /tmp/fedora-harden-test-*.log
```

### Local Development Workflow

```bash
# 1. Make changes to script
nano fedora-harden.sh

# 2. Quick syntax check
bash -n fedora-harden.sh

# 3. Fast container test
./test-in-podman.sh --quick --dry-run

# 4. Test specific section
./test-in-podman.sh --quick --only 5 --dry-run

# 5. Interactive debugging
./test-in-podman.sh --quick -it
# Inside: ./fedora-harden.sh --dry-run --only 5

# 6. Full system test before commit
./test-in-podman.sh --dry-run
```

## Advanced Testing

### Manual Container Operations

```bash
# Build image manually
podman build -f Dockerfile.test -t fedora-harden:test .

# Build quick variant
podman build --target test-only -f Dockerfile.test -t fedora-harden:test-only .

# Run container directly with full control
podman run -it --rm \
  --memory 512m \
  --cpus 2 \
  --volume ./fedora-harden.sh:/root/fedora-harden.sh:ro \
  fedora-harden:test /bin/bash

# View container logs after test
podman logs <container-name>

# Inspect running container
podman exec -it <container-name> /bin/bash

# List all containers
podman ps -a

# Remove dangling images
podman image prune -f
```

### Testing with Network Isolation

```bash
# Test without network access (safer, faster)
./test-in-podman.sh --quick --dry-run

# Or manually disable network
podman run --rm --network none \
  --volume ./fedora-harden.sh:/root/fedora-harden.sh:ro \
  fedora-harden:test-only /root/fedora-harden.sh --dry-run --yes
```

### Testing with Volume Mounts

```bash
# Test with audit output saved to host
podman run --rm \
  --volume ./fedora-harden.sh:/root/fedora-harden.sh:ro \
  --volume /tmp/fedora-harden-output:/var/log/fedora-harden:rw \
  fedora-harden:test-only /root/fedora-harden.sh --dry-run --yes

# View results on host
ls -la /tmp/fedora-harden-output/
cat /tmp/fedora-harden-output/harden-*.log
```

## Troubleshooting

### Container Won't Start

```bash
# Check if podman is running
podman --version

# Verify image exists
podman image ls | grep fedora-harden

# Rebuild from scratch
rm -f ~/.local/share/containers/storage/images/*/fedora-harden*
./test-in-podman.sh --quick --dry-run
```

### Out of Memory

```bash
# Increase memory limit
./test-in-podman.sh --quick --memory 512m --dry-run

# Check host memory
free -h
```

### Slow Performance

```bash
# Check CPU allocation
./test-in-podman.sh --quick --cpus 2 --dry-run

# View system load
top  # Or: htop

# Use more CPUs if available
./test-in-podman.sh --cpus 4 --dry-run
```

### Permission Denied Errors

```bash
# Ensure podman has proper permissions
groups $USER | grep -q podman || usermod -aG podman $USER

# Restart user session or use sudo temporarily
newgrp podman

# Or run with sudo (less ideal)
sudo ./test-in-podman.sh --quick --dry-run
```

## Performance Benchmarks

Typical execution times on modern hardware:

| Test Type | Memory | CPUs | Time | Notes |
|-----------|--------|------|------|-------|
| Quick (no systemd) | 256 MB | 1 | 1-2 min | Best for CI |
| Quick (full script) | 256 MB | 2 | 2-3 min | |
| Full (with systemd) | 512 MB | 2 | 3-5 min | More realistic |
| Full (verbose) | 512 MB | 4 | 2-3 min | Faster output |

First run includes image build (~1-2 min). Subsequent runs use cached layer.

## Image Size Optimization

Current image sizes:

```
fedora-harden:test-only    ~150 MB (quick variant)
fedora-harden:test         ~400 MB (full variant with systemd)
```

Optimizations applied:
- Minimal base image (fedora:44-minimal)
- Disabled documentation in DNF
- Disabled weak dependencies
- Removed package manager cache
- Single RUN layer where possible

## Security Considerations

Testing containers are configured with:
- **Dropped capabilities**: All except required ones
- **Read-only mounts**: Script mounted as read-only
- **Isolated network**: Optional network isolation
- **Resource limits**: Prevent resource exhaustion attacks
- **Non-root user**: Available for non-privileged testing

## See Also

- `fedora-harden.sh --help` - Script usage
- `Dockerfile.test` - Container configuration
- `test-in-podman.sh --help` - Test runner options
