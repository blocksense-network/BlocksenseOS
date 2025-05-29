# BlocksenseOS Maintainer Guide

This document contains technical information for maintainers and contributors working on BlocksenseOS.

## Table of Contents

- [Development Environment Setup](#development-environment-setup)
- [CI/CD Pipeline](#cicd-pipeline)
- [Build System](#build-system)
- [Testing Strategy](#testing-strategy)
- [Dependency Management](#dependency-management)
- [Release Process](#release-process)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

## Development Environment Setup

### Prerequisites

BlocksenseOS uses Nix for reproducible development environments. The project is designed to work seamlessly with:

- **Nix Flakes**: For dependency management and reproducible builds
- **Just**: For task automation (installed via Nix)
- **Dev Container**: Pre-configured Ubuntu 24.04.2 LTS environment

### Getting Started

1. **Enter the development environment**:
   ```bash
   nix develop
   ```

2. **Available Just commands**:
   ```bash
   just --list
   ```

3. **Build all components**:
   ```bash
   just build-all
   ```

### Development Tools

The development environment includes:
- Git (built from source)
- Rust toolchain with necessary targets
- C++ development tools (CMake, GCC)
- Security scanning tools
- Documentation generators

## CI/CD Pipeline

BlocksenseOS uses a comprehensive multi-stage CI pipeline that ensures code quality, security, and reproducibility.

### Pipeline Architecture

The CI system is implemented across multiple GitHub Actions workflows:

#### 1. Main CI Pipeline (`.github/workflows/ci.yml`)

**Triggers**:
- Push to `main` or `develop` branches
- Pull requests to `main`

**Stages**:

1. **Code Quality & Security**
   - Static analysis and linting
   - Secret scanning with TruffleHog
   - Change detection for selective testing
   - Nix flake validation

2. **Build Matrix**
   - Parallel builds of all components:
     - `cpp-echo-service`
     - `rust-echo-service` 
     - `attestation-agent`
     - `derivation-hasher`
   - Artifact upload for downstream testing

3. **Service Integration Tests**
   - Cross-service communication testing
   - API contract validation
   - Performance benchmarking

4. **VM and System Tests**
   - Full system integration testing
   - NixOS module validation
   - Security policy enforcement testing

5. **Security & Attestation Tests**
   - Cryptographic attestation validation
   - TEE (Trusted Execution Environment) testing
   - Security boundary verification

6. **Documentation & Reproducibility**
   - Documentation generation and validation
   - Reproducible build verification
   - Nix derivation integrity checks

#### 2. Dependency Updates (`.github/workflows/dependency-updates.yml`)

**Schedule**: Weekly on Mondays at 6 AM UTC

**Automated Tasks**:
- Nix flake input updates
- Rust crate dependency updates
- Dependency freshness checking
- Automated PR creation with test results

### CI Environment Configuration

```yaml
env:
  NIX_CONFIG: |
    experimental-features = nix-command flakes
    accept-flake-config = true
```

### Workflow Dependencies

The pipeline uses conditional execution based on change detection:

- **Nix changes**: `**/*.nix`, `flake.lock`, `flake.nix`
- **Rust changes**: `**/Cargo.toml`, `**/Cargo.lock`, `**/*.rs`
- **C++ changes**: `**/*.cpp`, `**/*.h`, `**/CMakeLists.txt`
- **Documentation**: `**/*.md`, `docs/**`
- **CI configuration**: `.github/workflows/**`

## Build System

### Just Commands

The project uses Just for task automation. Key commands include:

```bash
# Development
just build-all                    # Build all components
just build-cpp                    # Build C++ services
just build-rust                   # Build Rust services
just build-attestation           # Build attestation agent
just build-derivation-hasher     # Build derivation hasher
just build-client                # Build client applications

# Testing
just ci-code-quality             # Run code quality checks
just ci-build-matrix             # Run build matrix
just ci-service-tests            # Run service integration tests
just ci-vm-tests                 # Run VM and system tests
just ci-security-tests           # Run security and attestation tests
just ci-docs-reproducibility     # Run documentation and reproducibility tests
just ci-full                     # Run complete CI pipeline locally

# Maintenance
just check-dependency-freshness  # Check for outdated dependencies
just clean                       # Clean build artifacts
just format                      # Format all code
```

### Nix Flake Structure

The `flake.nix` defines:
- Development shells with all required tools
- Package definitions for all components
- NixOS modules for system integration
- Cross-platform build support

## Testing Strategy

### Test Categories

1. **Unit Tests**: Component-level testing within each service
2. **Integration Tests**: Cross-service communication and API testing
3. **System Tests**: Full system behavior in VM environments
4. **Security Tests**: Cryptographic operations and attestation validation
5. **Reproducibility Tests**: Build determinism and Nix derivation integrity

### Local Testing

Run the complete test suite locally:

```bash
just ci-full
```

For faster iteration during development:

```bash
just ci-code-quality    # Quick syntax and style checks
just ci-service-tests   # Test service interactions
```

## Dependency Management

### Automated Updates

The project uses automated dependency management:

- **Weekly Schedule**: Mondays at 6 AM UTC
- **Scope**: Nix flake inputs and Rust crate dependencies
- **Process**: Automated PR creation with test validation

### Manual Updates

For immediate dependency updates:

```bash
# Update Nix dependencies
nix flake update

# Update Rust dependencies
cd attestation-agent && cargo update
cd services/rust-echo && cargo update
cd clients/rust-client && cargo update
cd derivation-hasher && cargo update
```

### Dependency Freshness

Check for outdated dependencies:

```bash
just check-dependency-freshness
```

## Release Process

### Version Management

BlocksenseOS follows semantic versioning:
- **Major**: Breaking changes to public APIs
- **Minor**: New features with backward compatibility
- **Patch**: Bug fixes and security updates

### Release Checklist

1. **Pre-release Validation**
   - [ ] All CI stages pass
   - [ ] Security audit completed
   - [ ] Documentation updated
   - [ ] Performance benchmarks validated

2. **Release Creation**
   - [ ] Tag version in Git
   - [ ] Generate release notes
   - [ ] Build release artifacts
   - [ ] Sign and attest releases

3. **Post-release**
   - [ ] Update dependent projects
   - [ ] Monitor for issues
   - [ ] Prepare hotfix procedure if needed

## Security Considerations

### Secret Management

- **No secrets in repository**: All sensitive data managed externally
- **Secret scanning**: TruffleHog integration in CI
- **Access control**: Limited write access to main branches

### Attestation

- **Build attestation**: All releases include cryptographic attestations
- **Reproducible builds**: Nix ensures build determinism
- **Supply chain security**: Dependency provenance tracking

### Security Testing

- **Static analysis**: Code quality checks include security linting
- **Dynamic testing**: Runtime security validation in VM tests
- **Cryptographic validation**: TEE and attestation testing

## Troubleshooting

### Common Issues

#### Build Failures

1. **Nix cache issues**:
   ```bash
   nix-collect-garbage
   nix develop --refresh
   ```

2. **Rust compilation errors**:
   ```bash
   cargo clean
   just build-rust
   ```

3. **C++ build issues**:
   ```bash
   rm -rf build/
   just build-cpp
   ```

#### CI Pipeline Issues

1. **Flaky tests**: Check VM resource constraints
2. **Dependency conflicts**: Review recent dependency updates
3. **Timeout issues**: Monitor CI runner capacity

### Getting Help

For maintainer-specific issues:
1. Check recent CI runs for similar failures
2. Review dependency update PRs for related changes
3. Consult the development team for complex issues

### Performance Monitoring

Monitor CI pipeline performance:
- **Build times**: Track across components and stages
- **Test execution**: Identify slow or flaky tests
- **Resource usage**: VM and container resource consumption

---

**Last Updated**: May 29, 2025
**Maintainer Contact**: Development Team