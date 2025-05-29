# Development and CI Agent Guidelines

This document outlines the principles and guidelines for maintaining consistency between CI workflows and local development in the BlocksenseOS project.

## Core Principle: CI-Local Parity

**Everything that CI does MUST be available as a `just` target for local testing.**

This ensures:
- Developers can reproduce CI failures locally
- No surprises when code is pushed to CI
- Consistent development experience across team members
- Easy debugging and iteration

## Build System Requirements

### CMake: Always Use Out-of-Source Builds

**MANDATORY**: All CMake builds MUST use out-of-source builds to maintain clean source trees and enable reproducible builds.

❌ **DON'T** build in the source directory:
```bash
cd services/cpp-echo
cmake .
make
```

✅ **DO** use out-of-source builds:
```bash
cd services/cpp-echo
mkdir -p build
cd build
cmake ..
make
```

**Rationale**:
- Keeps source directory clean for version control
- Enables multiple build configurations (debug/release)
- Prevents contamination of source files with build artifacts
- Essential for Nix reproducible builds
- Allows parallel builds with different toolchains

**Implementation**:
- All CMake projects should include `build/` in `.gitignore`
- CI scripts must create separate build directories
- `just` targets should enforce out-of-source builds
- Documentation should only show out-of-source examples

## Development Environment Setup

To ensure consistency between development and CI environments:

1. **Use Nix for Package Management**
   - All dependencies must be available in the Nix package manager.
   - Development environments should be reproducible using `nix-shell` or `nix develop`.

2. **Editor and IDE Configuration**
   - Configure editors to respect `.editorconfig` and project-specific settings.
   - Use language-specific plugins to enforce style and formatting.

3. **Shell Environment**
   - Use `direnv` or similar tools to manage environment variables and paths.
   - Ensure the shell configuration is compatible with CI environments.

4. **Docker (if applicable)**
   - Use Docker for services or components that require it.
   - Ensure Docker images are up-to-date and match the CI environment.

5. **Hardware Requirements**
   - Ensure local development machines meet the minimum hardware requirements for the project.
   - Consider using cloud-based development environments for resource-intensive tasks.

## Implementation Rules

### 1. No Direct Script Calls in CI

❌ **DON'T** call scripts directly in CI workflows:
```yaml
- name: Run security audit
  run: ./scripts/security-audit.sh
```

✅ **DO** use `just` targets:
```yaml
- name: Run security audit
  run: nix develop --command just security-audit
```

### 2. Just Targets Mirror CI Jobs

Every CI job should have a corresponding `just` target that developers can run locally:

| CI Job | Just Target | Purpose |
|--------|-------------|---------|
| Code Quality & Security | `just ci-code-quality` | Linting, formatting, basic security |
| Build Matrix | `just ci-build-matrix` | Build all components |
| Unit Tests | `just test` | Run unit tests |
| Integration Tests | `just ci-service-tests` | Service integration testing |
| System Tests | `just ci-vm-tests` | VM and system testing |
| Security Tests | `just ci-security-tests` | Security and attestation |
| Documentation | `just ci-docs-reproducibility` | Docs and reproducible builds |

### 3. Complete CI Equivalence

Developers can run the entire CI pipeline locally:

```bash
# Run the complete CI pipeline locally (without Docker)
just ci-full

# Or run individual stages
just ci-code-quality
just ci-build-matrix
just ci-service-tests
just ci-vm-tests
just ci-security-tests
just ci-docs-reproducibility
```

### GitHub Workflows (with Docker)
If you have Docker available, you can run the actual GitHub workflows locally:
```bash
# Check Docker availability
just check-docker

# Run individual workflows
just run-workflow ci
just run-workflow security-audit
just run-workflow performance

# Run all workflows
just run-all-workflows
```

### Docker-Free Alternative
```bash
# Run CI equivalent without Docker
just run-ci-equivalent
```

## Guidelines for New Features

When adding new CI jobs or development tasks:

1. **Create the just target first**
   - Make it work locally
   - Test it thoroughly
   - Document it in the Justfile

2. **Create modular scripts if needed**
   - Accept command-line options
   - Support individual components
   - Provide clear help text

3. **Update CI to use just targets**
   - Never call scripts directly
   - Always use `nix develop --command just <target>`
   - Test that CI uses the same commands developers use

4. **Document the relationship**
   - Update this AGENTS.md file
   - Add comments in the Justfile
   - Update README.md if needed

## Examples of Correct Implementation

### Security Testing
```yaml
# CI Workflow
- name: Run security audit
  run: nix develop --command just security-audit

# Local Development
$ just security-audit
```

### Performance Testing
```yaml
# CI Workflow  
- name: Run performance tests
  run: nix develop --command just test-service-startup

# Local Development
$ just test-service-startup
```

### Build Testing
```yaml
# CI Workflow
- name: Build all components
  run: nix develop --command just build-all

# Local Development
$ just build-all
```

## Validation Checklist

Before adding any CI job, verify:

- [ ] There's a corresponding `just` target
- [ ] The `just` target works in a clean Nix environment
- [ ] The CI workflow uses the `just` target, not direct script calls
- [ ] Developers can reproduce the CI behavior locally
- [ ] The `just` target is documented in the Justfile

## Troubleshooting

### CI Failure Can't Be Reproduced Locally
This indicates a violation of the CI-local parity principle:
1. Check if CI is calling scripts directly instead of just targets
2. Verify the just target uses the same commands as CI
3. Test in a clean Nix environment (`nix develop`)

### Script Works Locally But Not in CI
This usually means:
1. Missing Nix packages in the development environment
2. Path dependencies not properly handled
3. Environment variables not set consistently

### Different Behavior Between Local and CI
Investigate:
1. Are both using the same Nix environment?
2. Are both calling the same just targets?
3. Are there hardcoded paths or assumptions?

## Maintenance

This principle requires ongoing maintenance:

- **Weekly**: Review new CI jobs for compliance
- **Monthly**: Test `just ci-full` in a clean environment
- **Quarterly**: Review and update this documentation
- **Per PR**: Verify new features follow these guidelines

---

**Remember**: If it runs in CI, it must run locally with `just`. No exceptions.