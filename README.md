# BlocksenseOS

BlocksenseOS is the Blocksense network's **attested configuration of
[ReproOS](https://github.com/metacraft-labs/reprobuild-specs/blob/latest/ReproOS-Remote-Attestation.md)** —
a curated system profile that runs Blocksense workloads inside hardware TEEs
(AMD SEV-SNP, Intel TDX) so that anyone can remotely verify, via hardware
attestation of a reproducibly built image, exactly which software stack a
node is running, and so that service responses can be proven authentic —
including on-chain via zero-knowledge proofs.

The reusable platform machinery (attestable image profile, TEE backends,
measurement tooling, verifier, secret provisioning, sealed storage) is
developed upstream in ReproOS. This repository contains the
Blocksense-specific layer: the configuration itself, service identity and
signed responses, the ZK verification client, and measurement governance.

> **Status:** this repository currently contains the v0.1.0 NixOS-based
> prototype, which is being migrated onto the ReproOS foundation. In the
> prototype, all TEE attestation paths are **mocked** — do not deploy it
> with security expectations. See the
> [migration plan](./docs/ReproOS-Migration.milestones.org) for the
> component-by-component disposition and gates.

## Architecture

Current prototype components:
- **C++ Echo Service**: TCP echo server demonstrating native service integration
- **Rust Echo Service**: Async TCP echo server showcasing Rust workloads
- **Attestation Agent**: HTTP attestation service (prototype; mock TEE backends — to be replaced by the upstream ReproOS agent)
- **Rust Client**: client for testing services (attestation verification not yet implemented)
- **NixOS Modules**: system configuration (to be replaced by the ReproOS `system.nim` profile)

See the [BlocksenseOS Design](./docs/BlocksenseOS-Design.md) document (v0.2.0) for the target architecture and the division of responsibilities between ReproOS and this repository.

## Quick Start

### Prerequisites
- Nix with flakes enabled
- Just command runner (optional but recommended)

### Development Environment
```bash
# Enter development shell (includes all tools and dependencies)
nix develop
# OR using just
just dev

# Build all services
just build-all

# Start services (in separate terminals)
just start-cpp-echo-service      # Port 8080
just start-rust-echo-service     # Port 8081
just start-attestation-agent     # Port 3000

# Test the services
just test-echo-cpp-service
just test-echo-rust-service
```

### Building Individual Components
```bash
# Build specific services
just build-cpp-echo-service
just build-rust-echo-service
just build-attestation-agent
just build-rust-client
just build-derivation-hasher

# Build system images
just build-vm                    # VM image for testing
just build-iso                   # ISO image for deployment
```

## Development Commands

The project uses [Just](https://github.com/casey/just) as a command runner. Run `just` to see all available commands.

### Build Commands
- `just build-all` - Build all core services
- `just build-all-with-client` - Build all services including rust-client
- `just build-cpp-echo-service` - Build C++ echo service
- `just build-rust-echo-service` - Build Rust echo service
- `just build-attestation-agent` - Build attestation agent
- `just build-rust-client` - Build Rust client
- `just build-derivation-hasher` - Build derivation hasher utility
- `just build-vm` - Build VM image for testing
- `just build-iso` - Build ISO image for deployment

### Service Commands
- `just start-cpp-echo-service` - Start C++ echo service (port 8080)
- `just start-rust-echo-service` - Start Rust echo service (port 8081)
- `just start-attestation-agent` - Start attestation agent (port 3000)

### Testing Commands
- `just test` - Run all tests
- `just test-build` - Test build functionality only
- `just test-vm` - Test VM configuration
- `just test-integration` - Test integration scenarios
- `just test-echo-cpp-service` - Test C++ echo service with netcat
- `just test-echo-rust-service` - Test Rust echo service with netcat
- `just test-client-cpp-service` - Test C++ service using Rust client
- `just test-client-rust-service` - Test Rust service using Rust client
- `just test-attestation` - Test attestation functionality

### Code Quality Commands
- `just lint` - Lint all code (Nix, Rust, C++)
- `just lint-nix` - Lint only Nix files
- `just lint-rust` - Lint only Rust code
- `just lint-cpp` - Lint only C++ code
- `just fmt` - Format all code
- `just fmt-nix` - Format only Nix files
- `just fmt-rust` - Format only Rust code
- `just fmt-cpp` - Format only C++ code

### Maintenance Commands
- `just check` - Check flake configuration
- `just update` - Update flake dependencies
- `just clean` - Clean build artifacts
- `just info` - Show system and project information

### VM Operations
- `just run-vm` - Run VM for testing

## Manual Build (without Just)

If you prefer not to use Just, you can build manually:

```bash
# Enter development environment
nix develop

# Build services
nix build .#cpp-echo-service -o build/cpp-echo-service
nix build .#rust-echo-service -o build/rust-echo-service
nix build .#attestation-agent -o build/attestation-agent

# Run services
./build/cpp-echo-service/bin/cpp-echo-service
./build/rust-echo-service/bin/rust-echo-service
./build/attestation-agent/bin/attestation-agent
```

## Security Features

Prototype hardening that is actually in effect today:

- AppArmor and audit logging enabled
- Firewall configured for minimal attack surface
- Kernel hardening with sysctl parameters
- Blacklisted unnecessary kernel modules
- User isolation with dedicated service accounts

**Not yet real** (mocked or absent in the prototype; delivered by the
ReproOS migration): TEE attestation report generation and verification,
reproducible-image measurement, TPM-sealed disk encryption (the root
filesystem is currently plain ext4), and the ZK verification client.
See [THREAT-MODEL.md](./docs/THREAT-MODEL.md) and the
[migration plan](./docs/ReproOS-Migration.milestones.org).

### Security Audit

The project includes comprehensive security auditing:

```bash
# Run full security audit
just security-audit

# Run specific security checks
just security-rust-audit       # Rust vulnerability scanning
just security-sbom             # Generate Software Bill of Materials
just security-vulnerability-scan # Comprehensive vulnerability scan
just security-secret-scan      # Scan for hardcoded secrets
```

### Security Configuration

For production deployments, enable branch protection on GitHub:
1. Go to repository Settings → Branches
2. Add branch protection rule for `main`
3. Enable "Require pull request reviews before merging"
4. Enable "Restrict pushes that create files larger than 100 MB"
5. Enable "Require status checks to pass before merging"

The security audit will identify additional hardening opportunities.

## Documentation

- [Design Document](./docs/BlocksenseOS-Design.md) - Target architecture on the ReproOS foundation (v0.2.0)
- [Threat Model](./docs/THREAT-MODEL.md) - Blocksense-layer threat analysis
- [ReproOS Migration Plan](./docs/ReproOS-Migration.milestones.org) - The active implementation roadmap
- [ReproOS Remote Attestation](https://github.com/metacraft-labs/reprobuild-specs/blob/latest/ReproOS-Remote-Attestation.md) - The upstream platform design this configuration builds on

## License

See [LICENSE](./LICENSE) for license information.