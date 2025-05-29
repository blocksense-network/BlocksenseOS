# BlocksenseOS

A Linux distribution based on NixOS designed for remote TEE (Trusted Execution Environment) environments. BlocksenseOS provides confidential computing capabilities with built-in attestation services and secure workload execution.

## Architecture

BlocksenseOS includes:
- **C++ Echo Service**: TCP echo server demonstrating native service integration
- **Rust Echo Service**: Async TCP echo server showcasing Rust workloads  
- **Attestation Agent**: TEE attestation verification service
- **Rust Client**: Verification client for testing services and attestations
- **NixOS Modules**: Security-hardened system configuration

See the [BlocksenseOS Design](./docs/BlocksenseOS-Design.md) document for detailed architecture information.

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

- AppArmor and audit logging enabled
- Firewall configured for minimal attack surface
- Kernel hardening with sysctl parameters
- TPM2 support for hardware-based attestation
- Blacklisted unnecessary kernel modules
- User isolation with dedicated service accounts

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

- [Design Document](./docs/BlocksenseOS-Design.md) - Architecture and design decisions
- [Development Plan](./docs/BlocksenseOS-DevelopmentPlan.md) - Implementation roadmap

## License

See [LICENSE](./LICENSE) for license information.