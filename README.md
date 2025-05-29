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
# Enter development shell
nix develop
# or with just
just dev
```

## Build Commands

### Using Just (Recommended)

View all available commands:
```bash
just
```

#### Building Services
```bash
# Build all services
just build-all

# Build individual services
just build-cpp          # C++ echo service
just build-rust         # Rust echo service  
just build-attestation  # Attestation agent
just build-client       # Rust verification client
```

#### Building Images
```bash
# Build VM image for testing
just build-vm

# Build ISO image for deployment
just build-iso
```

#### Testing
```bash
# Run all tests
just test

# Test builds only
just test-build

# Test VM configuration
just test-vm

# Run integration tests
just test-integration
```

#### Running Services
```bash
# Start individual services (for development/testing)
just start-cpp          # Start C++ echo service on port 8080
just start-rust         # Start Rust echo service on port 8081
just start-attestation  # Start attestation agent
```

#### Testing Services
```bash
# Test with netcat
just test-echo-cpp      # Test C++ service
just test-echo-rust     # Test Rust service

# Test with Rust client
just test-client-cpp    # Test C++ service via client
just test-client-rust   # Test Rust service via client
```

#### Development
```bash
# Check flake configuration
just check

# Update dependencies
just update

# Format Nix files
just fmt

# Clean build artifacts
just clean

# Show system information
just info
```

#### VM Operations
```bash
# Run VM for testing
just run-vm
```

### Using Nix Directly

If you prefer using Nix commands directly:

```bash
# Build services
nix build .#cpp-echo-service
nix build .#rust-echo-service
nix build .#attestation-agent
nix build .#rust-client

# Build VM
nix build .#blocksenseOS-vm

# Run tests
./scripts/test.sh all
```

## Development Workflow

1. **Setup Development Environment**:
   ```bash
   nix develop  # or: just dev
   ```

2. **Build and Test Services**:
   ```bash
   just build-all
   just test
   ```

3. **Test Individual Services**:
   ```bash
   # Terminal 1: Start C++ service
   just start-cpp
   
   # Terminal 2: Test the service
   just test-echo-cpp
   ```

4. **Build and Test VM**:
   ```bash
   just build-vm
   just test-vm
   just run-vm
   ```

## Service Ports

- **C++ Echo Service**: Port 8080
- **Rust Echo Service**: Port 8081
- **Attestation Agent**: Port 3000 (HTTP API)

## Testing Services

### Using netcat
```bash
echo "Hello World!" | nc localhost 8080  # C++ service
echo "Hello World!" | nc localhost 8081  # Rust service
```

### Using the Rust Client
```bash
./result/bin/rust-client test-echo --service cpp-echo --message "Test message"
./result/bin/rust-client test-echo --service rust-echo --message "Test message"
./result/bin/rust-client attest --service cpp-echo
```

## Security Features

- AppArmor and audit logging enabled
- Firewall configured for minimal attack surface
- Kernel hardening with sysctl parameters
- TPM2 support for hardware-based attestation
- Blacklisted unnecessary kernel modules
- User isolation with dedicated service accounts

## Documentation

- [Design Document](./docs/BlocksenseOS-Design.md) - Architecture and design decisions
- [Development Plan](./docs/BlocksenseOS-DevelopmentPlan.md) - Implementation roadmap

## License

See [LICENSE](./LICENSE) for license information.
