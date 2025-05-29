# BlocksenseOS Justfile
# Common build and development commands

# Default recipe that shows available commands
default:
    @just --list

# Build all services
build-all:
    mkdir -p build
    nix build .#cpp-echo-service -o build/cpp-echo-service
    nix build .#rust-echo-service -o build/rust-echo-service  
    nix build .#attestation-agent -o build/attestation-agent

# Build all services including rust-client (requires committed Cargo.lock)
build-all-with-client:
    mkdir -p build
    nix build .#cpp-echo-service -o build/cpp-echo-service
    nix build .#rust-echo-service -o build/rust-echo-service
    nix build .#attestation-agent -o build/attestation-agent
    nix build .#rust-client -o build/rust-client

# Build individual services
build-cpp:
    mkdir -p build
    nix build .#cpp-echo-service -o build/cpp-echo-service

build-rust:
    mkdir -p build
    nix build .#rust-echo-service -o build/rust-echo-service

build-attestation:
    mkdir -p build
    nix build .#attestation-agent -o build/attestation-agent

build-client:
    mkdir -p build
    nix build .#rust-client -o build/rust-client

# Build VM image for testing
build-vm:
    mkdir -p build
    nix build .#blocksenseOS-vm -o build/vm

# Build ISO image for deployment
build-iso:
    mkdir -p build
    nix build .#blocksenseOS-image -o build/iso

# Development shell
dev:
    nix develop

# Run the VM for testing
run-vm: build-vm
    ./build/vm/bin/run-nixos-vm

# Test all components
test: build-all
    ./scripts/test.rb all

# Test only builds (no integration tests)
test-build:
    ./scripts/test.rb build

# Test VM configuration
test-vm:
    ./scripts/test.rb vm

# Run integration tests (assumes services are running)
test-integration:
    ./scripts/test.rb integration

# Clean build artifacts
clean:
    rm -rf build
    nix-collect-garbage

# Check flake
check:
    nix flake check

# Update flake inputs
update:
    nix flake update

# Format Nix files
fmt:
    nix fmt

# Start C++ echo service (for testing)
start-cpp: build-cpp
    ./build/cpp-echo-service

# Start Rust echo service (for testing)
start-rust: build-rust
    ./build/rust-echo-service

# Start attestation agent (for testing)
start-attestation: build-attestation
    ./build/attestation-agent

# Test echo services with netcat
test-echo-cpp:
    echo "Hello BlocksenseOS!" | nc localhost 8080

test-echo-rust:
    echo "Hello BlocksenseOS!" | nc localhost 8081

# Test services using the Rust client
test-client-cpp: build-client
    ./build/rust-client test-echo --service cpp-echo --message "Hello from Just!"

test-client-rust: build-client
    ./build/rust-client test-echo --service rust-echo --message "Hello from Just!"

# Show system info
info:
    @echo "BlocksenseOS Development Environment"
    @echo "===================================="
    @echo "OS: $(uname -a)"
    @echo "Nix version: $(nix --version)"
    @echo "Available packages:"
    @nix flake show . | head -20