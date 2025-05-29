# BlocksenseOS Justfile
# Common build and development commands

# Default recipe that shows available commands
default:
    @just --list

# === BUILD TARGETS ===

# Build all services
build-all: build-cpp-echo-service build-rust-echo-service build-attestation-agent build-derivation-hasher

# Build all services including rust-client (requires committed Cargo.lock)
build-all-with-client: build-all build-rust-client

# Build individual services (with output to build/ folder)
build-cpp-echo-service:
    nix build .#cpp-echo-service -o build/cpp-echo-service

build-rust-echo-service:
    nix build .#rust-echo-service -o build/rust-echo-service

build-attestation-agent:
    nix build .#attestation-agent -o build/attestation-agent

build-rust-client:
    nix build .#rust-client -o build/rust-client

build-derivation-hasher:
    nix build .#derivation-hasher -o build/derivation-hasher

# Build release artifacts
build-release: build-all-with-client

# Build VM image for testing
build-vm:
    nix build .#vm -o build/vm

# Build ISO image for deployment
build-iso:
    nix build .#iso -o build/iso

# === DEVELOPMENT ENVIRONMENT ===

# Enter development shell
dev:
    nix develop

# === START SERVICES ===

# Start C++ echo service on port 8080
start-cpp-echo-service:
    ./build/cpp-echo-service

# Start Rust echo service on port 8081
start-rust-echo-service:
    ./build/rust-echo-service

# Start attestation agent on port 3000
start-attestation-agent:
    ./build/attestation-agent

# === TESTING ===

# Run all tests
test:
    ./scripts/test.rb all

# Test build functionality only
test-build:
    ./scripts/test.rb build

# Test VM configuration
test-vm:
    ./scripts/test.rb vm

# Test integration scenarios
test-integration:
    ./scripts/test.rb integration

# Test service startup performance
test-service-startup:
    @echo "Testing service startup times..."
    @echo "Starting C++ service..."
    @time just start-cpp-echo-service &
    @CPP_PID=$!
    @sleep 2
    @echo "Starting Rust service..."
    @time just start-rust-echo-service &
    @RUST_PID=$!
    @sleep 2
    @echo "Starting attestation agent..."
    @time just start-attestation-agent &
    @ATTESTATION_PID=$!
    @sleep 2
    @echo "Cleaning up..."
    @kill $CPP_PID $RUST_PID $ATTESTATION_PID 2>/dev/null || true

# Test C++ echo service with netcat
test-echo-cpp-service:
    @echo "Testing C++ echo service on port 8080..."
    echo "Hello from C++ service test!" | nc localhost 8080

# Test Rust echo service with netcat
test-echo-rust-service:
    @echo "Testing Rust echo service on port 8081..."
    echo "Hello from Rust service test!" | nc localhost 8081

# Test C++ service using Rust client
test-client-cpp-service:
    ./build/rust-client/bin/rust-client test-echo --service cpp-echo --message "Test message from client"

# Test Rust service using Rust client
test-client-rust-service:
    ./build/rust-client/bin/rust-client test-echo --service rust-echo --message "Test message from client"

# Test attestation functionality
test-attestation:
    ./build/rust-client/bin/rust-client attest --service cpp-echo

# === CI TARGETS ===

# Run code quality checks for CI
ci-code-quality: lint

# Run build matrix for CI
ci-build-matrix: build-all

# Run service integration tests for CI
ci-service-tests: test-integration

# Run VM and system tests for CI
ci-vm-tests: test-vm

# Run security and attestation tests for CI
ci-security-tests: test-attestation security-audit

# Run documentation and reproducibility tests for CI
ci-docs-reproducibility: check generate-docs

# Run full CI pipeline locally
ci-full: ci-code-quality ci-build-matrix ci-service-tests ci-vm-tests ci-security-tests ci-docs-reproducibility

# === LINTING AND FORMATTING ===

# Lint all code
lint: lint-nix lint-rust lint-cpp

# Lint Nix files using alejandra
lint-nix:
    @echo "=== Linting Nix files with alejandra ==="
    alejandra --check .

# Format Nix files using alejandra
fmt-nix:
    @echo "=== Formatting Nix files with alejandra ==="
    alejandra .

# Lint Rust code
lint-rust:
    @echo "=== Linting Rust code ==="
    cd attestation-agent && cargo clippy -- -D warnings && cargo fmt --check
    cd services/rust-echo && cargo clippy -- -D warnings && cargo fmt --check
    cd clients/rust-client && cargo clippy -- -D warnings && cargo fmt --check
    cd derivation-hasher && cargo clippy -- -D warnings && cargo fmt --check

# Format Rust code
fmt-rust:
    @echo "=== Formatting Rust code ==="
    cd attestation-agent && cargo fmt
    cd services/rust-echo && cargo fmt
    cd clients/rust-client && cargo fmt
    cd derivation-hasher && cargo fmt

# Lint C++ code
lint-cpp:
    @echo "=== Linting C++ code ==="
    cd services/cpp-echo && clang-format --dry-run --Werror *.cpp

# Format C++ code
fmt-cpp:
    @echo "=== Formatting C++ code ==="
    cd services/cpp-echo && clang-format -i *.cpp

# Format all code
fmt: fmt-nix fmt-rust fmt-cpp

# === SECURITY ===

# Run comprehensive security audit
security-audit:
    @echo "=== Running Security Audit ==="
    @echo "Checking for known vulnerabilities in Rust dependencies..."
    cd attestation-agent && cargo audit
    cd services/rust-echo && cargo audit
    cd clients/rust-client && cargo audit
    cd derivation-hasher && cargo audit

# Check license compliance
license-check:
    @echo "=== Checking License Compliance ==="
    @echo "Checking Rust crate licenses..."
    cd attestation-agent && cargo deny check licenses
    cd services/rust-echo && cargo deny check licenses
    cd clients/rust-client && cargo deny check licenses
    cd derivation-hasher && cargo deny check licenses

# === DOCUMENTATION ===

# Generate documentation
generate-docs:
    @echo "=== Generating Documentation ==="
    mkdir -p docs/build
    @echo "Generating Rust documentation..."
    cd attestation-agent && cargo doc --no-deps
    cd services/rust-echo && cargo doc --no-deps
    cd clients/rust-client && cargo doc --no-deps
    cd derivation-hasher && cargo doc --no-deps
    @echo "Copying documentation to docs/build..."
    cp -r attestation-agent/target/doc docs/build/rust-docs 2>/dev/null || true

# === MAINTENANCE ===

# Check dependency freshness
check-dependency-freshness:
    @echo "=== Checking Dependency Freshness ==="
    @echo "Checking Nix flake inputs..."
    nix flake metadata --json | jq -r '.locks.nodes | to_entries[] | select(.key != "root") | "\(.key): \(.value.locked.lastModified // "unknown")"'
    @echo ""
    @echo "Checking Rust dependencies..."
    cd attestation-agent && cargo outdated || echo "cargo-outdated not available"
    cd services/rust-echo && cargo outdated || echo "cargo-outdated not available"
    cd clients/rust-client && cargo outdated || echo "cargo-outdated not available"
    cd derivation-hasher && cargo outdated || echo "cargo-outdated not available"

# Check flake configuration
check:
    nix flake check

# Update flake dependencies
update:
    nix flake update

# Clean build artifacts
clean:
    rm -rf build result result-*

# Show system and project information
info:
    @echo "=== System Information ==="
    @echo "OS: $(uname -s)"
    @echo "Architecture: $(uname -m)"
    @echo "Nix version: $(nix --version)"
    @echo "Just version: $(just --version)"
    @echo ""
    @echo "=== Project Information ==="
    @echo "Available build targets:"
    @nix eval --raw .#packages.x86_64-linux --apply 'pkgs: builtins.concatStringsSep "\n" (builtins.attrNames pkgs)'

# === VM OPERATIONS ===

# Run VM for testing
run-vm:
    nix run .#vm

# === GITHUB WORKFLOWS ===

# Run GitHub workflows locally using act (requires Docker)
run-github-workflows:
    @echo "=== Running GitHub Workflows Locally ==="
    @if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then \
        echo "❌ Docker is not available or not running."; \
        echo ""; \
        echo "To run GitHub workflows locally, you need Docker running."; \
        echo "Alternatively, you can run the equivalent CI commands directly:"; \
        echo ""; \
        echo "  just ci-full                    # Run full CI pipeline locally"; \
        echo "  just ci-code-quality           # Code quality checks"; \
        echo "  just ci-build-matrix           # Build all components"; \
        echo "  just ci-service-tests          # Service integration tests"; \
        echo "  just ci-vm-tests               # VM and system tests"; \
        echo "  just ci-security-tests         # Security and attestation tests"; \
        echo "  just ci-docs-reproducibility   # Documentation tests"; \
        echo ""; \
        exit 1; \
    fi
    @echo "Running main CI pipeline..."
    act -W .github/workflows/ci.yml

# Run GitHub workflows locally (Docker-free alternative)
run-ci-equivalent:
    @echo "=== Running CI Pipeline Equivalent (Docker-free) ==="
    @echo "This runs the same tests as GitHub workflows but without Docker dependency"
    @echo ""
    just ci-full

# Run specific GitHub workflow (requires Docker)
run-workflow workflow:
    @echo "=== Running {{workflow}} workflow locally ==="
    @if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then \
        echo "❌ Docker is not available or not running."; \
        echo "Please start Docker or use 'just run-ci-equivalent' for Docker-free testing."; \
        exit 1; \
    fi
    act -W .github/workflows/{{workflow}}.yml

# Run all GitHub workflows for testing (requires Docker)
run-all-workflows:
    @echo "=== Running All GitHub Workflows Locally ==="
    @if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then \
        echo "❌ Docker is not available or not running."; \
        echo "Please start Docker or use 'just run-ci-equivalent' for Docker-free testing."; \
        exit 1; \
    fi
    @echo "1. Running CI workflow..."
    act -W .github/workflows/ci.yml || echo "CI workflow completed"
    @echo ""
    @echo "2. Running Performance tests..."
    act -W .github/workflows/performance.yml || echo "Performance tests completed"
    @echo ""
    @echo "3. Running TEE Attestation tests..."
    act -W .github/workflows/tee-attestation.yml || echo "TEE attestation tests completed"
    @echo ""
    @echo "4. Running Security Audit..."
    act -W .github/workflows/security-audit.yml || echo "Security audit completed"
    @echo ""
    @echo "5. Running Dependency Updates..."
    act -W .github/workflows/dependency-updates.yml || echo "Dependency updates completed"

# Check if Docker is available for running workflows
check-docker:
    @echo "=== Checking Docker Availability ==="
    @if command -v docker >/dev/null 2>&1; then \
        echo "✅ Docker command found"; \
        if docker info >/dev/null 2>&1; then \
            echo "✅ Docker daemon is running"; \
            echo "✅ Ready to run GitHub workflows locally with act"; \
        else \
            echo "❌ Docker daemon is not running"; \
            echo "Please start Docker to use 'just run-github-workflows'"; \
        fi; \
    else \
        echo "❌ Docker command not found"; \
        echo "Please install Docker to use 'just run-github-workflows'"; \
    fi
    @echo ""
    @echo "Alternative: Use 'just run-ci-equivalent' for Docker-free CI testing"
