# BlocksenseOS Justfile
# Common build and development commands

set shell := ["./scripts/nix-env.sh", "-c"]

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
    nix build .#blocksenseOS-vm -o build/vm

# Build ISO image for deployment
build-iso:
    nix build .#blocksenseOS-iso -o build/iso

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
test-integration: build-all
    @echo "=== Running Comprehensive Integration Tests ==="
    ./scripts/integration-tests.rb

# === PERFORMANCE TESTING ===

# Run performance testing suite
test-performance: test-startup-performance test-load test-memory-usage

# Test service startup performance
test-startup-performance:
    @echo "=== Service Startup Performance Testing ==="
    ./scripts/test.rb performance-startup

# Run load testing on all services
test-load:
    @echo "=== Load Testing Suite ==="
    ./scripts/test.rb load-testing

# Test memory usage and resource consumption
test-memory-usage:
    @echo "=== Memory Usage Testing ==="
    ./scripts/test.rb memory-testing

# === ATTESTATION TESTING ===

# Run comprehensive attestation testing suite
test-attestation-full: test-attestation-e2e test-tee-compatibility test-attestation-security test-derivation-consistency

# Run end-to-end attestation workflow testing
test-attestation-e2e:
    @echo "=== End-to-End Attestation Testing ==="
    ./scripts/test.rb attestation-e2e

# Test TEE compatibility matrix (SEV-SNP, TDX, SGX)
test-tee-compatibility:
    @echo "=== TEE Compatibility Matrix Testing ==="
    ./scripts/test.rb tee-compatibility

# Test attestation security validation
test-attestation-security:
    @echo "=== Attestation Security Validation ==="
    ./scripts/test.rb attestation-security

# Test derivation hash consistency
test-derivation-consistency:
    @echo "=== Derivation Hash Consistency Testing ==="
    ./scripts/test.rb derivation-consistency

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
    @echo "Starting attestation agent for testing..."
    @./build/attestation-agent/bin/attestation-agent & echo $$! > /tmp/attestation.pid; sleep 3
    @echo "Testing attestation with rust-client..."
    @./build/rust-client/bin/rust-client attest --service cpp-echo || (kill `cat /tmp/attestation.pid` 2>/dev/null; rm -f /tmp/attestation.pid; exit 1)
    @echo "Stopping attestation agent..."
    @kill `cat /tmp/attestation.pid` 2>/dev/null || true
    @rm -f /tmp/attestation.pid

# === CI TARGETS ===

# Run code quality checks for CI
ci-code-quality: lint

# Run build matrix for CI
ci-build-matrix: build-all

# Run unit tests for all Rust components
ci-unit-tests:
    @echo "=== Running Unit Tests for All Components ==="
    cd attestation-agent && cargo test --verbose
    cd services/rust-echo && cargo test --verbose
    cd clients/rust-client && cargo test --verbose
    cd derivation-hasher && cargo test --verbose
    @echo "=== Running Property-Based Tests ==="
    cd attestation-agent && cargo test --verbose --release -- --ignored
    cd services/rust-echo && cargo test --verbose --release -- --ignored
    cd clients/rust-client && cargo test --verbose --release -- --ignored
    cd derivation-hasher && cargo test --verbose --release -- --ignored

# Run service integration tests for CI
ci-service-tests: test-integration

# Run VM and system tests for CI
ci-vm-tests: test-vm build-vm build-iso

# Run security and attestation tests for CI
ci-security-tests: test-attestation security-audit

# Run performance testing suite for CI
ci-performance-tests: test-performance

# Run TEE attestation testing suite for CI
ci-attestation-tests: test-attestation-full

# Run documentation and reproducibility tests for CI
ci-docs-reproducibility: check generate-docs

# Run vulnerability scanning (like CI does)
ci-vulnerability-scan:
    @echo "=== Running Vulnerability Scanning ==="
    trivy fs --format table .

# Run supply chain security checks
ci-supply-chain: security-sbom
    @echo "=== Supply Chain Security Checks Complete ==="

# === WORKFLOW-SPECIFIC CI AGGREGATES ===

# Run main CI pipeline (matches ci.yml workflow)
ci-main: ci-code-quality ci-build-matrix ci-unit-tests ci-service-tests ci-vm-tests ci-docs-reproducibility
    @echo "✅ Main CI pipeline completed successfully!"

# Run security audit workflow (matches security-audit.yml workflow)
ci-security-workflow: security-audit ci-vulnerability-scan ci-supply-chain
    @echo "✅ Security audit workflow completed successfully!"

# Run performance workflow (matches performance.yml workflow)
ci-performance-workflow: ci-performance-tests
    @echo "✅ Performance workflow completed successfully!"

# Run TEE attestation workflow (matches tee-attestation.yml workflow)
ci-tee-workflow: ci-attestation-tests
    @echo "✅ TEE attestation workflow completed successfully!"

# Run COMPLETE CI pipeline (all workflows combined)
ci-full: ci-main ci-security-workflow ci-performance-workflow ci-tee-workflow
    @echo ""
    @echo "🎉 =========================================="
    @echo "🎉 COMPLETE CI PIPELINE FINISHED"
    @echo "🎉 =========================================="
    @echo ""
    @echo "✅ Main CI Pipeline"
    @echo "✅ Security Audit Workflow" 
    @echo "✅ Performance Testing Workflow"
    @echo "✅ TEE Attestation Workflow"
    @echo ""
    @echo "All CI workflows completed successfully!"

# Run minimal CI for quick local testing
ci-quick: ci-code-quality ci-build-matrix ci-service-tests
    @echo "✅ Quick CI checks completed!"

# Run CI without long-running tests (useful for development)
ci-fast: ci-code-quality ci-build-matrix ci-unit-tests ci-service-tests
    @echo "✅ Fast CI pipeline completed!"

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

# Run comprehensive security audit (calls all security components)
security-audit:
    @echo "=== Running Comprehensive Security Audit ==="
    ./scripts/security-audit.rb all

# Run individual security components
security-rust-audit:
    @echo "=== Running Rust Security Audit ==="
    ./scripts/security-audit.rb rust-audit

security-sbom:
    @echo "=== Generating SBOM ==="
    ./scripts/security-audit.rb sbom

security-vulnerability-scan:
    @echo "=== Running Vulnerability Scan ==="
    ./scripts/security-audit.rb vulnerability-scan

security-secret-scan:
    @echo "=== Scanning for Secrets ==="
    ./scripts/security-audit.rb secret-scan

security-nix-validate:
    @echo "=== Validating Nix Configurations ==="
    ./scripts/security-audit.rb nix-validate

security-report:
    @echo "=== Generating Security Report ==="
    ./scripts/security-audit.rb report

# Legacy aliases for backward compatibility (now call the modular script)
generate-sbom: security-sbom

vulnerability-scan: security-vulnerability-scan

secret-scan: security-secret-scan

# Enhanced security audit with custom output directory
security-audit-custom output_dir:
    @echo "=== Running Security Audit with Custom Output ==="
    ./scripts/security-audit.rb -o {{output_dir}} all

# Verbose security audit
security-audit-verbose:
    @echo "=== Running Verbose Security Audit ==="
    ./scripts/security-audit.rb -v all

# Generate JSON security report
security-audit-json:
    @echo "=== Running Security Audit with JSON Report ==="
    ./scripts/security-audit.rb -f json all

# === DOCUMENTATION ===

# Generate clean repomix document containing only git-tracked files for AI review
generate-repomix:
    @echo "=== Generating Clean Repomix Document for AI Review ==="
    @echo "This will create a markdown file containing all git-tracked source files"
    repomix \
        --output blocksense-codebase-clean.md \
        --ignore "**/target/**" \
        --ignore "**/build/**" \
        --ignore "**/result*/**" \
        --ignore "**/.direnv/**" \
        --ignore "**/docs/build/**" \
        --ignore "**/security/reports/**" \
        --ignore "**/security/rust-audit/**" \
        --ignore "**/security/sbom/**" \
        --ignore "**/security/scan-results/**" \
        --ignore "**/security/nix-validation/**" \
        --ignore "**/security/secret-scan/**" \
        --ignore "blocksense-*.md" \
        --ignore "**/*.log" \
        --ignore "**/.cache/**" \
        --ignore "**/__pycache__/**" \
        --ignore "**/*.pyc" \
        --ignore "**/*.pyo"
    @echo "✅ Generated: blocksense-codebase-clean.md"
    @echo "📊 File statistics:"
    @wc -l blocksense-codebase-clean.md
    @du -h blocksense-codebase-clean.md
    @echo ""
    @echo "🤖 This file is optimized for AI code review and should fit within token limits"

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

# Run actual GitHub workflows locally using act
ci-github-main:
  #!/usr/bin/env bash
  set -euo pipefail
  echo "Running GitHub CI workflow locally..."
  act workflow_dispatch -W .github/workflows/ci.yml

ci-github-performance:
  #!/usr/bin/env bash
  set -euo pipefail
  echo "Running GitHub Performance workflow locally..."
  act workflow_dispatch -W .github/workflows/performance.yml

ci-github-security:
  #!/usr/bin/env bash
  set -euo pipefail
  echo "Running GitHub Security Audit workflow locally..."
  act workflow_dispatch -W .github/workflows/security-audit.yml

ci-github-attestation:
  #!/usr/bin/env bash
  set -euo pipefail
  echo "Running GitHub TEE Attestation workflow locally..."
  act workflow_dispatch -W .github/workflows/tee-attestation.yml

ci-github-all: ci-github-main ci-github-performance ci-github-security ci-github-attestation

# Run workflows with custom secrets (recommended approach)
ci-github-main-with-secrets:
  #!/usr/bin/env bash
  set -euo pipefail
  if [[ ! -f .github/act-secrets.local.env ]]; then
    echo "Error: .github/act-secrets.local.env not found"
    echo "Run: ./.github/scripts/get-auth-tokens.sh"
    echo "Or copy .github/act-secrets.local.env.example to .github/act-secrets.local.env and fill in your secrets"
    exit 1
  fi
  echo "Running GitHub CI workflow with local secrets..."
  act workflow_dispatch -W .github/workflows/ci.yml --secret-file .github/act-secrets.local.env --env-file .github/act-env.env

ci-github-performance-with-secrets:
  #!/usr/bin/env bash
  set -euo pipefail
  if [[ ! -f .github/act-secrets.local.env ]]; then
    echo "Error: .github/act-secrets.local.env not found"
    echo "Run: ./.github/scripts/get-auth-tokens.sh"
    echo "Or copy .github/act-secrets.local.env.example to .github/act-secrets.local.env and fill in your secrets"
    exit 1
  fi
  echo "Running GitHub Performance workflow with local secrets..."
  act workflow_dispatch -W .github/workflows/performance.yml --secret-file .github/act-secrets.local.env --env-file .github/act-env.env

ci-github-security-with-secrets:
  #!/usr/bin/env bash
  set -euo pipefail
  if [[ ! -f .github/act-secrets.local.env ]]; then
    echo "Error: .github/act-secrets.local.env not found"
    echo "Run: ./.github/scripts/get-auth-tokens.sh"
    echo "Or copy .github/act-secrets.local.env.example to .github/act-secrets.local.env and fill in your secrets"
    exit 1
  fi
  echo "Running GitHub Security Audit workflow with local secrets..."
  act workflow_dispatch -W .github/workflows/security-audit.yml --secret-file .github/act-secrets.local.env --env-file .github/act-env.env

ci-github-attestation-with-secrets:
  #!/usr/bin/env bash
  set -euo pipefail
  if [[ ! -f .github/act-secrets.local.env ]]; then
    echo "Error: .github/act-secrets.local.env not found"
    echo "Run: ./.github/scripts/get-auth-tokens.sh"
    echo "Or copy .github/act-secrets.local.env.example to .github/act-secrets.local.env and fill in your secrets"
    exit 1
  fi
  echo "Running GitHub TEE Attestation workflow with local secrets..."
  act workflow_dispatch -W .github/workflows/tee-attestation.yml --secret-file .github/act-secrets.local.env --env-file .github/act-env.env

# Generate auth tokens automatically
setup-act-secrets:
  #!/usr/bin/env bash
  set -euo pipefail
  echo "Setting up act secrets using automated token retrieval..."
  ./.github/scripts/get-auth-tokens.sh

# Debug specific workflow events
ci-github-debug-push:
  #!/usr/bin/env bash
  set -euo pipefail
  echo "Simulating push event to main branch..."
  act push -W .github/workflows/ci.yml --eventpath .github/act-events.json

ci-github-debug-pr:
  #!/usr/bin/env bash
  set -euo pipefail
  echo "Simulating pull request event..."
  act pull_request -W .github/workflows/ci.yml --eventpath .github/act-events.json

# List available workflows and jobs
ci-github-list:
  #!/usr/bin/env bash
  set -euo pipefail
  echo "Available GitHub workflows:"
  act --list

# Dry run to see what would execute
ci-github-dry-run:
  #!/usr/bin/env bash
  set -euo pipefail
  echo "Dry run of ci.yml workflow..."
  act workflow_dispatch -W .github/workflows/ci.yml --dry-run

# Run Docker-based GitHub workflows (legacy)
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
        echo "Or use act-based commands (no Docker required):"; \
        echo "  just setup-act-secrets         # Generate tokens automatically"; \
        echo "  just ci-github-main-with-secrets  # Run main CI with act"; \
        echo ""; \
        exit 1; \
    fi
    @echo "Running main CI pipeline..."
    act -W .github/workflows/ci.yml

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
    @echo "Alternative: Use 'just ci-all' for Docker-free CI testing"

# === DEPENDENCY MANAGEMENT ===

# Update all dependencies (Nix flake + Rust crates)
update-dependencies:
    @echo "=== Updating All Dependencies ==="
    @echo "Updating Nix flake inputs..."
    nix flake update
    @echo "Updating Rust dependencies..."
    @for package in attestation-agent services/rust-echo clients/rust-client derivation-hasher; do \
        if [ -d "$$package" ]; then \
            echo "Updating $$package dependencies..."; \
            cd "$$package"; \
            cargo update; \
            cd - >/dev/null; \
        fi; \
    done
    @echo "Testing updated dependencies..."
    just ci-code-quality
    just ci-build-matrix

# === RELEASE MANAGEMENT ===

# Build release artifacts and packages
build-release-artifacts:
    @echo "=== Building Release Artifacts ==="
    just build-release
    @echo "Packaging release artifacts..."
    @VERSION=$${VERSION:-development}; \
    mkdir -p dist; \
    tar -czf "dist/blocksense-os-$${VERSION}-x86_64-linux.tar.gz" \
        build/ \
        README.md \
        LICENSE \
        docs/
