{
  description = "BlocksenseOS - Confidential Computing Operating System";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    nixpkgs-unstable,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {inherit system;};
      unstablePkgs = import nixpkgs-unstable {inherit system;};
      # Define Linux-specific packages that aren't available on all platforms
      linuxOnlyPackages = pkgs.lib.optionals pkgs.stdenv.isLinux [
        pkgs.tpm2-tools
        pkgs.qemu
        pkgs.gdb
        pkgs.netcat-gnu
      ];
    in {
      devShells.default = pkgs.mkShell {
        buildInputs = with pkgs;
          [
            git
            figlet
            just # Command runner for common tasks
            ruby # For the test script
            # Build tools
            cmake
            cargo
            rustc
            clippy # Rust linting tool
            rustfmt # Rust formatting tool
            # C++ development tools
            clang-tools # Includes clang-format for C++ linting
            # Modern C++ async I/O library
            asio # Standalone ASIO for coroutines and async networking
            # Attestation libraries
            openssl
            # Additional tools for development
            pkg-config
            gcc
            # Nix tools
            nixfmt-rfc-style
            alejandra # Nix formatter
            # Configuration and data tools
            dhall # Dhall configuration language
            dhall-json # Dhall to JSON conversion (needed for act token script)
            # GitHub Actions and CI tools
            act # Run GitHub Actions locally
            jq # JSON processor for dependency checks
            # Networking tools for CI tests
            netcat-gnu # For testing echo services
            curl # For HTTP endpoint testing
            # Security audit tools
            cargo-audit
            cargo-deny
            cargo-outdated
            # Additional security tools for comprehensive auditing
            semgrep # Static analysis security scanner
            bandit # Python security linter (in case we add Python scripts)
            shellcheck # Shell script analysis
            # Performance testing tools
            hey # HTTP load testing tool
            # Documentation tools
            mdbook # For generating documentation
            # Supply chain security tools
            cargo-cyclonedx # SBOM generation for Rust projects
            cyclonedx-cli # CycloneDX CLI tool for SBOM analysis
            unstablePkgs.trivy # Use latest Trivy version from unstable to fix AWS policy parsing issues
            cosign # Container signing
            syft # SBOM generation alternative
            # Repository packaging tools
            repomix # AI-friendly repository packaging
          ]
          ++ linuxOnlyPackages; # Add Linux-specific packages conditionally
        shellHook = ''
          figlet "BlocksenseOS"
          echo "TEE-enabled confidential computing environment"

          echo "Available commands:"
          echo "  just --list              # Show all available Just commands"
          echo "  just build-all           # Build all services"
          echo "  just test                # Run all tests"
          echo "  just ci-full             # Run full CI pipeline locally"
          echo "  just run-github-workflows # Run GitHub workflows locally"
          echo "  just dev                 # Enter development shell"
          echo "  repomix                  # Package repository for AI analysis"
          echo ""
          echo "Direct Nix commands:"
          echo "  nix build .#cpp-echo-service"
          echo "  nix build .#rust-echo-service"
          echo "  nix build .#attestation-agent"
        '';
      };

      packages = {
        cpp-echo-service = pkgs.stdenv.mkDerivation {
          pname = "cpp-echo-service";
          version = "0.2.0";
          src = ./services/cpp-echo;
          nativeBuildInputs = [pkgs.cmake pkgs.pkg-config];
          buildInputs = [pkgs.asio pkgs.openssl];

          configurePhase = ''
            cmake -B build -S . -DCMAKE_INSTALL_PREFIX=$out
          '';

          buildPhase = ''
            cmake --build build
          '';

          installPhase = ''
            cmake --install build
          '';
        };

        rust-echo-service = pkgs.rustPlatform.buildRustPackage {
          pname = "rust-echo-service";
          version = "0.1.0";
          src = ./services/rust-echo;
          cargoLock = {
            lockFile = ./services/rust-echo/Cargo.lock;
          };
        };

        attestation-agent = pkgs.rustPlatform.buildRustPackage {
          pname = "attestation-agent";
          version = "0.1.0";
          src = ./attestation-agent;
          cargoLock = {
            lockFile = ./attestation-agent/Cargo.lock;
          };
          buildInputs = [pkgs.openssl];
          nativeBuildInputs = [pkgs.pkg-config];
        };

        derivation-hasher = pkgs.rustPlatform.buildRustPackage {
          pname = "derivation-hasher";
          version = "0.1.0";
          src = ./derivation-hasher;
          cargoLock = {
            lockFile = ./derivation-hasher/Cargo.lock;
          };
        };

        rust-client = pkgs.rustPlatform.buildRustPackage {
          pname = "rust-client";
          version = "0.1.0";
          src = ./clients/rust-client;
          cargoLock = {
            lockFile = ./clients/rust-client/Cargo.lock;
          };
          buildInputs = [pkgs.openssl];
          nativeBuildInputs = [pkgs.pkg-config];
        };

        # VM image for local testing
        blocksenseOS-vm = self.nixosConfigurations.blocksenseOS.config.system.build.vm;

        # ISO image for deployment
        blocksenseOS-iso = self.nixosConfigurations.blocksenseOS-iso.config.system.build.isoImage;
      };
    })
    // {
      # NixOS configurations at flake root level
      nixosConfigurations.blocksenseOS = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          ./nixos-modules/base.nix
          ./nixos-modules/security.nix
          ./nixos-modules/services.nix
          {
            _module.args.self = self;
          }
        ];
      };

      # ISO image configuration with installation-cd profile
      nixosConfigurations.blocksenseOS-iso = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          "${nixpkgs}/nixos/modules/installer/cd-dvd/installation-cd-minimal.nix"
          ./nixos-modules/base.nix
          ./nixos-modules/security.nix
          ./nixos-modules/services.nix
          {
            _module.args.self = self;
            isoImage.makeEfiBootable = true;
            isoImage.makeUsbBootable = true;
            # Override SSH settings for installation media
            services.openssh.settings.PermitRootLogin = nixpkgs.lib.mkForce "yes";
            # Disable wireless to avoid conflict with NetworkManager
            networking.wireless.enable = nixpkgs.lib.mkForce false;
          }
        ];
      };
    };
}
