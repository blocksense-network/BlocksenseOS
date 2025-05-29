{
  description = "BlocksenseOS - Confidential Computing Operating System";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            git
            figlet
            just  # Command runner for common tasks
            ruby  # For the test script
            # TEE development tools
            tpm2-tools
            qemu
            # Build tools
            cmake
            cargo
            rustc
            # Attestation libraries
            openssl
            # Additional tools for development
            pkg-config
            gcc
            gdb
            # Network testing tools
            netcat-gnu
            # Nix tools
            nixfmt-rfc-style
          ];
          shellHook = ''
            figlet "BlocksenseOS"
            echo "TEE-enabled confidential computing environment"
            echo "Available commands:"
            echo "  just --list              # Show all available Just commands"
            echo "  just build-all           # Build all services"
            echo "  just test                # Run all tests"
            echo "  just dev                 # Enter development shell"
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
            version = "0.1.0";
            src = ./services/cpp-echo;
            nativeBuildInputs = [ pkgs.cmake pkgs.pkg-config ];
            buildInputs = [ pkgs.openssl ];
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
            buildInputs = [ pkgs.openssl ];
            nativeBuildInputs = [ pkgs.pkg-config ];
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
            buildInputs = [ pkgs.openssl ];
            nativeBuildInputs = [ pkgs.pkg-config ];
          };

          # VM image for local testing
          blocksenseOS-vm = self.nixosConfigurations.blocksenseOS.config.system.build.vm;
          
          # ISO image for deployment
          blocksenseOS-iso = self.nixosConfigurations.blocksenseOS-iso.config.system.build.isoImage;
        };
      }) // {
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
