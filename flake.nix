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
          ];
          shellHook = ''
            figlet "BlocksenseOS"
            echo "TEE-enabled confidential computing environment"
            echo "Available commands:"
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
        };

        nixosConfigurations.blocksenseOS = nixpkgs.lib.nixosSystem {
          inherit system;
          modules = [
            ./nixos-modules/base.nix
            ./nixos-modules/security.nix
            ./nixos-modules/services.nix
          ];
        };
      });
}
