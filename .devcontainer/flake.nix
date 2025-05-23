{
  description = "BlocksenseOS Dev Container & Distribution";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachSystem ["x86_64-linux" "aarch64-linux"] (system: let
      pkgs = import nixpkgs {inherit system;};
    in {
      # ── Dev‑time conveniences ──────────────────────────────────────
      devShells.default = pkgs.mkShell {
        buildInputs = [pkgs.git pkgs.cacert pkgs.nixFlakes];
        shellHook = ''
          echo "Welcome to the BlocksenseOS distribution dev shell"
        '';
      };

      packages.default = pkgs.runCommandNoCC "blocksenseos-dummy" {} ''
        mkdir -p $out
        echo "Hello from BlocksenseOS" > $out/README
      '';

      # ── NixOS configuration for this system ───────────────────────
      nixosConfigurations.${system}.default = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [./configuration.nix];
      };
    })
    // {
      # Convenience alias so the attribute path in Dockerfile is shorter.
      nixosConfigurations = {
        default = self.nixosConfigurations.x86_64-linux.default;
      };
    };
}
