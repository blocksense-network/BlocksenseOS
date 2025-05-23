{
  description = "Blocksense OS";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs { inherit system; };
  in
  {
    devShells.${system}.default = pkgs.mkShell {
      buildInputs = [
        pkgs.git
        pkgs.figlet
        # pkgs.cacert
        # pkgs.nixFlakes
      ];
      shellHook = ''
        figlet "Blocksense OS"
      '';
    };

    packages.${system}.default = pkgs.stdenv.mkDerivation {
      name = "Blocksense OS";
      src = ./.;
      buildInputs = [ pkgs.nix ];
      buildPhase = ''
        nix build
      '';
      installPhase = ''
        mkdir -p $out/bin
        cp -r result $out/
      '';
    };
  };
}
