{
  config,
  pkgs,
  ...
}: {
  # Container‑friendly minimal boot setup
  boot.isContainer = true;

  # Enable Flakes & the new CLI
  nix.settings.experimental-features = ["nix-command" "flakes"];

  networking.hostName = "devcontainer";

  users.groups.vscode.gid = 100;
  users.users.vscode = {
    isNormalUser = true;
    uid = 1000;
    group = "vscode";
    extraGroups = ["wheel"];
    shell = pkgs.bashInteractive;
    initialHashedPassword = "";
  };

  security.sudo.enable = true;
  security.sudo.wheelNeedsPassword = false;

  environment.systemPackages = with pkgs; [
    gnused # required by dev‑containers helpers
    git
  ];
}
