{
  config,
  lib,
  pkgs,
  ...
}: {
  # Base system configuration
  system.stateVersion = "24.11";

  # Boot configuration
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  # File systems - basic configuration for VM/container environments
  fileSystems."/" = {
    device = "/dev/disk/by-label/nixos";
    fsType = "ext4";
  };

  fileSystems."/boot" = {
    device = "/dev/disk/by-label/boot";
    fsType = "vfat";
  };

  # Enable Nix flakes
  nix.settings.experimental-features = ["nix-command" "flakes"];

  # Network configuration for VM/container environments
  networking.hostName = "blocksense-os";
  networking.networkmanager.enable = true;

  # Basic packages
  environment.systemPackages = with pkgs; [
    git
    vim
    curl
    wget
    tree
    htop
    netcat-gnu # For testing TCP services
    tcpdump # For network debugging
  ];

  # SSH configuration
  services.openssh = {
    enable = true;
    settings.PasswordAuthentication = false;
    settings.PermitRootLogin = "no";
  };

  # User configuration - ensure group exists
  users.groups.blocksense = {};
  users.users.blocksense = {
    isNormalUser = true;
    group = "blocksense";
    extraGroups = ["wheel" "networkmanager"];
    openssh.authorizedKeys.keys = [
      # Add your SSH public key here
    ];
  };
}
