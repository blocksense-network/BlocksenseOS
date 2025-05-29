{ config, lib, pkgs, ... }:

{
  # Base system configuration
  system.stateVersion = "24.11";
  
  # Boot configuration
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;
  
  # Enable Nix flakes
  nix.settings.experimental-features = [ "nix-command" "flakes" ];
  
  # Basic packages
  environment.systemPackages = with pkgs; [
    git
    vim
    curl
    wget
    tree
    htop
  ];
  
  # SSH configuration
  services.openssh = {
    enable = true;
    settings.PasswordAuthentication = false;
    settings.PermitRootLogin = "no";
  };
  
  # User configuration
  users.users.blocksense = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];
    openssh.authorizedKeys.keys = [
      # Add your SSH public key here
    ];
  };
}