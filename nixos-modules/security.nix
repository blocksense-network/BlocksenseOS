{ config, lib, pkgs, ... }:

{
  # Security hardening for TEE environment
  security.apparmor.enable = true;
  security.audit.enable = true;
  
  # Restrict kernel modules
  boot.blacklistedKernelModules = [
    "bluetooth" "btusb" # Bluetooth not needed in TEE
    "pcspkr" # PC speaker
    "joydev" # Joystick
  ];
  
  # Network security
  networking.firewall.enable = true;
  networking.firewall.allowedTCPPorts = [ 22 ]; # SSH only
  
  # Disable unnecessary services
  services.avahi.enable = false;
  services.printing.enable = false;
  sound.enable = false;
  
  # Kernel hardening
  boot.kernel.sysctl = {
    "kernel.dmesg_restrict" = 1;
    "kernel.kptr_restrict" = 2;
    "kernel.yama.ptrace_scope" = 1;
    "net.core.bpf_jit_harden" = 2;
  };
  
  # TPM configuration for attestation
  security.tpm2.enable = true;
  security.tpm2.pkcs11.enable = true;
  security.tpm2.tctiEnvironment.enable = true;
}