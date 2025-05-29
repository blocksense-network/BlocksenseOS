{
  config,
  lib,
  pkgs,
  ...
}: {
  # Security hardening for TEE environment
  security.apparmor.enable = true;
  security.audit.enable = true;

  # Restrict kernel modules
  boot.blacklistedKernelModules = [
    "bluetooth"
    "btusb" # Bluetooth not needed in TEE
    "pcspkr" # PC speaker
    "joydev" # Joystick
    "usb-storage" # USB storage as recommended for server-side
    "uas" # USB Attached SCSI
    "firewire-core" # FireWire
    "thunderbolt" # Thunderbolt
  ];

  # Network security
  networking.firewall.enable = true;
  networking.firewall.allowedTCPPorts = [
    22 # SSH
    8080 # C++ Echo Service
    8081 # Rust Echo Service
  ];

  # Disable unnecessary services
  services.avahi.enable = false;
  services.printing.enable = false;

  # Kernel hardening
  boot.kernel.sysctl = {
    "kernel.dmesg_restrict" = 1;
    "kernel.kptr_restrict" = 2;
    "kernel.yama.ptrace_scope" = 1;
    "net.core.bpf_jit_harden" = 2;
    # SECURITY FIX: Enable full ASLR as recommended in review
    "kernel.randomize_va_space" = 2; # Full ASLR (heap, stack, VDSO, mmap)
    # Additional hardening
    "kernel.kexec_load_disabled" = 1;
    "kernel.unprivileged_bpf_disabled" = 1;
    "net.ipv4.ip_forward" = 0;
    "net.ipv4.conf.all.send_redirects" = 0;
    "net.ipv4.conf.default.send_redirects" = 0;
    "net.ipv4.conf.all.accept_redirects" = 0;
    "net.ipv4.conf.default.accept_redirects" = 0;
    "net.ipv6.conf.all.accept_redirects" = 0;
    "net.ipv6.conf.default.accept_redirects" = 0;
  };

  # TPM configuration for attestation
  security.tpm2.enable = true;
  security.tpm2.pkcs11.enable = true;
  security.tpm2.tctiEnvironment.enable = true;
}
