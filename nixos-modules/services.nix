{ config, lib, pkgs, ... }:

{
  # BlocksenseOS service definitions
  systemd.services.cpp-echo = {
    description = "C++ Echo Service";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      ExecStart = "${pkgs.cpp-echo-service}/bin/echo-service";
      Restart = "always";
      User = "blocksense";
      Group = "users";
    };
  };
  
  systemd.services.rust-echo = {
    description = "Rust Echo Service";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      ExecStart = "${pkgs.rust-echo-service}/bin/rust-echo-service";
      Restart = "always";
      User = "blocksense";
      Group = "users";
    };
  };
  
  systemd.services.attestation-agent = {
    description = "TEE Attestation Agent";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      ExecStart = "${pkgs.attestation-agent}/bin/attestation-agent";
      Restart = "always";
      User = "blocksense";
      Group = "users";
    };
  };
}