{
  config,
  lib,
  pkgs,
  self,
  ...
}: {
  # BlocksenseOS service definitions
  systemd.services.cpp-echo = {
    description = "C++ Echo Service";
    after = ["network.target"];
    wantedBy = ["multi-user.target"];
    serviceConfig = {
      ExecStart = "${self.packages.${pkgs.system}.cpp-echo-service}/bin/cpp-echo-service";
      Restart = "always";
      User = "blocksense";
      Group = "blocksense";
    };
  };

  systemd.services.rust-echo = {
    description = "Rust Echo Service";
    after = ["network.target"];
    wantedBy = ["multi-user.target"];
    serviceConfig = {
      ExecStart = "${self.packages.${pkgs.system}.rust-echo-service}/bin/rust-echo-service";
      Restart = "always";
      User = "blocksense";
      Group = "blocksense";
    };
  };

  systemd.services.attestation-agent = {
    description = "TEE Attestation Agent";
    after = ["network.target"];
    wantedBy = ["multi-user.target"];
    serviceConfig = {
      ExecStart = "${self.packages.${pkgs.system}.attestation-agent}/bin/attestation-agent";
      Restart = "always";
      User = "blocksense";
      Group = "blocksense";
    };
  };
}
