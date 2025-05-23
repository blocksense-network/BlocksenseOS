# Start from minimal Nix tool-only image
FROM nixos/nix:2.28.3

# Enable nix-command and flakes for every invocation
RUN mkdir -p /etc/nix \
 && echo "experimental-features = nix-command flakes" >> /etc/nix/nix.conf

# Copy the flake and its module
COPY flake.nix flake.lock configuration.nix /etc/nixos/

# Build and activate the NixOS system that matches the container’s CPU
RUN set -euo pipefail; \
    export TARGET="$(nix eval --impure --raw --expr builtins.currentSystem)"; \
    nix build "/etc/nixos#nixosConfigurations.${TARGET}.default.config.system.build.toplevel"; \
    ./result/bin/switch-to-configuration --install switch; \
    rm -rf result

# Switch to the declaratively-created non-root user
USER vscode

ENTRYPOINT ["bash", "-l"]
