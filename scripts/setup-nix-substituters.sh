#!/bin/bash
# Setup Nix binary cache substituters for faster builds
# This script configures trusted substituters to speed up CI builds

set -euo pipefail

echo "Setting up Nix substituters for faster builds..."

# Create Nix config directory if it doesn't exist
mkdir -p ~/.config/nix

# Ensure we have the latest substituters configuration
if [ -f ~/.config/nix/nix.conf ]; then
    echo "Nix configuration already exists, verifying substituters..."
    if grep -q "cache.nixos.org" ~/.config/nix/nix.conf; then
        echo "✅ Substituters already configured"
    else
        echo "⚠️  Adding missing substituters to existing config"
        echo "" >> ~/.config/nix/nix.conf
        echo "substituters = https://cache.nixos.org/ https://cache.metacraft-labs.com/blocksense-public" >> ~/.config/nix/nix.conf
        echo "trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY= blocksense-public:OOgTc0ye1FONCiVHMrbpScc/HP+lX3uoU0EfwzX6ypE=" >> ~/.config/nix/nix.conf
    fi
else
    echo "❌ Nix configuration not found - should be copied during Docker build"
    exit 1
fi

echo "✅ Nix substituters setup complete"