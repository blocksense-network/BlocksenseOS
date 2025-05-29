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
        echo "substituters = https://cache.nixos.org/ https://nix-community.cachix.org" >> ~/.config/nix/nix.conf
        echo "trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY= nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCYg3Fs=" >> ~/.config/nix/nix.conf
    fi
else
    echo "❌ Nix configuration not found - should be copied during Docker build"
    exit 1
fi

echo "✅ Nix substituters setup complete"