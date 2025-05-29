#!/bin/bash
# Sync Cargo caches between host and container for optimal performance
# This script efficiently synchronizes Cargo registry and git caches

set -euo pipefail

echo "Syncing Cargo caches for optimal build performance..."

# Check if host cargo cache is available
if [ -d "/host-cargo" ]; then
    echo "Host Cargo cache found, syncing..."
    
    # Sync registry cache (crate files)
    if [ -d "/host-cargo/registry" ]; then
        echo "Syncing registry cache..."
        rsync -av --ignore-existing /host-cargo/registry/ ~/.cargo/registry/ || true
    fi
    
    # Sync git cache (git dependencies)
    if [ -d "/host-cargo/git" ]; then
        echo "Syncing git cache..."
        rsync -av --ignore-existing /host-cargo/git/ ~/.cargo/git/ || true
    fi
    
    echo "✅ Cargo cache sync complete"
else
    echo "⚠️  Host Cargo cache not mounted, using container-only cache"
fi