#!/usr/bin/env bash

# Script to automatically retrieve authentication tokens from CLI tools
# This eliminates the need for users to manually provide tokens in secrets files

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}" >&2  # Send to stderr
}

# Function to get GitHub token
get_github_token() {
    print_status "$YELLOW" "Retrieving GitHub token from gh CLI..."

    if ! command -v gh &> /dev/null; then
        print_status "$RED" "Error: GitHub CLI (gh) is not installed or not in PATH"
        print_status "$YELLOW" "Please install it with: sudo apt install gh  # or your package manager"
        return 1
    fi

    if ! gh auth status &> /dev/null; then
        print_status "$RED" "Error: Not logged in to GitHub CLI"
        print_status "$YELLOW" "Please run: gh auth login"
        return 1
    fi

    local token
    token=$(gh auth token 2>/dev/null)
    if [[ -n "$token" ]]; then
        print_status "$GREEN" "✓ GitHub token retrieved successfully"
        echo "$token"  # Only the token goes to stdout
    else
        print_status "$RED" "Error: Failed to retrieve GitHub token"
        return 1
    fi
}

# Function to get Cachix token
get_cachix_token() {
    print_status "$YELLOW" "Retrieving Cachix token from cachix CLI..."

    # Try different possible config locations
    local config_paths=(
        "$HOME/.config/cachix/cachix.dhall"
        "$HOME/.cachix/cachix.dhall"
    )

    # Add XDG_CONFIG_HOME path only if the variable is set
    if [[ -n "${XDG_CONFIG_HOME:-}" ]]; then
        config_paths+=("$XDG_CONFIG_HOME/cachix/cachix.dhall")
    fi

    for config_path in "${config_paths[@]}"; do
        if [[ -f "$config_path" ]]; then
            print_status "$YELLOW" "Found Cachix config at: $config_path"

            # Use dhall-to-json and jq to properly parse the Dhall config
            local token
            token=$(dhall-to-json <<< "($(<"$config_path")).authToken" 2>/dev/null | jq -r '.' 2>/dev/null)

            if [[ -n "$token" && "$token" != "null" ]]; then
                print_status "$GREEN" "✓ Cachix token retrieved successfully"
                echo "$token"  # Only the token goes to stdout
                return 0
            fi
        fi
    done

    print_status "$RED" "Error: Could not find Cachix authentication token"
    print_status "$YELLOW" "Please run: cachix authtoken <your-token>"
    print_status "$YELLOW" "Or login via: cachix use <your-cache-name>"
    return 1
}

# Function to create/update act secrets file
create_act_secrets() {
    local github_token=$1
    local cachix_token=$2
    local secrets_file=".github/act-secrets.local.env"

    print_status "$YELLOW" "Creating/updating $secrets_file..."

    cat > "$secrets_file" << EOF
# Auto-generated secrets file from CLI tool logins
# Generated on: $(date)

# =============================================================================
# REQUIRED FOR WORKFLOW EXECUTION (Auto-retrieved)
# =============================================================================

# Cachix authentication token for blocksense-os cache (from cachix CLI)
CACHIX_AUTH_TOKEN=$cachix_token

# GitHub personal access token (from gh CLI)
GITHUB_TOKEN=$github_token

# =============================================================================
# OPTIONAL (for full workflow functionality)
# =============================================================================
# Note: These tokens still need to be manually configured if needed

# Codecov upload token (if using Codecov)
# Get from: https://codecov.io/ -> Your repo -> Settings -> Repository Upload Token
# CODECOV_TOKEN=your_codecov_token_here
EOF

    print_status "$GREEN" "✓ Created $secrets_file with retrieved tokens"
    print_status "$YELLOW" "Note: Optional tokens (Codecov) still need manual configuration if required"
}

# Main execution
main() {
    print_status "$GREEN" "=== Auto Token Retrieval Script ==="
    print_status "$YELLOW" "This script will retrieve tokens from your existing CLI tool logins"

    cd "$(dirname "$0")/../.." # Go to repo root

    local github_token cachix_token

    # Get GitHub token
    if github_token=$(get_github_token); then
        print_status "$GREEN" "GitHub token: ${github_token:0:8}..." # Show only first 8 chars
    else
        print_status "$RED" "Failed to get GitHub token"
        exit 1
    fi

    # Get Cachix token
    if cachix_token=$(get_cachix_token); then
        print_status "$GREEN" "Cachix token: ${cachix_token:0:8}..." # Show only first 8 chars
    else
        print_status "$RED" "Failed to get Cachix token"
        exit 1
    fi

    # Create secrets file
    create_act_secrets "$github_token" "$cachix_token"

    print_status "$GREEN" "=== Setup Complete ==="
    print_status "$YELLOW" "You can now run workflows locally with: act"
    print_status "$YELLOW" "The tokens will be automatically loaded from your CLI tool logins"
}

# Run main function
main "$@"