# GitHub Workflows Pattern Documentation

This document describes the standardized pattern used across all GitHub Actions workflows in the BlocksenseOS project.

## Workflow Pattern

All workflows that need to run commands in the Nix development environment follow this consistent pattern:

### 1. Use the Shared Composite Action

```yaml
steps:
- uses: ./.github/actions/setup-nix
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    cachix_auth_token: ${{ secrets.CACHIX_AUTH_TOKEN }}
```

### 2. Set Default Shell for Jobs

```yaml
job-name:
  defaults:
    run:
      shell: "nix develop . --impure --accept-flake-config --command bash -l {0}"
```

### 3. Run Commands Directly

Commands no longer need the `nix develop --command` prefix:

```yaml
# Before (old pattern)
- run: nix develop --command just build-all

# After (new pattern)  
- run: just build-all
```

## Benefits

1. **DRY Principle**: Eliminates repetitive Nix setup code across workflows
2. **Maintainability**: Centralized Nix configuration in one reusable action
3. **Consistency**: All workflows use the same pattern
4. **Simplicity**: Commands run directly without wrapper prefixes
5. **Error Reduction**: Less chance for copy-paste errors in setup

## Composite Action

The shared setup action (`.github/actions/setup-nix/action.yml`) handles:
- Nix installation via cachix/install-nix-action
- Cachix configuration for caching

## Environment Variables

Global environment variables are set at the workflow level:

```yaml
env:
  NIX_CONFIG: |
    experimental-features = nix-command flakes
    accept-flake-config = true
```

## Exception Cases

Some jobs don't need the Nix environment. These jobs maintain their original simple structure without the defaults pattern.

## Migrating New Workflows

When creating new workflows that need Nix:

1. Set the global `NIX_CONFIG` environment
2. Add `defaults.run.shell` to jobs that run Nix commands
3. Use the `setup-nix` composite action as the first step immediately after the checkout step
4. Run commands directly without `nix develop --command` prefix

This pattern ensures consistency across the entire CI/CD pipeline while maintaining clean, readable workflow files.
