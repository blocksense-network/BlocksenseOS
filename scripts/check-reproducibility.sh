#!/usr/bin/env bash
#
# Reproducibility gate for BlocksenseOS.
#
# This is the single implementation, used by both:
#   - .github/workflows/ci.yml, job `documentation-reproducibility`
#   - the `ci-docs-reproducibility` Justfile recipe (so `just ci-main` runs it)
# so that the CI gate and the local command cannot drift apart.
#
# For each component we build it, then re-execute the derivation with
# `nix build --rebuild`. The `--rebuild` flag is what makes this a real check:
# a plain second `nix build` is a no-op that resolves to the store path that is
# already there, so the two out-links would be the same path and the comparison
# would succeed no matter what. With `--rebuild`, Nix runs the build again and
# compares the fresh output against the store.
#
# Any difference prints the full diff and exits non-zero. This gate must never
# report success on a real difference.

set -euo pipefail

components=(
  "rust-echo-service|result-1|result-1-rebuild"
  "attestation-agent|result-2|result-2-rebuild"
)

for entry in "${components[@]}"; do
  IFS='|' read -r component first second <<< "$entry"
  nix build ".#$component" -o "$first"
  nix build ".#$component" --rebuild -o "$second"
done

rc=0
for entry in "${components[@]}"; do
  IFS='|' read -r component first second <<< "$entry"
  echo "=== Reproducibility check: $component ($first vs $second) ==="
  if diff -r "$first" "$second"; then
    echo "OK: $component is reproducible"
  else
    echo "FAIL: build not reproducible for $component (diff shown above)"
    rc=1
  fi
done

if [ "$rc" -ne 0 ]; then
  echo "Reproducibility gate failed: at least one component produced differing outputs."
fi
exit "$rc"
