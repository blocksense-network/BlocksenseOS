#!/bin/bash
# Efficient copy utility for development environments
# Uses rsync for fast, incremental copying with progress

set -euo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <source> <destination> [rsync-options]"
    echo "Example: $0 /source/dir/ /dest/dir/ --exclude='*.tmp'"
    exit 1
fi

SOURCE="$1"
DEST="$2"
shift 2
EXTRA_OPTS="$@"

echo "Efficiently copying from $SOURCE to $DEST..."

# Use rsync for efficient copying with progress
rsync -av --progress $EXTRA_OPTS "$SOURCE" "$DEST"

echo "✅ Copy complete"