#!/bin/bash
# PledgeRecon CI Cache Pre-Population
# Run this before your scan to pre-download the advisory database for offline scans.
#
# Usage:
#   ./pledgerecon-cache-pre-populate.sh [cache-dir]
#
# This script downloads the advisory database to the specified cache directory
# so that subsequent scans can run fully offline.

set -euo pipefail

CACHE_DIR="${1:-.pledgerecon-cache}"
mkdir -p "$CACHE_DIR"

echo "📦 Pre-populating PledgeRecon advisory cache..."

# Download the advisory database snapshot
if command -v pledgerecon &>/dev/null; then
    # Use PledgeRecon's built-in cache download
    pledgerecon cache download --output "$CACHE_DIR"
    echo "✅ Advisory cache pre-populated at $CACHE_DIR"
else
    echo "⚠️  PledgeRecon not found. Install it first:"
    echo "   curl -L https://github.com/pledgeandgrow/pledgerecon/releases/latest/download/pledgerecon-linux-amd64 -o /usr/local/bin/pledgerecon"
    echo "   chmod +x /usr/local/bin/pledgerecon"
    exit 1
fi
