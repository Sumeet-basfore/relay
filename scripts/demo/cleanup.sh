#!/usr/bin/env bash
# =============================================================================
# Relay Golden Reference Demo - Cleanup Script
# Safely wipes the disposable demonstration environment
# =============================================================================
set -euo pipefail

DEMO_DIR="${RELAY_DEMO_DIR:-/tmp/relay-golden-demo}"

echo "=================================================="
echo "   Relay Golden Reference Demo - Cleanup"
echo "=================================================="

if [ -d "$DEMO_DIR" ]; then
    echo "Cleaning up demo environment at: $DEMO_DIR"
    rm -rf "$DEMO_DIR"
    echo "✓ Demo environment cleaned up successfully."
else
    echo "No demo environment found at $DEMO_DIR. Nothing to clean."
fi
