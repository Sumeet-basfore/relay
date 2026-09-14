#!/usr/bin/env bash
# =============================================================================
# Relay Golden Reference Demo - Main Runner Script
# Executes the canonical end-to-end demonstration
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEMO_DIR="${RELAY_DEMO_DIR:-/tmp/relay-golden-demo}"

# Ensure environment is initialized
"$SCRIPT_DIR/setup.sh"

# Locate Relay binary
RELAY_BIN=""
if command -v relay >/dev/null 2>&1; then
    RELAY_BIN="$(command -v relay)"
elif [ -f "$REPO_ROOT/target/release/relay" ]; then
    RELAY_BIN="$REPO_ROOT/target/release/relay"
elif [ -f "$REPO_ROOT/target/debug/relay" ]; then
    RELAY_BIN="$REPO_ROOT/target/debug/relay"
fi

# Run orchestrator
python3 "$SCRIPT_DIR/demo_orchestrator.py" "$RELAY_BIN" "$DEMO_DIR"

echo ""
echo "=================================================="
echo "✓ Golden Reference Demonstration Completed!"
echo "  Artifacts saved in: $DEMO_DIR/demo-output/"
echo "  To clean up: run './scripts/demo/cleanup.sh'"
echo "=================================================="
