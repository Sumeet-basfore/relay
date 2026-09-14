#!/usr/bin/env bash
# =============================================================================
# Relay Golden Reference Demo - Setup & Initialization Script
# Creates a clean, isolated, disposable reference demonstration environment
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEMO_DIR="${RELAY_DEMO_DIR:-/tmp/relay-golden-demo}"

echo "=================================================="
echo "   Relay Golden Reference Demo - Environment Setup"
echo "=================================================="

# 1. Locate Relay binary
RELAY_BIN=""
if command -v relay >/dev/null 2>&1; then
    RELAY_BIN="$(command -v relay)"
elif [ -f "$REPO_ROOT/target/release/relay" ]; then
    RELAY_BIN="$REPO_ROOT/target/release/relay"
elif [ -f "$REPO_ROOT/target/debug/relay" ]; then
    RELAY_BIN="$REPO_ROOT/target/debug/relay"
else
    echo "Building Relay binary in release mode..."
    cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml"
    RELAY_BIN="$REPO_ROOT/target/release/relay"
fi

echo "Using Relay Binary: $RELAY_BIN"
"$RELAY_BIN" --version

# 2. Verify Python 3 presence for demo MCP server
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required to run the reference demo MCP server." >&2
    exit 1
fi

# 3. Clean and recreate disposable demo workspace
echo "Initializing clean demo workspace: $DEMO_DIR"
rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR/policies"
mkdir -p "$DEMO_DIR/fixtures/output"
mkdir -p "$DEMO_DIR/.relay"
mkdir -p "$DEMO_DIR/demo-output/receipts"
mkdir -p "$DEMO_DIR/demo-output/ledger"
mkdir -p "$DEMO_DIR/demo-output/logs"

# 4. Copy Cedar policies and schema
cp "$REPO_ROOT/demo/policies/demo.cedar" "$DEMO_DIR/policies/demo.cedar"
cp "$REPO_ROOT/demo/policies/relay_schema.cedarschema" "$DEMO_DIR/policies/relay_schema.cedarschema"

# 5. Copy Fixtures
cp "$REPO_ROOT/demo/fixtures/public.txt" "$DEMO_DIR/fixtures/public.txt"
cp "$REPO_ROOT/demo/fixtures/protected.txt" "$DEMO_DIR/fixtures/protected.txt"
cp "$REPO_ROOT/demo/fixtures/schema.sql" "$DEMO_DIR/fixtures/schema.sql"
cp "$REPO_ROOT/demo/adversarial-mcp/server.py" "$DEMO_DIR/server.py"
chmod +x "$DEMO_DIR/server.py"

# 6. Generate configuration file (relay.toml)
cat << TOML_EOF > "$DEMO_DIR/relay.toml"
[security]
default_deny = true
approval_timeout_secs = 30
max_frame_size_bytes = 4194304

[policy]
policy_dir = "policies"

[storage]
ledger_path = ".relay/ledger.db"

[proxy]
bind_host = "127.0.0.1"
port = 0
TOML_EOF

# 7. Apply restrictive filesystem permissions (SI-014)
chmod 0700 "$DEMO_DIR"
chmod 0700 "$DEMO_DIR/.relay"
chmod 0600 "$DEMO_DIR/relay.toml"

# 8. Run Relay Doctor check
echo "Verifying Relay system configuration..."
(cd "$DEMO_DIR" && "$RELAY_BIN" --config relay.toml doctor || true)

echo "=================================================="
echo "✓ Relay Golden Reference Demo initialized successfully!"
echo "  Workspace: $DEMO_DIR"
echo "  Next step: Run './scripts/demo/run.sh' to execute the demo."
echo "=================================================="
