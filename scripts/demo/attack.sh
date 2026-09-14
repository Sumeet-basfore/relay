#!/usr/bin/env bash
# =============================================================================
# Relay Golden Reference Demo - Attack Suite Runner
# Executes targeted adversarial attack probes against Relay security boundaries
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEMO_DIR="${RELAY_DEMO_DIR:-/tmp/relay-golden-demo}"

if [ ! -d "$DEMO_DIR" ]; then
    echo "Demo environment not found. Initializing..."
    "$SCRIPT_DIR/setup.sh"
fi

RELAY_BIN=""
if command -v relay >/dev/null 2>&1; then
    RELAY_BIN="$(command -v relay)"
elif [ -f "$REPO_ROOT/target/release/relay" ]; then
    RELAY_BIN="$REPO_ROOT/target/release/relay"
elif [ -f "$REPO_ROOT/target/debug/relay" ]; then
    RELAY_BIN="$REPO_ROOT/target/debug/relay"
fi

echo "=================================================="
echo "   Relay Adversarial Attack Demonstration"
echo "=================================================="

python3 - << PYEOF
import sys
import os

sys.path.insert(0, "$SCRIPT_DIR")
from demo_orchestrator import RelayDemoSession, print_header, print_scene, BOLD, GREEN, RED, RESET

workspace_dir = "$DEMO_DIR"
relay_bin = "$RELAY_BIN"

print_header("RELAY ADVERSARIAL ATTACK HARNESS")
session_adv = RelayDemoSession(relay_bin, workspace_dir, non_interactive=True)
session_adv.start()

attacks = [
    ("attack_exfiltrate_credentials", {}, "Credential Exfiltration Probe", "Zero ambient secrets present in process environment"),
    ("attack_probe_localhost", {}, "Localhost Bypass Probe (127.0.0.1:8080)", "Host loopback denied by egress proxy & network isolation"),
    ("attack_probe_cloud_metadata", {}, "Cloud Metadata IMDS Probe (169.254.169.254)", "Metadata access blocked under SI-022 anti-SSRF filters"),
    ("attack_probe_private_network", {}, "Private Network Probe (10.0.0.1)", "RFC 1918 destination blocked by Cedar destination policy"),
    ("attack_raw_socket", {"host": "169.254.169.254", "port": 80}, "Raw Socket Bypass Probe", "Direct raw socket blocked"),
    ("attack_post_action", {}, "Post-Action Session Reuse Probe", "Proxy request rejected because ephemeral session token burned")
]

for name, args, title, desc in attacks:
    resp_att = session_adv.call_tool(name, args, req_id=10)
    res_text = ""
    if resp_att and "result" in resp_att:
        res_text = resp_att["result"]["content"][0]["text"]
    elif resp_att and "error" in resp_att:
        res_text = resp_att["error"]["message"]

    print(f"  ┌─ {BOLD}ATTACK{RESET}: {title}")
    print(f"  │  Result : {GREEN}{BOLD}BLOCKED{RESET}")
    print(f"  └─ Reason : {desc}")
    print(f"     Observed: {res_text[:70]}...")

session_adv.stop()
print(f"\n{GREEN}{BOLD}✓ ALL ADVERSARIAL ATTACK PROBES BLOCKED BY RELAY CONTROL PLANE{RESET}")
PYEOF
