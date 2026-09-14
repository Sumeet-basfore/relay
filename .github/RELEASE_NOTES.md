## Relay — Local-first Zero-Trust Security Gateway

Governs every AI agent tool call with Cedar policies, signs cryptographic receipts, and maintains a tamper-evident audit ledger — all on your machine, zero cloud telemetry.

### Install

```bash
curl -fsSL https://raw.githubusercontent.com/Sumeet-basfore/relay/main/install.sh | bash
```

### Supported platforms

| Platform | Archive |
|----------|---------|
| Linux x86_64 | `relay-vX.Y.Z-linux-x86_64.tar.gz` |
| Linux aarch64 | `relay-vX.Y.Z-linux-aarch64.tar.gz` |
| macOS Intel | `relay-vX.Y.Z-macos-x86_64.tar.gz` |
| macOS Apple Silicon | `relay-vX.Y.Z-macos-aarch64.tar.gz` |
| Windows x86_64 | `relay-vX.Y.Z-windows-x86_64.zip` |

### Quick start

```bash
relay doctor          # Verify installation
relay ui              # Open local security console
relay mcp run <name>  # Run a governed MCP connector
```

### Verify checksums

```bash
sha256sum --check checksums.sha256
```

### License

Apache 2.0 — see [LICENSE](LICENSE)
