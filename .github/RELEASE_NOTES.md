## Relay — Local-first Zero-Trust Security Gateway

Governs every AI agent tool call with Cedar policies, signs cryptographic receipts, and maintains a tamper-evident audit ledger — all on your machine, zero cloud telemetry.

### Install

```bash
curl -fsSL https://raw.githubusercontent.com/Sumeet-basfore/relay/main/install.sh | bash
```

### Supported platforms

| Platform | Archive |
|----------|---------|
| Linux x86_64 | `relay-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz` |
| Linux aarch64 | `relay-vX.Y.Z-aarch64-unknown-linux-gnu.tar.gz` |
| macOS Intel | `relay-vX.Y.Z-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon | `relay-vX.Y.Z-aarch64-apple-darwin.tar.gz` |
| Windows x86_64 | `relay-vX.Y.Z-x86_64-pc-windows-msvc.zip` |

### Quick start

```bash
relay doctor                  # Verify installation & sandbox health
relay policy scaffold --dry-run -- <mcp-server-command>  # Auto-scaffold Cedar policies
relay run -- <mcp-server-command>                        # Run governed with default deny
relay ui                      # Open local security console
```

### Verify checksums

```bash
sha256sum --check checksums.sha256
```

### License

Apache 2.0 — see [LICENSE](LICENSE)
