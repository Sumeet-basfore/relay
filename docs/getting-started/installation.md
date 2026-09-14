# Installation Guide — Relay

This guide walks through installing and verifying Relay on your system.

---

## 1. Quick Install (Recommended)

Relay provides a secure, non-root installation script that detects your operating system and architecture, verifies SHA-256 checksums, and installs the standalone `relay` binary into `~/.local/bin`.

```bash
curl -fsSL https://raw.githubusercontent.com/relay-security/relay/main/install.sh | bash
```

### Custom Installation Directory
To install to a custom path (e.g. `/usr/local/bin` for system-wide availability):

```bash
curl -fsSL https://raw.githubusercontent.com/relay-security/relay/main/install.sh | INSTALL_DIR=/usr/local/bin bash
```

---

## 2. Manual Installation

### Step 1: Download Release Archive
Download the appropriate tarball for your platform from the [GitHub Releases](https://github.com/relay-security/relay/releases) page:

- **Linux x86_64:** `relay-v0.1.0-x86_64-unknown-linux-gnu.tar.gz`
- **Linux ARM64:** `relay-v0.1.0-aarch64-unknown-linux-gnu.tar.gz`
- **macOS Apple Silicon:** `relay-v0.1.0-aarch64-apple-darwin.tar.gz`
- **macOS Intel:** `relay-v0.1.0-x86_64-apple-darwin.tar.gz`
- **Windows x86_64:** `relay-v0.1.0-x86_64-pc-windows-msvc.zip`

### Step 2: Verify SHA-256 Checksum
Download the `SHA256SUMS` file and verify the archive integrity:

```bash
# On Linux
sha256sum --check --ignore-missing SHA256SUMS

# On macOS
shasum -a 256 --check --ignore-missing SHA256SUMS
```

### Step 3: Extract and Place Binary
Extract the archive and move the binary to a directory on your `PATH`:

```bash
tar -xzf relay-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
mkdir -p ~/.local/bin
cp relay-v0.1.0-x86_64-unknown-linux-gnu/relay ~/.local/bin/
chmod 0755 ~/.local/bin/relay
```

### Step 4: Configure PATH (if needed)
If `~/.local/bin` is not already in your `PATH`, add the following line to your shell configuration file (`~/.bashrc`, `~/.zshrc`, or `~/.profile`):

```bash
export PATH="$HOME/.local/bin:$PATH"
```

---

## 3. Building from Source

To compile Relay directly from source, ensure you have Rust 1.78+ installed:

```bash
git clone https://github.com/relay-security/relay.git
cd relay
cargo build --release --bin relay
cp target/release/relay ~/.local/bin/
```

---

## 4. Verifying Installation

Verify that Relay is properly installed and run system diagnostics:

```bash
# Check version
relay --version

# Run diagnostic health check
relay doctor
```

Expected `doctor` output:
```text
=== Relay System Health & Foundation Diagnostics ===
Relay Version       : 0.1.0
Target OS           : linux
Target Architecture : x86_64
Working Directory   : /home/user/workspace
Config Directory    : /home/user/.config/relay [EXISTS]
Ledger Path         : .relay/ledger.db [EXISTS (mode 0600)]
Policy Directory    : policies [DEFAULT (in-binary bundled)]
Terminal (TTY)      : Interactive TTY Available (/dev/tty)
Status              : MCP Gateway Milestone B002 Operational (RC001 Release Candidate)
=====================================================
```
