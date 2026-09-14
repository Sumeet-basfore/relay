# Operations Guide: Cryptographic Signing Key Management

This document details Relay's asymmetric cryptographic key architecture, generation, rotation, export, and verification protocols.

---

## 1. Key Architecture & Cryptographic Primitives

Relay utilizes Ed25519 (Edwards-curve Digital Signature Algorithm over Curve25519, RFC 8032) for creating non-repudiable cryptographic receipts:

- **Key Format:** 32-byte private seed generating a 64-byte expanded secret key and a 32-byte public key.
- **RNG:** CSPRNG via `rand_core::OsRng`.
- **Memory Protection:** Private key material is scrubbed from RAM on `Drop` via `zeroize::Zeroize` and masked in all `Debug` / `Display` formatters (`"[REDACTED SECRET KEY]"`).
- **Filesystem Permissions:** Signing key files must strictly enforce `0600` (`-rw-------`) permissions on Unix platforms.

---

## 2. Key Lifecycle Operations

### 2.1 Key Generation
When Relay initializes a new node without an existing signing key, it automatically generates a high-entropy Ed25519 key pair and persists the seed:

```bash
# Explicit Key Generation & Verification
relay doctor
```

The key seed is stored at `~/.config/relay/signing_key.seed`.

### 2.2 Public Key Export
To export the public key for external verification or auditor configuration:

```bash
# Public key is displayed during doctor checks and recorded in ledger genesis
relay doctor
```

In forensic verification, the public key is automatically extracted from the `node_identity` table in `ledger.db` or supplied explicitly via `--pubkey <path>`.

### 2.3 Key Rotation Protocol
To rotate a node signing key:
1. Complete all inflight agent tool executions.
2. Verify the historical ledger up to the current head sequence:
   ```bash
   relay verify --ledger ~/.local/share/relay/ledger.db
   ```
3. Archive the existing key seed:
   ```bash
   mv ~/.config/relay/signing_key.seed ~/.config/relay/signing_key.seed.v1
   ```
4. Generate a new key seed:
   Relay will automatically generate a new key on the next execution and record the rotation metadata.
5. Historical receipts remain verifiable using the previous public key recorded in the genesis/identity block, while new receipts are signed with the active key.
