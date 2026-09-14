# Operations Guide: Binary Upgrades & Version Migration

This document outlines the upgrade strategy, state compatibility, and rollback procedures for Relay.

---

## 1. Upgrade Principles & Guarantees

Relay is architected with strict operational guarantees across upgrades:

1. **Zero State Loss:** Upgrading the Relay binary never mutates, deletes, or truncates existing audit ledgers (`ledger.db`), signing keys (`signing_key.seed`), or configuration files (`relay.toml`).
2. **Immutable Append-Only Continuity:** Existing ledger entries remain immutable. An upgraded Relay binary reads historical entries, validates existing cryptographic hash chains, and appends new entries seamlessly.
3. **Pure Forward Migrations:** SQLite schema evolution uses strictly additive migrations tracked in `schema_migrations`.
4. **Offline Verifiability:** Historical ledgers produced by older Relay releases can always be verified offline by newer versions via `relay verify --ledger <path>`.

---

## 2. Standard Upgrade Procedure

### Step 1: Backup Existing State (Recommended)
Before upgrading, take a point-in-time snapshot of the active ledger:

```bash
# SQLite Online Backup / Safe Copy
relay verify --ledger ~/.local/share/relay/ledger.db
cp ~/.local/share/relay/ledger.db ~/.local/share/relay/ledger.db.backup
```

### Step 2: Download and Install New Release
Run the official installer to fetch and place the updated binary:

```bash
curl -fsSL https://raw.githubusercontent.com/relay-security/relay/main/install.sh | bash
```

Or manually replace the executable in `~/.local/bin/relay` with the newly downloaded binary:

```bash
tar -xzf relay-v0.2.0-x86_64-unknown-linux-gnu.tar.gz
cp relay-v0.2.0-x86_64-unknown-linux-gnu/relay ~/.local/bin/relay
chmod 0755 ~/.local/bin/relay
```

### Step 3: Verify Version and State
Run health diagnostics and verify the historical ledger chain:

```bash
relay --version
relay doctor
relay verify --ledger ~/.local/share/relay/ledger.db
```

---

## 3. Rollback Procedure

Because Relay maintains backward-compatible SQLite schemas and forward-chaining hashes, rolling back to a previous binary version is straightforward:

1. Stop any running Relay gateway instances.
2. Replace `~/.local/bin/relay` with the previous version binary.
3. Run `relay doctor` to verify system health.
4. Run `relay verify --ledger ~/.local/share/relay/ledger.db` to confirm hash-chain validity.
