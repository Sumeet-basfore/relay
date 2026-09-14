# Operations Guide: Backup & Disaster Recovery

This guide describes how to securely back up, restore, and verify Relay ledgers, cryptographic signing keys, and policy configurations.

---

## 1. Inventory of Persistent State

Relay manages three primary categories of persistent state:

| Component | Path | Sensitivity | Format / Structure |
|:---|:---|:---|:---|
| **Audit Ledger** | `.relay/ledger.db` or `~/.local/share/relay/ledger.db` | High (Tamper-evident Audit) | SQLite database (WAL mode, mode 0600) |
| **Node Signing Key** | `~/.config/relay/signing_key.seed` | Critical (Private Key) | 32-byte raw binary seed (mode 0600) |
| **Configuration & Policies** | `~/.config/relay/relay.toml`, `~/.config/relay/policies/` | Medium | TOML config and Cedar policy text files |

---

## 2. Backup Procedures

### 2.1 Audit Ledger Backup
Because SQLite operates in WAL (Write-Ahead Logging) mode, a safe backup requires either the SQLite `.backup` API, a transaction-safe lock, or copying while no active writes are executing:

```bash
# Safe point-in-time copy of SQLite DB and WAL files
mkdir -p ~/backups/relay-$(date +%Y%m%d)
sqlite3 ~/.local/share/relay/ledger.db ".backup '~/backups/relay-$(date +%Y%m%d)/ledger.db'"
chmod 0600 ~/backups/relay-$(date +%Y%m%d)/ledger.db
```

Verify the integrity of the backup immediately:
```bash
relay verify --ledger ~/backups/relay-$(date +%Y%m%d)/ledger.db
```

### 2.2 Node Signing Key Backup
The Ed25519 signing key seed must be backed up securely to encrypted cold storage:

```bash
# Encrypted backup using GPG
gpg --symmetric --cipher-algo AES256 -o ~/backups/relay-$(date +%Y%m%d)/signing_key.seed.gpg ~/.config/relay/signing_key.seed
```

---

## 3. Disaster Recovery Procedure

### Scenario: Restoring onto a New Machine
1. Install Relay binary via `install.sh`.
2. Restore configuration directory:
   ```bash
   mkdir -p ~/.config/relay ~/.local/share/relay
   chmod 0700 ~/.config/relay ~/.local/share/relay
   ```
3. Restore signing key seed:
   ```bash
   gpg -d ~/backups/signing_key.seed.gpg > ~/.config/relay/signing_key.seed
   chmod 0600 ~/.config/relay/signing_key.seed
   ```
4. Restore SQLite ledger:
   ```bash
   cp ~/backups/ledger.db ~/.local/share/relay/ledger.db
   chmod 0600 ~/.local/share/relay/ledger.db
   ```
5. Verify cryptographic integrity:
   ```bash
   relay doctor
   relay verify --ledger ~/.local/share/relay/ledger.db
   ```
