# Third-Party Software Licenses & Attribution: Relay v0.1.0

**Document ID:** `LIC-ATT-001`  
**Release:** `v0.1.0`  
**Date:** 2026-09-14  
**Primary License:** `Apache-2.0`  

---

## 1. Primary License

Relay is distributed under the terms of the **Apache License, Version 2.0**.

```text
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/
```

---

## 2. Third-Party Dependencies & Licenses Inventory

The following open-source libraries are incorporated into the Relay binary distribution:

| Dependency Crate | Direct / Transitive | Version | License | Copyright / Origin |
|:---|:---:|:---:|:---:|:---|
| `cedar-policy` | Direct | 4.0 | Apache-2.0 | Amazon Web Services |
| `tokio` | Direct | 1.38 | MIT | Tokio Contributors |
| `ed25519-dalek` | Direct | 2.1 | BSD-3-Clause | Dalek Cryptography |
| `rusqlite` | Direct | 0.31 | MIT | Rusqlite Authors |
| `sqlparser` | Direct | 0.47 | Apache-2.0 | SQLParser Authors |
| `serde` | Direct | 1.0 | MIT / Apache-2.0 | David Tolnay & Serde Contributors |
| `serde_json` | Direct | 1.0 | MIT / Apache-2.0 | David Tolnay & Serde Contributors |
| `serde_jcs` | Direct | 0.1 | MIT / Apache-2.0 | Serde JCS Contributors |
| `sha2` | Direct | 0.10 | MIT / Apache-2.0 | RustCrypto Project Developers |
| `zeroize` | Direct | 1.8 | Apache-2.0 / MIT | RustCrypto Project Developers |
| `secrecy` | Direct | 0.8 | Apache-2.0 / MIT | RustCrypto Project Developers |
| `keyring` | Direct | 3.2 | MIT / Apache-2.0 | Keyring-rs Contributors |
| `clap` | Direct | 4.5 | MIT / Apache-2.0 | Clap Authors |
| `toml` | Direct | 0.8 | MIT / Apache-2.0 | Alex Crichton & TOML Contributors |
| `uuid` | Direct | 1.9 | Apache-2.0 / MIT | UUID Authors |
| `chrono` | Direct | 0.4 | MIT / Apache-2.0 | Chrono Contributors |
| `tracing` | Direct | 0.1 | MIT | Tokio Project |
| `tracing-subscriber` | Direct | 0.3 | MIT | Tokio Project |
| `regex` | Direct | 1.10 | MIT / Apache-2.0 | The Rust Project Developers |
| `reqwest` | Direct | 0.12 | MIT / Apache-2.0 | Sean McArthur |
| `rustls` | Direct | 0.23 | Apache-2.0 / ISC / MIT | Rustls Contributors |
| `webpki-roots` | Direct | 0.26 | MPL-2.0 | Mozilla & Webpki Contributors |
| `base64` | Direct | 0.22 | MIT / Apache-2.0 | Alice Maz & Base64 Contributors |
| `libc` | Direct | 0.2 | MIT / Apache-2.0 | The Rust Project Developers |
| `thiserror` | Direct | 1.0 | MIT / Apache-2.0 | David Tolnay |
| `async-trait` | Direct | 0.1 | MIT / Apache-2.0 | David Tolnay |
| `color-eyre` | Direct | 0.6 | MIT / Apache-2.0 | Jane Lusby |
| `tokio-postgres` | Direct | 0.7 | MIT / Apache-2.0 | Steven Fackler |
| `postgres-types` | Direct | 0.2 | MIT / Apache-2.0 | Steven Fackler |
| `postgres_rustls` | Direct | 0.1 | MIT / Apache-2.0 | Steven Fackler |

---

## 3. License Compatibility & Export Classification

1. **Permissive Licensing:** All dependencies use permissive open-source licenses (`Apache-2.0`, `MIT`, `BSD-3-Clause`, `ISC`, `MPL-2.0`).
2. **No Copyleft Contamination:** No GPL/AGPL copyleft libraries are linked into the Relay binary.
3. **Cryptographic Compliance:** Standard, publicly reviewed cryptographic primitives (Ed25519 via `ed25519-dalek`, SHA-256 via `sha2`, TLS 1.3 via `rustls`) are utilized in compliance with standard software distribution guidelines.
