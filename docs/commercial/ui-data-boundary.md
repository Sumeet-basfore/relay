# CR002 Local UI — Data Boundary Specification

**Document ID:** `CR001-UI-001`  
**Version:** `1.0.0`  
**Status:** PLANNED — CR002 milestone  
**Applies To:** Future Relay Local Security Console  
**Last Updated:** 2026-09-14  

---

## 1. Purpose

Define what data a future Relay local UI (CR002) may display, store, or transmit **before** implementation begins. The UI must respect the same least-privilege model as the Relay gateway.

**v0.1.0 status:** No UI exists. CLI (`relay`) is the only management surface.

---

## 2. Design Principles

1. **Localhost by default** — bind to `127.0.0.1`, not `0.0.0.0`
2. **Read-mostly** — UI observes Relay state; mutations go through governed CLI/API
3. **No credential rendering** — never display PATs, DB passwords, or lease tokens
4. **No cloud sync by default** — all data from local Relay instance
5. **Minimal retention** — UI cache is ephemeral; ledger remains source of truth

---

## 3. Safe Display Candidates

| Data Element | Display Level | Rationale |
|:---|:---|:---|
| Action status (pending/approved/denied) | ✓ Safe | Operational visibility |
| ActionHash / receipt ID | ✓ Safe | Integrity verification |
| Tool name | ✓ Safe | Authorization context |
| Policy decision (allow/deny + policy ID) | ✓ Safe | Audit transparency |
| Approval status | ✓ Safe | Human gate visibility |
| Receipt verification result | ✓ Safe | `relay verify` equivalent |
| Ledger sequence number / head hash | ✓ Safe | Chain integrity |
| Connector status (connected/error) | ✓ Safe | Ops diagnostics |
| Sandbox status (Linux netns) | ✓ Safe | Security posture |
| Relay version | ✓ Safe | Support |
| Policy file names (not full content by default) | ✓ Safe | Navigation |
| Timestamp (UTC) | ✓ Safe | Audit ordering |

---

## 4. Restricted Display (Explicit User Action Required)

| Data Element | Default | Expanded Access |
|:---|:---|:---|
| Sanitized tool arguments | Hidden | Show redacted preview with "reveal" + warning |
| Full Cedar policy text | Collapsed | Expand on click; warn if contains resource identifiers |
| Receipt JSON (DSSE envelope) | Summary only | Download/export button with audit log |
| Filesystem paths in receipts | Redacted | Partial path display (basename only) by default |
| SQL query text | Redacted | Hash + length only by default |

---

## 5. Prohibited Display (Never)

| Data Element | Reason |
|:---|:---|
| Raw target credentials | SI-001 violation risk |
| OS keyring secret values | Secret tier |
| Signing key private material | Cryptographic compromise |
| Egress proxy lease tokens | Session hijack |
| Full agent prompts | Highly sensitive; out of scope |
| Full database result sets | Data exfiltration surface |
| Arbitrary filesystem contents | Path traversal / data exposure |
| Unscrubbed receipt payloads | May contain embedded secrets |

---

## 6. API Boundary (Planned)

```text
Browser (localhost) ──HTTP──► Relay Local API ──► Read local ledger/config
                                    │
                                    └── No external network calls
```

| API Property | Requirement |
|:---|:---|
| Bind address | `127.0.0.1` default |
| Authentication | Local token or OS-user scoped socket |
| CSRF protection | Required for mutating endpoints |
| CORS | Deny cross-origin by default |
| Rate limiting | Prevent DoS on local API |
| Mutations | Require same approval model as CLI |

---

## 7. Local UI Privacy Model (CR002 Phase 29)

| Concern | Requirement |
|:---|:---|
| Local-only binding | No `0.0.0.0` without explicit `--insecure-expose` flag + warning |
| Authentication | Required if API exposed beyond single user |
| CSRF | Token on all state-changing requests |
| Browser origin | Strict same-origin policy |
| Local network exposure | mDNS/Bonjour **disabled** by default |
| API authorization | Scoped read vs write tokens |
| Sensitive rendering | Redact by default; no auto-expand |
| Clipboard | Never auto-copy secrets; warn on receipt export |
| Downloadable receipts | User-initiated; optional encryption prompt |
| Session expiration | Idle timeout (default 30 min TBD) |

---

## 8. Data Flow: UI vs Cloud

| Flow | Default | Opt-In Future |
|:---|:---|:---|
| UI → local ledger | ✓ Allowed | — |
| UI → Relay cloud | **Prohibited** | Hosted dashboard (separate product) |
| UI → analytics | **Prohibited** | None planned |
| UI → clipboard | User gesture only | — |

---

## 9. Commercial Model Alignment (Model B)

CR002 Local Security Console is an **optional paid local component** under Model B:

- Does not require Relay account for core function
- Does not transmit execution data to Relay infrastructure
- May offer premium features (policy simulator, advanced visualization) still local-only
- License entitlement mechanism TBD — must not phone home with execution content

---

## 10. Acceptance Criteria (CR002)

Before CR002 ships:

- [ ] All §5 prohibited data confirmed unreachable via UI/API
- [ ] Default bind is `127.0.0.1`
- [ ] Security review of API auth model
- [ ] Privacy review against this document
- [ ] No regression of SI-001–SI-024

---

## 11. Related Documents

- `docs/commercial/product-boundary.md`
- `docs/commercial/privacy-threat-model.md` (P-14–P-16)
- `docs/commercial/security-requirements.md` (UI-01–UI-05)
