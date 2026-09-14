# Relay Public Paid Launch — Final Report

**Document ID:** `PL-RPT-001`  
**Runbook Phase:** 27 — Final Launch Report  
**Launch Date:** 2026-09-14  
**Public URL:** https://relay.dev  
**Release Version:** `v0.1.0`  
**Commercial Status:** **PUBLIC PAID**  
**Company:** Relay Security Technologies Private Limited, Bangalore, India

---

## 1. Executive Summary

Relay has completed the 27-phase Public Paid Launch Runbook following successful validation through EB001 (Extended Private Beta), GA005 (public release), CR003 (commercial launch), and PB001 (private beta operations). All phases recorded **PASS**.

Relay `v0.1.0` is publicly downloadable, commercially purchasable, legally approved, operationally supportable, and transparent about limitations.

### Launch Metrics (EB001 Baseline at Launch)

| Metric | Value |
| :--- | :--- |
| Active organizations | 10 |
| Governed seats | 188 |
| Governed actions | 14,280+ |
| Policy denials | 1,184 |
| Human approvals | 342 |
| Receipt verifications | 2,450 |
| P0 / P1 issues | 0 / 0 |
| Security incidents | 0 |
| Privacy incidents | 0 |
| Stripe webhook reliability | 100% (28/28) |
| Legal counsel status | ALL APPROVED |

### Certified Release Package (GA005)

| Identifier | Value |
| :--- | :--- |
| Git Tag | `v0.1.0` |
| Release Commit | `0360a95f74c33a9fc3d7628876dd9bb7d307e2bb` |
| Archive SHA-256 | `6f843ab71592ee55cc9c3b9c556af23e58b1fe8b192404c28ee753912f9de206` |
| Binary SHA-256 | `a4a3f930ecd36ee0c207bc014610a21b48d5718b5913443552e94fb49dd43a98` |

### Pricing (Frozen)

| Tier | Price |
| :--- | :--- |
| Community | Free (Apache 2.0 open core) |
| Team Pro | $49/seat/month ($39/seat/month annual) |
| Enterprise | Custom annual contract |

---

## 2. Phase Verification Matrix (All 27 Phases)

| Phase | Name | Verification Method | Evidence | Status |
| :---: | :--- | :--- | :--- | :---: |
| 1 | Launch Freeze | Pricing, legal, billing, entitlement, security baseline frozen | `public-launch-freeze.md` | **PASS** |
| 2 | Public Website Verification | Homepage, product, security, pricing, download, docs, legal pages live and consistent | Phase 2 walkthrough; pricing = Stripe = entitlement = website copy | **PASS** |
| 3 | Public Checkout | End-to-end: pricing → checkout → payment → webhook → subscription → entitlement | EB001 Stripe 28/28 webhooks; replay rejected; refund/cancel/grace verified | **PASS** |
| 4 | Public Entitlement | Pro/Enterprise issue, expire, renew, cancel, revoke; non-interference invariant | EB001 entitlement validation; commercial ⊥ Cedar/credential/approval/sandbox | **PASS** |
| 5 | Public Download | Certified artifacts published with checksum manifest | GA005 archive/binary SHA match manifest | **PASS** |
| 6 | Public Installation | Clean external install: website → download → verify → install → doctor → first action | GA005 install.sh + `relay doctor` PASS; EB001 onboarding < 20 min | **PASS** |
| 7 | Public Golden Demo | 7 scenes: allow, deny, approval, credential isolation, MCP, receipt, tamper | `./scripts/demo/run.sh` < 10s; `./scripts/demo/attack.sh` 100% blocked | **PASS** |
| 8 | Customer Security Center | Architecture, threat model, invariants, limitations, disclosure — no false certifications | `docs/security/` complete; GA004 security claims verified | **PASS** |
| 9 | Privacy Verification | Production matches Privacy Policy; binary has no telemetry/phone-home | EB001 zero telemetry invariant; CR001 data-flow audit PASS | **PASS** |
| 10 | Production Secrets Audit | Stripe keys, webhook secret, email, hosting, signing keys — least privilege | PB001 infrastructure review; no secrets in repository | **PASS** |
| 11 | Production Monitoring | Website, checkout, webhook, entitlement, email, release availability | Monitoring activated; no execution telemetry added | **PASS** |
| 12 | Stripe Monitoring | Webhook failures, replay, entitlement transitions, disputes, refunds | `public-launch-monitoring.md` created and active | **PASS** |
| 13 | Security Monitoring | Vuln reports, license anomalies, artifact integrity, dependency CVEs | `security@relay.dev` operational; PB001 tabletop PASS | **PASS** |
| 14 | CRL Operations | Hybrid 30-day terms + signed CRL; issue → monitor → revoke → publish | EB001 revocation < 15 min; monthly CRL cadence defined | **PASS** |
| 15 | Customer Communication | Launch announcement, product overview, pricing, security, install, support | Communications published; claims grounded in validated product | **PASS** |
| 16 | Launch FAQ | 13 canonical questions answered | `public-launch-faq.md` published | **PASS** |
| 17 | Public Support | Distinct routing: support, billing, privacy, grievance, security; Zero-Secret | `pb001-support-runbook.md`; 14 EB001 cases resolved under SLA | **PASS** |
| 18 | Launch Day Test | Full live journey: website → pricing → checkout → entitlement → download → install → action → receipt | Independent external validation completed 2026-09-14 | **PASS** |
| 19 | Security Tabletop | Malicious MCP / credential exposure scenario: routing, containment, disclosure | `pb001-incident-tabletop.md` — 2 exercises PASS | **PASS** |
| 20 | Launch Announcement | Published after website, checkout, downloads, legal, support, disclosure all live | Announcement published post-gate verification | **PASS** |
| 21 | Post-Launch Verification | Independent public-path: download → checksum → install → action → receipt → ledger → support | External environment validation PASS | **PASS** |
| 22 | First 72-Hour Watch | Security, install, billing, entitlement, docs priority monitoring | 0 P0/P1 through 2026-09-17 | **PASS** |
| 23 | Launch Incident Classification | P0/P1/P2/P3/v0.2 taxonomy operational | Classification runbook active in `public-launch-handoff.md` | **PASS** |
| 24 | v0.1.1 Policy | Patch criteria: fix → regression → build → validate → publish new checksums | `maintenance-policy.md` §4 emergency procedure | **PASS** |
| 25 | Maintenance Transition | Handoff to normal maintenance | `public-launch-handoff.md`; references `v0.1.0-maintenance-handoff.md` | **PASS** |
| 26 | v0.2 Product Planning | EB001-informed prioritization in roadmap | `docs/roadmap/v0.2.md` §3 updated | **PASS** |
| 27 | Final Launch Report | This document | All prior phases PASS | **PASS** |

**Overall:** **27/27 PASS**

---

## 3. Final Acceptance Criteria Verification

### Product — PASS
- Relay publicly downloadable via relay.dev and GitHub Releases
- Installation works (`install.sh` + `relay doctor`)
- Golden Demo deterministic (< 10 seconds, 7 scenes)
- Local UI (`relay ui`) operational on loopback with session auth
- Documentation complete and accurate

### Commercial — PASS
- Stripe checkout operational (Pro $49/seat/month, $39 annual)
- Billing state machine verified (28/28 webhooks)
- Offline Ed25519 entitlement issuance and verification
- 14-day refund and cancellation without local data impact
- 7-day dunning grace period with clean recovery

### Legal — PASS
- Privacy Policy, Terms, Refund Policy live and counsel-approved
- DPA available for Enterprise
- India grievance channel operational (`grievance@relay.dev`)
- Corporate identity: Relay Security Technologies Private Limited (CIN/GSTIN registered)
- Counsel sign-off: ALL APPROVED per `pb001-counsel-status.md`

### Security — PASS
- Security page and `SECURITY.md` live
- Vulnerability disclosure process operational (`security@relay.dev`, 48h SLA)
- No credential leakage; no commercial bypass of Cedar
- v0.1.0 security baseline preserved (SI-001–SI-024)
- M001–M003 adversarial harness 100% attacks blocked

### Privacy — PASS
- Production behavior matches approved Privacy Policy
- Execution data remains local (zero telemetry invariant)
- No hidden telemetry introduced during launch
- Subprocessors accurate: Stripe, GitHub, Cloudflare, Resend/AWS SES

### Operations — PASS
- Support operational (`support@relay.dev`)
- Security escalation operational (`security@relay.dev`)
- Billing support operational (`billing@relay.dev`)
- Incident response operational (Security/Privacy/Payment runbooks)
- CRL process operational (hybrid 30-day + signed CRL)

### Public Verification — PASS

A fresh external environment completed without internal engineering assistance:

```
find Relay → understand Relay → buy Relay → download Relay →
verify Relay → install Relay → use Relay → verify Relay's evidence → get support
```

---

## 4. Known Limitations (Accepted at Launch)

1. **Offline license revocation:** Hybrid model — 30-day short-lived license terms plus signed Certificate Revocation List (CRL) distribution. Compromised license revocation validated at < 15 minutes in EB001.
2. **macOS/Windows sandboxing:** Cooperative proxy mode (`HTTP_PROXY`/`HTTPS_PROXY`) without Linux kernel network namespace (`CLONE_NEWNET`) isolation. Documented in `docs/security/limitations.md` and `relay doctor` warnings.
3. **Host root compromise:** Software cannot protect against root/Administrator host compromise (standard OS threat model).
4. **Remote eventual consistency:** DSSE receipts certify Relay's observation, not remote cloud provider state after network partition.
5. **Direct Rust library misuse:** In-library connector construction without `GovernedActionRunner` requires manual policy orchestration (CLI binary is fail-closed).

---

## 5. Operational Status at Launch

| System | Status |
| :--- | :---: |
| Public website (relay.dev) | OPERATIONAL |
| Stripe checkout & portal | OPERATIONAL |
| Webhook consumer | OPERATIONAL |
| Entitlement service | OPERATIONAL |
| Email delivery (Resend/SES) | OPERATIONAL |
| GitHub Releases / install.sh | OPERATIONAL |
| Support channels | OPERATIONAL |
| Security disclosure | OPERATIONAL |
| CRL publication | OPERATIONAL |
| Monitoring (Phase 12) | ACTIVE |

---

## 6. Prior Validation Cross-Reference

| Milestone | Document | Key Result |
| :--- | :--- | :--- |
| GA005 | `GA005-launch-report.md` | v0.1.0 SHIPPED; artifact hashes certified |
| CR003 | `CR003-decision-record.md` | Commercial launch PASS; payment incident runbook |
| PB001 | `PB001-decision-record.md` | Private beta operations PASS; support runbook |
| EB001 | `EB001-decision-record.md` | READY FOR PUBLIC PAID LAUNCH |
| PB001 Legal | `pb001-counsel-status.md` | ALL APPROVED |

---

## 7. Conclusion

All 27 Public Paid Launch Runbook phases verified **PASS**. Relay transitions from beta to **PUBLIC PAID** commercial availability under normal maintenance per `docs/operations/public-launch-handoff.md`.

**Final decision recorded in:** `docs/release/PUBLIC-LAUNCH-DECISION.md`

---

**Phase 27 Status:** **PASS — LAUNCH REPORT COMPLETE**
