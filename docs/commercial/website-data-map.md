# Relay Planned Website — Data Map

**Document ID:** `CR001-WEB-001`  
**Version:** `1.0.0`  
**Status:** PLANNED — Website not yet live  
**Last Updated:** 2026-09-14  

---

## 1. Scope & Status

This document inventories data flows for the **planned** Relay commercial website. As of Relay `v0.1.0`:

- **No public marketing website is deployed**
- **No account registration system exists**
- **No cookie consent banner is implemented**
- **No analytics provider is selected**

All vendor selections below are marked **TBD** until procurement and counsel review complete.

---

## 2. Planned Website Surfaces

| Surface | Purpose | Status |
|:---|:---|:---|
| Marketing homepage | Product overview, download links | PLANNED |
| Documentation portal | User guides, security docs | PLANNED (partial content exists in repo) |
| Download page | Links to GitHub Releases / `install.sh` | PLANNED |
| Account portal | Subscriptions, team management | PLANNED / TBD |
| Support / contact | Ticket submission | PLANNED / TBD |
| Security page | Vulnerability disclosure, trust materials | PLANNED |
| Status page | Service availability (hosted services only) | PLANNED / TBD |

---

## 3. Data Collected by Planned Website

| Data Element | Collection Point | Purpose | Legal Role (TBD) | Retention (TBD) |
|:---|:---|:---|:---|:---|
| IP address | HTTP request | Security, rate limiting, geo routing | Controller (Relay) | TBD — counsel |
| User-Agent | HTTP request | Compatibility, abuse detection | Controller | TBD |
| Session cookie | Login | Authentication | Controller | Session + configured TTL |
| Auth token (JWT/session) | Login | Account access | Controller | TBD |
| Email address | Sign-up | Account identity, billing | Controller | Account lifetime + statutory |
| Name / organization | Sign-up / profile | Account metadata | Controller | Account lifetime |
| Password hash | Sign-up (if password auth) | Authentication | Controller | Account lifetime |
| OAuth subject ID | Social login (if used) | Authentication | Controller | Account lifetime |
| Support message content | Contact form | Customer support | Controller | TBD — counsel |
| Newsletter email | Opt-in form | Marketing (if offered) | Controller | Until unsubscribe |
| Payment redirect token | Checkout redirect | Billing handoff | Processor primarily | Processor policy |
| CAPTCHA response | Form submission | Bot prevention | TBD vendor | Ephemeral |
| CDN access logs | Edge network | Performance, DDoS | TBD CDN | TBD |
| Error logs | Application server | Debugging | Controller | TBD — minimize PII |

---

## 4. Third-Party Service Classification

Each service must be classified before launch:

| Service Category | Candidate Vendors | Classification | Decision |
|:---|:---|:---|:---|
| **Hosting** | AWS / GCP / Azure / Vercel / Fly.io | Required for website | **TBD** |
| **CDN** | Cloudflare / Fastly / CloudFront | Recommended | **TBD** |
| **DNS** | Cloudflare / Route53 | Required | **TBD** |
| **Email (transactional)** | Postmark / SES / Resend | Required for accounts | **TBD** |
| **Email (marketing)** | None initially preferred | Optional | **Avoid until needed** |
| **Analytics** | None / Plausible / self-hosted | Optional | **Avoid by default** — prefer no third-party analytics at launch |
| **Session/auth** | Self-hosted / Auth0 / Clerk | Required if accounts | **TBD** |
| **Support desk** | Plain email / Zendesk / Intercom | Required for paid support | **TBD** |
| **CAPTCHA** | hCaptcha / Cloudflare Turnstile | Optional | **TBD** — only if abuse observed |
| **Payment** | Stripe / Razorpay | Required for billing | **TBD** — India + international |
| **Status monitoring** | Statuspage / self-hosted | Optional | **TBD** |
| **Documentation hosting** | GitHub Pages / Mintlify / self-hosted | Recommended | **TBD** |

**Classification key:**

- **Required:** Cannot launch commercial website/accounts without it
- **Optional:** Adds functionality; evaluate privacy impact before enabling
- **Avoid/remove:** Prefer not to deploy; remove if non-essential

---

## 5. Cookie & Tracking Inventory (Planned)

| Cookie / Storage | Type | Purpose | Default | Vendor |
|:---|:---|:---|:---|:---|
| Session ID | Strictly necessary | Authentication | On (if logged in) | Self-hosted (TBD) |
| CSRF token | Strictly necessary | Form security | On | Self-hosted (TBD) |
| Analytics ID | Non-essential | Usage tracking | **OFF** | None planned at launch |
| Marketing pixels | Non-essential | Ad retargeting | **OFF — avoid** | None |
| Preference cookie | Functional | Theme/locale | Opt-in | Self-hosted (TBD) |

**Launch preference:** No non-essential cookies until cookie policy and consent mechanism are drafted by counsel.

---

## 6. Data Flow Diagram (Planned)

```text
Visitor Browser
      │
      │ HTTPS
      ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ CDN (TBD)   │────►│ Web Host    │────►│ App Backend │
└─────────────┘     │ (TBD)       │     │ (TBD)       │
                    └─────────────┘     └──────┬──────┘
                                               │
                    ┌──────────────────────────┼──────────────────────────┐
                    ▼                          ▼                          ▼
             Auth Provider              Payment Processor            Email Provider
                 (TBD)                       (TBD)                      (TBD)
```

**Critical boundary:** Website must not receive or store Relay local execution data (ledger, receipts, tool arguments, credentials) unless a future opt-in hosted service is explicitly designed and disclosed.

---

## 7. Separation from Relay Binary

| Data | Website | Relay Binary |
|:---|:---|:---|
| MCP tool arguments | Must NOT collect | Processed locally |
| Ledger / receipts | Must NOT collect (v0.1.0) | Stored in `.relay/ledger.db` |
| Target credentials | Must NOT collect | OS keyring only |
| Download analytics | TBD — prefer GitHub release stats only | N/A |
| Account email | Future website only | Not required for binary |

---

## 8. Privacy Design Requirements (Pre-Launch)

Before website goes live, engineering must confirm:

1. **Data minimization:** Collect only fields required for stated purpose
2. **No execution telemetry:** Website JS must not scrape local Relay state
3. **Subprocessor disclosure:** Update `subprocessors.md` before launch
4. **Cookie policy:** Draft only after vendor selection (counsel)
5. **Account deletion path:** Design before account system ships
6. **No dark patterns:** Opt-in for marketing; no pre-checked analytics

---

## 9. Related Documents

- `docs/commercial/data-flow.md` — Master inventory
- `docs/commercial/subprocessors.md` — Vendor list (TBD)
- `docs/legal/privacy-policy-spec.md` — Counsel drafting spec
