# Security Policy

## 1. Supported Versions

Relay maintains security patches and updates for the following release lines:

| Version | Supported | Security Maintenance Level |
|:---:|:---:|:---|
| `0.1.x` (MVP) | :white_check_mark: | Active Security Updates & Patches |
| `< 0.1.0` | :x: | End of Life (Development Pre-releases) |

---

## 2. Reporting a Vulnerability

We take the security of Relay seriously. If you discover a vulnerability, security flaw, or cryptographic weakness, please report it privately to our security team.

**Do NOT report security vulnerabilities via public GitHub issues, pull requests, or discussions.**

### Contact Information:
- **Email:** `security@relay.dev`
- **PGP Fingerprint (Optional):** Available upon request for encrypted communications.

### What to Include in Your Report:
1. **Description:** A detailed description of the vulnerability, potential impact, and affected components.
2. **Steps to Reproduce:** Minimal reproduction steps, script, or configuration file.
3. **Attack Preconditions:** What privileges or preconditions are required for exploitation (e.g. prompt injection, unprivileged local user).
4. **Proposed Fix (Optional):** If you have identified a potential fix, feel free to include a patch or suggested remediation.

---

## 3. Vulnerability Response Timeline

Upon receiving a private vulnerability disclosure:
1. **Initial Acknowledgment:** Within **48 business hours**, we will acknowledge receipt of your report.
2. **Assessment & Validation:** Within **7 business days**, we will confirm reproduction and assess severity.
3. **Remediation & Patching:** We will work on a patch and coordinate a mutual release date for public disclosure.
4. **Public Credit:** We will publicly credit your contribution in the release notes (unless you prefer anonymity).

---

## 4. Security Scope & Boundaries

### In-Scope Vulnerabilities:
- Circumvention of Cedar policy enforcement (e.g. bypassing default-deny).
- Leaking target API keys, passwords, or tokens to the agent or subprocesses.
- Unauthorized execution of unpermitted filesystem, SQL, or GitHub actions.
- Tampering with Action Receipts or SQLite ledger entries without detection.
- Cross-action reuse or forgery of human interactive approvals.
- Memory corruption, secret persistence, or denial-of-service in Relay's core parser or gateway.

### Out-of-Scope Vulnerabilities:
- Attacks requiring `root` or administrator access on the host operating system.
- Direct physical memory acquisition (e.g. hardware cold boot attacks).
- Insecure behavior resulting from intentionally permissive user-configured policies (e.g. `permit(principal, action, resource)`).
- Third-party target service downtime, cloud API rate limiting, or remote server compromises.
- Prompt injection against LLMs that does *not* violate Relay's Cedar policy boundary.
