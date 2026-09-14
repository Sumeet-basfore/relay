# Relay Policy Security Model

**Document ID:** `SEC-POL-001`  
**Version:** `0.1.0`  
**Author:** Principal Security Architect  
**Status:** Approved Specification  

---

## 1. AWS Cedar Authorization Engine

Relay utilizes [AWS Cedar](https://www.cedarpolicy.com/) (v4.0) as its embedded, deterministic Policy Decision Point (PDP) and Policy Enforcement Point (PEP).

Cedar was chosen over custom DSLs or regex filters because it provides:
1. **Deterministic Evaluation:** Fast, pure boolean decision engine without side effects or ambient I/O.
2. **Formal Verification:** Built on automated reasoning and formal verification proofs.
3. **Explicit Schema Typing:** Rejects unknown actions, unmapped entities, or malformed attributes before policy evaluation.

---

## 2. Relay Entity & Schema Model

Relay defines three primary entity types within the `Relay` namespace:

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                               RELAY CEDAR SCHEMA                                 │
├───────────────────┬──────────────────────────────────┬───────────────────────────┤
│ ENTITY TYPE       │ IDENTIFIER FORMAT                │ ATTRIBUTES                │
├───────────────────┼──────────────────────────────────┼───────────────────────────┤
│ `Relay::Agent`    │ `principal:agent:<id>`           │ `model`, `framework`      │
│ `Relay::Action`   │ `fs.<action>`, `github.<action>`,│ `step_up_approval` (bool) │
│                   │ `postgres.<action>`              │                           │
│ `Relay::Resource` │ `file:///...`, `github://...`,   │ `path`, `schema`, `table`,│
│                   │ `postgres://...`                 │ `owner`, `repo`           │
└───────────────────┴──────────────────────────────────┴───────────────────────────┘
```

---

## 3. Core Policy Semantics

### 3.1 Strict Default-Deny
If no explicit `permit` rule matches an authorization request, Cedar evaluates to `Deny`. Furthermore, any matching `forbid` rule unconditionally overrides any number of `permit` rules.

### 3.2 Policy-Set Digest Binding (SI-010)
When Relay loads policies from a directory or embedded binary resources, it computes a deterministic SHA-256 digest over the sorted, canonical representation of all active Cedar rules:
$$\text{PolicyDigest} = \text{SHA256}(\text{SortedPolicyRules})$$

This `PolicyDigest` is recorded in every policy decision and sealed into the resulting signed `ActionReceipt`, guaranteeing non-repudiable binding between the executed action and the active governance policy.

---

## 4. Example Cedar Policies

### 4.1 Production Secure Policy Example (Recommended)

```cedar
// 1. Unconditionally forbid access to sensitive system paths and credentials
forbid (
    principal,
    action,
    resource is Relay::Resource
)
when {
    resource.path like "*/.ssh/*" ||
    resource.path like "*/.env*" ||
    resource.path like "*/.aws/*" ||
    resource.path like "/etc/*"
};

// 2. Permit read-only workspace filesystem access
permit (
    principal == Relay::Agent::"principal:agent:claude-code",
    action in [
        Relay::Action::"fs.read_file",
        Relay::Action::"fs.list_directory",
        Relay::Action::"fs.stat_path"
    ],
    resource is Relay::Resource
)
when {
    resource.path like "/home/user/workspace/*"
};

// 3. Permit workspace file creation/modification
permit (
    principal == Relay::Agent::"principal:agent:claude-code",
    action == Relay::Action::"fs.write_file",
    resource is Relay::Resource
)
when {
    resource.path like "/home/user/workspace/*"
};

// 4. Require interactive human approval for file deletions
permit (
    principal == Relay::Agent::"principal:agent:claude-code",
    action == Relay::Action::"fs.delete_file",
    resource is Relay::Resource
)
when {
    resource.path like "/home/user/workspace/*"
};
```

---

### 4.2 Permissive Development Policy (DEVELOPMENT ONLY)

> [!CAUTION]
> **DEVELOPMENT ONLY:** The following policy permits all agent actions without restriction. Never deploy this policy in production environments.

```cedar
// WARNING: Permissive development-only policy. DO NOT USE IN PRODUCTION.
permit (
    principal,
    action,
    resource
);
```
