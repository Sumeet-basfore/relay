# Prompt Injection & Compromised Agent Model

**Document ID:** `SEC-PI-001`  
**Version:** `0.1.0`  
**Author:** Principal Security Architect  
**Status:** Approved Specification  

---

## 1. The Core Threat Assumption

Relay's security architecture is built upon a single, uncompromising foundational premise:

> **Assume the AI agent is 100% prompt-injection compromised.**

Whether through direct jailbreaking, indirect prompt injection from untrusted web pages, adversarial tool outputs, or context-window poisoning, Relay assumes the agent's natural-language intent and generated tool arguments are under total adversary control.

---

## 2. Why Relay Rejects LLM-Based Guardrails

Traditional "LLM guardrails" and input filters attempt to solve prompt injection using heuristic natural-language classifiers or secondary LLM evaluators.

Relay rejects this approach because:
1. **Probabilistic Failure:** Natural language is infinitely expressive and cannot provide mathematically sound security boundaries.
2. **Double-Inference Overhead:** Querying secondary LLM classifiers introduces hundreds of milliseconds of latency and substantial financial cost.
3. **Semantic Confusion:** An attacker can bypass text classifiers through encoding, obfuscation, or multi-turn persona shifts.

---

## 3. Authority Explicit at the Action Boundary

Instead of attempting to fix the agent's internal psychology, Relay enforces security **at the action execution boundary**.

Security decisions are evaluated on concrete, deterministic, typed facts:

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                         DETERMINISTIC ACTION BOUNDARY                            │
├──────────────────────────┬───────────────────────────────────────────────────────┤
│ 1. Canonical Arguments   │ Parsed into typed structs using RFC 8785 JCS;         │
│                          │ duplicate keys and parameter smuggling are rejected.  │
├──────────────────────────┼───────────────────────────────────────────────────────┤
│ 2. Concrete Resources    │ URIs and filesystem paths are lexically normalized and│
│                          │ resolved against strict jails (e.g. workspace root).  │
├──────────────────────────┼───────────────────────────────────────────────────────┤
│ 3. Explicit Actions      │ Tools map to strictly typed Cedar actions             │
│                          │ (`fs.read_file`, `postgres.query`, etc.).             │
├──────────────────────────┼───────────────────────────────────────────────────────┤
│ 4. Deterministic Policy  │ AWS Cedar evaluates boolean rules in <2ms with zero   │
│                          │ ambient I/O or probabilistic heuristics.              │
└──────────────────────────┴───────────────────────────────────────────────────────┘
```

---

## 4. What a Fully Compromised Agent Can and Cannot Do

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                     COMPROMISED AGENT CAPABILITY BOUNDARY                        │
├────────────────────────────────────────┬─────────────────────────────────────────┤
│ CANNOT DO (PREVENTED BY RELAY):        │ CAN DO (WITHIN POLICY PERMISSIONS):     │
├────────────────────────────────────────┼─────────────────────────────────────────┤
│ ✗ Steal target API keys or passwords   │ ✓ Read files explicitly permitted by    │
│ ✗ Access paths outside workspace jail  │   administrator Cedar policy            │
│ ✗ Drop database tables under read policy│ ✓ Submit valid queries against permitted │
│ ✗ Delete files without human approval  │   tables within permitted schemas       │
│ ✗ Tamper with historical audit receipts│ ✓ Create issues in permitted GitHub repos│
│ ✗ Bypass default-deny Cedar rules      │                                         │
└────────────────────────────────────────┴─────────────────────────────────────────┘
```

Relay confines a fully compromised agent strictly to the blast radius explicitly authorized by the administrator's Cedar security policy.
