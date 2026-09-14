# Relay Evidence & Receipt Model

**Document ID:** `SEC-EVID-001`  
**Version:** `0.1.0`  
**Author:** Principal Security Architect  
**Status:** Approved Specification  

---

## 1. Epistemology of Action Receipts

A core objective of Relay is generating non-repudiable, tamper-evident cryptographic evidence for every governed tool execution.

To prevent security overstatement and forensic confusion, Relay strictly delineates what an `ActionReceipt` **asserts**, what it **observed**, and what it **does not prove**.

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              ACTION RECEIPT EPISTEMOLOGY                               │
├────────────────────────────┬────────────────────────────┬──────────────────────────────┤
│    ASSERTED BY RELAY       │    OBSERVED BY RELAY       │    NOT PROVEN BY RELAY       │
├────────────────────────────┼────────────────────────────┼──────────────────────────────┤
│ • Canonical ActionHash     │ • Exact start/end timestamp│ • Permanent remote DB state  │
│ • Tool Identity & Resource │ • Elapsed execution latency│ • Eventual cloud consistency │
│ • Evaluated Cedar Policies │ • HTTP response status code│ • Absence of external rollback│
│ • Active PolicySet Digest  │ • Response payload digest  │ • Downstream async queues    │
│ • Human Approval Binding   │ • Execution exit status    │ • Human business semantics   │
│ • Credential Lease Binding │ • Observed bytes returned  │ • Physical-world side effects│
│ • Node Signing Key Identity│                            │                              │
└────────────────────────────┴────────────────────────────┴──────────────────────────────┘
```

---

## 2. Receipt Architecture: DSSE & in-toto v1.0

Relay Action Receipts strictly adhere to open cryptographic and supply-chain evidence standards:

1. **Envelope Format:** Dead Simple Signing Envelope (DSSE, [RFC 9598](https://datatracker.ietf.org/doc/rfc9598/)).
2. **Payload Type:** `application/vnd.in-toto+json` (in-toto Statement v1.0 specification).
3. **Canonicalization:** RFC 8785 JSON Canonicalization Scheme (JCS).
4. **Signature Algorithm:** Ed25519 (RFC 8032) over DSSE Pre-Authentication Encoding (PAE):
   $$\text{PAE} = \text{"DSSEv1" } \parallel \text{len}(type) \parallel type \parallel \text{len}(body) \parallel body$$

### Receipt JSON Structure:
```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64_encoded_in_toto_statement>",
  "signatures": [
    {
      "keyid": "relay-node-ed25519-01",
      "sig": "<base64_encoded_ed25519_signature>"
    }
  ]
}
```

---

## 3. in-toto Statement Predicate Schema

The decoded payload contains an in-toto v1.0 Statement with predicate type `https://relay.dev/attestation/action-receipt/v1`:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "resource:file:///home/user/workspace/report.txt",
      "digest": {
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      }
    }
  ],
  "predicateType": "https://relay.dev/attestation/action-receipt/v1",
  "predicate": {
    "actionId": "01918a20-4321-7000-8000-000000000001",
    "sessionId": "session-prod-01",
    "actor": {
      "principal": "principal:agent:claude-code",
      "model": "claude-3-5-sonnet",
      "channel": "stdio"
    },
    "canonicalAction": {
      "tool": "relay.fs.write_file",
      "actionHash": "a6b4c3d2e1f0...",
      "parametersJcs": "{\"content\":\"...\",\"path\":\"...\"}"
    },
    "policyDecision": {
      "decision": "Allow",
      "policyDigest": "9f8e7d6c5b4a...",
      "determiningPolicies": ["permit-workspace-write"]
    },
    "approval": null,
    "credentialLease": null,
    "execution": {
      "executionId": "01918a20-9999-7000-8000-000000000002",
      "route": "Native",
      "startedAt": "2026-09-14T12:00:00.000Z",
      "completedAt": "2026-09-14T12:00:00.015Z",
      "latencyMs": 15
    },
    "observation": {
      "status": "Success",
      "exitCode": 0,
      "outputHash": "7b2a1c...",
      "bytesWritten": 1024,
      "summary": "Executed fs.write_file successfully"
    }
  }
}
```

---

## 4. Handling Ambiguous Mutation Outcomes

When an external target operation experiences a network drop, connection timeout, or server reset *after* the request was dispatched across the network, the ultimate state of the remote system is unknown to Relay.

In accordance with **SI-015**, Relay implements the following protocol:
1. **No Simulated Success:** Relay never returns a fabricated success response to the agent.
2. **Explicit Error Code:** Emits JSON-RPC error `-32010 Ambiguous Mutation`.
3. **Receipt Generation:** Generates an `ActionReceipt` with:
   - `governance_status = GovernanceStatus::AmbiguousMutation`
   - `observation.status = ExecutionObservationStatus::Undetermined`
4. **Ledger Recording:** The receipt is appended to the ledger to record that a mutation was dispatched but its final disposition could not be confirmed.
5. **No Blind Retries:** Automated retries of non-idempotent operations are blocked until manual or operational reconciliation.
