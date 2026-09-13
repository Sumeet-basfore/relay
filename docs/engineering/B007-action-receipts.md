# Milestone B007: Action Receipt & Evidence Packaging Subsystem

**Status:** Completed & Verified  
**Milestone:** B007  
**Specification References:** [R011 Action Receipts](../research/R011-action-receipts.md), [R015 Build Gate](../research/R015-build-gate.md), [A001 System Architecture](../architecture/A001-system-architecture.md), [A002 Domain Model](../architecture/A002-domain-model.md), [A003 Interfaces & Contracts](../architecture/A003-interfaces-and-contracts.md), [A004 Security Invariants](../architecture/A004-security-invariants.md), [A005 Test Strategy](../architecture/A005-test-strategy.md), [A006 Persistence & Storage](../architecture/A006-persistence-and-storage.md), [A008 Dependency Architecture](../architecture/A008-rust-dependency-architecture.md), [A010 Build Specification](../architecture/A010-build-specification.md)  
**Implementation Crates:** `crates/relay-receipts`, `crates/relay-domain`, `crates/relay-connectors`

---

## 1. Executive Summary

Milestone B007 implements Relay's **Action Receipt and Evidence Packaging Subsystem**.

In autonomous agent systems, trusting agent-reported outcomes creates severe security and auditability risks. Agents can hallucinate success, misreport target responses, suppress side effects, or hide failed or ambiguous mutations. Relay resolves this by acting as the authoritative, cryptographically verifiable witness to every governed operation.

Every action executed through Relay produces an immutable, cryptographically signed **Action Receipt** that bundles the full chain of custody:
1. **Proposal Evidence:** The canonical action proposal from the agent (`CanonicalAction` and its canonical `ActionHash`).
2. **Policy Evidence:** The policy authorization decision from Cedar (`PolicyDecision`, including `policy_digest` and determining policies).
3. **Approval Evidence:** The interactive human approval record, if required (`ApprovalEvidence`).
4. **Credential Lease Evidence:** Ephemeral lease audit metadata (`CredentialLeaseEvidence`: lease ID, provider, key alias, issued/expires timestamps — **strictly zero secret material**).
5. **Execution Evidence:** Dispatch metadata (`ExecutionEvidence`: execution ID, route, connector, operation, endpoint, timing).
6. **Observation Evidence:** Authoritative telemetry observed by Relay (`ObservationEvidence`: HTTP status code, output byte count, response body digest, and ambiguous mutation flags).
7. **Epistemological Fact Segregation:** Explicit demarcation separating Relay-asserted facts, Relay-observed telemetry, and unverified target server claims.

The evidence is serialized to **RFC 8785 JSON Canonicalization Scheme (JCS)**, scrubbed against known secret token signatures, formatted as an **in-toto Statement v1.0**, and signed using an **Ed25519 digital signature** wrapped in an **RFC 9598 Dead Simple Signing Envelope (DSSE)**.

```text
+----------------------------------------------------------------------------------------------------+
|                                 B007 ACTION RECEIPT PIPELINE                                        |
|                                                                                                    |
|  [CanonicalAction] ──► [PolicyDecision] ──► [Approval (if req)] ──► [CredentialLease (Metadata)]   |
|         │                     │                    │                        │                      |
|         └─────────────────────┼────────────────────┼────────────────────────┘                      |
|                               ▼                                                                    |
|                    [Governed HTTP Execution]                                                       |
|                               │                                                                    |
|                               ▼                                                                    |
|                   [Relay Execution Observation]                                                    |
|                               │                                                                    |
|                               ▼                                                                    |
|                  [DomainActionReceipt Assembly]                                                    |
|                               │  • Validate ActionHash bindings across all evidence (SI-005/006)   |
|                               │  • Enforce Policy ALLOW (Fails closed on Deny) (SI-002)            |
|                               │  • Enforce AmbiguousMutation status on timeouts (SI-015)           |
|                               ▼                                                                    |
|                  [in-toto Statement v1.0 Mapping]                                                  |
|                               │  • _type: "https://in-toto.io/Statement/v1"                        |
|                               │  • subject: ResourceUri + sha256:ActionHash                        |
|                               │  • predicateType: "https://relay.dev/ActionReceipt/v1"             |
|                               ▼                                                                    |
|                 [RFC 8785 JCS Canonicalization]                                                    |
|                               │  • Deterministic key ordering and whitespace stripping             |
|                               ▼                                                                    |
|                  [Defensive Secret Scrubbing]                                                      |
|                               │  • Reject ghp_, gho_, sk-proj-, AKIA, Bearer, PEM keys             |
|                               ▼                                                                    |
|                 [RFC 9598 DSSE Envelope & Sign]                                                    |
|                               │  • PAE("application/vnd.in-toto+json", canonical_bytes)           |
|                               │  • Ed25519 Dalek Signature                                         |
|                               ▼                                                                    |
|                      [Signed ActionReceipt] ──► (Handoff to B008 SQLite Ledger)                    |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. What a Relay Receipt Proves vs. What It Does NOT Prove

A fundamental requirement of Relay's security architecture ([R011](../research/R011-action-receipts.md), [A004](../architecture/A004-security-invariants.md) SI-015) is **epistemological honesty**. Receipts must never make claims about external system states that Relay cannot cryptographically or direct-observationally prove.

### What a Relay Receipt PROVES:
1. **Authorization:** That the specific canonical action represented by `ActionHash` was evaluated against an identified Cedar policy set (`policy_digest`) and resulted in an explicit `ALLOW`.
2. **Approval:** That if step-up human approval was required by policy, a specific authenticated approver approved the exact `ActionHash` before execution.
3. **Mediation:** That the network request was dispatched through Relay's native connector, with credentials acquired via an ephemeral, single-use lease tied to the `ActionHash`.
4. **Dispatched Payload:** That the request method, endpoint, and serialized arguments dispatched over the network matched the canonical action.
5. **Observed Telemetry:** That Relay directly received the observed HTTP status code, response headers, response body byte count, and SHA-256 response digest at the recorded timestamp.
6. **Non-Tampering:** That the entire statement has not been modified since signing, verified by the Ed25519 signature over the DSSE Pre-Authentication Encoding.

### What a Relay Receipt DOES NOT Prove:
1. **Target Internal State:** A receipt does **not** prove that the remote third-party service (e.g., GitHub) correctly committed the transaction to its underlying database.
2. **Side-Effect Permanence:** A receipt does **not** prove that a created resource was not subsequently deleted, overwritten, or rolled back by an asynchronous worker or administrator on the remote server.
3. **Agent Intent:** A receipt does **not** prove that the agent's high-level goal was benign or aligned; it only proves that the concrete operational invocation was authorized by the configured Cedar policies.
4. **Third-Party Claims:** A receipt does **not** endorse or verify the truth of arbitrary JSON response bodies returned by third-party APIs.

This distinction is formally recorded inside every in-toto receipt predicate in the `epistemology` block:
```json
"epistemology": {
  "asserted_by_relay": [
    "canonical_action_hash",
    "policy_evaluation_decision",
    "authorization_binding",
    "jit_lease_governance"
  ],
  "observed_by_relay": [
    "transport_dispatch_timing",
    "http_status_code",
    "stdout_byte_length",
    "raw_response_digest"
  ],
  "unverified_target_claims": [
    "remote_server_database_state_mutation",
    "third_party_resource_final_persistence"
  ]
}
```

---

## 3. Ambiguous Mutation Semantics (SI-015)

When a mutating network operation (e.g. `POST`, `PATCH`, `DELETE`, `PUT`) is dispatched to a remote service, and the connection experiences a timeout, TCP reset, or transport failure before a full HTTP response is received, the remote state is **indeterminate**:
- The remote server may have processed the mutation and committed it, but failed to transmit the HTTP response.
- The remote server may have dropped the request before processing.

Under invariant **SI-015**, Relay enforces:
1. **Never False Success:** Mutating timeouts must NEVER be marked as successful.
2. **Never False Clean-Failure:** Mutating timeouts must NEVER be marked as a simple non-mutating failure (which would invite unsafe automated retries).
3. **Explicit Ambiguous Mutation:** The observation status MUST be `ExecutionObservationStatus::AmbiguousMutation`.
4. **Attestation Flags:**
   - `is_ambiguous_mutation = true`
   - `retry_classification = "AmbiguousRequiresVerification"`
   - `error_class = "AmbiguousMutationOutcome"`
5. **Signed Receipt Production:** An `ActionReceipt` MUST still be generated, signed, and persisted, attesting that execution was dispatched but the outcome is ambiguous.

---

## 4. Zero Secret Material Guarantee (SI-001, SI-008)

Relay enforces that confidential tokens, API keys, and session secrets are never captured in receipts:
1. **Metadata-Only Evidence:** `CredentialLeaseEvidence` captures only structural audit data: `lease_id`, `provider`, `key_alias`, `scope`, `action_hash`, `issued_at`, and `expires_at`. The secret bytes are zeroized immediately after HTTP dispatch.
2. **Defensive Scrubbing Engine:** Before signing, canonical statement bytes are scanned by `relay_receipts::scrub::scrub_payload` against signature patterns:
   - `ghp_` (GitHub personal access tokens)
   - `gho_` (GitHub OAuth tokens)
   - `github_pat_` (GitHub fine-grained tokens)
   - `sk-proj-` (OpenAI project keys)
   - `AKIA` (AWS access keys)
   - `-----BEGIN PRIVATE KEY-----` / `-----BEGIN RSA PRIVATE KEY-----` (PEM keys)
   - `Authorization: Bearer ` (Ambient bearer token strings)
3. **Fail-Closed on Secret Detection:** If any pattern matches, receipt generation aborts with `ReceiptError::ProhibitedSecretDetected`.

---

## 5. Cryptographic & Serialization Architecture

### RFC 8785 JSON Canonicalization Scheme (JCS)
All in-toto statements are canonicalized via `serde_jcs` prior to signing:
- Object keys sorted lexicographically by UTF-16 code units (equivalent to byte ordering for ASCII/UTF-8).
- Minimal JSON representation without extraneous whitespace or formatting.
- Strict IEEE 754 float formatting.
- Determinism guarantee: Two distinct runs with identical domain data produce bit-for-bit identical byte slices.

### RFC 9598 Pre-Authentication Encoding (PAE)
To eliminate canonicalization confusion attacks in the signature envelope, digital signatures are calculated over the DSSE PAE structure:
$$\text{PAE}(t, p) = \text{"DSSEv1"} \parallel \text{" "} \parallel \text{len}(t) \parallel \text{" "} \parallel t \parallel \text{" "} \parallel \text{len}(p) \parallel \text{" "} \parallel p$$
Where $t = \text{"application/vnd.in-toto+json"}$ and $p$ is the JCS-canonicalized statement bytes.

### Ed25519 Signatures & Memory Zeroization
- Key generation uses cryptographically secure system randomness (`OsRng`).
- `Ed25519ReceiptSigner` implements `zeroize::ZeroizeOnDrop` ensuring secret key material is overwritten with zeroes upon deallocation.
- Signer `Debug` implementation masks secret keys (`[REDACTED SECRET KEY]`), outputting only public key hex and key identifier.

---

## 6. Security Invariant Matrix (A004 Mapping)

| Invariant | Description | Enforcement Mechanism in B007 | Verification Test |
| :--- | :--- | :--- | :--- |
| **SI-001** | Zero Credentials in Receipts | `CredentialLeaseEvidence` stores metadata only; JCS payload scrubbed against secret token regexes. | `test_action_with_credential_lease_metadata_only`, `test_prohibited_secret_patterns_rejected_before_signing` |
| **SI-002** | Complete Mediation | `ActionReceiptBuilder` rejects non-Allow policy decisions (`ReceiptError::UnauthorizedExecution`). | `test_denied_action_fails_closed`, `test_pipeline_deny_produces_no_receipt` |
| **SI-005** | ActionHash Immutability | Pre-signing assertion: `canonical_action.action_hash == decision.action_hash`. | `test_action_hash_mismatch_between_action_and_decision` |
| **SI-006** | Lease Binding | Lease `action_hash` validated against canonical action hash prior to receipt generation. | `test_action_hash_mismatch_between_action_and_lease` |
| **SI-008** | Auditable Receipts | Produces compliant in-toto v1.0 Statement and DSSE envelope with Ed25519 signature. | `test_in_toto_statement_schema_compliance`, `test_dsse_envelope_schema_compliance` |
| **SI-011** | Approval Binding | Approval `action_hash` and approved state verified prior to receipt assembly. | `test_action_with_valid_approval`, `test_action_hash_mismatch_between_action_and_approval` |
| **SI-015** | Epistemological Honesty | Fact segregation block included; ambiguous mutations explicitly flagged and never marked clean. | `test_action_with_ambiguous_mutation`, `test_ambiguous_mutation_timeout_produces_signed_receipt` |

---

## 7. Performance Characterization & Micro-Benchmarks

Micro-benchmarks were executed using the release build (`--release`) with 200 iterations over realistic GitHub issue creation workloads:

| Pipeline Stage | Measured Latency | A005 Target / Budget | Margin |
| :--- | :--- | :--- | :--- |
| **Domain Receipt Construction** | **2.36 µs** | < 100 µs | **42x faster** |
| **RFC 8785 JCS Canonicalization** | **17.60 µs** | < 500 µs | **28x faster** |
| **RFC 9598 DSSE PAE Computation** | **70 ns** | < 10 µs | **140x faster** |
| **Ed25519 Signing** | **52.99 µs** | < 1,000 µs (1.0 ms) | **18x faster** |
| **Ed25519 Verification** | **68.13 µs** | < 1,000 µs (1.0 ms) | **14x faster** |
| **Total End-to-End Pipeline** | **123.61 µs** | < 5,000 µs (5.0 ms) | **40x faster** |

Both signing (53 µs) and verification (68 µs) operate comfortably below the 1.0 ms budget, while total receipt generation overhead (124 µs) is an order of magnitude below the 5.0 ms ceiling.

---

## 8. Verification & Test Suite Summary

Milestone B007 added **43 new tests** across 8 dedicated test suites, bringing the total workspace test count to **279 passing tests**:

1. `crates/relay-receipts/tests/construction_tests.rs` (6 tests):
   - Valid receipt from allowed action
   - Denied action fail-closed
   - Valid step-up approval inclusion
   - Credential lease metadata inclusion
   - Failed execution observation capture
   - Ambiguous mutation observation capture
2. `crates/relay-receipts/tests/binding_tests.rs` (5 tests):
   - ActionHash mismatch between action and decision
   - ActionHash mismatch between action and approval
   - ActionHash mismatch between action and lease
   - Policy digest verification and match
   - Principal and resource scope cross-validation
3. `crates/relay-receipts/tests/crypto_tests.rs` (8 tests):
   - Ed25519 sign and verify success
   - Verification failure with wrong public key
   - Verification failure with corrupted payload
   - Verification failure with corrupted signature
   - Verification failure with invalid payloadType
   - Public key export and import round-trip
   - Distinct keys produce distinct signatures
   - Direct DSSE envelope verification
4. `crates/relay-receipts/tests/serialization_tests.rs` (6 tests):
   - Deterministic JCS byte identity across multiple serializations
   - RFC 8785 lexicographical key sorting
   - RFC 8785 whitespace stripping
   - In-toto Statement v1.0 schema compliance
   - DSSE envelope schema compliance
   - Malformed JSON / base64 error handling
5. `crates/relay-receipts/tests/secret_scrub_tests.rs` (2 tests):
   - Prohibited secret pattern rejection (`ghp_`, `gho_`, `github_pat_`, `sk-proj-`, `AKIA`, PEM keys, Bearer headers)
   - Benign similar strings permitted without false positives
6. `crates/relay-receipts/tests/performance_tests.rs` (1 test):
   - Micro-benchmarks validating signing (<1ms), verification (<1ms), and total pipeline (<5ms)
7. `crates/relay-receipts/tests/integration_tests.rs` (3 tests):
   - End-to-end governed pipeline with Cedar PEP and Credential Broker
   - Ambiguous mutation pipeline receipt
   - Policy denial fail-closed
8. `crates/relay-connectors/tests/receipt_integration_tests.rs` (3 tests):
   - Full live WireMock pipeline producing signed and verified receipt
   - Ambiguous mutation timeout producing verified ambiguous receipt
   - Policy denial producing zero receipts and zero network calls
9. `crates/relay-receipts/src/` unit tests (9 tests):
   - Canonicalization, DSSE PAE, secret scrubber, and signer unit tests

**Quality Gates:**
- `cargo test --workspace`: **279 passed, 0 failed**
- `cargo clippy --workspace --all-targets -- -D warnings`: **0 warnings**
- `cargo fmt --all -- --check`: **Clean**

---

## 9. Handoff to Milestone B008 (SQLite Ledger)

Milestone B007 provides the immutable `ActionReceipt` data structure and cryptographic packaging pipeline required by Milestone B008:
- **Receipt Payload:** `ActionReceipt` contains `receipt_id`, `action_id`, `session_id`, `action_hash`, `receipt_hash`, `parent_receipt_hash`, `dsse_envelope`, and `created_at`.
- **Hash-Chaining:** The `parent_receipt_hash` field connects each receipt into a tamper-evident append-only hash chain.
- **Verification Engine:** `ReceiptVerifier` allows B008 to verify stored ledger entries independently against the public key without needing private signing keys.
- **Persistence Readiness:** Serialized DSSE envelopes and receipt metadata are ready for insertion into SQLite ledger tables.
