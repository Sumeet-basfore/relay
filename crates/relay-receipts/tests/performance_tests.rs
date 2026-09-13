mod common;

use common::*;
use relay_receipts::{
    canonicalize_statement, compute_pae, ActionReceiptBuilder, Ed25519ReceiptSigner,
    ReceiptVerifier,
};
use std::time::Instant;

#[test]
fn test_performance_targets_microbenchmark() {
    let (action, action_hash) = create_test_action();
    let decision = create_test_decision(action_hash, true);
    let lease = create_test_lease(action_hash, &action.principal, &action.resource);
    let signer = Ed25519ReceiptSigner::generate("bench-signer");
    let verifier = ReceiptVerifier::new(signer.verifying_key());

    let iterations = 200;

    // 1. Benchmark Receipt construction
    let builder = ActionReceiptBuilder::new(&action, &decision).with_credential_lease(Some(&lease));

    let start = Instant::now();
    for _ in 0..iterations {
        let _domain = builder.build_domain().unwrap();
    }
    let construction_avg = start.elapsed() / iterations;

    // 2. Benchmark JCS canonicalization
    let domain = builder.build_domain().unwrap();
    let statement = domain.to_in_toto_statement().unwrap();

    let start = Instant::now();
    for _ in 0..iterations {
        let _bytes = canonicalize_statement(&statement).unwrap();
    }
    let jcs_avg = start.elapsed() / iterations;

    // 3. Benchmark DSSE PAE computation
    let canonical_bytes = canonicalize_statement(&statement).unwrap();
    let start = Instant::now();
    for _ in 0..iterations {
        let _pae = compute_pae("application/vnd.in-toto+json", &canonical_bytes);
    }
    let pae_avg = start.elapsed() / iterations;

    // 4. Benchmark Ed25519 signing
    let start = Instant::now();
    for _ in 0..iterations {
        let _env = signer
            .sign_payload_bytes_sync("application/vnd.in-toto+json", &canonical_bytes)
            .unwrap();
    }
    let signing_avg = start.elapsed() / iterations;

    // 5. Benchmark Ed25519 verification
    let receipt = builder.build_and_sign(&signer).unwrap();
    let start = Instant::now();
    for _ in 0..iterations {
        let res = verifier.verify_receipt(&receipt, Some(&action_hash), None);
        assert!(res.is_valid());
    }
    let verification_avg = start.elapsed() / iterations;

    // 6. Benchmark End-to-end receipt pipeline
    let start = Instant::now();
    for _ in 0..iterations {
        let r = builder.build_and_sign(&signer).unwrap();
        let res = verifier.verify_receipt(&r, Some(&action_hash), None);
        assert!(res.is_valid());
    }
    let e2e_avg = start.elapsed() / iterations;

    println!("\n=== Relay B007 Receipt Micro-benchmarks ===");
    println!("Domain construction:     {:?}", construction_avg);
    println!("JCS canonicalization:    {:?}", jcs_avg);
    println!("DSSE PAE computation:    {:?}", pae_avg);
    println!("Ed25519 signing:         {:?}", signing_avg);
    println!("Ed25519 verification:    {:?}", verification_avg);
    println!("End-to-end total:        {:?}", e2e_avg);
    println!("==========================================\n");

    let (max_signing_us, max_verification_us, max_e2e_us) = if cfg!(debug_assertions) {
        (25_000, 25_000, 50_000)
    } else {
        // Enforce A005 performance budgets in optimized mode:
        // Signing < 1ms (1,000 µs), Verification < 1ms (1,000 µs), Total overhead < 5ms (5,000 µs)
        (1_000, 1_000, 5_000)
    };

    assert!(
        signing_avg.as_micros() < max_signing_us,
        "Signing average {:?} exceeds budget ({} µs)",
        signing_avg,
        max_signing_us
    );
    assert!(
        verification_avg.as_micros() < max_verification_us,
        "Verification average {:?} exceeds budget ({} µs)",
        verification_avg,
        max_verification_us
    );
    assert!(
        e2e_avg.as_micros() < max_e2e_us,
        "End-to-end average {:?} exceeds budget ({} µs)",
        e2e_avg,
        max_e2e_us
    );
}
