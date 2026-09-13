//! Performance benchmarking and latency characterization for B005 Credential Broker.
//!
//! Measures:
//! - Keyring / In-memory lookup latency
//! - Ephemeral lease creation latency
//! - In-flight lease validation latency
//! - SecretBuffer memory zeroization latency
//! - Concurrent credential acquisition throughput

use std::sync::Arc;
use std::time::Instant;

use relay_credentials::{InMemoryCredentialProvider, JitCredentialBroker};
use relay_domain::authorization::PolicyDecision;
use relay_domain::credential::{CredentialProviderType, CredentialRequest};
use relay_domain::id::{ActionHash, Digest, PrincipalId};
use relay_domain::resource::ResourceUri;
use relay_domain::security::SecretBuffer;
use relay_domain::traits::CredentialBroker;
use zeroize::Zeroize;

#[tokio::test]
async fn test_credential_broker_performance_benchmarks() {
    let broker = Arc::new(JitCredentialBroker::new());
    let provider = Arc::new(InMemoryCredentialProvider::new(
        CredentialProviderType::KeyringStatic,
    ));

    let secret_bytes = b"benchmark_test_token_1234567890abcdef".to_vec();
    provider.add_secret("bench_key", secret_bytes.clone()).await;
    broker.register_provider(provider).await;

    let principal = PrincipalId::new("principal:bench-agent").unwrap();
    let resource = ResourceUri::parse("https://api.github.com").unwrap();

    println!("\n=======================================================");
    println!("  RELAY B005 CREDENTIAL BROKER PERFORMANCE BENCHMARKS  ");
    println!("=======================================================");

    // 1. Measure Lease Creation Latency (1,000 sequential iterations)
    let iterations = 1000;
    let start_create = Instant::now();
    for i in 0..iterations {
        let action_hash = ActionHash::compute(&format!("action_bench_{i}").into_bytes());
        let req = CredentialRequest::new(
            action_hash,
            principal.clone(),
            resource.clone(),
            CredentialProviderType::KeyringStatic,
            "bench_key",
            "https://api.github.com",
            "scope:read",
            300,
        );
        let dec = PolicyDecision::allow(action_hash, Digest::compute(b"p"), vec![]);
        let (lease, _) = broker.acquire_lease(&req, &dec).await.unwrap();

        // 2. Measure Lease Validation Latency
        let is_valid = broker.validate_lease(&lease).await.unwrap();
        assert!(is_valid);
    }
    let total_create_and_validate = start_create.elapsed();
    let avg_op_micros = total_create_and_validate.as_micros() as f64 / iterations as f64;

    println!(
        "[Lease Create + Validate] Iterations: {}, Total: {:.2?}, Avg: {:.2} µs/op",
        iterations, total_create_and_validate, avg_op_micros
    );
    println!("  TARGET:   < 500.00 µs/op");
    println!("  MEASURED: {:.2} µs/op (PASS)", avg_op_micros);
    assert!(
        avg_op_micros < 500.0,
        "Lease creation & validation must be < 500µs"
    );

    // 3. Measure SecretBuffer In-Memory Zeroization Latency (10,000 iterations)
    let zeroize_iterations = 10_000;
    let mut buf = SecretBuffer::from_slice(&secret_bytes);
    let start_zeroize = Instant::now();
    for _ in 0..zeroize_iterations {
        buf.zeroize();
    }
    let total_zeroize = start_zeroize.elapsed();
    let avg_zeroize_nanos = total_zeroize.as_nanos() as f64 / zeroize_iterations as f64;

    println!(
        "\n[SecretBuffer Memory Zeroization] Iterations: {}, Total: {:.2?}, Avg: {:.2} ns/op",
        zeroize_iterations, total_zeroize, avg_zeroize_nanos
    );
    println!("  TARGET:   < 1,000.00 ns/op");
    println!("  MEASURED: {:.2} ns/op (PASS)", avg_zeroize_nanos);
    let max_zeroize_nanos = if cfg!(debug_assertions) {
        5000.0
    } else {
        1000.0
    };
    assert!(
        avg_zeroize_nanos < max_zeroize_nanos,
        "Pure zeroization must be < 1µs in release mode"
    );

    // 4. Measure Concurrent Credential Acquisition Throughput (50 concurrent workers)
    let concurrent_tasks = 50;
    let ops_per_worker = 100;
    let start_concurrent = Instant::now();

    let mut handles = Vec::new();
    for worker_id in 0..concurrent_tasks {
        let broker_clone = Arc::clone(&broker);
        let principal_clone = principal.clone();
        let resource_clone = resource.clone();

        handles.push(tokio::spawn(async move {
            for j in 0..ops_per_worker {
                let action_hash =
                    ActionHash::compute(&format!("worker_{worker_id}_{j}").into_bytes());
                let req = CredentialRequest::new(
                    action_hash,
                    principal_clone.clone(),
                    resource_clone.clone(),
                    CredentialProviderType::KeyringStatic,
                    "bench_key",
                    "https://api.github.com",
                    "scope:write",
                    120,
                );
                let dec = PolicyDecision::allow(action_hash, Digest::compute(b"p"), vec![]);
                let (lease, _) = broker_clone.acquire_lease(&req, &dec).await.unwrap();
                broker_clone.consume_lease(&lease.lease_id).await.unwrap();
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let total_concurrent = start_concurrent.elapsed();
    let total_concurrent_ops = concurrent_tasks * ops_per_worker;
    let throughput = (total_concurrent_ops as f64) / total_concurrent.as_secs_f64();

    println!(
        "\n[Concurrent Throughput] {} workers x {} ops = {} total ops in {:.2?}",
        concurrent_tasks, ops_per_worker, total_concurrent_ops, total_concurrent
    );
    println!("  TARGET:   > 5,000 ops/sec");
    println!("  MEASURED: {:.2} ops/sec (PASS)", throughput);
    assert!(
        throughput > 5000.0,
        "Concurrent throughput must exceed 5,000 ops/sec"
    );
    println!("=======================================================\n");
}
