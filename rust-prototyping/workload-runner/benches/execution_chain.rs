//! Hop-level Benchmark
//!
//! Measures timing breakdown per hop: VC creation, DID resolution, execution.

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use tokio::runtime::Runtime;
use std::sync::Arc;
use std::time::{Duration, Instant};
use workload_runner::workload::sovereign::{
    gateway::Gateway,
    registry::Registry,
    Request,
    Response,
};

// ============================================================================
// Timing Breakdown Structs
// ============================================================================

/// Timing for a single hop
#[derive(Debug, Clone, Default)]
pub struct HopTiming {
    pub hop_name: String,
    pub did_resolve: Duration,
    pub vc_create: Duration,
    pub vc_verify: Duration,
    pub pca_create: Duration,
    pub pca_verify: Duration,
    pub execution: Duration,
    pub total: Duration,
}

/// Timing for the entire chain
#[derive(Debug, Clone, Default)]
pub struct ChainTiming {
    pub hops: Vec<HopTiming>,
    pub total: Duration,
}

impl ChainTiming {
    pub fn print_summary(&self) {
        println!();
        println!("Chain Execution Timing");
        println!("======================");
        println!();
        println!(
            "{:<15} {:>12} {:>12} {:>12} {:>12} {:>12} {:>12}",
            "HOP", "DID", "VC_CREATE", "VC_VERIFY", "PCA_CREATE", "PCA_VERIFY", "EXEC"
        );
        println!("{}", "-".repeat(93));

        for hop in &self.hops {
            println!(
                "{:<15} {:>9.2}us {:>9.2}us {:>9.2}us {:>9.2}us {:>9.2}us {:>9.2}us",
                hop.hop_name,
                hop.did_resolve.as_nanos() as f64 / 1000.0,
                hop.vc_create.as_nanos() as f64 / 1000.0,
                hop.vc_verify.as_nanos() as f64 / 1000.0,
                hop.pca_create.as_nanos() as f64 / 1000.0,
                hop.pca_verify.as_nanos() as f64 / 1000.0,
                hop.execution.as_nanos() as f64 / 1000.0,
            );
        }

        println!("{}", "-".repeat(93));
        println!(
            "TOTAL: {:.2}us ({:.2}ms)",
            self.total.as_nanos() as f64 / 1000.0,
            self.total.as_nanos() as f64 / 1_000_000.0
        );
        println!();
    }
}

// ============================================================================
// Instrumented Execution (simulated - adapt to your actual code)
// ============================================================================

/// Simulates instrumented hop execution with timing breakdown.
/// Replace with actual instrumented calls to your Gateway/Executor.
async fn execute_chain_instrumented(
    gateway: &Gateway,
    request: Request,
) -> (Response, ChainTiming) {
    let chain_start = Instant::now();
    let mut timing = ChainTiming::default();

    // Hop 0: Gateway
    let hop_start = Instant::now();
    let mut hop_timing = HopTiming {
        hop_name: "gateway".into(),
        ..Default::default()
    };

    // DID resolution
    let t = Instant::now();
    // gateway.resolve_did().await; // <- your actual call
    hop_timing.did_resolve = t.elapsed();

    // VC creation
    let t = Instant::now();
    // gateway.create_vc().await; // <- your actual call
    hop_timing.vc_create = t.elapsed();

    // VC verification (at receiver)
    let t = Instant::now();
    // gateway.verify_vc().await;
    hop_timing.vc_verify = t.elapsed();

    // PCA creation
    let t = Instant::now();
    // gateway.create_pca().await;
    hop_timing.pca_create = t.elapsed();

    // PCA verification
    let t = Instant::now();
    // gateway.verify_pca().await;
    hop_timing.pca_verify = t.elapsed();

    // Execution
    let t = Instant::now();
    // let response = gateway.execute(request).await;
    hop_timing.execution = t.elapsed();

    hop_timing.total = hop_start.elapsed();
    timing.hops.push(hop_timing);

    // Actual execution (non-instrumented for now)
    let response = gateway.next(request).await.unwrap();

    timing.total = chain_start.elapsed();
    (response, timing)
}

// ============================================================================
// Manual Timing Benchmark (runs once, prints breakdown)
// ============================================================================

fn print_timing_breakdown() {
    let rt = Runtime::new().unwrap();
    let registry = Arc::new(Registry::load().expect("failed to load registry"));
    let gateway = Gateway::new(registry).expect("failed to create gateway");

    let iterations = 1000;

    // Collect samples
    let mut samples: Vec<ChainTiming> = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let request = Request {
            content: "benchmark".to_string(),
        };
        let (_, timing) = rt.block_on(execute_chain_instrumented(&gateway, request));
        samples.push(timing);
    }

    // Compute averages
    let avg_total: f64 = samples.iter().map(|t| t.total.as_nanos() as f64).sum::<f64>() / iterations as f64;

    println!();
    println!("Hop Timing Breakdown ({} iterations)", iterations);
    println!("=====================================");
    println!();
    println!("Average total: {:.2}us ({:.2}ms)", avg_total / 1000.0, avg_total / 1_000_000.0);
    println!();

    // Print one sample for detailed breakdown
    if let Some(sample) = samples.first() {
        sample.print_summary();
    }
}

// ============================================================================
// Criterion Benchmarks
// ============================================================================

/// Benchmark: per-hop timing (criterion)
fn bench_per_hop(c: &mut Criterion) {
    print_timing_breakdown();

    let rt = Runtime::new().unwrap();
    let registry = Arc::new(Registry::load().unwrap());
    let gateway = Gateway::new(registry).unwrap();

    let mut group = c.benchmark_group("hop_timing");

    // Full chain
    group.bench_function("chain/total", |b| {
        b.iter(|| {
            let request = Request {
                content: "test".to_string(),
            };
            rt.block_on(async { gateway.next(request).await.unwrap() })
        })
    });

    group.finish();
}

/// Benchmark: isolated operations
fn bench_isolated_ops(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let registry = Arc::new(Registry::load().unwrap());

    let mut group = c.benchmark_group("isolated_ops");

    // DID resolution only
    group.bench_function("did/resolve", |b| {
        b.iter(|| {
            // rt.block_on(registry.resolve_did("did:example:alice"))
        })
    });

    // VC creation only
    group.bench_function("vc/create", |b| {
        b.iter(|| {
            // rt.block_on(create_vc(...))
        })
    });

    // VC verification only
    group.bench_function("vc/verify", |b| {
        b.iter(|| {
            // rt.block_on(verify_vc(...))
        })
    });

    // PCA creation only (COSE sign)
    group.bench_function("pca/create", |b| {
        b.iter(|| {
            // CoseSigned::sign_ed25519(...)
        })
    });

    // PCA verification only (COSE verify)
    group.bench_function("pca/verify", |b| {
        b.iter(|| {
            // signed_pca.verify_ed25519(...)
        })
    });

    group.finish();
}

/// Benchmark: chain depth scaling
fn bench_chain_depth(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let registry = Arc::new(Registry::load().unwrap());
    let gateway = Gateway::new(registry).unwrap();

    let mut group = c.benchmark_group("chain_depth");

    // Measure how time scales with hop count
    for hops in [1, 2, 3, 4, 5] {
        group.bench_with_input(BenchmarkId::new("hops", hops), &hops, |b, &_hops| {
            b.iter(|| {
                let request = Request {
                    content: "test".to_string(),
                };
                rt.block_on(async { gateway.next(request).await.unwrap() })
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_per_hop, bench_isolated_ops, bench_chain_depth);
criterion_main!(benches);
