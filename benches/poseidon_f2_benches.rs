use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use merlin::Transcript;
use rand::thread_rng;
use schmivitz::{insecure::InsecureVole, Proof};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::{fs, io::Cursor, path::Path, time::Instant};
use sysinfo::{PidExt, ProcessExt, System, SystemExt};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkResult {
    proof_generation_time_ms: u64,
    proof_verification_time_ms: u64,
    proof_size_bytes: usize,
    communication_overhead_bytes: usize, // Added for Prover-Verifier communication
    prover_cpu_usage: f32,
    prover_memory_usage_mb: f64,
    verifier_cpu_usage: f32,
    verifier_memory_usage_mb: f64,
}

fn get_process_usage() -> (f32, f64) {
    std::thread::sleep(std::time::Duration::from_millis(100));

    let mut system = System::new_all();
    system.refresh_all();

    let pid = std::process::id();

    if let Some(process) = system.process(sysinfo::Pid::from_u32(pid)) {
        let cpu_usage = process.cpu_usage();
        let memory_usage = process.memory() as f64 / 1024.0 / 1024.0;
        return (cpu_usage, memory_usage);
    }

    (0.0, 0.0)
}

/// Create a new benchmark transcript
fn create_transcript() -> Transcript {
    Transcript::new(b"bench poseidon transcript")
}

/// Run the proof generation and verification process with detailed measurements
/// Performs 10 runs and averages the results
fn run_proof(
    circuit_path_str: &str,
    private_input_path_str: &str,
    public_input_path_str: &str,
) -> BenchmarkResult {
    // Number of runs to average
    const NUM_RUNS: u32 = 10;

    // Read circuit and input files
    let circuit_path = Path::new(circuit_path_str);
    let circuit_bytes = fs::read_to_string(circuit_path)
        .unwrap_or_else(|_| panic!("Failed to read circuit file at {:?}", circuit_path));
    let circuit_bytes_slice = circuit_bytes.as_bytes();

    let private_input_path = Path::new(private_input_path_str);
    assert!(
        private_input_path.exists(),
        "Private input file does not exist at {:?}",
        private_input_path
    );

    let public_input_path = Path::new(public_input_path_str);
    assert!(
        public_input_path.exists(),
        "Public input file does not exist at {:?}",
        public_input_path
    );

    println!("Running {} iterations for accurate measurements...", NUM_RUNS);

    // System stabilization before measuring
    std::thread::sleep(std::time::Duration::from_millis(200));

    // ----- PROVER MEASUREMENTS -----
    // Measure prover resource usage before proof generation
    let (cpu_before_prove, mem_before_prove) = get_process_usage();

    // First, generate a proof we'll keep for verification later and measuring size
    let circuit_for_proof = &mut Cursor::new(circuit_bytes_slice);
    let mut transcript_for_proof = create_transcript();
    let rng_for_proof = &mut thread_rng();

    let mut total_proving_time = Duration::ZERO;

    // Generate the first proof and measure its time
    let start_main = Instant::now();
    let proof = Proof::<InsecureVole>::prove::<_, _>(
        circuit_for_proof,
        private_input_path,
        &mut transcript_for_proof,
        rng_for_proof,
    )
    .expect("Failed to generate main proof");
    total_proving_time += start_main.elapsed();

    // Run additional (NUM_RUNS-1) iterations for a total of NUM_RUNS
    for i in 1..NUM_RUNS {
        let circuit_run = &mut Cursor::new(circuit_bytes_slice);
        let mut transcript_run = create_transcript();
        let rng_run = &mut thread_rng();

        let start = Instant::now();
        let _ = Proof::<InsecureVole>::prove::<_, _>(
            circuit_run,
            private_input_path,
            &mut transcript_run,
            rng_run,
        )
        .expect(&format!("Failed to generate proof in iteration {}", i));
        total_proving_time += start.elapsed();
    }

    // Calculate average proving time across all runs
    let prove_duration = total_proving_time / NUM_RUNS;
    println!("Average proving time ({} runs): {:?}", NUM_RUNS, prove_duration);

    // Measure prover resource usage after proof generation
    let (cpu_after_prove, mem_after_prove) = get_process_usage();

    // Calculate proof size in bytes
    let proof_string = format!("{:?}", proof);
    let proof_size_bytes = proof_string.len();
    println!("Proof size: {} bytes", proof_size_bytes);

    // Calculate communication overhead (proof size plus public inputs and protocol overhead)
    // Read public input file to calculate its size for communication overhead
    let public_input_content =
        fs::read_to_string(public_input_path).unwrap_or_else(|_| "".to_string());
    let public_input_size = public_input_content.len();

    // Communication overhead includes the proof size and the public inputs
    // Plus a fixed protocol overhead for messages exchanged (estimated at 128 bytes)
    let protocol_overhead = 128; // Estimated overhead for protocol messages
    let communication_overhead_bytes = proof_size_bytes + public_input_size + protocol_overhead;

    println!("Communication overhead: {} bytes", communication_overhead_bytes);

    // Allow system to stabilize before verification
    std::thread::sleep(std::time::Duration::from_millis(200));

    // ----- VERIFIER MEASUREMENTS -----
    // Measure verifier resource usage before verification
    let (cpu_before_verify, mem_before_verify) = get_process_usage();

    // Measure verification time with NUM_RUNS iterations
    let mut total_verification_time = Duration::ZERO;
    for i in 0..NUM_RUNS {
        // Reset circuit cursor for verification
        let circuit_verify = &mut Cursor::new(circuit_bytes_slice);
        let mut verification_transcript = create_transcript();

        let start = Instant::now();
        let verification_result = proof.verify(circuit_verify, &mut verification_transcript);
        total_verification_time += start.elapsed();

        assert!(
            verification_result.is_ok(),
            "{}",
            &format!("Proof verification failed in iteration {}", i)
        );
    }

    // Calculate average verification time
    let verify_duration = total_verification_time / NUM_RUNS;
    println!("Average verification time ({} runs): {:?}", NUM_RUNS, verify_duration);

    // Measure verifier resource usage after verification
    let (cpu_after_verify, mem_after_verify) = get_process_usage();

    // Compile benchmark results
    BenchmarkResult {
        proof_generation_time_ms: prove_duration.as_millis() as u64,
        proof_verification_time_ms: verify_duration.as_millis() as u64,
        proof_size_bytes,
        communication_overhead_bytes,
        prover_cpu_usage: cpu_after_prove - cpu_before_prove,
        prover_memory_usage_mb: mem_after_prove - mem_before_prove,
        verifier_cpu_usage: cpu_after_verify - cpu_before_verify,
        verifier_memory_usage_mb: mem_after_verify - mem_before_verify,
    }
}

/// Run a benchmark with detailed measurements for each metric
fn run_detailed_benchmark(
    c: &mut Criterion,
    group_name: &str,
    circuit_path: &str,
    private_path: &str,
    public_path: &str,
) {
    // Verify all files exist before benchmarking
    assert!(Path::new(circuit_path).exists(), "Circuit file does not exist at {}", circuit_path);
    assert!(
        Path::new(private_path).exists(),
        "Private input file does not exist at {}",
        private_path
    );
    assert!(Path::new(public_path).exists(), "Public input file does not exist at {}", public_path);

    println!("\n====== {} BENCHMARK START ======", group_name);

    // Get circuit size as parameter for throughput measurements
    let circuit_size = fs::read_to_string(circuit_path).unwrap().len();
    println!("Circuit size: {} bytes", circuit_size);

    // Create a benchmark group
    let mut group = c.benchmark_group(group_name);
    group.sample_size(10); // Run 10 times for Criterion measurements
    group.throughput(Throughput::Bytes(circuit_size as u64));

    println!("Running detailed benchmark with 10 iterations...");

    // Run the complete benchmark to get detailed metrics outside of criterion's timing
    let benchmark_result = run_proof(circuit_path, private_path, public_path);

    // --- Benchmark 1: Proof Generation Time using Criterion ---
    println!("Running Criterion measurements for proof generation...");
    group.bench_function("proof_generation_time", |b| {
        b.iter_custom(|iters| {
            let mut total_time = Duration::ZERO;

            for _ in 0..iters {
                // Set up for proof generation
                let circuit_bytes = fs::read_to_string(circuit_path).unwrap();
                let circuit_bytes_slice = circuit_bytes.as_bytes();
                let circuit = &mut Cursor::new(circuit_bytes_slice);
                let mut transcript_instance = create_transcript();
                let rng = &mut thread_rng();

                // Measure proof generation time
                let start = Instant::now();
                let _proof = Proof::<InsecureVole>::prove::<_, _>(
                    circuit,
                    Path::new(private_path),
                    &mut transcript_instance,
                    rng,
                )
                .expect("Failed to generate proof");
                total_time += start.elapsed();
            }

            total_time
        });
    });

    // --- Benchmark 2: Proof Verification Time using Criterion ---
    println!("Running Criterion measurements for verification...");
    group.bench_function("proof_verification_time", |b| {
        b.iter_custom(|iters| {
            // Generate the proof once outside the timing loop
            let circuit_bytes = fs::read_to_string(circuit_path).unwrap();
            let circuit_bytes_slice = circuit_bytes.as_bytes();
            let circuit = &mut Cursor::new(circuit_bytes_slice);
            let mut transcript_instance = create_transcript();
            let rng = &mut thread_rng();

            let proof = Proof::<InsecureVole>::prove::<_, _>(
                circuit,
                Path::new(private_path),
                &mut transcript_instance,
                rng,
            )
            .expect("Failed to generate proof");

            let mut total_time = Duration::ZERO;

            for _ in 0..iters {
                // Reset circuit cursor for verification
                let circuit = &mut Cursor::new(circuit_bytes_slice);
                let mut verification_transcript = create_transcript();

                // Measure verification time
                let start = Instant::now();
                let _ = proof.verify(circuit, &mut verification_transcript);
                total_time += start.elapsed();
            }

            total_time
        });
    });

    // --- Report comprehensive metrics ---
    println!("\n====== {} BENCHMARK RESULTS ======", group_name);
    println!(
        "Proof Generation Time: {:?} ({} ms)",
        Duration::from_millis(benchmark_result.proof_generation_time_ms),
        benchmark_result.proof_generation_time_ms
    );
    println!(
        "Proof Verification Time: {:?} ({} ms)",
        Duration::from_millis(benchmark_result.proof_verification_time_ms),
        benchmark_result.proof_verification_time_ms
    );

    println!("Proof Size: {} bytes", benchmark_result.proof_size_bytes);
    println!("Communication Overhead: {} bytes", benchmark_result.communication_overhead_bytes);
    println!("Circuit Size: {} bytes", circuit_size);

    println!("Prover Computation Load:");
    println!("  - CPU Usage: {:.10}%", benchmark_result.prover_cpu_usage);
    println!("  - Memory Usage: {:.2} MB", benchmark_result.prover_memory_usage_mb);
    println!("Verifier Computation Load:");
    println!("  - CPU Usage: {:.10}%", benchmark_result.verifier_cpu_usage);
    println!("  - Memory Usage: {:.2} MB", benchmark_result.verifier_memory_usage_mb);

    // --- Save detailed results to a JSON file ---
    let results_dir = Path::new("benchmark_results");
    if !results_dir.exists() {
        fs::create_dir_all(results_dir).expect("Failed to create benchmark_results directory");
    }

    let result_path = format!("benchmark_results/{}_metrics.json", group_name);
    let result_json = serde_json::to_string_pretty(&benchmark_result)
        .expect("Failed to serialize benchmark results");
    fs::write(&result_path, result_json).expect("Failed to write benchmark results to file");

    println!("\nDetailed metrics saved to {}", result_path);
    println!("====== {} BENCHMARK COMPLETE ======\n", group_name);

    group.finish();
}

/// Add benchmarks for F2 Single Hash
fn bench_f2_single(c: &mut Criterion) {
    let circuit_path = "circuits/poseidon/f2/single/circuit.txt";
    let private_path = "circuits/poseidon/f2/single/private.txt";
    let public_path = "circuits/poseidon/f2/single/public.txt";

    run_detailed_benchmark(c, "F2_Single_Hash", circuit_path, private_path, public_path);
}

/// Add benchmarks for F2 Hash Chain (10 iterations)
fn bench_f2_hash_chain_10(c: &mut Criterion) {
    let circuit_path = "circuits/poseidon/f2/hash_chain_10/circuit.txt";
    let private_path = "circuits/poseidon/f2/hash_chain_10/private.txt";
    let public_path = "circuits/poseidon/f2/hash_chain_10/public.txt";

    run_detailed_benchmark(c, "F2_Hash_Chain_10", circuit_path, private_path, public_path);
}

criterion_group!(benches, bench_f2_single, bench_f2_hash_chain_10);
criterion_main!(benches);
