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
fn run_proof(
    circuit_path_str: &str,
    private_input_path_str: &str,
    public_input_path_str: &str,
) -> BenchmarkResult {
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

    // System stabilization before measuring
    std::thread::sleep(std::time::Duration::from_millis(200));

    // ----- PROVER MEASUREMENTS -----
    // Measure prover resource usage before proof generation
    let (cpu_before_prove, mem_before_prove) = get_process_usage();

    // Run the proof operation multiple times to get more accurate system usage readings
    let mut prove_duration = Duration::ZERO;

    // Do some warmup iterations
    for _ in 0..3 {
        let circuit_warmup = &mut Cursor::new(circuit_bytes_slice);
        let mut transcript_warmup = create_transcript();
        let rng_warmup = &mut thread_rng();

        let _ = Proof::<InsecureVole>::prove::<_, _>(
            circuit_warmup,
            private_input_path,
            &mut transcript_warmup,
            rng_warmup,
        )
        .expect("Failed in warmup proof generation");
    }

    // First, generate a proof we'll keep for verification later and measuring size
    let circuit_for_proof = &mut Cursor::new(circuit_bytes_slice);
    let mut transcript_for_proof = create_transcript();
    let rng_for_proof = &mut thread_rng();

    let start_main = Instant::now();
    let proof = Proof::<InsecureVole>::prove::<_, _>(
        circuit_for_proof,
        private_input_path,
        &mut transcript_for_proof,
        rng_for_proof,
    )
    .expect("Failed to generate main proof");
    let main_duration = start_main.elapsed();
    prove_duration = main_duration;

    // Additional runs for more accurate CPU measurement
    for _ in 0..4 {
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
        .expect("Failed to generate additional proof");
        prove_duration += start.elapsed();
    }

    // Calculate average proving time across all runs
    prove_duration = prove_duration / 5;

    // Measure prover resource usage after proof generation
    let (cpu_after_prove, mem_after_prove) = get_process_usage();

    // Calculate proof size in bytes
    let proof_string = format!("{:?}", proof);
    let proof_size_bytes = proof_string.len();

    // Allow system to stabilize before verification
    std::thread::sleep(std::time::Duration::from_millis(200));

    // ----- VERIFIER MEASUREMENTS -----
    // Measure verifier resource usage before verification
    let (cpu_before_verify, mem_before_verify) = get_process_usage();

    // Measure verification time (with multiple iterations for better measurement)
    let mut verify_duration = Duration::ZERO;
    for _ in 0..5 {
        // Reset circuit cursor for verification
        let circuit_verify = &mut Cursor::new(circuit_bytes_slice);
        let mut verification_transcript = create_transcript();

        let start = Instant::now();
        let verification_result = proof.verify(circuit_verify, &mut verification_transcript);
        verify_duration += start.elapsed();

        assert!(verification_result.is_ok(), "Proof verification failed");
    }
    // Calculate average verification time
    verify_duration = verify_duration / 5;

    // Measure verifier resource usage after verification
    let (cpu_after_verify, mem_after_verify) = get_process_usage();

    // Compile benchmark results
    BenchmarkResult {
        proof_generation_time_ms: prove_duration.as_millis() as u64,
        proof_verification_time_ms: verify_duration.as_millis() as u64,
        proof_size_bytes,
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

    // Get circuit size as parameter for throughput measurements
    let circuit_size = fs::read_to_string(circuit_path).unwrap().len();

    // Create a benchmark group
    let mut group = c.benchmark_group(group_name);
    group.sample_size(10); // Run 10 times
    group.throughput(Throughput::Bytes(circuit_size as u64));

    // Run a single complete benchmark to get detailed metrics outside of criterion's timing
    let benchmark_result = run_proof(circuit_path, private_path, public_path);

    // --- Benchmark 1: Proof Generation Time ---
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

    // --- Benchmark 2: Proof Verification Time ---
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

    // --- Report static metrics ---
    println!("\n{} Benchmark Results:", group_name);
    println!("Proof Size: {} bytes", benchmark_result.proof_size_bytes);
    println!("Prover CPU Usage: {:.2}%", benchmark_result.prover_cpu_usage);
    println!("Prover Memory Usage: {:.2} MB", benchmark_result.prover_memory_usage_mb);
    println!("Verifier CPU Usage: {:.2}%", benchmark_result.verifier_cpu_usage);
    println!("Verifier Memory Usage: {:.2} MB", benchmark_result.verifier_memory_usage_mb);

    // --- Save detailed results to a JSON file ---
    let results_dir = Path::new("benchmark_results");
    if !results_dir.exists() {
        fs::create_dir_all(results_dir).expect("Failed to create benchmark_results directory");
    }

    let result_path = format!("benchmark_results/{}_metrics.json", group_name);
    let result_json = serde_json::to_string_pretty(&benchmark_result)
        .expect("Failed to serialize benchmark results");
    fs::write(&result_path, result_json).expect("Failed to write benchmark results to file");

    println!("Detailed metrics saved to {}", result_path);

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
