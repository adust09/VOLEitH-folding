use eyre::{Result, WrapErr};
use merlin::Transcript;
use rand::thread_rng;
use schmivitz::parameters::FIELD_SIZE;
use schmivitz::{insecure::InsecureVole, Proof};
use serde::{Deserialize, Serialize};
use std::{fs, io::Cursor, path::Path, time::Instant};
use sysinfo::{ProcessExt, System, SystemExt};

/// Struct to store measurement metrics for the proof system
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct MeasurementMetrics {
    // Time measurements (in milliseconds)
    pub proof_generation_time_ms: u128,
    pub proof_verification_time_ms: u128,

    // Size measurements (in bytes)
    pub proof_size_bytes: usize,

    // Prover resource usage
    pub prover_cpu_usage_percent: f32,
    pub prover_memory_usage_mb: u64,

    // Verifier resource usage
    pub verifier_cpu_usage_percent: f32,
    pub verifier_memory_usage_mb: u64,

    // Communication overhead (total data exchanged)
    pub communication_overhead_bytes: usize,
}

impl MeasurementMetrics {
    /// Create a new instance with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Display the measurement metrics in a formatted way
    pub fn display(&self) {
        println!("\n====== MEASUREMENT MATRIX ======");
        println!("Proof Generation Time: {} ms", self.proof_generation_time_ms);
        println!("Proof Verification Time: {} ms", self.proof_verification_time_ms);
        println!("Proof Size: {} bytes", self.proof_size_bytes);
        println!(
            "Prover Computation Load: {:.2}% CPU, {:.2} MB memory",
            self.prover_cpu_usage_percent,
            self.prover_memory_usage_mb as f64 / 1024.0
        );
        println!(
            "Verifier Computation Load: {:.2}% CPU, {:.2} MB memory",
            self.verifier_cpu_usage_percent,
            self.verifier_memory_usage_mb as f64 / 1024.0
        );
        println!("Communication Overhead: {} bytes", self.communication_overhead_bytes);
        println!("=================================\n");
    }

    /// Save metrics to a JSON file
    pub fn save_to_file(&self, path: &str) -> Result<()> {
        let json =
            serde_json::to_string_pretty(self).wrap_err("Failed to serialize metrics to JSON")?;
        fs::write(path, json)
            .wrap_err_with(|| format!("Failed to write metrics to file at {}", path))?;
        println!("Measurement metrics saved to {}", path);
        Ok(())
    }
}

/// Helper function to get the current system resource usage
fn get_system_usage(sys: &mut System, pid: i32) -> (f32, u64) {
    sys.refresh_all();

    // Get process info
    let cpu_usage = match sys.process(sysinfo::Pid::from(pid as usize)) {
        Some(process) => process.cpu_usage(),
        None => 0.0,
    };

    let memory_usage = match sys.process(sysinfo::Pid::from(pid as usize)) {
        Some(process) => process.memory(),
        None => 0,
    };

    (cpu_usage, memory_usage)
}

pub fn main() -> Result<()> {
    // Determine which field size to use based on FIELD_SIZE
    let field_type = match FIELD_SIZE {
        2 => ("F_2", "f2"),
        // 128 => ("F_128", "f128"),
        // 18446744073709551616 => ("F64", "f64"),
        _ => return Err(eyre::eyre!("Unsupported field size: {}", FIELD_SIZE)),
    };

    println!("Using {} ({} field) implementation", field_type.0, field_type.1);
    let metrics = prove(field_type.1, "proof.json")?;

    // Display and save the measurement metrics
    metrics.display();
    metrics.save_to_file("measurement_metrics.json")?;

    Ok(())
}

pub fn prove(field: &str, proof_output_path: &str) -> Result<MeasurementMetrics> {
    // Build paths for standard circuit
    let circuit_path_str = format!("src/circuits/poseidon/{}/poseidon.txt", field);
    let private_input_path_str = format!("src/circuits/poseidon/{}/poseidon_private.txt", field);
    let public_input_path_str = format!("src/circuits/poseidon/{}/poseidon_public.txt", field);

    // Call the more general function with the specific paths
    prove_with_paths(
        &circuit_path_str,
        &private_input_path_str,
        &public_input_path_str,
        proof_output_path,
    )
}

pub fn prove_with_paths(
    circuit_path_str: &str,
    private_input_path_str: &str,
    public_input_path_str: &str,
    proof_output_path: &str,
) -> Result<MeasurementMetrics> {
    // Create a measurement metrics struct to store results
    let mut metrics = MeasurementMetrics::new();

    // Initialize system monitoring
    let mut sys = System::new_all();
    let pid = std::process::id() as i32;

    // Read circuit and input files
    let circuit_path = Path::new(circuit_path_str);
    let circuit_bytes = fs::read_to_string(circuit_path)
        .wrap_err_with(|| format!("Failed to read circuit file at {:?}", circuit_path))?;
    let circuit_bytes_slice = circuit_bytes.as_bytes();

    // Count input size for communication overhead
    let mut total_input_size = circuit_bytes_slice.len();

    let private_input_path = Path::new(private_input_path_str);
    if !private_input_path.exists() {
        return Err(eyre::eyre!("Private input file does not exist at {:?}", private_input_path));
    }

    // Add private input size to communication overhead
    let private_input_size = fs::metadata(&private_input_path)?.len() as usize;
    total_input_size += private_input_size;

    let public_input_path = Path::new(public_input_path_str);
    if !public_input_path.exists() {
        return Err(eyre::eyre!("Public input file does not exist at {:?}", public_input_path));
    }

    // Add public input size to communication overhead
    let public_input_size = fs::metadata(&public_input_path)?.len() as usize;
    total_input_size += public_input_size;

    let circuit = &mut Cursor::new(circuit_bytes_slice);
    let mut transcript_instance = create_transcript();
    let rng = &mut thread_rng();

    // Start timing for proof generation
    let proof_gen_start = Instant::now();

    // Refresh system stats before generating proof
    sys.refresh_all();

    // Generate proof
    let proof = Proof::<InsecureVole>::prove::<_, _>(
        circuit,
        private_input_path,
        &mut transcript_instance,
        rng,
    )
    .wrap_err("Failed to generate proof")?;

    // Take measurements after proof generation
    let (cpu_usage, memory_usage) = get_system_usage(&mut sys, pid);

    // Set prover resource metrics
    metrics.prover_cpu_usage_percent = cpu_usage;
    metrics.prover_memory_usage_mb = memory_usage / (1024 * 1024); // Convert B to MB

    // End timing for proof generation
    let proof_gen_duration = proof_gen_start.elapsed();
    metrics.proof_generation_time_ms = proof_gen_duration.as_millis();

    println!("Proof generation successful!");
    println!("  Time: {} ms", metrics.proof_generation_time_ms);

    // Write proof to file
    let proof_path = proof_output_path;

    // Create a string representation of the proof
    let proof_string = format!("{:?}", proof);

    // Measure proof size
    metrics.proof_size_bytes = proof_string.len();

    // Add proof size to communication overhead
    metrics.communication_overhead_bytes = total_input_size + metrics.proof_size_bytes;

    fs::write(proof_path, &proof_string)
        .wrap_err_with(|| format!("Failed to write proof to file at {}", proof_path))?;

    println!("Proof written to {}", proof_path);
    println!("  Size: {} bytes", metrics.proof_size_bytes);

    // Reset circuit cursor for verification
    let circuit = &mut Cursor::new(circuit_bytes_slice);

    // Create a new transcript for verification
    let mut verification_transcript = create_transcript();

    // Refresh system stats before verification
    sys.refresh_all();

    // Start timing for proof verification
    let verification_start = Instant::now();

    // Verify the proof
    let verification_result = proof.verify(circuit, &mut verification_transcript);
    assert!(verification_result.is_ok(), "Proof verification failed");

    // Take measurements after verification
    let (cpu_usage, memory_usage) = get_system_usage(&mut sys, pid);

    // Set verifier resource metrics
    metrics.verifier_cpu_usage_percent = cpu_usage;
    metrics.verifier_memory_usage_mb = memory_usage / (1024 * 1024); // Convert B to MB

    // End timing for proof verification
    let verification_duration = verification_start.elapsed();
    metrics.proof_verification_time_ms = verification_duration.as_millis();

    println!("Proof verification successful!");
    println!("  Time: {} ms", metrics.proof_verification_time_ms);

    Ok(metrics)
}

fn create_transcript() -> Transcript {
    Transcript::new(b"basic happy test transcript")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn test_main() {
        // Run the test based on the current FIELD_SIZE
        let result = main();
        assert!(result.is_ok(), "Failed to execute main function: {:?}", result);
    }

    #[test]
    fn test_create_transcript() {
        let _transcript = create_transcript();

        // Check that the transcript was created with the expected label
        // Note: Merlin::Transcript doesn't expose its label, so we can only verify
        // that the function doesn't panic
        assert!(true, "create_transcript should not panic");
    }

    #[test]
    fn test_prove_with_valid_inputs() {
        // Determine which field size to use based on FIELD_SIZE
        let field_type = match FIELD_SIZE {
            2 => "f2",
            // 128 => "f128",
            // 18446744073709551616 => "f64",
            _ => {
                // Skip test for unsupported field sizes
                println!(
                    "Skipping test_prove_with_valid_inputs for unsupported field size: {}",
                    FIELD_SIZE
                );
                return;
            }
        };

        // Verify that the circuit and input files exist
        let circuit_path = format!("src/circuits/poseidon/{}/poseidon.txt", field_type);
        let private_input_path =
            format!("src/circuits/poseidon/{}/poseidon_private.txt", field_type);
        let public_input_path = format!("src/circuits/poseidon/{}/poseidon_public.txt", field_type);

        assert!(
            PathBuf::from(&circuit_path).exists(),
            "Circuit file does not exist: {}",
            circuit_path
        );
        assert!(
            PathBuf::from(&private_input_path).exists(),
            "Private input file does not exist: {}",
            private_input_path
        );
        assert!(
            PathBuf::from(&public_input_path).exists(),
            "Public input file does not exist: {}",
            public_input_path
        );

        // Use a unique filename for this test
        let proof_path = "proof_valid_test.json";

        // Run the prove function
        let result = prove(field_type, proof_path);
        assert!(result.is_ok(), "Failed to generate proof: {:?}", result);

        // Verify that metrics were generated properly
        if let Ok(metrics) = result {
            // Validate that measurements are reasonable
            assert!(
                metrics.proof_generation_time_ms > 0,
                "Proof generation time should be positive"
            );
            assert!(metrics.proof_size_bytes > 0, "Proof size should be positive");
            assert!(
                metrics.communication_overhead_bytes >= metrics.proof_size_bytes,
                "Communication overhead should be at least as large as proof size"
            );
        }

        // Verify that the proof file was created

        // Read the file content directly instead of just checking existence
        let content = fs::read_to_string(proof_path);
        assert!(content.is_ok(), "Failed to read proof file: {:?}", content.err());
        assert!(!content.unwrap().is_empty(), "Proof file is empty");

        // Clean up the proof file
        let _ = fs::remove_file(proof_path);

        // Clean up metrics file if it exists
        let _ = fs::remove_file("measurement_metrics.json");
    }

    #[test]
    fn test_prove_with_invalid_field() {
        // Test with an invalid field type
        let result = prove("invalid_field", "proof_invalid_test.json");
        assert!(result.is_err(), "Expected error for invalid field type");
    }

    #[test]
    fn test_proof_serialization() {
        // Determine which field size to use based on FIELD_SIZE
        let field_type = match FIELD_SIZE {
            2 => "f2",
            // 128 => "f128",
            // 18446744073709551616 => "f64",
            _ => {
                // Skip test for unsupported field sizes
                println!(
                    "Skipping test_proof_serialization for unsupported field size: {}",
                    FIELD_SIZE
                );
                return;
            }
        };
        // Use a unique filename for this test
        let proof_path = "proof_serialization_test.json";

        // Generate a proof and get metrics
        let metrics_result = prove(field_type, proof_path);
        assert!(metrics_result.is_ok(), "Failed to generate proof");

        // Test that metrics can be serialized to JSON
        if let Ok(metrics) = metrics_result {
            let json = serde_json::to_string_pretty(&metrics);
            assert!(json.is_ok(), "Failed to serialize metrics to JSON");

            // Verify that all metric fields are included in the JSON
            let json_str = json.unwrap();
            assert!(
                json_str.contains("proof_generation_time_ms"),
                "JSON missing proof_generation_time_ms"
            );
            assert!(
                json_str.contains("proof_verification_time_ms"),
                "JSON missing proof_verification_time_ms"
            );
            assert!(json_str.contains("proof_size_bytes"), "JSON missing proof_size_bytes");
            assert!(
                json_str.contains("prover_cpu_usage_percent"),
                "JSON missing prover_cpu_usage_percent"
            );
            assert!(
                json_str.contains("verifier_cpu_usage_percent"),
                "JSON missing verifier_cpu_usage_percent"
            );
        }

        // Verify that the proof file exists and can be read
        let proof_content = fs::read_to_string(proof_path);
        assert!(proof_content.is_ok(), "Failed to read proof file: {:?}", proof_content.err());

        // Verify that the proof content is not empty
        let content = proof_content.unwrap();
        assert!(!content.is_empty(), "Proof file is empty");

        // Clean up the proof file
        let _ = fs::remove_file(proof_path);

        // Clean up metrics file if it exists
        let _ = fs::remove_file("measurement_metrics.json");
    }
}
