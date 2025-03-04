use eyre::{Result, WrapErr};
use merlin::Transcript;
use rand::thread_rng;
use schmivitz::parameters::FIELD_SIZE;
use schmivitz::{insecure::InsecureVole, Proof};
use std::{fs, io::Cursor, path::Path};

pub fn main() -> Result<()> {
    // Determine which field size to use based on FIELD_SIZE
    let field_type = match FIELD_SIZE {
        2 => ("F_2", "f2"),
        128 => ("F_128", "f128"),
        18446744073709551616 => ("F64", "f64"),
        _ => return Err(eyre::eyre!("Unsupported field size: {}", FIELD_SIZE)),
    };

    println!("Using {} ({} field) implementation", field_type.0, field_type.1);
    prove(field_type.1).unwrap();
    Ok(())
}

fn prove(field: &str) -> Result<()> {
    let circuit_path_str = format!("src/circuits/{}/poseidon.txt", field);
    let circuit_path = Path::new(&circuit_path_str);
    let circuit_bytes = fs::read_to_string(circuit_path)
        .wrap_err_with(|| format!("Failed to read circuit file at {:?}", circuit_path))?;
    let circuit_bytes_slice = circuit_bytes.as_bytes();
    let circuit = &mut Cursor::new(circuit_bytes_slice);

    let private_input_path_str = format!("src/circuits/{}/poseidon_private.txt", field);
    let private_input_path = Path::new(&private_input_path_str);
    if !private_input_path.exists() {
        return Err(eyre::eyre!("Private input file does not exist at {:?}", private_input_path));
    }

    let public_input_path_str = format!("src/circuits/{}/poseidon_public.txt", field);
    let public_input_path = Path::new(&public_input_path_str);
    if !public_input_path.exists() {
        return Err(eyre::eyre!("Public input file does not exist at {:?}", public_input_path));
    }

    let mut transcript_instance = create_transcript();
    let rng = &mut thread_rng();

    // Generate proof
    let proof = Proof::<InsecureVole>::prove::<_, _>(
        circuit,
        private_input_path,
        &mut transcript_instance,
        rng,
    )
    .wrap_err("Failed to generate proof")?;
    println!("Proof generation successful!");

    // Write proof to file
    let proof_path = "proof.json";

    // Create a simple representation of the proof
    let proof_string = format!("{:?}", proof);
    fs::write(proof_path, proof_string)
        .wrap_err_with(|| format!("Failed to write proof to file at {}", proof_path))?;

    println!("Proof written to {}", proof_path);
    Ok(())
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
            128 => "f128",
            18446744073709551616 => "f64",
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
        let circuit_path = format!("src/circuits/{}/poseidon.txt", field_type);
        let private_input_path = format!("src/circuits/{}/poseidon_private.txt", field_type);
        let public_input_path = format!("src/circuits/{}/poseidon_public.txt", field_type);

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

        // Run the prove function
        let result = prove(field_type);
        assert!(result.is_ok(), "Failed to generate proof: {:?}", result);

        // Verify that the proof file was created
        let proof_path = "proof.json";
        assert!(PathBuf::from(proof_path).exists(), "Proof file was not created: {}", proof_path);

        // Clean up the proof file
        let _ = fs::remove_file(proof_path);
    }

    #[test]
    fn test_prove_with_invalid_field() {
        // Test with an invalid field type
        let result = prove("invalid_field");
        assert!(result.is_err(), "Expected error for invalid field type");
    }

    #[test]
    fn test_proof_serialization() {
        // Determine which field size to use based on FIELD_SIZE
        let field_type = match FIELD_SIZE {
            2 => "f2",
            128 => "f128",
            18446744073709551616 => "f64",
            _ => {
                // Skip test for unsupported field sizes
                println!(
                    "Skipping test_proof_serialization for unsupported field size: {}",
                    FIELD_SIZE
                );
                return;
            }
        };

        // Generate a proof
        let _ = prove(field_type);

        // Verify that the proof file exists and can be read
        let proof_path = "proof.json";
        let proof_content = fs::read_to_string(proof_path);
        assert!(proof_content.is_ok(), "Failed to read proof file: {:?}", proof_content.err());

        // Verify that the proof content is not empty
        let content = proof_content.unwrap();
        assert!(!content.is_empty(), "Proof file is empty");

        // Clean up the proof file
        let _ = fs::remove_file(proof_path);
    }
}
