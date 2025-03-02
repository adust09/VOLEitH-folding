use eyre::{Result, WrapErr};
use merlin::Transcript;
use rand::thread_rng;
use schmivitz::parameters::FIELD_SIZE;
use schmivitz::{insecure::InsecureVole, Proof};
use std::{fs, io::Cursor, path::Path};

pub fn main() -> Result<()> {
    println!("Starting proof generation with Poseidon hash function...");
    println!("FIELD_SIZE: {}", FIELD_SIZE);

    // Set file paths
    let circuit_path = Path::new("src/circuits/poseidon.txt");
    println!("Circuit path: {:?}", circuit_path);

    // Read circuit file
    let circuit_bytes = fs::read_to_string(circuit_path)
        .wrap_err_with(|| format!("Failed to read circuit file at {:?}", circuit_path))?;
    println!("Successfully read circuit file");

    let circuit = &mut Cursor::new(circuit_bytes.as_bytes());

    // Set private_input file path
    let private_input_path = Path::new("src/circuits/poseidon_private.txt");
    println!("Private input path: {:?}", private_input_path);

    // Check if private_input file exists
    if !private_input_path.exists() {
        return Err(eyre::eyre!("Private input file does not exist at {:?}", private_input_path));
    }
    println!("Private input file exists");

    // Set public_input file path
    let public_input_path = Path::new("src/circuits/poseidon_public.txt");
    println!("Public input path: {:?}", public_input_path);

    // Check if public_input file exists
    if !public_input_path.exists() {
        return Err(eyre::eyre!("Public input file does not exist at {:?}", public_input_path));
    }
    println!("Public input file exists");

    // Display public_input file content
    let public_input_bytes = fs::read_to_string(public_input_path)
        .wrap_err_with(|| format!("Failed to read public input file at {:?}", public_input_path))?;
    println!("Public input file content:\n{}", public_input_bytes);

    // Set up transcript and RNG
    let mut transcript_instance = create_transcript();
    let rng = &mut thread_rng();

    // Generate proof
    println!("Generating proof...");
    let proof = Proof::<InsecureVole>::prove::<_, _>(
        circuit,
        private_input_path,
        &mut transcript_instance,
        rng,
    )
    .wrap_err("Failed to generate proof")?;

    println!("Proof generation successful!");

    // Verify proof
    println!("Verifying proof...");
    let circuit_for_verification = &mut Cursor::new(circuit_bytes.as_bytes());
    let mut transcript_for_verification = create_transcript();
    proof
        .verify(circuit_for_verification, &mut transcript_for_verification)
        .wrap_err("Failed to verify proof")?;

    println!("Proof verification successful!");

    // Description of Poseidon hash function implementation on F_2
    println!("\nPoseidon hash function implementation on F_2:");
    println!("1. Input: 3 values (1, 0, 1)");
    println!("2. Round constants: 6 values (1, 0, 1, 1, 0, 1)");
    println!("3. State initialization: Initialize state from input values using XOR operations");
    println!(
        "4. Full round 1: Non-linear layer (AND operations) and linear layer (XOR operations)"
    );
    println!("5. Full round 2: Non-linear layer and linear layer");
    println!("6. Partial round: Simplified non-linear layer and linear layer");
    println!("7. Final round: Non-linear layer and linear layer");
    println!("8. Output: First element of the final state");

    Ok(())
}

fn create_transcript() -> Transcript {
    Transcript::new(b"basic happy test transcript")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_main() {
        // Actually generate and verify the proof
        let result = main();
        assert!(result.is_ok(), "Failed to generate and verify proof: {:?}", result);
    }
}
