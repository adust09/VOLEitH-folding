use eyre::{Result, WrapErr};
use merlin::Transcript;
use rand::thread_rng;
use schmivitz::parameters::FIELD_SIZE;
use schmivitz::{insecure::InsecureVole, Proof};
use std::{fs, io::Cursor, path::Path};

pub fn main() -> Result<()> {
    println!("Starting proof generation with Poseidon hash function...");
    println!("FIELD_SIZE: {}", FIELD_SIZE);

    // Determine which field size to use based on FIELD_SIZE
    if FIELD_SIZE == 2 {
        println!("Using F_2 (binary field) implementation");
        generate_and_verify_proof_f2()
    } else if FIELD_SIZE == 128 {
        println!("Using F_128 implementation");
        generate_and_verify_proof_f128()
    } else if FIELD_SIZE == 18446744073709551616 {
        println!("Using F64 (prime field) implementation");
        generate_and_verify_proof_f64()
    } else {
        Err(eyre::eyre!("Unsupported field size: {}", FIELD_SIZE))
    }
}

fn generate_and_verify_proof_f2() -> Result<()> {
    // Set file paths for F_2 implementation
    let circuit_path = Path::new("src/circuits/f2/poseidon.txt");
    println!("Circuit path: {:?}", circuit_path);

    // Read circuit file
    let circuit_bytes = fs::read_to_string(circuit_path)
        .wrap_err_with(|| format!("Failed to read circuit file at {:?}", circuit_path))?;
    println!("Successfully read circuit file");

    let circuit = &mut Cursor::new(circuit_bytes.as_bytes());

    // Set private_input file path
    let private_input_path = Path::new("src/circuits/f2/poseidon_private.txt");
    println!("Private input path: {:?}", private_input_path);

    // Check if private_input file exists
    if !private_input_path.exists() {
        return Err(eyre::eyre!("Private input file does not exist at {:?}", private_input_path));
    }
    println!("Private input file exists");

    // Set public_input file path
    let public_input_path = Path::new("src/circuits/f2/poseidon_public.txt");
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
    println!("Generating proof for F_2 implementation...");
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

    // Description of F_2 Poseidon hash function implementation
    println!("\nF_2 Poseidon hash function implementation:");
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

fn generate_and_verify_proof_f128() -> Result<()> {
    // Set file paths for F_128 implementation
    let circuit_path = Path::new("src/circuits/f128/poseidon.txt");
    println!("Circuit path: {:?}", circuit_path);

    // Read circuit file
    let circuit_bytes = fs::read_to_string(circuit_path)
        .wrap_err_with(|| format!("Failed to read circuit file at {:?}", circuit_path))?;
    println!("Successfully read circuit file");

    let circuit = &mut Cursor::new(circuit_bytes.as_bytes());

    // Set private_input file path
    let private_input_path = Path::new("src/circuits/f128/poseidon_private.txt");
    println!("Private input path: {:?}", private_input_path);

    // Check if private_input file exists
    if !private_input_path.exists() {
        return Err(eyre::eyre!("Private input file does not exist at {:?}", private_input_path));
    }
    println!("Private input file exists");

    // Set public_input file path
    let public_input_path = Path::new("src/circuits/f128/poseidon_public.txt");
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
    println!("Generating proof for F_128 implementation...");
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

    // Description of F_128 Poseidon hash function implementation
    println!("\nF_128 Poseidon hash function implementation:");
    println!("1. Input: 3 values");
    println!("2. Round constants: 30 values (3 per round)");
    println!("3. State initialization: Initialize state with input values");
    println!("4. Full rounds (first set): 3 rounds with S-box (x^3) applied to all state elements");
    println!("5. Partial rounds: 4 rounds with S-box applied only to first state element");
    println!("6. Full rounds (final set): 3 rounds with S-box applied to all state elements");
    println!("7. MDS matrix multiplication: Applied in each round for diffusion");
    println!("8. Output: First element of the final state");

    Ok(())
}

fn generate_and_verify_proof_f64() -> Result<()> {
    // Set file paths for F64 implementation
    let circuit_path = Path::new("src/circuits/f64/poseidon.txt");
    println!("Circuit path: {:?}", circuit_path);

    // Read circuit file
    let circuit_bytes = fs::read_to_string(circuit_path)
        .wrap_err_with(|| format!("Failed to read circuit file at {:?}", circuit_path))?;
    println!("Successfully read circuit file");

    let circuit = &mut Cursor::new(circuit_bytes.as_bytes());

    // Set private_input file path
    let private_input_path = Path::new("src/circuits/f64/poseidon_private.txt");
    println!("Private input path: {:?}", private_input_path);

    // Check if private_input file exists
    if !private_input_path.exists() {
        return Err(eyre::eyre!("Private input file does not exist at {:?}", private_input_path));
    }
    println!("Private input file exists");

    // Set public_input file path
    let public_input_path = Path::new("src/circuits/f64/poseidon_public.txt");
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
    println!("Generating proof for F64 implementation...");
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

    // Description of F64 Poseidon hash function implementation
    println!("\nF64 Poseidon hash function implementation:");
    println!("1. Input: 3 values");
    println!("2. Round constants: 24 values (3 per round)");
    println!("3. State initialization: Initialize state with input values");
    println!("4. Full rounds (first set): 4 rounds with S-box (x^5) applied to all state elements");
    println!("5. Partial rounds: 2 rounds with S-box applied only to first state element");
    println!("6. Full rounds (final set): 2 rounds with S-box applied to all state elements");
    println!("7. MDS matrix multiplication: Applied in each round for diffusion");
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
        // Run the test based on the current FIELD_SIZE
        let result = main();
        assert!(result.is_ok(), "Failed to execute main function: {:?}", result);
    }
}
