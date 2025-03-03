use eyre::{Result, WrapErr};
use merlin::Transcript;
use rand::thread_rng;
use schmivitz::parameters::FIELD_SIZE;
use schmivitz::{insecure::InsecureVole, Proof};
use serde_json;
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
    generate_and_verify_proof(field_type.1)
}

fn generate_and_verify_proof(field: &str) -> Result<()> {
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
    let public_input_bytes = fs::read_to_string(public_input_path)
        .wrap_err_with(|| format!("Failed to read public input file at {:?}", public_input_path))?;

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
    let proof_path = "proof.txt";

    // Create a simple representation of the proof
    let proof_string = format!("{:?}", proof);
    fs::write(proof_path, proof_string)
        .wrap_err_with(|| format!("Failed to write proof to file at {}", proof_path))?;

    println!("Proof written to {}", proof_path);

    // Verify proof
    let circuit_for_verification = &mut Cursor::new(circuit_bytes.as_bytes());
    let mut transcript_for_verification = create_transcript();
    proof
        .verify(circuit_for_verification, &mut transcript_for_verification)
        .wrap_err("Failed to verify proof")?;

    println!("Proof verification successful!");

    // Print implementation details based on field type
    print_implementation_details(field);

    Ok(())
}

fn print_implementation_details(field: &str) {
    match field {
        "f2" => {
            println!("\nF_2 Poseidon hash function implementation:");
            println!("1. Input: 3 values (1, 0, 1)");
            println!("2. Round constants: 6 values (1, 0, 1, 1, 0, 1)");
            println!(
                "3. State initialization: Initialize state from input values using XOR operations"
            );
            println!("4. Full round 1: Non-linear layer (AND operations) and linear layer (XOR operations)");
            println!("5. Full round 2: Non-linear layer and linear layer");
            println!("6. Partial round: Simplified non-linear layer and linear layer");
            println!("7. Final round: Non-linear layer and linear layer");
            println!("8. Output: First element of the final state");
        }
        "f128" => {
            println!("\nF_128 Poseidon hash function implementation:");
            println!("1. Input: 3 values");
            println!("2. Round constants: 30 values (3 per round)");
            println!("3. State initialization: Initialize state with input values");
            println!("4. Full rounds (first set): 3 rounds with S-box (x^3) applied to all state elements");
            println!("5. Partial rounds: 4 rounds with S-box applied only to first state element");
            println!(
                "6. Full rounds (final set): 3 rounds with S-box applied to all state elements"
            );
            println!("7. MDS matrix multiplication: Applied in each round for diffusion");
            println!("8. Output: First element of the final state");
        }
        "f64" => {
            println!("\nF64 Poseidon hash function implementation:");
            println!("1. Input: 3 values");
            println!("2. Round constants: 24 values (3 per round)");
            println!("3. State initialization: Initialize state with input values");
            println!("4. Full rounds (first set): 4 rounds with S-box (x^5) applied to all state elements");
            println!("5. Partial rounds: 2 rounds with S-box applied only to first state element");
            println!(
                "6. Full rounds (final set): 2 rounds with S-box applied to all state elements"
            );
            println!("7. MDS matrix multiplication: Applied in each round for diffusion");
            println!("8. Output: First element of the final state");
        }
        _ => {}
    }
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
