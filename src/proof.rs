use eyre::Result;

use schmivitz::Proof;
use std::fs;
use std::path::Path;

pub fn main() -> Result<()> {
    let keccak_circuit_path = Path::new("keccak.txt");
    let keccak_circuit_dsl =
        fs::read_to_string(keccak_circuit_path).expect("Failed to read keccak.txt");

    let keccak_private_input_path = Path::new("keccak_private_input.txt");
    let keccak_private_input_dsl = fs::read_to_string(keccak_private_input_path)
        .expect("Failed to read keccak_private_input.txt");

    let (proof, mut circuit) = Proof::prove(&keccak_circuit_dsl, &keccak_private_input_dsl)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use eyre::Result;
    use schmivitz::Proof;
    use std::fs;
    use std::path::Path;

    #[test]
    fn test_keccak_proof_verification() -> Result<()> {
        let keccak_circuit_path = Path::new("keccak.txt");
        let keccak_private_input_path = Path::new("keccak_private_input.txt");

        let keccak_circuit_dsl =
            fs::read_to_string(keccak_circuit_path).expect("Failed to read keccak.txt");

        let keccak_private_input_dsl = fs::read_to_string(keccak_private_input_path)
            .expect("Failed to read keccak_private_input.txt");

        let (proof, mut circuit) = create_proof(&keccak_circuit_dsl, &keccak_private_input_dsl)?;

        assert!(proof.verify(&mut circuit, &mut transcript()).is_ok());

        Ok(())
    }
}
