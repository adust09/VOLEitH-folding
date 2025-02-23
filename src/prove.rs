use eyre::Result;
use merlin::Transcript;
use rand::thread_rng;
use schmivitz::Proof;
use std::path::Path;
use std::{fs, io::Cursor};

pub fn main() -> Result<()> {
    let circuit_path = Path::new("./circuits/keccak.txt");
    let circuit_bytes = fs::read_to_string(circuit_path).expect("Failed to read keccak.txt");
    let circuit = &mut Cursor::new(circuit_bytes.as_bytes());

    let private_input_path = Path::new("keccak_private_input.txt");
    let mut private_input =
        fs::read_to_string(private_input_path).expect("Failed to read keccak_private_input.txt");

    let mut transcript = transcript();
    let rng = &mut thread_rng();

    let proof: Proof<schmivitz::vole::RandomVole> =
        Proof::prove(circuit, private_input_path, &mut transcript, rng)?;

    Ok(())
}

fn transcript() -> Transcript {
    Transcript::new(b"basic happy test transcript")
}
