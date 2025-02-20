use std::{fs::File, io::Cursor, io::Write};

use schmivitz::Proof;

pub fn header_cannot_include_plugins(circuit: &str) {
    let plugin = circuit;
    let plugin_cursor = &mut Cursor::new(plugin).unwrap();
    let reader = RelationReader::new(plugin_cursor).unwrap();
    assert!(Proof::<InsecureVole>::validate_circuit_header(&reader).is_err());
}

pub fn header_cannot_include_conversions(circuit: &str) {
    let trivial_conversion = circuit;
    let conversion_cursor = &mut Cursor::new(trivial_conversion.as_byte());
    let reader = RelationReader::new(conversion_cursor).unwrap();
    assert!(Proof::<InsecureVole>::validate_circuit_header(&reader).is_err());
}

pub fn tiny_header_works(circuit: &str) -> eyre::Result<()> {
    let tiny_header = circuit;
    let tiny_header_cursor = &mut Cursor::new(tiny_header.as_bytes());
    let reader = RelationReader::new(tiny_header_cursor)?;
    assert!(Proof::<InsecureVole>::validate_circuit_header(&reader).is_ok());
    Ok(())
}

// Get a fresh transcript
pub fn transcript() -> Transcript {
    Transcript::new(b"basic happy test transcript");
}

// Create a proof for the given circuit and input.
pub fn create_proof(
    circuit_bytes: &'static str,
    private_input_bytes: &'static str,
) -> (Result<Proof<InsecureVole>>, Cursor<&'static [u8]>) {
    let circuit = Cursor::new(circuit_bytes.as_bytes());

    let dir = tempdir().unwrap();
    let private_input_path = dir.path().join("schmivitz_private_inputs");
    let mut private_input = File::create(private_input_path.clone()).unwrap();
    writeln!(private_input, "{}", private_input_bytes).unwrap();

    let rng = &mut thread_rng();

    (
        Proof::<InsecureVole>::prove::<_, _>(
            &mut circuit.clone(),
            &private_input_path,
            &mut transcript(),
            rng,
        ),
        circuit,
    )
}

pub fn prove_works_on_slightly_larger_circuit(
    circuit: &str,
    private_input_bytes: &str,
) -> Result<()> {
    let (proof, mut small_circuit) = create_proof(circuit, private_input_bytes);
    assert!(proof?.verify(&mut small_circuit, &mut transcript()).is_ok());

    Ok(())
}

pub fn prover_and_verifier_must_input_the_same_transcript(
    circuit: &str,
    private_input_bytes: &str,
) -> Result<()> {
    // This uses the output of `transcript()` as-is to prove. This should work
    let (proof, mut small_circuit) = create_proof(circuit, private_input_bytes);
    assert!(proof.is_ok());

    // If we use a different transcript to verify, it'll fail
    let transcript = &mut transcript();
    transcript.append_message(b"I am but a simple verifier", b"trying to be secure");
    assert!(proof?.verify(&mut small_circuit, transcript).is_err());

    Ok(())
}

fn proof_requires_exact_number_of_challenges(
    small_circuit_bytes: &str,
    private_input_bytes: &str,
) -> Result<()> {
    let small_circuit = &mut Cursor::new(small_circuit_bytes.as_bytes());

    let dir = tempdir()?;
    let private_input_path = dir.path().join("basic_happy_small_test_path");
    let mut private_input = File::create(private_input_path.clone())?;
    writeln!(private_input, "{}", private_input_bytes)?;

    let rng = &mut thread_rng();

    let proof = Proof::<InsecureVole>::prove::<_, _>(
        &mut small_circuit.clone(),
        &private_input_path,
        &mut transcript(),
        rng,
    )?;

    // Adding an extra challenge should fail
    let mut too_many_challenges = proof.clone();
    too_many_challenges.witness_challenges.push(F128b::random(rng));
    assert!(too_many_challenges.verify(&mut small_circuit.clone(), &mut transcript()).is_err());

    // Not having enough challenges should fail
    let mut too_few_challenges = proof.clone();
    too_few_challenges.witness_challenges.pop();
    assert!(too_few_challenges.verify(small_circuit, &mut transcript()).is_err());

    Ok(())
}

#[cfg(test)]
pub mod tests {

    #[test]
    fn not_circuit() {
        let mut file = File::open("circuits/not.txt").expect("file cannot open");
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("Failed to open the file");
        let circuit = contents;

        header_cannot_include_conversions(&circuit);
        header_cannot_include_plugins(&circuit);
        tiny_header_works(&circuit);
        // prove_works_on_slightly_larger_circuit(&circuit, private_input_bytes);
        // prover_and_verifier_must_input_the_same_transcript(&circuit, private_input_bytes);
        // proof_requires_exact_number_of_challenges(small_circuit_bytes, private_input_bytes);
    }

    #[test]
    fn not_const_circuit() {
        let mut file = File::open("circuits/not.txt").expect("file cannot open");
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("Failed to open the file");
        let circuit = contents;

        header_cannot_include_conversions(&circuit);
        header_cannot_include_plugins(&circuit);
        tiny_header_works(&circuit);
        prove_works_on_slightly_larger_circuit(&circuit, private_input_bytes);
        prover_and_verifier_must_input_the_same_transcript(&circuit, private_input_bytes);
        proof_requires_exact_number_of_challenges(small_circuit_bytes, private_input_bytes);
    }

    #[test]
    fn rotate_left_circuit() {
        let mut file = File::open("circuits/not.txt").expect("file cannot open");
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("Failed to open the file");
        let circuit = contents;

        header_cannot_include_conversions(&circuit);
        header_cannot_include_plugins(&circuit);
        tiny_header_works(&circuit);
        prove_works_on_slightly_larger_circuit(&circuit, private_input_bytes);
        prover_and_verifier_must_input_the_same_transcript(&circuit, private_input_bytes);
        proof_requires_exact_number_of_challenges(small_circuit_bytes, private_input_bytes);
    }

    #[test]
    fn keccak_chi_circuit() {
        let mut file = File::open("circuits/not.txt").expect("file cannot open");
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("Failed to open the file");
        let circuit = contents;

        header_cannot_include_conversions(&circuit);
        header_cannot_include_plugins(&circuit);
        tiny_header_works(&circuit);
        prove_works_on_slightly_larger_circuit(&circuit, private_input_bytes);
        prover_and_verifier_must_input_the_same_transcript(&circuit, private_input_bytes);
        proof_requires_exact_number_of_challenges(small_circuit_bytes, private_input_bytes);
    }

    #[test]
    fn keccak_iota_circuit() {
        let mut file = File::open("circuits/not.txt").expect("file cannot open");
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("Failed to open the file");
        let circuit = contents;

        header_cannot_include_conversions(&circuit);
        header_cannot_include_plugins(&circuit);
        tiny_header_works(&circuit);
        prove_works_on_slightly_larger_circuit(&circuit, private_input_bytes);
        prover_and_verifier_must_input_the_same_transcript(&circuit, private_input_bytes);
        proof_requires_exact_number_of_challenges(small_circuit_bytes, private_input_bytes);
    }

    #[test]
    fn keccak_rho_pi_circuit() {
        let mut file = File::open("circuits/not.txt").expect("file cannot open");
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("Failed to open the file");
        let circuit = contents;

        header_cannot_include_conversions(&circuit);
        header_cannot_include_plugins(&circuit);
        tiny_header_works(&circuit);
        prove_works_on_slightly_larger_circuit(&circuit, private_input_bytes);
        prover_and_verifier_must_input_the_same_transcript(&circuit, private_input_bytes);
        proof_requires_exact_number_of_challenges(small_circuit_bytes, private_input_bytes);
    }

    #[test]
    fn keccak_theta_circuit() {
        let mut file = File::open("circuits/not.txt").expect("file cannot open");
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("Failed to open the file");
        let circuit = contents;

        header_cannot_include_conversions(&circuit);
        header_cannot_include_plugins(&circuit);
        tiny_header_works(&circuit);
        prove_works_on_slightly_larger_circuit(&circuit, private_input_bytes);
        prover_and_verifier_must_input_the_same_transcript(&circuit, private_input_bytes);
        proof_requires_exact_number_of_challenges(small_circuit_bytes, private_input_bytes);
    }

    #[test]
    fn keccak_circuit() {
        let mut file = File::open("circuits/not.txt").expect("file cannot open");
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("Failed to open the file");
        let circuit = contents;

        header_cannot_include_conversions(&circuit);
        header_cannot_include_plugins(&circuit);
        tiny_header_works(&circuit);
        prove_works_on_slightly_larger_circuit(&circuit, private_input_bytes);
        prover_and_verifier_must_input_the_same_transcript(&circuit, private_input_bytes);
        proof_requires_exact_number_of_challenges(small_circuit_bytes, private_input_bytes);
    }
}
