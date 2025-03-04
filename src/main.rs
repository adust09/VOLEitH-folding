mod all_but_one_vc;
mod prove;
mod vc;
mod vc_blake3;
mod verify; // Add the module declaration for fold

fn main() {
    // Choose which module to run
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 {
        match args[1].as_str() {
            "prove" => prove::main().expect("Failed to prove"),
            "verify" => verify::main().expect("Failed to verify"),
            "vc" => vc::main().expect("Failed to run VC with SHA-256"),
            "vc-blake3" => vc_blake3::main().expect("Failed to run VC with Blake3"),
            "fold" => {
                // Create a dummy proof.json file
                let initial_state = all_but_one_vc::InitialState {
                    h: [0u8; 32],
                    pdecom: Vec::new(),
                    index_bits: Vec::new(),
                    iv: [0u8; 16],
                    current_level: 0,
                };

                // Serialize the initial state to JSON
                let json_string = serde_json::to_string(&initial_state).unwrap();

                // Write the JSON string to a file
                std::fs::write("proof.json", json_string).expect("Unable to write file");

                // Load the initial state from proof.json
                let initial_state = all_but_one_vc::load_initial_state("proof.json");

                // Perform the folding steps
                let final_state = all_but_one_vc::fold_verification(&initial_state);

                // Verify the final state
                let is_valid = all_but_one_vc::verify_final_state(final_state, &initial_state);

                println!("Verification result: {}", is_valid);
            }
            _ => {
                println!("Unknown command: {}", args[1]);
                println!("Available commands: prove, verify, vc, vc-blake3, fold");
            }
        }
    } else {
        // Default behavior
        prove::main().expect("Failed to prove");
    }
}
