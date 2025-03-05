mod all_but_one_vc;
mod gadget;
mod merkle_blake3;
mod merkle_sha;
mod prove;
mod verify; // Add the module declaration for fold

fn main() {
    // Choose which module to run
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 {
        match args[1].as_str() {
            "prove" => prove::main().expect("Failed to prove"),
            "verify" => verify::main().expect("Failed to verify"),
            "merkle_sha" => merkle_sha::main().expect("Failed to run Merkle proof with SHA-256"),
            "merkle-blake3" => {
                merkle_blake3::main().expect("Failed to run Merkle proof with Blake3")
            }
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
