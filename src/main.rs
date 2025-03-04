mod prove;
mod vc;
mod vc_blake3;
mod verify;

fn main() {
    // Choose which module to run
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 {
        match args[1].as_str() {
            "prove" => prove::main().expect("Failed to prove"),
            "verify" => verify::main().expect("Failed to verify"),
            "vc" => vc::main().expect("Failed to run VC with SHA-256"),
            "vc-blake3" => vc_blake3::main().expect("Failed to run VC with Blake3"),
            _ => {
                println!("Unknown command: {}", args[1]);
                println!("Available commands: prove, verify, vc, vc-blake3");
            }
        }
    } else {
        // Default behavior
        prove::main().expect("Failed to prove");
    }
}
