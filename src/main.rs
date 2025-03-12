mod all_but_one_vc;
mod gadget;
mod keccak;
mod prove;
mod verify; // Add the module declaration for fold

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    Prove,
    Fold,
    Keccak(keccak::KeccakArgs),
}

fn main() -> eyre::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Prove) => prove::main(),
        Some(Commands::Fold) => {
            // Create a dummy proof.json file
            let initial_state = all_but_one_vc::InitialState {
                h: [0u8; 32],
                pdecom: Vec::new(),
                index_bits: Vec::new(),
                iv: [0u8; 16],
                current_level: 0,
            };

            // Serialize the initial state to JSON
            let json_string = serde_json::to_string(&initial_state)?;

            // Write the JSON string to a file
            std::fs::write("proof.json", json_string)?;
            println!("Created dummy proof.json file");
            Ok(())
        }
        Some(Commands::Keccak(args)) => keccak::keccak_main(args),
        None => {
            // Default behavior
            println!("No command specified, running 'prove' by default");
            prove::main()
        }
    }
}
