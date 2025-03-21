mod keccak;
mod prove;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    Prove {
        #[arg(short, long)]
        field: Option<String>,

        #[arg(short, long)]
        circuit: Option<String>,
    },
}

fn main() -> eyre::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Prove { field, circuit }) => {
            let field_type = field.as_deref().unwrap_or("f64");
            let circuit_type = circuit.as_deref().unwrap_or("standard");

            println!("Running prove with field: {}, circuit: {}", field_type, circuit_type);

            // Different output paths based on circuit type
            let (circuit_path, private_path, public_path, output_prefix) = if circuit_type
                == "hash_chain"
            {
                // Currently only F2 is supported by the underlying prover system
                if field_type != "f2" {
                    return Err(eyre::eyre!(
                        "Hash chain circuit is only available for F2 field due to limitations in the underlying proving system. \
                        Although we've created an F64 hash chain circuit implementation, the current prover only supports F2 for hash chains."
                    ));
                }
                (
                    format!("src/circuits/poseidon/f2/hash_chain/poseidon_chain.txt"),
                    format!("src/circuits/poseidon/f2/hash_chain/poseidon_chain_private.txt"),
                    format!("src/circuits/poseidon/f2/hash_chain/poseidon_chain_public.txt"),
                    format!("hash_chain_{}", field_type),
                )
            } else {
                // Single Poseidon circuit
                (
                    format!("src/circuits/poseidon/{}/single/poseidon.txt", field_type),
                    format!("src/circuits/poseidon/{}/single/poseidon_private.txt", field_type),
                    format!("src/circuits/poseidon/{}/single/poseidon_public.txt", field_type),
                    format!("standard_{}", field_type),
                )
            };

            // Create output paths
            let output_path = format!("results/proofs/proof_{}.json", output_prefix);
            let metrics_path = format!("results/metrics/metrics_{}.json", output_prefix);

            // Run proof with the selected circuit
            let metrics =
                prove::prove_with_paths(&circuit_path, &private_path, &public_path, &output_path)?;

            // Display and save metrics
            metrics.display();
            metrics.save_to_file(&metrics_path)?;
            Ok(())
        }
        None => {
            // Default behavior with improved help message
            println!(
                "No command specified. Using default: 'prove' with f64 field and standard circuit."
            );
            println!("Available options:");
            println!("  --field: f2 or f64 (default: f64)");
            println!("  --circuit: standard or hash_chain (default: standard)");
            println!("");
            println!("Examples:");
            println!("  cargo run -- prove --field f2 --circuit hash_chain   # Run hash chain with F2 (only F2 is supported for hash chains)");
            println!("  cargo run -- prove --field f64                       # Run standard Poseidon with F64");
            println!("  cargo run -- prove --field f2                        # Run standard Poseidon with F2");
            println!("");

            // Same default as if called explicitly
            let field_type = "f64";
            let circuit_type = "standard";

            // Use the same path construction logic as in the explicit command
            let (circuit_path, private_path, public_path, output_prefix) = (
                format!("src/circuits/poseidon/{}/single/poseidon.txt", field_type),
                format!("src/circuits/poseidon/{}/single/poseidon_private.txt", field_type),
                format!("src/circuits/poseidon/{}/single/poseidon_public.txt", field_type),
                format!("standard_{}", field_type),
            );

            let output_path = format!("results/proofs/proof_{}.json", output_prefix);
            let metrics_path = format!("results/metrics/metrics_{}.json", output_prefix);

            println!("Running prove with field: {}, circuit: {}", field_type, circuit_type);
            let metrics =
                prove::prove_with_paths(&circuit_path, &private_path, &public_path, &output_path)?;
            metrics.display();
            metrics.save_to_file(&metrics_path)?;
            Ok(())
        }
    }
}
