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
            let field_type = field.as_deref().unwrap_or("f2");
            let circuit_type = circuit.as_deref().unwrap_or("single");

            println!("Running prove with field: {}, circuit: {}", field_type, circuit_type);

            // Different output paths based on circuit type
            let (circuit_path, private_path, public_path, output_prefix) = (
                format!("circuits/poseidon/{}/{}/circuit.txt", field_type, circuit_type),
                format!("circuits/poseidon/{}/{}/private.txt", field_type, circuit_type),
                format!("circuits/poseidon/{}/{}/public.txt", field_type, circuit_type),
                format!("{}_{}", field_type, circuit_type),
            );

            // Create output paths
            let output_path = format!("results/proofs/{}.json", output_prefix);
            let metrics_path = format!("results/metrics/{}.json", output_prefix);

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
                "No command specified. Using default: 'prove' with f2 field and single circuit."
            );
            println!("Available options:");
            println!("  --field: f2 (default: f2)");
            println!("  --circuit: single or hash_chain (default: single)");
            println!("");
            println!("Examples:");
            println!("  cargo run -- prove --field f2 --circuit hash_chain_10   # Run hash chain with F2 (only F2 is supported for hash chains)");
            println!("  cargo run -- prove --field f2                        # Run single Poseidon with F2");
            println!("");

            // Same default as if called explicitly
            let field_type = "f2";
            let circuit_type = "single";

            // Use the same path construction logic as in the explicit command
            let (circuit_path, private_path, public_path, output_prefix) = (
                format!("circuits/poseidon/{}/single/poseidon.txt", field_type),
                format!("circuits/poseidon/{}/single/poseidon_private.txt", field_type),
                format!("circuits/poseidon/{}/single/poseidon_public.txt", field_type),
                format!("single_{}", field_type),
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
