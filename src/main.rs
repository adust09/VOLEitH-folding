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
                if field_type != "f2" {
                    return Err(eyre::eyre!("Hash chain circuit is only available for F2 field"));
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
            // Default behavior
            println!("No command specified, running 'prove' with f64 field and standard circuit by default");
            let circuit_path = "src/circuits/poseidon/f64/poseidon.txt";
            let private_path = "src/circuits/poseidon/f64/poseidon_private.txt";
            let public_path = "src/circuits/poseidon/f64/poseidon_public.txt";
            let output_path = "results/proofs/proof_standard_f64.json";

            let metrics =
                prove::prove_with_paths(circuit_path, private_path, public_path, output_path)?;
            metrics.display();
            metrics.save_to_file("results/metrics/metrics_standard_f64.json")?;
            Ok(())
        }
    }
}
