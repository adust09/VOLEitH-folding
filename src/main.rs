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
    },
}

fn main() -> eyre::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Prove { field }) => {
            let field_type = field.as_deref().unwrap_or("f64");
            println!("Running prove with field: {}", field_type);

            // Different output paths using dedicated directories
            let output_path = format!("results/proofs/proof_{}.json", field_type);
            let metrics = prove::prove(field_type, &output_path)?;

            // Display and save metrics
            metrics.display();
            metrics.save_to_file(&format!("results/metrics/metrics_{}.json", field_type))?;
            Ok(())
        }
        None => {
            // Default behavior
            println!("No command specified, running 'prove' with f64 field by default");
            let metrics = prove::prove("f64", "results/proofs/proof_f64.json")?;
            metrics.display();
            metrics.save_to_file("results/metrics/metrics_f64.json")?;
            Ok(())
        }
    }
}
