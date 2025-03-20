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
    Prove,
}

fn main() -> eyre::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Prove) => prove::main(),
        None => {
            // Default behavior
            println!("No command specified, running 'prove' by default");
            prove::main()
        }
    }
}
