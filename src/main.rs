use clap::{Parser, Subcommand};
use reachability_toolkit::migration::{Migrate, VulnComponentBatch};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Create example vulnerable batch data file
    Example,

    /// Create migration from vulenrable data batch file
    Migrate {
        // File from which to create migration file
        file: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Example => VulnComponentBatch::make_example(&PathBuf::from("example.yml")),
        Commands::Migrate { file } => VulnComponentBatch::make_migration(file),
    }
}
