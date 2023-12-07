use chrono::Utc;
use clap::{Parser, Subcommand};
use reachability_toolkit::migration::{
    example::get_example,
    util::{entries_from, mk_migration, write_file},
};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
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
        Some(Commands::Example) => write_file("example.yml", get_example()),
        Some(Commands::Migrate { file }) => {
            let entries = entries_from(file)?;
            write_file(
                &format!(
                    "{}-vulnComponent-automated.js",
                    Utc::now().format("%Y%m%d%H%M%S")
                ),
                &mk_migration(entries),
            )
        }
        _ => Ok(()),
    }
}
