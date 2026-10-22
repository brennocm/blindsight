//! Command-line entry point. Parses arguments, calls the library and sets the
//! exit code; all logic lives in the library.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Offline verifier for Safe multisig transactions.
#[derive(Parser)]
#[command(name = "blindsight", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print version information.
    Version,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            // Exit code 2: input or usage error (see docs once the CLI is complete).
            ExitCode::from(2)
        }
    }
}

fn run(cli: &Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Version => {
            println!("blindsight {}", blindsight::VERSION);
            Ok(())
        }
    }
}
