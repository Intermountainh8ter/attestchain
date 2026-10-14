//! attestchain CLI — scaffold.
//!
//! `verify` reads a policy, a quote, and the input/output bytes from disk
//! and prints the chain report. The `verify-live` subcommand that pulls a
//! quote from a running TEE-attested endpoint is TODO; the pre-registration
//! locks the chain check before any live verification ships.

use attestchain::{verify_chain, Policy, Quote};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "attestchain",
    version,
    about = "TEE-attested LLM chain-of-custody auditor"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Verify a captured chain-of-custody bundle.
    Verify {
        policy: std::path::PathBuf,
        quote: std::path::PathBuf,
        input: std::path::PathBuf,
        output: std::path::PathBuf,
    },
    /// Print the version banner and exit.
    Version,
}

fn load_json<T: serde::de::DeserializeOwned>(p: &std::path::Path) -> anyhow::Result<T> {
    Ok(serde_json::from_str(&std::fs::read_to_string(p)?)?)
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Verify {
            policy,
            quote,
            input,
            output,
        } => {
            let p: Policy = load_json(&policy)?;
            let q: Quote = load_json(&quote)?;
            let i = std::fs::read(&input)?;
            let o = std::fs::read(&output)?;
            let r = verify_chain(&p, &q, &i, &o);
            println!("{}", serde_json::to_string_pretty(&r)?);
        }
        Cmd::Version => println!("attestchain {}", env!("CARGO_PKG_VERSION")),
    }
    Ok(())
}
