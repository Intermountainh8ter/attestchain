//! attestchain CLI — scaffold.
//!
//! `verify` reads a policy, a quote, the client-chosen nonce the client
//! sent to the enclave, and the input/output bytes from disk, then prints
//! the chain report. The `verify-live` subcommand that pulls a quote from
//! a running TEE-attested endpoint is TODO; the pre-registration locks
//! the chain check before any live verification ships.

use attestchain::{leaderboard_row, verify_chain, ChainReport, Policy, Quote, Vendor};
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
        /// Hex-encoded client-chosen nonce the client sent to the
        /// enclave. The audit refuses to run if the quote's bound nonce
        /// is empty.
        #[arg(long)]
        nonce: String,
    },
    /// Build one leaderboard row from a directory of committed
    /// `ChainReport` JSONs (one per audited call). Pre-reg §4: no
    /// numbers in the leaderboard that are not produced from
    /// `results/*.json`. Exits 1 when the sample is not
    /// leaderboard-eligible (any PendingCertChain or Broken).
    Leaderboard {
        /// Directory of ChainReport JSON files to aggregate.
        reports_dir: std::path::PathBuf,
        #[arg(long)]
        endpoint: String,
        /// `intel-tdx` or `amd-sev-snp`.
        #[arg(long)]
        vendor: String,
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
            nonce,
        } => {
            let p: Policy = load_json(&policy)?;
            let q: Quote = load_json(&quote)?;
            let i = std::fs::read(&input)?;
            let o = std::fs::read(&output)?;
            match verify_chain(&p, &q, &nonce, &i, &o) {
                Ok(r) => println!("{}", serde_json::to_string_pretty(&r)?),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(2);
                }
            }
        }
        Cmd::Leaderboard {
            reports_dir,
            endpoint,
            vendor,
        } => {
            let vendor = match vendor.to_ascii_lowercase().as_str() {
                "intel-tdx" | "tdx" => Vendor::IntelTdx,
                "amd-sev-snp" | "sev-snp" | "sevsnp" => Vendor::AmdSevSnp,
                other => anyhow::bail!(
                    "unknown vendor: {other}. Use `intel-tdx` or `amd-sev-snp`."
                ),
            };
            let mut reports: Vec<ChainReport> = Vec::new();
            let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(&reports_dir)?
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
                .collect();
            entries.sort();
            if entries.is_empty() {
                anyhow::bail!("no .json files in {}", reports_dir.display());
            }
            for p in &entries {
                let r: ChainReport = load_json(p)?;
                reports.push(r);
            }
            let row = leaderboard_row(&endpoint, vendor, &reports);
            let eligible = row.leaderboard_eligible;
            println!("{}", serde_json::to_string_pretty(&row)?);
            if !eligible {
                std::process::exit(1);
            }
        }
        Cmd::Version => println!("attestchain {}", env!("CARGO_PKG_VERSION")),
    }
    Ok(())
}
