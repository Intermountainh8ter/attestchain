//! attestchain CLI — scaffold.
//!
//! `verify` reads a policy, a quote, the client-chosen nonce the client
//! sent to the enclave, and the input/output bytes from disk, then prints
//! the chain report. The `verify-live` subcommand that pulls a quote from
//! a running TEE-attested endpoint is TODO; the pre-registration locks
//! the chain check before any live verification ships.

use attestchain::{
    http::{fetch_attested, ProviderProfile},
    leaderboard_row, verify_chain, ChainReport, Policy, Quote, Vendor,
};
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
    /// Fetch a policy + quote from a live TEE-attested endpoint using a
    /// provider profile, verify the chain, write the ChainReport to disk,
    /// and exit 0 (Attested or PendingCertChain) / 1 (Broken).
    Audit {
        /// Provider profile JSON.
        #[arg(long)]
        profile: std::path::PathBuf,
        /// File holding the prompt bytes.
        #[arg(long)]
        prompt: std::path::PathBuf,
        /// Hex-encoded client-chosen nonce the client expects the enclave
        /// to bind. Required: the audit refuses to run without one.
        #[arg(long)]
        nonce: String,
        /// Destination directory for the audited bundle:
        /// `policy.json`, `quote.json`, `input.bin`, `output.bin`,
        /// `chain_report.json`.
        #[arg(long)]
        out: std::path::PathBuf,
    },
    /// Model-free tamper benchmark over seeded synthetic record chains.
    Tamperbench {
        #[arg(long)]
        seed: u64,
        #[arg(long)]
        chains: usize,
        #[arg(long)]
        len: usize,
        #[arg(long)]
        out: std::path::PathBuf,
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
        Cmd::Audit {
            profile,
            prompt,
            nonce,
            out,
        } => {
            let profile: ProviderProfile = load_json(&profile)?;
            let prompt_bytes = std::fs::read(&prompt)?;
            let fetched = fetch_attested(&profile, &prompt_bytes, &nonce)?;
            let report = verify_chain(
                &fetched.policy,
                &fetched.quote,
                &nonce,
                &prompt_bytes,
                &fetched.output_bytes,
            )?;
            std::fs::create_dir_all(&out)?;
            std::fs::write(
                out.join("policy.json"),
                serde_json::to_string_pretty(&fetched.policy)?,
            )?;
            std::fs::write(
                out.join("quote.json"),
                serde_json::to_string_pretty(&fetched.quote)?,
            )?;
            std::fs::write(out.join("input.bin"), &prompt_bytes)?;
            std::fs::write(out.join("output.bin"), &fetched.output_bytes)?;
            std::fs::write(
                out.join("chain_report.json"),
                serde_json::to_string_pretty(&report)?,
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if report.verdict == attestchain::Verdict::Broken {
                std::process::exit(1);
            }
        }
        Cmd::Tamperbench { seed, chains, len, out } => {
            let started = std::time::SystemTime::now();
            let t0 = std::time::Instant::now();
            let rep = attestchain::tamper::run(seed, chains, len);
            let mut v = serde_json::to_value(&rep)?;
            let ts = started.duration_since(std::time::UNIX_EPOCH)?.as_secs();
            let (days, rem) = (ts / 86400, ts % 86400);
            // civil-from-days
            let z = days as i64 + 719468;
            let era = z / 146097;
            let doe = z - era * 146097;
            let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
            let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
            let mp = (5 * doy + 2) / 153;
            let d = doy - (153 * mp + 2) / 5 + 1;
            let m = if mp < 10 { mp + 3 } else { mp - 9 };
            let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
            let started_at = format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                y, m, d, rem / 3600, rem % 3600 / 60, rem % 60
            );
            v["provenance"] = serde_json::json!({
                "started_at": started_at,
                "seeds": [seed],
                "command": format!("cargo run --locked -q --release -- tamperbench --seed {seed} --chains {chains} --len {len} --out results/592-tamper-checkpoint.json"),
                "hardware": format!("{} {} (cpu only)", std::env::consts::OS, std::env::consts::ARCH),
                "wall_s": t0.elapsed().as_secs_f64(),
                "data_sources": [{"url": "synthetic: generated in-crate from a seeded PRNG, no external data", "license": "MIT (this repository)"}],
            });
            if let Some(dir) = out.parent() { std::fs::create_dir_all(dir)?; }
            std::fs::write(&out, serde_json::to_string_pretty(&v)?)?;
            println!("{}", serde_json::to_string_pretty(&v["tamper"])?);
        }
        Cmd::Version => println!("attestchain {}", env!("CARGO_PKG_VERSION")),
    }
    Ok(())
}
