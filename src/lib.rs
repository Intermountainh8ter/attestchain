//! Core types and chain-verification primitives for attestchain.
//!
//! The audit answers one question: for a TEE-attested LLM inference call,
//! are the bytes the enclave reports *the same bytes the client sent*, is
//! the enclave running the measurement the vendor's policy claims, and is
//! the response signed by a chain that terminates in a hardware root of
//! trust (Intel DCAP or AMD SEV-SNP)?
//!
//! This crate ships the data structures and the hash-level comparison. The
//! vendor-specific quote verifiers (DCAP, SEV-SNP) are stubbed behind
//! feature flags and arrive in follow-up releases; see
//! `docs/PREREGISTRATION.md` for the full plan.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// What the TEE vendor advertises as the measurement the enclave should
/// run. Published alongside the service, hashed into the audit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    pub endpoint: String,
    pub vendor: Vendor,
    /// Hex-encoded measurement (MRTD for TDX, LD for SEV-SNP).
    pub measurement_hex: String,
    /// Hex-encoded sha256 of the policy's own canonical serialization,
    /// used so a drift between the policy you were served and the policy
    /// the quote references is detectable.
    pub policy_sha256_hex: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum Vendor {
    IntelTdx,
    AmdSevSnp,
}

/// A quote retrieved from a TEE-attested inference endpoint. The exact
/// decoder is vendor-specific and arrives in follow-up releases; the fields
/// here are the ones the chain verification needs to see.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Quote {
    pub vendor: Vendor,
    /// Hex-encoded measurement the quote asserts the enclave is running.
    pub measurement_hex: String,
    /// Hex-encoded sha256 of the input the enclave received. For an LLM
    /// call this is the serialized prompt.
    pub input_sha256_hex: String,
    /// Hex-encoded sha256 of the output the enclave produced.
    pub output_sha256_hex: String,
    /// Raw cert chain, in order leaf -> root. Verification against the
    /// vendor root is a follow-up.
    pub cert_chain: Vec<Vec<u8>>,
}

/// Verification outcome of a single call's chain-of-custody.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainReport {
    pub policy_matches_quote: bool,
    pub input_matches_quote: bool,
    pub output_matches_quote: bool,
    /// Set only when the cert chain is fully verified against a vendor
    /// root; stays false until the vendor-specific verifier lands.
    pub cert_chain_verified: bool,
    /// Verdict: the whole chain is sound only when every field above
    /// is true.
    pub verdict: Verdict,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Verdict {
    /// Every check passed. The chain of custody from client input to
    /// signed output is intact.
    Attested,
    /// At least one check failed. Report which.
    Broken,
    /// Shape is right but the cert chain verifier has not landed yet;
    /// the measurement/input/output checks pass. The only honest verdict
    /// until the vendor code is written.
    PendingCertChain,
}

/// Compute the sha256 of a byte string in the hex form the quotes use.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Verify the audit-level checks that this crate implements today.
/// `input_bytes` and `output_bytes` are the client-side canonical byte
/// serializations of the prompt and the response.
pub fn verify_chain(
    policy: &Policy,
    quote: &Quote,
    input_bytes: &[u8],
    output_bytes: &[u8],
) -> ChainReport {
    let policy_matches_quote = policy.measurement_hex == quote.measurement_hex;
    let input_matches_quote = sha256_hex(input_bytes) == quote.input_sha256_hex;
    let output_matches_quote = sha256_hex(output_bytes) == quote.output_sha256_hex;
    let cert_chain_verified = false; // TODO: wire vendor-specific verifier
    let verdict = if !policy_matches_quote || !input_matches_quote || !output_matches_quote {
        Verdict::Broken
    } else {
        Verdict::PendingCertChain
    };
    ChainReport {
        policy_matches_quote,
        input_matches_quote,
        output_matches_quote,
        cert_chain_verified,
        verdict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(input: &[u8], output: &[u8], meas: &str) -> Quote {
        Quote {
            vendor: Vendor::IntelTdx,
            measurement_hex: meas.into(),
            input_sha256_hex: sha256_hex(input),
            output_sha256_hex: sha256_hex(output),
            cert_chain: vec![],
        }
    }

    fn p(meas: &str) -> Policy {
        Policy {
            endpoint: "https://example".into(),
            vendor: Vendor::IntelTdx,
            measurement_hex: meas.into(),
            policy_sha256_hex: "0".repeat(64),
        }
    }

    #[test]
    fn clean_chain_is_pending_cert() {
        let r = verify_chain(&p("deadbeef"), &q(b"in", b"out", "deadbeef"), b"in", b"out");
        assert_eq!(r.verdict, Verdict::PendingCertChain);
        assert!(r.policy_matches_quote && r.input_matches_quote && r.output_matches_quote);
    }

    #[test]
    fn drifted_input_breaks_chain() {
        let r = verify_chain(
            &p("deadbeef"),
            &q(b"what-the-client-said", b"out", "deadbeef"),
            b"what-the-enclave-told-the-client",
            b"out",
        );
        assert_eq!(r.verdict, Verdict::Broken);
        assert!(!r.input_matches_quote);
    }

    #[test]
    fn policy_measurement_drift_breaks_chain() {
        let r = verify_chain(&p("deadbeef"), &q(b"in", b"out", "cafef00d"), b"in", b"out");
        assert_eq!(r.verdict, Verdict::Broken);
        assert!(!r.policy_matches_quote);
    }
}
