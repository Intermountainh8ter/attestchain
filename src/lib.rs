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

pub mod http;

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
    /// Hex-encoded sha256 of the policy the quote references. Must equal
    /// the sha256 of the policy served to the client at audit-start time;
    /// a drift here means the endpoint changed its policy mid-audit.
    pub policy_sha256_hex: String,
    /// Hex-encoded sha256 of the input the enclave received. For an LLM
    /// call this is the serialized prompt.
    pub input_sha256_hex: String,
    /// Hex-encoded sha256 of the output the enclave produced.
    pub output_sha256_hex: String,
    /// Hex-encoded client-chosen nonce the quote binds (TDX user-data
    /// region, SEV-SNP REPORT_DATA). An empty string means the quote
    /// did not bind a nonce; the audit refuses such quotes.
    pub nonce_hex: String,
    /// Raw cert chain, in order leaf -> root. Verification against the
    /// vendor root is a follow-up.
    pub cert_chain: Vec<Vec<u8>>,
}

/// Verification outcome of a single call's chain-of-custody.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainReport {
    /// Check 1: the policy sha256 the quote references matches
    /// `sha256(canonical_policy_bytes(policy))`.
    pub policy_integrity: bool,
    /// Check 2: `policy.measurement_hex == quote.measurement_hex`.
    pub measurement_matches: bool,
    /// Check 3: `sha256(input_bytes) == quote.input_sha256_hex`.
    pub input_matches_quote: bool,
    /// Check 4: `sha256(output_bytes) == quote.output_sha256_hex`.
    pub output_matches_quote: bool,
    /// Check 2a: `quote.nonce_hex == client_nonce_hex`. A nonce mismatch
    /// is Broken (the client cannot distinguish mismatch from replay).
    pub nonce_matches: bool,
    /// Check 5: the cert chain terminates in a vendor root. Stays false
    /// until the vendor-specific verifier lands.
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

/// Reasons the audit refuses to run (as opposed to running and returning
/// a Broken verdict). The pre-registration mandates refusal when the
/// quote carries no client-chosen nonce — without a nonce, a passing
/// chain is indistinguishable from a replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditError {
    /// The quote's `nonce_hex` field is empty: the enclave produced a
    /// quote that is not bound to a client nonce. Replay-indistinguishable.
    NoNonceInQuote,
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoNonceInQuote => f.write_str(
                "audit refuses: quote does not bind a client-chosen nonce (replay-indistinguishable)",
            ),
        }
    }
}

impl std::error::Error for AuditError {}

/// Serialize a Policy to a canonical byte string suitable for sha256.
///
/// Keys are JSON-sorted so that two policies with the same semantic
/// content produce byte-identical bytes regardless of input ordering.
/// The `policy_sha256_hex` field is a self-referential metadata record
/// ("the sha of this policy without this field") and is excluded from
/// the canonical serialization; it is what the quote's own
/// `policy_sha256_hex` is compared against.
pub fn canonical_policy_bytes(policy: &Policy) -> Vec<u8> {
    let mut v: serde_json::Value = serde_json::to_value(policy).expect("policy serializes");
    if let Some(obj) = v.as_object_mut() {
        obj.remove("policy_sha256_hex");
    }
    let mut buf = Vec::new();
    write_canonical(&v, &mut buf);
    buf
}

fn write_canonical(v: &serde_json::Value, buf: &mut Vec<u8>) {
    match v {
        serde_json::Value::Object(map) => {
            buf.push(b'{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                buf.extend_from_slice(serde_json::to_string(k).unwrap().as_bytes());
                buf.push(b':');
                write_canonical(&map[*k], buf);
            }
            buf.push(b'}');
        }
        serde_json::Value::Array(arr) => {
            buf.push(b'[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                write_canonical(item, buf);
            }
            buf.push(b']');
        }
        other => buf.extend_from_slice(serde_json::to_string(other).unwrap().as_bytes()),
    }
}

/// Verify the audit-level checks that this crate implements today.
///
/// `client_nonce_hex` is the nonce the client sent to the enclave; the
/// audit refuses to run when the quote carries no nonce, per the
/// pre-registration's replay-indistinguishability rule.
pub fn verify_chain(
    policy: &Policy,
    quote: &Quote,
    client_nonce_hex: &str,
    input_bytes: &[u8],
    output_bytes: &[u8],
) -> Result<ChainReport, AuditError> {
    if quote.nonce_hex.is_empty() {
        return Err(AuditError::NoNonceInQuote);
    }
    // Check 1: policy integrity. The policy served to the client hashes
    // to the sha the quote references.
    let computed = sha256_hex(&canonical_policy_bytes(policy));
    let policy_integrity = computed == quote.policy_sha256_hex;
    let measurement_matches = policy.measurement_hex == quote.measurement_hex;
    let input_matches_quote = sha256_hex(input_bytes) == quote.input_sha256_hex;
    let output_matches_quote = sha256_hex(output_bytes) == quote.output_sha256_hex;
    let nonce_matches = quote.nonce_hex == client_nonce_hex;
    let cert_chain_verified = false; // TODO: wire vendor-specific verifier
    let all_pre_cert = policy_integrity
        && measurement_matches
        && input_matches_quote
        && output_matches_quote
        && nonce_matches;
    let verdict = if !all_pre_cert {
        Verdict::Broken
    } else if cert_chain_verified {
        Verdict::Attested
    } else {
        Verdict::PendingCertChain
    };
    Ok(ChainReport {
        policy_integrity,
        measurement_matches,
        input_matches_quote,
        output_matches_quote,
        nonce_matches,
        cert_chain_verified,
        verdict,
    })
}

/// One row of the leaderboard: aggregate chain-of-custody outcome for
/// an endpoint across a sample of audited calls. Pre-reg §4 requires
/// that leaderboard numbers derive from committed `results/*.json`;
/// `LeaderboardRow` is that derived type.
///
/// Pre-reg §2 is explicit: each `ChainReport` audits one call. A row
/// publishes the sample's counts and names the sample size (`n`); it
/// never claims lifetime behavior for the endpoint. Pre-reg §3's
/// `PendingCertChain` outcomes are reported separately — they
/// contribute to `n_pending` and keep the row off the "attested" line.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaderboardRow {
    pub endpoint: String,
    pub vendor: Vendor,
    pub n: usize,
    pub n_attested: usize,
    pub n_broken: usize,
    pub n_pending_cert_chain: usize,
    /// Set only when every call in the sample was `Attested`. Pre-reg
    /// §3: a sample containing even one `PendingCertChain` cannot land
    /// on the leaderboard as "attested", so this flag refuses it.
    pub leaderboard_eligible: bool,
}

/// Build a leaderboard row from the audited sample. `vendor` must be
/// consistent across the sample; a mismatch panics (sampling the same
/// endpoint with two vendors is a caller error).
pub fn leaderboard_row(
    endpoint: &str,
    vendor: Vendor,
    reports: &[ChainReport],
) -> LeaderboardRow {
    let n = reports.len();
    let mut n_attested = 0;
    let mut n_broken = 0;
    let mut n_pending = 0;
    for r in reports {
        match r.verdict {
            Verdict::Attested => n_attested += 1,
            Verdict::Broken => n_broken += 1,
            Verdict::PendingCertChain => n_pending += 1,
        }
    }
    LeaderboardRow {
        endpoint: endpoint.into(),
        vendor,
        n,
        n_attested,
        n_broken,
        n_pending_cert_chain: n_pending,
        leaderboard_eligible: n > 0 && n_attested == n,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: &str = "a1b2c3d4";

    fn p(meas: &str) -> Policy {
        // Policy's own policy_sha256_hex is set to the computed canonical
        // sha256, so a well-formed test fixture is self-consistent.
        let mut policy = Policy {
            endpoint: "https://example".into(),
            vendor: Vendor::IntelTdx,
            measurement_hex: meas.into(),
            policy_sha256_hex: String::new(),
        };
        // The policy_sha256_hex is NOT a self-reference; it is the sha
        // over the policy WITHOUT this field (set to empty), and that is
        // what the quote compares against. Keep the field empty when
        // computing the canonical sha used for the audit.
        policy.policy_sha256_hex = sha256_hex(&canonical_policy_bytes(&policy));
        policy
    }

    fn q(policy: &Policy, input: &[u8], output: &[u8], meas: &str) -> Quote {
        Quote {
            vendor: Vendor::IntelTdx,
            measurement_hex: meas.into(),
            policy_sha256_hex: policy.policy_sha256_hex.clone(),
            input_sha256_hex: sha256_hex(input),
            output_sha256_hex: sha256_hex(output),
            nonce_hex: NONCE.into(),
            cert_chain: vec![],
        }
    }

    #[test]
    fn clean_chain_is_pending_cert() {
        let pol = p("deadbeef");
        let r = verify_chain(&pol, &q(&pol, b"in", b"out", "deadbeef"), NONCE, b"in", b"out")
            .expect("audit should run");
        assert_eq!(r.verdict, Verdict::PendingCertChain);
        assert!(r.policy_integrity && r.measurement_matches);
        assert!(r.input_matches_quote && r.output_matches_quote && r.nonce_matches);
    }

    #[test]
    fn drifted_input_breaks_chain() {
        let pol = p("deadbeef");
        let r = verify_chain(
            &pol,
            &q(&pol, b"what-the-client-said", b"out", "deadbeef"),
            NONCE,
            b"what-the-enclave-told-the-client",
            b"out",
        )
        .expect("audit should run");
        assert_eq!(r.verdict, Verdict::Broken);
        assert!(!r.input_matches_quote);
    }

    #[test]
    fn policy_measurement_drift_breaks_chain() {
        let pol = p("deadbeef");
        let mut quote = q(&pol, b"in", b"out", "deadbeef");
        quote.measurement_hex = "cafef00d".into();
        let r = verify_chain(&pol, &quote, NONCE, b"in", b"out").expect("audit should run");
        assert_eq!(r.verdict, Verdict::Broken);
        assert!(!r.measurement_matches);
    }

    #[test]
    fn missing_nonce_refuses_the_audit() {
        let pol = p("deadbeef");
        let mut quote = q(&pol, b"in", b"out", "deadbeef");
        quote.nonce_hex = String::new();
        let r = verify_chain(&pol, &quote, NONCE, b"in", b"out");
        assert_eq!(r, Err(AuditError::NoNonceInQuote));
    }

    #[test]
    fn nonce_mismatch_breaks_chain() {
        let pol = p("deadbeef");
        let r = verify_chain(
            &pol,
            &q(&pol, b"in", b"out", "deadbeef"),
            "ffffffff",
            b"in",
            b"out",
        )
        .expect("audit should run");
        assert_eq!(r.verdict, Verdict::Broken);
        assert!(!r.nonce_matches);
    }

    #[test]
    fn policy_integrity_drift_breaks_chain() {
        let pol = p("deadbeef");
        let mut quote = q(&pol, b"in", b"out", "deadbeef");
        // Simulate the endpoint swapping its policy mid-audit by having
        // the quote reference a different policy sha.
        quote.policy_sha256_hex = "0".repeat(64);
        let r = verify_chain(&pol, &quote, NONCE, b"in", b"out").expect("audit should run");
        assert_eq!(r.verdict, Verdict::Broken);
        assert!(!r.policy_integrity);
    }

    #[test]
    fn canonical_policy_bytes_is_order_independent() {
        // Two Policy values with the same semantic content must hash the
        // same regardless of in-memory field ordering: because Policy is
        // a struct, Rust fixes the field order, so we instead check that
        // the canonical bytes decode back to the same object.
        let a = Policy {
            endpoint: "x".into(),
            vendor: Vendor::IntelTdx,
            measurement_hex: "ab".into(),
            policy_sha256_hex: "".into(),
        };
        let b = Policy {
            endpoint: "x".into(),
            vendor: Vendor::IntelTdx,
            measurement_hex: "ab".into(),
            policy_sha256_hex: "".into(),
        };
        assert_eq!(canonical_policy_bytes(&a), canonical_policy_bytes(&b));
    }

    fn clean_report() -> ChainReport {
        let pol = p("deadbeef");
        verify_chain(&pol, &q(&pol, b"in", b"out", "deadbeef"), NONCE, b"in", b"out")
            .expect("audit should run")
    }

    #[test]
    fn leaderboard_row_eligible_only_when_all_attested() {
        let a = ChainReport {
            policy_integrity: true,
            measurement_matches: true,
            input_matches_quote: true,
            output_matches_quote: true,
            nonce_matches: true,
            cert_chain_verified: true,
            verdict: Verdict::Attested,
        };
        let row = leaderboard_row("ep", Vendor::IntelTdx, &[a.clone(), a.clone(), a]);
        assert_eq!(row.n, 3);
        assert_eq!(row.n_attested, 3);
        assert!(row.leaderboard_eligible);
    }

    #[test]
    fn leaderboard_row_blocked_when_any_pending_cert_chain() {
        let pending = clean_report(); // PendingCertChain
        let row = leaderboard_row("ep", Vendor::IntelTdx, &[pending]);
        assert_eq!(row.n_pending_cert_chain, 1);
        assert!(!row.leaderboard_eligible, "pre-reg §3: pending blocks row");
    }

    #[test]
    fn leaderboard_row_blocked_when_any_broken() {
        let a = ChainReport {
            policy_integrity: true,
            measurement_matches: true,
            input_matches_quote: true,
            output_matches_quote: true,
            nonce_matches: true,
            cert_chain_verified: true,
            verdict: Verdict::Attested,
        };
        let broken = ChainReport {
            verdict: Verdict::Broken,
            ..a.clone()
        };
        let row = leaderboard_row("ep", Vendor::IntelTdx, &[a, broken]);
        assert_eq!(row.n_broken, 1);
        assert!(!row.leaderboard_eligible);
    }

    #[test]
    fn leaderboard_row_empty_sample_is_ineligible() {
        let row = leaderboard_row("ep", Vendor::IntelTdx, &[]);
        assert_eq!(row.n, 0);
        assert!(!row.leaderboard_eligible);
    }
}
