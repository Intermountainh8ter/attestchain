//! Live HTTP attestation fetcher.
//!
//! The TEE-inference ecosystem has no shared protocol for serving a quote
//! alongside an inference response. Flashbots BuilderNet / BOB, Phala,
//! Marlin and Secret each wire it differently. This module takes a
//! `ProviderProfile` that names where to GET the policy, where to POST the
//! inference, and which JSON fields hold the quote and output in the
//! response — one adapter, N vendors.
//!
//! The adapter never prints or logs the raw response body or any auth
//! credential. The policy is read once, the inference call is made once,
//! and the result the caller sees is `(Policy, Quote, output_bytes)`
//! ready to feed into `verify_chain`.

use crate::{Policy, Quote};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

/// A description of one TEE-attested inference provider. Every URL is a
/// full URL; JSON paths are `/`-separated dot-free pointers rooted at
/// the response body (e.g. `"attestation/quote"` reads
/// `body["attestation"]["quote"]`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderProfile {
    pub name: String,
    pub policy_url: String,
    pub inference_url: String,
    /// JSON path to the Quote object in the inference response.
    pub quote_json_path: String,
    /// JSON path to the output bytes (hex-encoded) in the inference
    /// response. The adapter decodes the hex before returning.
    pub output_hex_json_path: String,
    /// Field name under which to POST the prompt bytes (hex-encoded).
    #[serde(default = "default_prompt_field")]
    pub prompt_hex_field: String,
    /// Field name under which to POST the client nonce.
    #[serde(default = "default_nonce_field")]
    pub nonce_hex_field: String,
    /// Env var holding an API key, if any. The resolved key never
    /// appears in `Debug`, logs, or errors.
    #[serde(default)]
    pub api_key_env: Option<String>,
    #[serde(default = "default_timeout_s")]
    pub timeout_s: u64,
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
}

fn default_prompt_field() -> String {
    "prompt_hex".into()
}

fn default_nonce_field() -> String {
    "nonce_hex".into()
}

fn default_timeout_s() -> u64 {
    30
}

fn default_max_retries() -> u32 {
    2
}

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("api_key_env `{0}` is set in profile but the environment variable is not set")]
    AuthMissing(String),
    #[error("endpoint refused authentication (HTTP {status})")]
    AuthRejected { status: u16 },
    #[error("endpoint returned HTTP {status} after {attempts} attempts")]
    HttpStatus { status: u16, attempts: u32 },
    #[error("response is missing field at JSON path `{path}`")]
    MissingField { path: String },
    #[error("response field at `{path}` could not be decoded: {msg}")]
    DecodeField { path: String, msg: String },
    #[error("response could not be parsed as JSON")]
    MalformedJson,
    #[error("transport error after {attempts} attempts: {source}")]
    Transport {
        attempts: u32,
        #[source]
        source: reqwest::Error,
    },
}

/// Everything the caller needs to then run `verify_chain`.
#[derive(Debug)]
pub struct AttestedResponse {
    pub policy: Policy,
    pub quote: Quote,
    pub output_bytes: Vec<u8>,
}

fn resolve_auth(profile: &ProviderProfile) -> Result<Option<String>, FetchError> {
    match &profile.api_key_env {
        None => Ok(None),
        Some(name) => std::env::var(name)
            .map(Some)
            .map_err(|_| FetchError::AuthMissing(name.clone())),
    }
}

fn pointer_from_path(path: &str) -> String {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        let mut s = String::with_capacity(trimmed.len() + 1);
        for seg in trimmed.split('/') {
            s.push('/');
            s.push_str(seg);
        }
        s
    }
}

fn get_at_path<'a>(
    body: &'a serde_json::Value,
    path: &str,
) -> Result<&'a serde_json::Value, FetchError> {
    let p = pointer_from_path(path);
    body.pointer(&p).ok_or(FetchError::MissingField {
        path: path.to_string(),
    })
}

/// Fetch policy + inference-response from a provider. Blocking facade.
pub fn fetch_attested(
    profile: &ProviderProfile,
    prompt: &[u8],
    client_nonce_hex: &str,
) -> Result<AttestedResponse, FetchError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime builds");
    rt.block_on(fetch_attested_async(profile, prompt, client_nonce_hex))
}

pub async fn fetch_attested_async(
    profile: &ProviderProfile,
    prompt: &[u8],
    client_nonce_hex: &str,
) -> Result<AttestedResponse, FetchError> {
    let auth = resolve_auth(profile)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(profile.timeout_s))
        .build()
        .map_err(|e| FetchError::Transport {
            attempts: 0,
            source: e,
        })?;

    let policy_body: serde_json::Value =
        send_with_retry(&client, &profile.policy_url, auth.as_deref(), None, profile.max_retries)
            .await?;
    let policy: Policy =
        serde_json::from_value(policy_body).map_err(|_| FetchError::MalformedJson)?;

    let prompt_hex = hex::encode(prompt);
    let infer_body = serde_json::json!({
        profile.prompt_hex_field.clone(): prompt_hex,
        profile.nonce_hex_field.clone(): client_nonce_hex,
    });
    let infer_resp: serde_json::Value = send_with_retry(
        &client,
        &profile.inference_url,
        auth.as_deref(),
        Some(infer_body),
        profile.max_retries,
    )
    .await?;

    let quote_val = get_at_path(&infer_resp, &profile.quote_json_path)?.clone();
    let quote: Quote = serde_json::from_value(quote_val).map_err(|e| FetchError::DecodeField {
        path: profile.quote_json_path.clone(),
        msg: e.to_string(),
    })?;

    let output_hex_val = get_at_path(&infer_resp, &profile.output_hex_json_path)?;
    let output_hex = output_hex_val
        .as_str()
        .ok_or_else(|| FetchError::DecodeField {
            path: profile.output_hex_json_path.clone(),
            msg: "value is not a JSON string".into(),
        })?;
    let output_bytes = hex::decode(output_hex).map_err(|e| FetchError::DecodeField {
        path: profile.output_hex_json_path.clone(),
        msg: e.to_string(),
    })?;

    Ok(AttestedResponse {
        policy,
        quote,
        output_bytes,
    })
}

async fn send_with_retry(
    client: &reqwest::Client,
    url: &str,
    auth: Option<&str>,
    body: Option<serde_json::Value>,
    max_retries: u32,
) -> Result<serde_json::Value, FetchError> {
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        let mut req = match &body {
            Some(b) => client.post(url).json(b),
            None => client.get(url),
        };
        if let Some(k) = auth {
            req = req.bearer_auth(k);
        }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    return resp.json().await.map_err(|_| FetchError::MalformedJson);
                }
                if status.as_u16() == 401 || status.as_u16() == 403 {
                    return Err(FetchError::AuthRejected {
                        status: status.as_u16(),
                    });
                }
                let retryable = status.as_u16() == 429 || status.is_server_error();
                if !retryable || attempt > max_retries {
                    return Err(FetchError::HttpStatus {
                        status: status.as_u16(),
                        attempts: attempt,
                    });
                }
            }
            Err(e) => {
                let retryable = e.is_timeout() || e.is_connect() || e.is_request();
                if !retryable || attempt > max_retries {
                    return Err(FetchError::Transport {
                        attempts: attempt,
                        source: e,
                    });
                }
            }
        }
        let delay_ms = 100u64.saturating_mul(1u64 << (attempt - 1).min(10));
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{canonical_policy_bytes, sha256_hex, verify_chain, Vendor, Verdict};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_policy() -> Policy {
        let mut p = Policy {
            endpoint: "https://example".into(),
            vendor: Vendor::IntelTdx,
            measurement_hex: "aa".repeat(48),
            policy_sha256_hex: String::new(),
        };
        p.policy_sha256_hex = sha256_hex(&canonical_policy_bytes(&p));
        p
    }

    fn make_quote(policy: &Policy, input: &[u8], output: &[u8], nonce_hex: &str) -> Quote {
        Quote {
            vendor: Vendor::IntelTdx,
            measurement_hex: policy.measurement_hex.clone(),
            policy_sha256_hex: policy.policy_sha256_hex.clone(),
            input_sha256_hex: sha256_hex(input),
            output_sha256_hex: sha256_hex(output),
            nonce_hex: nonce_hex.into(),
            cert_chain: vec![],
        }
    }

    fn profile(base: &str) -> ProviderProfile {
        ProviderProfile {
            name: "mock".into(),
            policy_url: format!("{base}/policy"),
            inference_url: format!("{base}/infer"),
            quote_json_path: "attestation/quote".into(),
            output_hex_json_path: "attestation/output_hex".into(),
            prompt_hex_field: "prompt_hex".into(),
            nonce_hex_field: "nonce_hex".into(),
            api_key_env: None,
            timeout_s: 2,
            max_retries: 2,
        }
    }

    fn make_body(policy: &Policy, quote: &Quote, output: &[u8]) -> serde_json::Value {
        serde_json::json!({
            "attestation": {
                "quote": quote,
                "output_hex": hex::encode(output),
            },
            "ignored_sibling": {"policy": policy}
        })
    }

    #[tokio::test(flavor = "current_thread")]
    async fn happy_path_yields_an_attested_verdict_once_verified() {
        let server = MockServer::start().await;
        let policy = make_policy();
        let prompt = b"hello";
        let output = b"world";
        let nonce = "ab".repeat(16);
        let quote = make_quote(&policy, prompt, output, &nonce);
        Mock::given(method("GET"))
            .and(path("/policy"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&policy))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/infer"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_body(
                &policy, &quote, output,
            )))
            .mount(&server)
            .await;
        let fetched = fetch_attested_async(&profile(&server.uri()), prompt, &nonce)
            .await
            .expect("fetches");
        let report = verify_chain(&fetched.policy, &fetched.quote, &nonce, prompt, &fetched.output_bytes)
            .expect("verifies");
        assert!(report.policy_integrity);
        assert!(report.measurement_matches);
        assert!(report.input_matches_quote);
        assert!(report.output_matches_quote);
        assert!(report.nonce_matches);
        assert_eq!(report.verdict, Verdict::PendingCertChain);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn drifted_policy_sha_breaks_the_chain() {
        let server = MockServer::start().await;
        let policy = make_policy();
        let prompt = b"hello";
        let output = b"world";
        let nonce = "ab".repeat(16);
        let mut quote = make_quote(&policy, prompt, output, &nonce);
        // Simulate the endpoint tampering: quote references a different policy.
        quote.policy_sha256_hex = "ff".repeat(32);
        Mock::given(method("GET"))
            .and(path("/policy"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&policy))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/infer"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_body(
                &policy, &quote, output,
            )))
            .mount(&server)
            .await;
        let fetched = fetch_attested_async(&profile(&server.uri()), prompt, &nonce)
            .await
            .expect("fetches");
        let report = verify_chain(&fetched.policy, &fetched.quote, &nonce, prompt, &fetched.output_bytes)
            .expect("verifies");
        assert!(!report.policy_integrity);
        assert_eq!(report.verdict, Verdict::Broken);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn missing_quote_field_is_a_descriptive_error() {
        let server = MockServer::start().await;
        let policy = make_policy();
        Mock::given(method("GET"))
            .and(path("/policy"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&policy))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/infer"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"attestation": {}})),
            )
            .mount(&server)
            .await;
        let err = fetch_attested_async(&profile(&server.uri()), b"x", "ab")
            .await
            .expect_err("missing field");
        match err {
            FetchError::MissingField { path } => assert_eq!(path, "attestation/quote"),
            e => panic!("wrong variant: {e:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retries_a_429_then_succeeds() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/policy"))
            .respond_with(ResponseTemplate::new(429))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        let policy = make_policy();
        let prompt = b"x";
        let output = b"y";
        let nonce = "cd".repeat(16);
        let quote = make_quote(&policy, prompt, output, &nonce);
        Mock::given(method("GET"))
            .and(path("/policy"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&policy))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/infer"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_body(
                &policy, &quote, output,
            )))
            .mount(&server)
            .await;
        let fetched = fetch_attested_async(&profile(&server.uri()), prompt, &nonce)
            .await
            .expect("retries succeed");
        assert_eq!(fetched.output_bytes, output);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn auth_rejected_is_fatal_and_not_retried() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/policy"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&server)
            .await;
        let err = fetch_attested_async(&profile(&server.uri()), b"x", "ab")
            .await
            .expect_err("auth refused");
        assert!(matches!(err, FetchError::AuthRejected { status: 401 }));
    }

    #[test]
    fn pointer_from_path_handles_leading_and_trailing_slashes() {
        assert_eq!(pointer_from_path("a/b"), "/a/b");
        assert_eq!(pointer_from_path("/a/b/"), "/a/b");
        assert_eq!(pointer_from_path(""), "");
    }
}
