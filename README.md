# attestchain

**End-to-end chain-of-custody auditor for TEE-attested LLM inference.** Given a
client prompt, a response, and a quote from a TEE-attested endpoint (Intel TDX,
AMD SEV-SNP), verify that: the enclave is running the measurement the
vendor's policy advertises; the input bytes the enclave reports match the
client's bytes; the output bytes the enclave reports match the response; and
the signature chain terminates in a hardware root of trust.

![status: initial scaffold](https://img.shields.io/badge/status-initial%20scaffold-lightgrey)
![language: Rust](https://img.shields.io/badge/language-Rust-blue)
![license: MIT](https://img.shields.io/badge/license-MIT-blue)

## Why

TEE-backed inference is being deployed in production right now (Flashbots
BuilderNet / BOB sandbox, Phala, Marlin, Secret Network) and clients are
being asked to trust the vendor's attestation docs. There is no OSS tool
that lets an independent party *actually run* the attestation chain and
report whether it holds.

attestchain is that tool.

## What is in this scaffold

- Core types: `Policy`, `Quote`, `ChainReport`, `Verdict`.
- `verify_chain(policy, quote, input_bytes, output_bytes)` — the audit-level
  check: measurement match, input-sha match, output-sha match. The
  vendor-specific cert-chain verifier is a follow-up and the verdict is
  `PendingCertChain` until it lands.
- `attestchain verify <policy.json> <quote.json> <input> <output>` CLI.
- `docs/PREREGISTRATION.md` with the chain check locked.

Not in this commit (openly tracked):

- Intel DCAP cert-chain verifier (TDX quotes).
- AMD SEV-SNP cert-chain verifier.
- `attestchain verify-live --endpoint <url> --prompt <path>` that drives
  the audit against a running endpoint.
- Fixtures: one captured bundle per public TEE-inference provider.

## Usage (scaffold)

```sh
cargo install --path .
attestchain verify policy.json quote.json input.bin output.bin
```

## License

MIT. See `LICENSE`.
