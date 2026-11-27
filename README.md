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

- Core types: `Policy`, `Quote`, `ChainReport`, `Verdict`, `AuditError`.
- `canonical_policy_bytes(policy)` — JSON-sorted canonical serialization
  excluding the self-referential `policy_sha256_hex` field, so a policy
  can carry its own content hash and the audit can recompute it.
- `verify_chain(policy, quote, client_nonce_hex, input_bytes, output_bytes)` —
  checks 1-4 of the pre-registered chain plus the nonce-replay guard:
  policy integrity, measurement match, nonce match, input-sha match,
  output-sha match. The vendor-specific cert-chain verifier (check 5)
  is a follow-up and the verdict is `PendingCertChain` until it lands.
  A quote with an empty nonce causes the audit to refuse (returns
  `Err(AuditError::NoNonceInQuote)`), per the pre-reg's
  replay-indistinguishability rule.
- `attestchain verify <policy.json> <quote.json> <input> <output> --nonce <hex>`
  CLI. Refusal exits 2.
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
attestchain verify policy.json quote.json input.bin output.bin --nonce <hex>
```

## Tamper benchmark (synthetic, model-free)

`attestchain tamperbench --seed 7 --chains 200 --len 16 --out results/592-tamper-checkpoint.json`
builds seeded synthetic SHA-256-linked record chains (no vendor data) and
applies four tampers. Results in `results/592-tamper-checkpoint.json`:
suffix truncation of 1 to 4 records is detected at rate 0.0
(`/tamper/suffix_truncation_detection_rate_link_only`) by link verification
alone and 1.0 (`/tamper/suffix_truncation_detection_rate_with_checkpoint`) once an
external (length, head-hash) checkpoint is compared. Bit flips, reorders and
injected-clock expiry are detected at rate 1.0 in both modes, and untampered
chains are never rejected. Limit: the chains are synthetic, so this shows a
property of the construction, not of any provider.

## Chain mutation benchmark (synthetic, model-free)

`attestchain chainbench --seed 7 --chains 200 --out results/595-chain-mutation.json`
builds seeded synthetic three-link certificate-chain records (root,
intermediate, leaf; not X.509, hash tags instead of signatures) and applies
four mutations. A full verifier (issuer links, pinned root) detects missing
intermediate at rate 1.0 (`/chain_mutation/missing_intermediate_detection_rate`),
and also swap order, repeated root and self-signed leaf, with a false-reject
rate of 0.0 (`/chain_mutation/full_false_reject_rate`). A leaf-only verifier
detects missing intermediate at rate 0.0
(`/chain_mutation/leaf_only_missing_intermediate_detection_rate`). Limit: this
tests chain-walking logic on synthetic records, not real DCAP or SEV-SNP chains.

## License

MIT. See `LICENSE`.

## Log cost (synthetic, model-free)

`attestchain logcost --seed 7 --out results/631-logcost-compact.json` counts SHA-256
calls for single-record inclusion checks over logs of 64 to 8192 records. Merkle
inclusion grows by 1.0 hash per doubling (`/sweep/merkle_inclusion_hashes_per_doubling`).
Replaying a hash-linked chain to the head grows by a mean factor of 1.979 per doubling
(`/sweep/chain_inclusion_cost_ratio_mean`), with a per-doubling minimum of 1.677
(`/sweep/chain_inclusion_cost_ratio_min`), below the 1.8 bound. Chain append costs 1 hash
per record. Limit: hash counts only, synthetic records, no writer axis.
