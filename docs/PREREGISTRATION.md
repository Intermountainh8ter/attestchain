# attestchain pre-registration

Locked before the first live-endpoint audit result is committed. Append-only.

## 1. Scope

The population under audit is **publicly listed TEE-attested LLM inference
endpoints** (Intel TDX, AMD SEV-SNP) that advertise an attestation policy,
return quotes with their responses, and sign the response bytes.

attestchain audits one call at a time. A failing audit on one call is a
publishable finding; a passing audit on a sample of calls is a statement
about the sample, never about the endpoint's lifetime behavior.

## 2. What "attested" means

For a call to pass audit it must clear **four** checks, in order:

1. **Policy integrity.** The policy served to the client when the audit
   started hashes to the policy sha256 the quote references. If the
   endpoint silently changes its policy between serve-time and quote-time
   the audit fails.
2. **Measurement match.** The quote's measurement equals the policy's
   advertised measurement, byte for byte.
3. **Byte match on input.** `sha256(client_bytes) == quote.input_sha256`.
4. **Byte match on output.** `sha256(enclave_response_bytes) == quote.output_sha256`.
5. **Cert chain verifies.** The quote's cert chain terminates in the
   vendor root certificate (Intel's for DCAP, AMD's for SEV-SNP) and is
   valid at the quote's timestamp.

All five must be true. Any single failure is reported with the field that
failed; the verdict is **Broken**. All five true is **Attested**.

## 3. "Pending cert chain" is a real verdict

Until the vendor-specific cert-chain verifier lands in this crate, the
honest verdict is `PendingCertChain`: checks 1-4 pass but check 5 is not
implemented. We refuse to call that **Attested** and refuse to call it
**Broken**; we name it for what it is. Reports with `PendingCertChain`
cannot land in the leaderboard.

## 4. What this repo refuses to do

- No "trust the vendor's own quote-verification service" shortcut. The
  verifier runs locally in this binary; a cert chain that only verifies
  against a vendor-run API is not a verified chain.
- No numbers in README or leaderboard that are not produced from a
  committed `results/*.json`.
- No sampling-based claims. Each audit is per-call; aggregate claims are
  explicit about N.
- No disclosure of a specific endpoint's break before the vendor has a
  reasonable disclosure window (90 days, standard). The repo publishes
  only the aggregate.

## 5. Threats to validity

- **Policy serving divergence.** The policy served over an HTTPS GET and
  the policy the enclave actually loaded can diverge; this is exactly
  what check 1 is for, but a vendor who serves two different policies to
  two different clients defeats a single audit.
- **Replay.** A quote collected from an honest call can be replayed to
  attest a dishonest call if the quote does not bind to a nonce. The
  pre-registered audit requires a client-chosen nonce in the quote's
  user-data region; without it the audit refuses.
- **Side channels.** attestchain measures byte-level chain of custody; it
  does not measure microarchitectural side channels, enclave speculation,
  or Rowhammer-class attacks. Those are out of scope.
