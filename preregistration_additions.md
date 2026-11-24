# Pre-registration additions

## 2026-11-24T12:49:00Z tamper-checkpoint proposal:011f0bca934b980ffccc9c2e0c7ed946088360d8315a3a1a8cfa38ec41a7b3e9

Hypothesis: on a seeded synthetic set of SHA-256-linked attestation-record
chains (no vendor data), suffix truncation of 1 to 4 records is detected in
0 of trials by chain-link verification alone and in all trials once an
external (length, head-hash) checkpoint is compared, while bit flips,
reorders and injected-clock expiry are detected in all trials by both modes.

Pre-registered metric: `/tamper/suffix_truncation_detection_rate_with_checkpoint`.
Expected: equals 1.0 with checkpoint and 0.0 without.

Falsifier: any truncated chain accepted when a checkpoint is supplied, or any
truncated chain rejected by link verification alone.

Command: `cargo run --locked -q --release -- tamperbench --seed 7 --chains 200 --len 16 --out results/592-tamper-checkpoint.json`

## 2026-11-24T12:57:51Z chain-mutation proposal:3d5f4e958881a0c833549bcf0ee7deac0ee94de5763f4901be5da46805f9383e

Hypothesis: on seeded synthetic three-link hash-linked certificate-chain records
(root, intermediate, leaf; not X.509, no vendor data), a verifier that checks each
link's issuer name and key and terminates at a pinned root detects four mutations
(swap order, missing intermediate, repeated root, self-signed leaf) at rate 1.0 with
no false rejects, while a leaf-only verifier that checks just the leaf's signature
against the issuer key the leaf itself carries detects missing-intermediate and
self-signed-leaf at a rate below 0.5 each.

Pre-registered metric: `/chain_mutation/missing_intermediate_detection_rate`.
Expected: full verifier equals 1.0; leaf-only comparator at most 0.5.

Falsifier: any mutation where the full verifier's detection rate is below 1.0, or an
untampered chain rejected (false-reject rate above 0.0).

Command: `cargo run --locked -q --release -- chainbench --seed 7 --chains 200 --out results/595-chain-mutation.json`
