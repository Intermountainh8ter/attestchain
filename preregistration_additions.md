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
