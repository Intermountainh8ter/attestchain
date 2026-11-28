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

## 2026-11-27T06:09:40Z logcost-compact proposal:d6d6ec315bdf1dd9237fa995daa6b14a26d55ac9e2e606976905a2b5cdd55b7c

Hypothesis: on seeded synthetic logs of 64, 128, ..., 8192 records, counting SHA-256
invocations (not wall time) and averaging over 50 seeded random record positions per
length, Merkle inclusion verification against a checkpoint costs exactly 1 more hash per
doubling of log length (mean increment within 0.01 of 1.0), while verifying a random
record's inclusion in a hash-linked chain against the head checkpoint costs a factor of at
least 1.8 more hashes per doubling; chain append costs exactly 1 hash per record.

Pre-registered metric: `/sweep/merkle_inclusion_hashes_per_doubling`.
Expected: equals 1.0 (within 0.01); mean chain inclusion cost ratio per doubling at least 1.8.

Falsifier: Merkle increment outside 0.99 to 1.01, chain ratio below 1.8, or chain append
cost differing from 1 hash per record.

Command: `cargo run --locked -q --release -- logcost --seed 7 --out results/631-logcost-compact.json`

## 2026-11-27T22:05:39Z tamperclass proposal:492af635adaedfe7ecf81f806e92d470b3d9cc08aa73d0d6e7d925aaa057c5d7

Hypothesis: on 200 seeded synthetic hash chains of length 16, a link-only verifier detects
exactly 6 of 8 tamper classes at rate 1.0 (tail truncation and prefix rewrite with recomputed
downstream hashes are missed at rate 0.0), a verifier that also compares an external
(length, head-hash) checkpoint detects all 8 at rate 1.0, the always-accept baseline detects 0,
and no untampered chain is rejected.

Pre-registered metric: `/detection/chain_only_classes_detected`.
Expected: chain-only verifier detects exactly 6 classes; checkpoint verifier detects 8.

Falsifier: chain_only_classes_detected differs from 6, checkpoint classes detected below 8, or
any untampered chain rejected.

Command: `cargo run --locked -q --release -- classbench --seed 7 --chains 200 --len 16 --out results/721-tamperclass.json`

## 2026-11-27T22:12:12Z canonbench proposal:322aed5ace1ba3837d5b82648fa76ee1a660d03021c48853e87cb4faa4db66ea

Hypothesis: on 200 seeded synthetic chains of length 16 whose JSON records are semantically
unchanged but re-serialised (key order, whitespace, unicode escapes, number formatting), a
verifier that hashes the received bytes reports a false tamper on every chain for each of the
four variations (rate 1.0), a verifier that canonicalises (sorted keys, minimal whitespace,
normalised numbers and escapes) before hashing reports 0.0, and the canonicalising verifier
still detects a real one-bit content flip at rate 1.0.

Pre-registered metric: `/false_tamper_rate_by_variation/naive_key_order`.
Expected: 1.0 for the naive verifier under key reordering; canonicalising verifier 0.0 on all
four variations.

Falsifier: naive rate below 1.0 for any variation, canonicalising false-tamper rate above 0.0,
or real content flip detected below rate 1.0.

Command: `cargo run --locked -q --release -- canonbench --seed 7 --chains 200 --len 16 --out results/723-canonbench.json`

## 2026-11-28T00:40:00Z truncsweep proposal:d3bff0eb74efd970cbbc5d7cc5617da290d415bab2ebc54dd68855812e4dee5f

Hypothesis: with logs of 64 records, uniformly random truncation to 1..63 records, and a
checkpoint every 8 records, the measured undetected-truncation share equals the analytic share
(cuts landing at or after the last checkpoint length) to within 0.02 absolute, is above 0 for
every period greater than 1, and is exactly 0.0 at period 1.

Model fixed before running: checkpoints are (length, head-hash) pairs taken at lengths
period, 2*period, ... strictly below the log length (the newest tail has no checkpoint yet);
the verifier compares the truncated log with the latest one. A cut to length L is undetected
iff L >= last checkpoint length. At period 8 the last checkpoint is at 56, so 8 of 63 cut
lengths (56..63) are undetected, 0.127; the proposal text said 7 of 63 and that is
the point of tension: the analytic share computed in code is the reference. At period 1 the
last checkpoint is at 63, so one cut length (63) is undetected, and the "exactly 0.0 at
period 1" clause is expected to fail under this model.

Pre-registered metric: `/truncation_sweep/undetected_share_by_period/8`.
Expected: about 0.11 to 0.13 (expected_range 0.09 to 0.13).

Falsifier: measured share at period 8 differs from the analytic share by more than 0.02, or any
truncation shorter than the last checkpoint length goes undetected, or period 1 yields a nonzero
share.

Command: `cargo run --locked -q --release -- truncsweep --seed 7 --chains 2000 --len 64 --out results/756-truncsweep.json`
