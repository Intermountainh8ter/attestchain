//! Per-class tamper detection over synthetic SHA-256 hash chains.
//!
//! Eight named tamper classes, three verifiers: link-only, link plus an
//! external (length, head-hash) checkpoint, and an always-accept baseline.

use crate::tamper::{build_chain, checkpoint_of, record_hash, verify, Record, Rng, NOT_AFTER};
use serde::Serialize;

pub const CLASSES: [&str; 8] = [
    "bit_flip",
    "reorder",
    "tail_truncation",
    "prefix_rewrite_rehashed",
    "mid_deletion",
    "duplicate_record",
    "prev_link_splice",
    "expired_collateral",
];

#[derive(Serialize)]
pub struct ClassRates {
    pub class: &'static str,
    pub trials: usize,
    pub chain_only: f64,
    pub with_checkpoint: f64,
    pub always_accept: f64,
}

#[derive(Serialize)]
pub struct Detection {
    pub classes: Vec<ClassRates>,
    pub chain_only_classes_detected: usize,
    pub checkpoint_classes_detected: usize,
    pub always_accept_classes_detected: usize,
    pub untampered_false_positive_rate_chain_only: f64,
    pub untampered_false_positive_rate_with_checkpoint: f64,
}

#[derive(Serialize)]
pub struct Report {
    pub seed: u64,
    pub chains: usize,
    pub len: usize,
    pub detection: Detection,
}

/// Returns (tampered chain, clock) for class `t`.
fn tamper(base: &[Record], t: usize, rng: &mut Rng) -> (Vec<Record>, u64) {
    let len = base.len();
    let mut c = base.to_vec();
    let mut now = 0;
    match t {
        0 => {
            let i = rng.below(len as u64) as usize;
            let mut b = c[i].payload.clone().into_bytes();
            let j = rng.below(b.len() as u64) as usize;
            b[j] = if b[j] == b'0' { b'1' } else { b'0' };
            c[i].payload = String::from_utf8(b).unwrap();
        }
        1 => {
            let a = rng.below(len as u64) as usize;
            let b = (a + 1 + rng.below(len as u64 - 1) as usize) % len;
            c.swap(a, b);
        }
        2 => c.truncate(len - 1 - rng.below(4) as usize),
        3 => {
            let i = rng.below(len as u64 / 2) as usize;
            c[i].payload = crate::sha256_hex(&rng.next().to_le_bytes());
            for k in i..len {
                if k > i {
                    c[k].prev = c[k - 1].hash.clone();
                }
                c[k].hash = record_hash(c[k].seq, &c[k].prev, &c[k].payload, c[k].not_after);
            }
        }
        4 => {
            let i = 1 + rng.below(len as u64 - 2) as usize;
            c.remove(i);
        }
        5 => {
            let i = rng.below(len as u64) as usize;
            let r = c[i].clone();
            c.insert(i, r);
        }
        6 => {
            let i = 1 + rng.below(len as u64 - 1) as usize;
            let j = (i - 1 + 1 + rng.below(len as u64 - 1) as usize) % len;
            c[i].prev = base[j].hash.clone();
            if c[i].prev == base[i - 1].hash {
                c[i].prev = "f".repeat(64);
            }
        }
        _ => now = NOT_AFTER + 1 + rng.below(100),
    }
    (c, now)
}

pub fn run(seed: u64, chains: usize, len: usize) -> Report {
    assert!(len >= 6, "len must be at least 6");
    let mut rng = Rng::new(seed);
    let mut det = [[0usize; 2]; 8];
    let (mut fl, mut fc) = (0usize, 0usize);
    for _ in 0..chains {
        let base = build_chain(&mut rng, len);
        let cp = checkpoint_of(&base);
        if !verify(&base, 0, None) { fl += 1; }
        if !verify(&base, 0, Some(&cp)) { fc += 1; }
        for t in 0..8 {
            let (c, now) = tamper(&base, t, &mut rng);
            if !verify(&c, now, None) { det[t][0] += 1; }
            if !verify(&c, now, Some(&cp)) { det[t][1] += 1; }
        }
    }
    let f = |x: usize| if chains == 0 { 0.0 } else { x as f64 / chains as f64 };
    let classes: Vec<ClassRates> = (0..8)
        .map(|t| ClassRates {
            class: CLASSES[t],
            trials: chains,
            chain_only: f(det[t][0]),
            with_checkpoint: f(det[t][1]),
            always_accept: 0.0,
        })
        .collect();
    let full = |g: &dyn Fn(&ClassRates) -> f64| classes.iter().filter(|c| g(c) >= 1.0).count();
    Report {
        seed,
        chains,
        len,
        detection: Detection {
            chain_only_classes_detected: full(&|c| c.chain_only),
            checkpoint_classes_detected: full(&|c| c.with_checkpoint),
            always_accept_classes_detected: full(&|c| c.always_accept),
            untampered_false_positive_rate_chain_only: f(fl),
            untampered_false_positive_rate_with_checkpoint: f(fc),
            classes,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_matches_hypothesis() {
        let a = serde_json::to_string(&run(7, 30, 16)).unwrap();
        assert_eq!(a, serde_json::to_string(&run(7, 30, 16)).unwrap());
        let r = run(7, 30, 16).detection;
        assert_eq!(r.chain_only_classes_detected, 6);
        assert_eq!(r.checkpoint_classes_detected, 8);
        assert_eq!(r.always_accept_classes_detected, 0);
        assert_eq!(r.untampered_false_positive_rate_chain_only, 0.0);
        assert_eq!(r.classes[2].chain_only, 0.0);
        assert_eq!(r.classes[3].chain_only, 0.0);
    }
}
