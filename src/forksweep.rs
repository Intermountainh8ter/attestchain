//! Model-free fork sweep: a writer serves two divergent histories; readers
//! detect the fork only by gossiping branch heads.

use crate::tamper::{record_hash, verify, build_chain, Record, Rng, NOT_AFTER};
use serde_json::{json, Map, Value};

pub const READERS: [usize; 4] = [2, 4, 8, 16];

fn unit(rng: &mut Rng) -> f64 {
    (rng.next() >> 11) as f64 / (1u64 << 53) as f64
}

/// Two valid histories sharing `shared` records, then diverging up to `len`.
pub fn fork_pair(rng: &mut Rng, len: usize, shared: usize) -> (Vec<Record>, Vec<Record>) {
    let a = build_chain(rng, len);
    let mut b: Vec<Record> = a[..shared].to_vec();
    for i in shared..len {
        let prev = b.last().map(|r| r.hash.clone()).unwrap();
        let payload = crate::sha256_hex(&rng.next().to_le_bytes());
        let hash = record_hash(i as u64, &prev, &payload, NOT_AFTER);
        b.push(Record { seq: i as u64, prev, payload, not_after: NOT_AFTER, hash });
    }
    (a, b)
}

fn binom(n: usize, k: usize) -> f64 {
    (0..k).fold(1.0, |acc, i| acc * (n - i) as f64 / (i + 1) as f64)
}

/// Exact detected share after `rounds`, readers split uniformly at random.
pub fn analytic_share(r: usize, rounds: usize, p: f64) -> f64 {
    let mut total = 0.0;
    for a in 1..r {
        let b = r - a;
        let pa = binom(r, a) / 2f64.powi(r as i32);
        let miss = (1.0 - p * b as f64 / (r - 1) as f64).powi(a as i32)
            * (1.0 - p * a as f64 / (r - 1) as f64).powi(b as i32);
        total += pa * (1.0 - miss.powi(rounds as i32));
    }
    total
}

/// Limit share: everything except the all-one-branch assignment.
pub fn limit_share(r: usize) -> f64 {
    1.0 - 2f64.powi(1 - r as i32)
}

pub fn run(seed: u64, trials: usize, rounds: usize, gossip: f64) -> Value {
    let mut rng = Rng::new(seed);
    let (mut share, mut limit, mut exact, mut median, mut single) =
        (Map::new(), Map::new(), Map::new(), Map::new(), Map::new());
    let mut single_total = 0usize;
    for r in READERS {
        let mut detected = 0usize;
        let mut rounds_seen: Vec<usize> = Vec::new();
        let mut single_hits = 0usize;
        for _ in 0..trials {
            let (a, b) = fork_pair(&mut rng, 8, 4);
            // single-log verification of each branch (no cross-reader information)
            if !verify(&a, 0, None) || !verify(&b, 0, None) {
                single_hits += 1;
            }
            let heads = [a.last().unwrap().hash.clone(), b.last().unwrap().hash.clone()];
            let branch: Vec<usize> = (0..r).map(|_| rng.below(2) as usize).collect();
            for round in 1..=rounds {
                let mut hit = false;
                for i in 0..r {
                    if unit(&mut rng) < gossip {
                        let mut j = rng.below((r - 1) as u64) as usize;
                        if j >= i {
                            j += 1;
                        }
                        if heads[branch[i]] != heads[branch[j]] {
                            hit = true;
                        }
                    }
                }
                if hit {
                    detected += 1;
                    rounds_seen.push(round);
                    break;
                }
            }
        }
        rounds_seen.sort();
        let med = if rounds_seen.is_empty() { Value::Null } else { json!(rounds_seen[rounds_seen.len() / 2]) };
        let k = r.to_string();
        share.insert(k.clone(), json!(detected as f64 / trials as f64));
        limit.insert(k.clone(), json!(limit_share(r)));
        exact.insert(k.clone(), json!(analytic_share(r, rounds, gossip)));
        median.insert(k.clone(), med);
        single.insert(k, json!(single_hits));
        single_total += single_hits;
    }
    json!({
        "seed": seed, "trials": trials, "rounds": rounds, "gossip": gossip,
        "fork_sweep": {
            "detected_share_by_readers": Value::Object(share),
            "analytic_limit_share_by_readers": Value::Object(limit),
            "analytic_exact_share_by_readers": Value::Object(exact),
            "median_detection_round_by_readers": Value::Object(median),
            "single_log_detected_count_by_readers": Value::Object(single),
            "single_log_detected_total": single_total,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fork_branches_valid_and_distinct() {
        let mut rng = Rng::new(1);
        let (a, b) = fork_pair(&mut rng, 8, 4);
        assert!(verify(&a, 0, None) && verify(&b, 0, None));
        assert_eq!(a[3].hash, b[3].hash);
        assert_ne!(a[7].hash, b[7].hash);
    }
    #[test]
    fn analytic_bounded_by_limit() {
        for r in READERS {
            assert!(analytic_share(r, 100, 0.1) <= limit_share(r) + 1e-12);
        }
        assert!((limit_share(2) - 0.5).abs() < 1e-12);
    }
    #[test]
    fn deterministic_and_single_log_blind() {
        let a = run(7, 50, 100, 0.1);
        assert_eq!(a, run(7, 50, 100, 0.1));
        assert_eq!(a["fork_sweep"]["single_log_detected_total"], 0);
    }
}
