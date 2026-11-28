//! Model-free outage sweep: each checkpoint publication is missed with
//! probability q; share of suffix truncations then left undetected.

use crate::tamper::{build_chain, checkpoint_of, Rng};
use serde_json::{json, Map, Value};

pub const MISS_RATES: [f64; 6] = [0.0, 0.1, 0.25, 0.5, 0.75, 0.9];

/// Checkpoint lengths strictly below `len`: period, 2*period, ...
pub fn checkpoint_lens(len: usize, period: usize) -> Vec<usize> {
    (1..).map(|i| i * period).take_while(|&l| l < len).collect()
}

/// Mean over cuts 1..len-1 of q^m(L), m(L) = checkpoints longer than L.
pub fn analytic_share(len: usize, period: usize, q: f64) -> f64 {
    let cps = checkpoint_lens(len, period);
    let total: f64 = (1..len)
        .map(|l| q.powi(cps.iter().filter(|&&c| c > l).count() as i32))
        .sum();
    total / (len - 1) as f64
}

fn unit(rng: &mut Rng) -> f64 {
    (rng.next() >> 11) as f64 / (1u64 << 53) as f64
}

pub fn run(seed: u64, chains: usize, len: usize, period: usize) -> Value {
    let mut rng = Rng::new(seed);
    let cps = checkpoint_lens(len, period);
    let logs: Vec<_> = (0..chains).map(|_| build_chain(&mut rng, len)).collect();
    let cuts: Vec<usize> = (0..chains).map(|_| 1 + rng.below((len - 1) as u64) as usize).collect();
    // one uniform draw per (chain, checkpoint); a checkpoint is missed iff draw < q
    let draws: Vec<Vec<f64>> = (0..chains).map(|_| cps.iter().map(|_| unit(&mut rng)).collect()).collect();
    let (mut share, mut analytic, mut median, mut early) =
        (Map::new(), Map::new(), Map::new(), Map::new());
    for q in MISS_RATES {
        let (mut und, mut early_n) = (0usize, 0usize);
        let mut lens = Vec::new();
        for ((log, &cut), d) in logs.iter().zip(&cuts).zip(&draws) {
            let last = cps.iter().zip(d).filter(|(_, &u)| u >= q).map(|(&c, _)| c).max();
            let accepted = match last {
                None => true,
                Some(c) => cut >= c && checkpoint_of(&log[..c]).head == log[c - 1].hash,
            };
            if accepted {
                und += 1;
                lens.push(len - cut);
                if last.is_some_and(|c| cut < c) {
                    early_n += 1;
                }
            }
        }
        lens.sort();
        let med = if lens.is_empty() { Value::Null } else { json!(lens[lens.len() / 2]) };
        let k = q.to_string();
        share.insert(k.clone(), json!(und as f64 / chains as f64));
        analytic.insert(k.clone(), json!(analytic_share(len, period, q)));
        median.insert(k.clone(), med);
        early.insert(k, json!(early_n));
    }
    json!({
        "seed": seed, "chains": chains, "len": len, "period": period,
        "outage_sweep": {
            "undetected_share_by_miss_rate": Value::Object(share),
            "analytic_share_by_miss_rate": Value::Object(analytic),
            "median_undetected_suffix_len_by_miss_rate": Value::Object(median),
            "undetected_before_last_published_count_by_miss_rate": Value::Object(early),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn analytic_matches_no_outage_and_grows() {
        assert!((analytic_share(64, 8, 0.0) - 8.0 / 63.0).abs() < 1e-12);
        assert!(analytic_share(64, 8, 0.5) > analytic_share(64, 8, 0.25));
        assert!((analytic_share(64, 8, 1.0) - 1.0).abs() < 1e-12);
    }
    #[test]
    fn deterministic_and_no_early_miss() {
        let a = run(7, 100, 64, 8);
        assert_eq!(a, run(7, 100, 64, 8));
        let e = &a["outage_sweep"]["undetected_before_last_published_count_by_miss_rate"];
        for q in MISS_RATES {
            assert_eq!(e[q.to_string()], 0);
        }
    }
}
