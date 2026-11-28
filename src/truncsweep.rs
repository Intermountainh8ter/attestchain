//! Model-free truncation sweep: share of suffix truncations that a
//! (length, head-hash) checkpoint taken every `period` records fails to catch.

use crate::tamper::{build_chain, checkpoint_of, verify, Rng};
use serde_json::{json, Map, Value};

pub const PERIODS: [usize; 6] = [1, 2, 4, 8, 16, 32];

/// Length of the latest checkpoint strictly below `len`.
pub fn last_checkpoint_len(len: usize, period: usize) -> usize {
    ((len - 1) / period) * period
}

/// Analytic undetected share over cut lengths 1..len-1: cuts at or past the checkpoint.
pub fn analytic_share(len: usize, period: usize) -> f64 {
    let c = last_checkpoint_len(len, period).max(1);
    (len - c) as f64 / (len - 1) as f64
}

pub fn run(seed: u64, chains: usize, len: usize) -> Value {
    let mut rng = Rng::new(seed);
    let mut measured = Map::new();
    let mut analytic = Map::new();
    let mut early_misses = Map::new();
    let mut untampered_rejects = 0usize;
    let logs: Vec<_> = (0..chains).map(|_| build_chain(&mut rng, len)).collect();
    let cuts: Vec<usize> = (0..chains).map(|_| 1 + rng.below((len - 1) as u64) as usize).collect();
    for p in PERIODS {
        let (mut und, mut early) = (0usize, 0usize);
        for (log, &cut) in logs.iter().zip(&cuts) {
            let c = last_checkpoint_len(len, p);
            // the checkpoint of the prefix at length c (none if c == 0)
            let cp = if c == 0 { None } else { Some(checkpoint_of(&log[..c])) };
            let prefix_ok = cp.as_ref().map_or(true, |k| log[k.len - 1].hash == k.head);
            if !verify(log, 0, None) || !prefix_ok {
                untampered_rejects += 1;
            }
            // A truncated log passes the checkpoint iff it still contains the checkpointed prefix.
            let accepted = match &cp {
                None => true,
                Some(k) => cut >= k.len && checkpoint_of(&log[..k.len]).head == k.head,
            };
            if accepted {
                und += 1;
                if cut < c {
                    early += 1;
                }
            }
        }
        measured.insert(p.to_string(), json!(und as f64 / chains as f64));
        analytic.insert(p.to_string(), json!(analytic_share(len, p)));
        early_misses.insert(p.to_string(), json!(early));
    }
    json!({
        "seed": seed, "chains": chains, "len": len,
        "truncation_sweep": {
            "undetected_share_by_period": Value::Object(measured),
            "analytic_share_by_period": Value::Object(analytic),
            "undetected_before_last_checkpoint_count_by_period": Value::Object(early_misses),
            "untampered_full_log_rejections": untampered_rejects,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn analytic_values() {
        assert_eq!(last_checkpoint_len(64, 8), 56);
        assert!((analytic_share(64, 8) - 8.0 / 63.0).abs() < 1e-12);
        assert!((analytic_share(64, 1) - 1.0 / 63.0).abs() < 1e-12);
    }
    #[test]
    fn deterministic_and_no_early_miss() {
        let a = run(7, 100, 64);
        assert_eq!(a, run(7, 100, 64));
        let e = &a["truncation_sweep"]["undetected_before_last_checkpoint_count_by_period"];
        for p in PERIODS {
            assert_eq!(e[p.to_string()], 0);
        }
        assert_eq!(a["truncation_sweep"]["untampered_full_log_rejections"], 0);
    }
}
