//! Model-free hash-count comparison: Merkle inclusion proof vs hash-linked
//! chain replay, over doubling log lengths. Counts SHA-256 calls.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

struct Counter(u64);

impl Counter {
    fn h(&mut self, parts: &[&[u8]]) -> [u8; 32] {
        self.0 += 1;
        let mut s = Sha256::new();
        for p in parts {
            s.update(p);
        }
        s.finalize().into()
    }
}

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Merkle levels over leaf hashes (length is a power of two here).
fn levels(c: &mut Counter, leaves: Vec<[u8; 32]>) -> Vec<Vec<[u8; 32]>> {
    let mut out = vec![leaves];
    while out.last().unwrap().len() > 1 {
        let prev = out.last().unwrap().clone();
        out.push(prev.chunks(2).map(|p| c.h(&[&p[0], &p[1]])).collect());
    }
    out
}

/// Verify inclusion of record `rec` at `idx` against `root`; returns validity.
fn merkle_verify(c: &mut Counter, rec: &[u8], mut idx: usize, lv: &[Vec<[u8; 32]>], root: &[u8; 32]) -> bool {
    let mut cur = c.h(&[rec]);
    for level in &lv[..lv.len() - 1] {
        let sib = level[idx ^ 1];
        cur = if idx % 2 == 0 { c.h(&[&cur, &sib]) } else { c.h(&[&sib, &cur]) };
        idx /= 2;
    }
    &cur == root
}

pub fn run(seed: u64) -> Value {
    let mut st = seed;
    let mut rows = vec![];
    let mut merkle_means = vec![];
    let mut chain_means = vec![];
    let mut append_ok = true;
    let mut all_valid = true;
    let mut n = 64usize;
    while n <= 8192 {
        let recs: Vec<[u8; 8]> = (0..n).map(|_| splitmix(&mut st).to_le_bytes()).collect();
        let mut c = Counter(0);
        let mut links = vec![[0u8; 32]];
        for r in &recs {
            let prev = *links.last().unwrap();
            links.push(c.h(&[&prev, r]));
        }
        append_ok &= c.0 == n as u64;
        let head = *links.last().unwrap();
        let leaves: Vec<_> = recs.iter().map(|r| c.h(&[r])).collect();
        let lv = levels(&mut c, leaves);
        let root = lv.last().unwrap()[0];
        let (mut m_tot, mut c_tot) = (0u64, 0u64);
        for _ in 0..50 {
            let i = (splitmix(&mut st) % n as u64) as usize;
            let mut mc = Counter(0);
            all_valid &= merkle_verify(&mut mc, &recs[i], i, &lv, &root);
            m_tot += mc.0;
            let mut cc = Counter(0);
            let mut cur = links[i];
            for r in &recs[i..] {
                cur = cc.h(&[&cur, r]);
            }
            all_valid &= cur == head;
            c_tot += cc.0;
        }
        let (mm, cm) = (m_tot as f64 / 50.0, c_tot as f64 / 50.0);
        merkle_means.push(mm);
        chain_means.push(cm);
        rows.push(json!({"len": n, "merkle_inclusion_hashes_mean": mm, "chain_inclusion_hashes_mean": cm}));
        n *= 2;
    }
    let d = merkle_means.len() - 1;
    let m_inc = (merkle_means[d] - merkle_means[0]) / d as f64;
    let ratios: Vec<f64> = chain_means.windows(2).map(|w| w[1] / w[0]).collect();
    let mean_ratio = ratios.iter().sum::<f64>() / ratios.len() as f64;
    json!({"sweep": {
        "rows": rows,
        "merkle_inclusion_hashes_per_doubling": m_inc,
        "chain_inclusion_cost_ratio_per_doubling": ratios,
        "chain_inclusion_cost_ratio_mean": mean_ratio,
        "chain_inclusion_cost_ratio_min": ratios.iter().cloned().fold(f64::MAX, f64::min),
        "chain_append_one_hash_per_record": append_ok,
        "all_proofs_valid": all_valid,
    }})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_grows_by_one_per_doubling() {
        let v = run(7);
        assert!((v["sweep"]["merkle_inclusion_hashes_per_doubling"].as_f64().unwrap() - 1.0).abs() < 1e-9);
        assert_eq!(v["sweep"]["chain_append_one_hash_per_record"], true);
        assert_eq!(v["sweep"]["all_proofs_valid"], true);
    }

    #[test]
    fn deterministic() {
        assert_eq!(run(3), run(3));
    }
}
