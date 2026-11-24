//! Model-free tamper benchmark over synthetic SHA-256-linked record chains.
//!
//! Each record commits to its predecessor's hash, a sequence number, a
//! payload digest and a `not_after` collateral expiry. Link verification
//! alone cannot see a deleted suffix; an externally retained
//! (length, head-hash) checkpoint can.

use crate::sha256_hex;
use serde::Serialize;

#[derive(Clone, Debug)]
pub struct Record {
    pub seq: u64,
    pub prev: String,
    pub payload: String,
    pub not_after: u64,
    pub hash: String,
}

pub struct Checkpoint {
    pub len: usize,
    pub head: String,
}

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn record_hash(seq: u64, prev: &str, payload: &str, not_after: u64) -> String {
    sha256_hex(format!("{seq}|{prev}|{payload}|{not_after}").as_bytes())
}

/// splitmix64: deterministic, no dependency.
pub struct Rng(u64);
impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Collateral validity window: every record is valid until this tick.
pub const NOT_AFTER: u64 = 1_000;

pub fn build_chain(rng: &mut Rng, len: usize) -> Vec<Record> {
    let mut out: Vec<Record> = Vec::with_capacity(len);
    for i in 0..len {
        let prev = out.last().map(|r| r.hash.clone()).unwrap_or_else(|| GENESIS.to_string());
        let payload = sha256_hex(&rng.next().to_le_bytes());
        let hash = record_hash(i as u64, &prev, &payload, NOT_AFTER);
        out.push(Record { seq: i as u64, prev, payload, not_after: NOT_AFTER, hash });
    }
    out
}

pub fn checkpoint_of(chain: &[Record]) -> Checkpoint {
    Checkpoint {
        len: chain.len(),
        head: chain.last().map(|r| r.hash.clone()).unwrap_or_default(),
    }
}

/// Link verification: sequence, back-links and self-hashes, plus expiry
/// against the injected clock `now`. Optionally compares a checkpoint.
pub fn verify(chain: &[Record], now: u64, checkpoint: Option<&Checkpoint>) -> bool {
    let mut prev = GENESIS.to_string();
    for (i, r) in chain.iter().enumerate() {
        if r.seq != i as u64 || r.prev != prev || r.hash != record_hash(r.seq, &r.prev, &r.payload, r.not_after) {
            return false;
        }
        if now > r.not_after {
            return false;
        }
        prev = r.hash.clone();
    }
    if let Some(c) = checkpoint {
        if chain.len() != c.len || chain.last().map(|r| r.hash.as_str()).unwrap_or("") != c.head {
            return false;
        }
    }
    true
}

#[derive(Serialize, Default)]
pub struct Rates {
    pub trials: usize,
    pub detection_rate_link_only: f64,
    pub detection_rate_with_checkpoint: f64,
}

#[derive(Serialize)]
pub struct Tamper {
    pub bit_flip: Rates,
    pub reorder: Rates,
    pub suffix_truncation: Rates,
    pub suffix_truncation_detection_rate_with_checkpoint: f64,
    pub suffix_truncation_detection_rate_link_only: f64,
    pub expired_collateral: Rates,
    pub untampered_false_positive_rate_link_only: f64,
    pub untampered_false_positive_rate_with_checkpoint: f64,
}

#[derive(Serialize)]
pub struct Report {
    pub seed: u64,
    pub chains: usize,
    pub len: usize,
    pub tamper: Tamper,
}

fn rates(trials: usize, link_det: usize, cp_det: usize) -> Rates {
    let f = |d: usize| if trials == 0 { 0.0 } else { d as f64 / trials as f64 };
    Rates { trials, detection_rate_link_only: f(link_det), detection_rate_with_checkpoint: f(cp_det) }
}

pub fn run(seed: u64, chains: usize, len: usize) -> Report {
    assert!(len >= 6, "len must be at least 6");
    let mut rng = Rng::new(seed);
    let (mut fl, mut fc) = (0usize, 0usize);
    let mut cnt = [[0usize; 2]; 4];
    for _ in 0..chains {
        let base = build_chain(&mut rng, len);
        let cp = checkpoint_of(&base);
        if !verify(&base, 0, None) { fl += 1; }
        if !verify(&base, 0, Some(&cp)) { fc += 1; }

        let mut variants: Vec<Vec<Record>> = Vec::new();
        let mut now = [0u64; 4];
        // bit flip: flip one bit in one payload hex char (value change), hash left stale
        let mut c = base.clone();
        let i = rng.below(len as u64) as usize;
        let mut bytes = c[i].payload.clone().into_bytes();
        let j = rng.below(bytes.len() as u64) as usize;
        bytes[j] = if bytes[j] == b'0' { b'1' } else { b'0' };
        c[i].payload = String::from_utf8(bytes).unwrap();
        variants.push(c);
        // reorder: swap two distinct records
        let mut c = base.clone();
        let a = rng.below(len as u64) as usize;
        let b = (a + 1 + rng.below(len as u64 - 1) as usize) % len;
        c.swap(a, b);
        variants.push(c);
        // suffix truncation of 1..=4
        let k = 1 + rng.below(4) as usize;
        variants.push(base[..len - k].to_vec());
        // expired collateral: clock past not_after, chain otherwise intact
        variants.push(base.clone());
        now[3] = NOT_AFTER + 1 + rng.below(100);
        for (t, v) in variants.iter().enumerate() {
            if !verify(v, now[t], None) { cnt[t][0] += 1; }
            if !verify(v, now[t], Some(&cp)) { cnt[t][1] += 1; }
        }
    }
    let fr = |t: usize| rates(chains, cnt[t][0], cnt[t][1]);
    let d = |x: usize| if chains == 0 { 0.0 } else { x as f64 / chains as f64 };
    Report {
        seed,
        chains,
        len,
        tamper: Tamper {
            bit_flip: fr(0),
            reorder: fr(1),
            suffix_truncation: fr(2),
            suffix_truncation_detection_rate_with_checkpoint: fr(2).detection_rate_with_checkpoint,
            suffix_truncation_detection_rate_link_only: fr(2).detection_rate_link_only,
            expired_collateral: fr(3),
            untampered_false_positive_rate_link_only: d(fl),
            untampered_false_positive_rate_with_checkpoint: d(fc),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_invisible_without_checkpoint() {
        let mut rng = Rng::new(1);
        let c = build_chain(&mut rng, 8);
        let cp = checkpoint_of(&c);
        let t = &c[..5];
        assert!(verify(t, 0, None));
        assert!(!verify(t, 0, Some(&cp)));
    }

    #[test]
    fn intact_chain_passes_both() {
        let mut rng = Rng::new(2);
        let c = build_chain(&mut rng, 8);
        let cp = checkpoint_of(&c);
        assert!(verify(&c, 0, Some(&cp)));
        assert!(!verify(&c, NOT_AFTER + 1, None));
    }

    #[test]
    fn run_is_deterministic_and_matches_hypothesis() {
        let a = serde_json::to_string(&run(7, 30, 16)).unwrap();
        let b = serde_json::to_string(&run(7, 30, 16)).unwrap();
        assert_eq!(a, b);
        let r = run(7, 30, 16);
        assert_eq!(r.tamper.suffix_truncation.detection_rate_link_only, 0.0);
        assert_eq!(r.tamper.suffix_truncation.detection_rate_with_checkpoint, 1.0);
        assert_eq!(r.tamper.bit_flip.detection_rate_link_only, 1.0);
        assert_eq!(r.tamper.reorder.detection_rate_link_only, 1.0);
        assert_eq!(r.tamper.expired_collateral.detection_rate_link_only, 1.0);
    }
}
