//! Model-free certificate-chain mutation benchmark over synthetic
//! three-link records (root, intermediate, leaf; not X.509). "Signatures"
//! are SHA-256 tags, so this tests chain-walking logic, not cryptography.

use crate::sha256_hex;
use crate::tamper::Rng;
use serde::Serialize;

#[derive(Clone, Debug)]
pub struct Cert {
    pub subject: String,
    pub key: String,
    pub issuer: String,
    pub issuer_key: String,
    pub sig: String,
}

fn sign(issuer_key: &str, subject: &str, key: &str) -> String {
    sha256_hex(format!("sig|{issuer_key}|{subject}|{key}").as_bytes())
}

fn cert(subject: &str, key: &str, issuer: &str, issuer_key: &str) -> Cert {
    Cert {
        subject: subject.into(),
        key: key.into(),
        issuer: issuer.into(),
        issuer_key: issuer_key.into(),
        sig: sign(issuer_key, subject, key),
    }
}

/// Order: leaf, intermediate, root. Returns the chain and the pinned root key.
pub fn build(rng: &mut Rng) -> (Vec<Cert>, String) {
    let mk = |rng: &mut Rng, role: &str| {
        let s = rng.next();
        (format!("{role}-{s:016x}"), sha256_hex(&rng.next().to_le_bytes()))
    };
    let (rn, rk) = mk(rng, "root");
    let (inn, ik) = mk(rng, "int");
    let (ln, lk) = mk(rng, "leaf");
    let chain = vec![cert(&ln, &lk, &inn, &ik), cert(&inn, &ik, &rn, &rk), cert(&rn, &rk, &rn, &rk)];
    (chain, rk)
}

/// Full verifier: exactly three links, each issuer matches the next
/// subject and key, every signature checks, leaf is not self-issued, the
/// last cert is self-signed and its key equals the pinned root.
pub fn verify_full(chain: &[Cert], pinned_root_key: &str) -> bool {
    if chain.len() != 3 {
        return false;
    }
    for (i, c) in chain.iter().enumerate() {
        if c.sig != sign(&c.issuer_key, &c.subject, &c.key) {
            return false;
        }
        if i + 1 < chain.len() {
            let n = &chain[i + 1];
            if c.issuer != n.subject || c.issuer_key != n.key || c.subject == c.issuer {
                return false;
            }
        }
    }
    let r = &chain[2];
    r.subject == r.issuer && r.key == r.issuer_key && r.key == pinned_root_key
}

/// Leaf-only comparator: checks the first cert's signature against the
/// issuer key that cert carries.
pub fn verify_leaf_only(chain: &[Cert], _pinned_root_key: &str) -> bool {
    chain.first().is_some_and(|c| c.sig == sign(&c.issuer_key, &c.subject, &c.key))
}

pub const MUTATIONS: [&str; 4] = ["swap_order", "missing_intermediate", "repeated_root", "self_signed_leaf"];

pub fn mutate(kind: &str, chain: &[Cert], rng: &mut Rng) -> Vec<Cert> {
    let mut c = chain.to_vec();
    match kind {
        "swap_order" => c.swap(0, 1),
        "missing_intermediate" => {
            c.remove(1);
        }
        "repeated_root" => c.push(chain[2].clone()),
        "self_signed_leaf" => {
            let key = sha256_hex(&rng.next().to_le_bytes());
            let name = chain[0].subject.clone();
            c[0] = cert(&name, &key, &name, &key);
        }
        _ => unreachable!(),
    }
    c
}

#[derive(Serialize, Debug, PartialEq)]
pub struct Rates {
    pub trials: usize,
    pub full_detection_rate: f64,
    pub leaf_only_detection_rate: f64,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct Report {
    pub chains: usize,
    pub seed: u64,
    pub chain_mutation: ChainMutation,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct ChainMutation {
    pub swap_order: Rates,
    pub missing_intermediate: Rates,
    pub repeated_root: Rates,
    pub self_signed_leaf: Rates,
    pub missing_intermediate_detection_rate: f64,
    pub leaf_only_missing_intermediate_detection_rate: f64,
    pub full_false_reject_rate: f64,
    pub leaf_only_false_reject_rate: f64,
}

pub fn run(seed: u64, chains: usize) -> Report {
    let mut rng = Rng::new(seed);
    let mut counts = [[0usize; 2]; 4];
    let (mut fr_full, mut fr_leaf) = (0usize, 0usize);
    for _ in 0..chains {
        let (chain, root) = build(&mut rng);
        if !verify_full(&chain, &root) {
            fr_full += 1;
        }
        if !verify_leaf_only(&chain, &root) {
            fr_leaf += 1;
        }
        for (i, k) in MUTATIONS.iter().enumerate() {
            let m = mutate(k, &chain, &mut rng);
            if !verify_full(&m, &root) {
                counts[i][0] += 1;
            }
            if !verify_leaf_only(&m, &root) {
                counts[i][1] += 1;
            }
        }
    }
    let f = |n: usize| if chains == 0 { 0.0 } else { n as f64 / chains as f64 };
    let r = |i: usize| Rates { trials: chains, full_detection_rate: f(counts[i][0]), leaf_only_detection_rate: f(counts[i][1]) };
    Report {
        chains,
        seed,
        chain_mutation: ChainMutation {
            swap_order: r(0),
            missing_intermediate: r(1),
            repeated_root: r(2),
            self_signed_leaf: r(3),
            missing_intermediate_detection_rate: f(counts[1][0]),
            leaf_only_missing_intermediate_detection_rate: f(counts[1][1]),
            full_false_reject_rate: f(fr_full),
            leaf_only_false_reject_rate: f(fr_leaf),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_chain_passes_both() {
        let (c, root) = build(&mut Rng::new(1));
        assert!(verify_full(&c, &root) && verify_leaf_only(&c, &root));
    }

    #[test]
    fn full_verifier_rejects_every_mutation() {
        let mut rng = Rng::new(2);
        let (c, root) = build(&mut rng);
        for k in MUTATIONS {
            assert!(!verify_full(&mutate(k, &c, &mut rng), &root), "{k}");
        }
    }

    #[test]
    fn leaf_only_misses_missing_intermediate_and_self_signed() {
        let mut rng = Rng::new(3);
        let (c, root) = build(&mut rng);
        assert!(verify_leaf_only(&mutate("missing_intermediate", &c, &mut rng), &root));
        assert!(verify_leaf_only(&mutate("self_signed_leaf", &c, &mut rng), &root));
    }

    #[test]
    fn wrong_pinned_root_rejected() {
        let (c, _) = build(&mut Rng::new(4));
        assert!(!verify_full(&c, "00"));
    }

    #[test]
    fn run_is_deterministic() {
        assert_eq!(run(7, 20), run(7, 20));
        assert_eq!(run(7, 20).chain_mutation.missing_intermediate_detection_rate, 1.0);
    }
}
