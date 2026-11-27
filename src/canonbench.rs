//! False-tamper rates of a raw-bytes verifier versus a canonicalising verifier
//! over synthetic hash-chained JSON records that are re-serialised in
//! semantically neutral ways. The canonical form here is a minimal subset of
//! RFC 8785 (sorted keys, no whitespace, raw UTF-8, shortest float); it is not
//! a full JCS implementation.

use crate::sha256_hex;
use crate::tamper::Rng;
use serde::Serialize;
use serde_json::Value;

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const NOTES: [&str; 4] = ["caf\u{e9} order", "na\u{ef}ve ok", "\u{fc}ber check", "r\u{e9}sum\u{e9} 7"];

/// One record's fields; serialised by hand so each variation is explicit.
#[derive(Clone)]
struct Rec {
    seq: u64,
    score: f64,
    note: String,
}

#[derive(Clone, Copy)]
enum Var {
    Canonical,
    KeyOrder,
    Whitespace,
    UnicodeEscape,
    NumberFormat,
}

fn esc(s: &str, ascii: bool) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        if ascii && !c.is_ascii() {
            o.push_str(&format!("\\u{:04x}", c as u32));
        } else {
            o.push(c);
        }
    }
    o.push('"');
    o
}

fn ser(r: &Rec, v: Var) -> String {
    let score = match v {
        Var::NumberFormat => format!("{}0", r.score),
        _ => format!("{}", r.score),
    };
    let mut fields = vec![
        ("note", esc(&r.note, matches!(v, Var::UnicodeEscape))),
        ("score", score),
        ("seq", r.seq.to_string()),
    ];
    if matches!(v, Var::KeyOrder) {
        fields.reverse();
    }
    let (sep, kv) = if matches!(v, Var::Whitespace) { (",\n  ", ": ") } else { (",", ":") };
    let body: Vec<String> = fields.iter().map(|(k, x)| format!("\"{k}\"{kv}{x}")).collect();
    if matches!(v, Var::Whitespace) {
        format!("{{\n  {}\n}}", body.join(sep))
    } else {
        format!("{{{}}}", body.join(sep))
    }
}

/// Parse and re-emit in the producer's canonical form.
fn canonicalise(bytes: &str) -> Option<String> {
    let v: Value = serde_json::from_str(bytes).ok()?;
    // serde_json without preserve_order keeps keys sorted and emits no whitespace.
    serde_json::to_string(&v).ok()
}

fn link(prev: &str, body: &str) -> String {
    sha256_hex(format!("{prev}|{body}").as_bytes())
}

/// Verify `bodies` against the producer's hashes. `canon` selects the verifier.
fn verify(bodies: &[String], hashes: &[String], canon: bool) -> bool {
    let mut prev = GENESIS.to_string();
    for (b, h) in bodies.iter().zip(hashes) {
        let used = if canon {
            match canonicalise(b) {
                Some(c) => c,
                None => return false,
            }
        } else {
            b.clone()
        };
        if link(&prev, &used) != *h {
            return false;
        }
        prev = h.clone();
    }
    true
}

#[derive(Serialize)]
pub struct Rates {
    pub naive_key_order: f64,
    pub naive_whitespace: f64,
    pub naive_unicode_escape: f64,
    pub naive_number_format: f64,
    pub canonical_key_order: f64,
    pub canonical_whitespace: f64,
    pub canonical_unicode_escape: f64,
    pub canonical_number_format: f64,
    pub naive_unvaried_control: f64,
    pub canonical_unvaried_control: f64,
}

#[derive(Serialize)]
pub struct Report {
    pub seed: u64,
    pub chains: usize,
    pub len: usize,
    pub false_tamper_rate_by_variation: Rates,
    pub real_flip_detection_rate_canonical: f64,
    pub real_flip_detection_rate_naive: f64,
}

pub fn run(seed: u64, chains: usize, len: usize) -> Report {
    let mut rng = Rng::new(seed);
    let vars = [Var::KeyOrder, Var::Whitespace, Var::UnicodeEscape, Var::NumberFormat, Var::Canonical];
    let mut naive = [0usize; 5];
    let mut canon = [0usize; 5];
    let (mut flip_c, mut flip_n) = (0usize, 0usize);
    for _ in 0..chains {
        let recs: Vec<Rec> = (0..len)
            .map(|i| Rec {
                seq: i as u64,
                // odd multiple of 1/8: non-integer, exactly representable.
                score: (2 * rng.below(8) + 1) as f64 / 8.0,
                note: NOTES[rng.below(NOTES.len() as u64) as usize].to_string(),
            })
            .collect();
        let mut hashes = Vec::with_capacity(len);
        let mut prev = GENESIS.to_string();
        for r in &recs {
            let h = link(&prev, &ser(r, Var::Canonical));
            hashes.push(h.clone());
            prev = h;
        }
        for (k, v) in vars.iter().enumerate() {
            let bodies: Vec<String> = recs.iter().map(|r| ser(r, *v)).collect();
            if !verify(&bodies, &hashes, false) {
                naive[k] += 1;
            }
            if !verify(&bodies, &hashes, true) {
                canon[k] += 1;
            }
        }
        // Real content flip: change the seq-independent score of one record, sent unvaried.
        let i = rng.below(len as u64) as usize;
        let mut bad = recs.clone();
        bad[i].score = if bad[i].score < 0.5 { bad[i].score + 0.5 } else { bad[i].score - 0.5 };
        let bodies: Vec<String> = bad.iter().map(|r| ser(r, Var::KeyOrder)).collect();
        if !verify(&bodies, &hashes, true) {
            flip_c += 1;
        }
        let bodies: Vec<String> = bad.iter().map(|r| ser(r, Var::Canonical)).collect();
        if !verify(&bodies, &hashes, false) {
            flip_n += 1;
        }
    }
    let f = |x: usize| x as f64 / chains as f64;
    Report {
        seed,
        chains,
        len,
        false_tamper_rate_by_variation: Rates {
            naive_key_order: f(naive[0]),
            naive_whitespace: f(naive[1]),
            naive_unicode_escape: f(naive[2]),
            naive_number_format: f(naive[3]),
            canonical_key_order: f(canon[0]),
            canonical_whitespace: f(canon[1]),
            canonical_unicode_escape: f(canon[2]),
            canonical_number_format: f(canon[3]),
            naive_unvaried_control: f(naive[4]),
            canonical_unvaried_control: f(canon[4]),
        },
        real_flip_detection_rate_canonical: f(flip_c),
        real_flip_detection_rate_naive: f(flip_n),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variations_differ_but_canonicalise_equal() {
        let r = Rec { seq: 3, score: 0.375, note: "caf\u{e9} order".into() };
        let base = ser(&r, Var::Canonical);
        for v in [Var::KeyOrder, Var::Whitespace, Var::UnicodeEscape, Var::NumberFormat] {
            let s = ser(&r, v);
            assert_ne!(s, base);
            assert_eq!(canonicalise(&s).unwrap(), base);
        }
    }

    #[test]
    fn rates_match_hypothesis() {
        let r = run(7, 20, 8);
        let t = &r.false_tamper_rate_by_variation;
        assert_eq!(t.naive_key_order, 1.0);
        assert_eq!(t.naive_number_format, 1.0);
        assert_eq!(t.canonical_whitespace, 0.0);
        assert_eq!(t.naive_unvaried_control, 0.0);
        assert_eq!(r.real_flip_detection_rate_canonical, 1.0);
    }
}
