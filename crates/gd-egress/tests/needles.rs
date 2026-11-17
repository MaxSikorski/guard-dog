//! Finding canaries in every encoding, and redacting them for printing.

// Test-only crate: see `crates/gd-core/tests/judge_d_injection.rs` for why helpers need this.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use data_encoding::{BASE32_NOPAD, BASE64, BASE64URL, HEXLOWER};
use gd_egress::canary::{Class, generate};
use gd_egress::needle::{HitKind, Needles};
use proptest::prelude::*;

fn proptest_config() -> ProptestConfig {
    // The house pattern (see crates/gd-core/src/untrusted.rs): fixed seed, `GD_PROPTEST_SEED=<n>` to explore.
    static ANNOUNCE: std::sync::Once = std::sync::Once::new();
    let seed = std::env::var("GD_PROPTEST_SEED")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(0x6764_5f65_6772_6573);
    ANNOUNCE.call_once(|| eprintln!("GD_PROPTEST_SEED={seed} (property test seed in use)"));
    ProptestConfig {
        rng_seed: proptest::test_runner::RngSeed::Fixed(seed),
        ..ProptestConfig::default()
    }
}

fn classes_found(needles: &Needles, hay: &[u8]) -> Vec<Class> {
    needles
        .scan(hay)
        .into_iter()
        .filter_map(|h| match h {
            HitKind::Canary(c) => Some(c),
            HitKind::Shape(_) => None,
        })
        .collect()
}

proptest! {
    #![proptest_config(proptest_config())]

    #[test]
    fn needles_find_every_encoding(
        seed in 1u64..100_000,
        class_index in 0usize..11,
        encoding in 0usize..9,
        prefix in proptest::collection::vec(any::<u8>(), 0..9),
        before in "[ -~]{0,40}",
        after in "[ -~]{0,40}",
    ) {
        let class = Class::ALL[class_index];
        // An IPv4 address is too short for its base64 and base32 forms to be searched without false hits.
        prop_assume!(!(class == Class::Ipv4 && matches!(encoding, 3 | 4 | 5 | 7)));
        let set = generate(seed);
        let needles = Needles::new(&set);
        let text = set.text(class);
        let mut with_prefix = prefix.clone();
        with_prefix.extend(text.as_bytes());
        let encoded: String = match encoding {
            0 => text.to_string(),
            1 => text.to_uppercase(),
            2 => HEXLOWER.encode(text.as_bytes()),
            3 => BASE64.encode(&with_prefix),
            4 => BASE64URL.encode(&with_prefix),
            5 => BASE32_NOPAD.encode(&with_prefix),
            6 => text.bytes().map(|b| format!("%{b:02X}")).collect(),
            7 => BASE64.encode(&with_prefix).replace('/', "\\/"),
            _ => format!("\"{text}\""),
        };
        // Spaces keep an IPv4 address clear of neighbouring digits.
        let hay = format!("{before} {encoded} {after}");
        let found = classes_found(&needles, hay.as_bytes());
        prop_assert!(found.contains(&class), "{} not found in encoding {encoding}", class.name());
    }

    #[test]
    fn needles_ignore_unrelated_traffic(bytes in proptest::collection::vec(0x20u8..0x7f, 0..4096)) {
        let needles = Needles::new(&generate(1));
        prop_assert!(needles.scan(&bytes).is_empty());
    }
}

#[test]
fn seed_phrase_is_found_with_any_separator() {
    let set = generate(5);
    let needles = Needles::new(&set);
    let words: Vec<&str> = set.text(Class::SeedPhrase).split(' ').collect();
    for separator in [" ", ",", "\", \"", "%20", "+", "\n", "-"] {
        let hay = format!("note: {}", words.join(separator));
        assert!(
            classes_found(&needles, hay.as_bytes()).contains(&Class::SeedPhrase),
            "separator {separator:?}"
        );
    }
    // Three words alone are enough; two are not.
    let three = words[5..8].join(" ");
    assert!(classes_found(&needles, three.as_bytes()).contains(&Class::SeedPhrase));
    let two = words[5..7].join(" ");
    assert!(classes_found(&needles, two.as_bytes()).is_empty());
}

#[test]
fn ipv4_needle_respects_digit_boundaries() {
    // Find a seed whose last octet is a single digit, so "...7" and "...71" are both interesting.
    let set = (1u64..)
        .map(generate)
        .find(|s| s.text(Class::Ipv4).len() == "198.51.100.7".len())
        .unwrap();
    let ip = set.text(Class::Ipv4).to_string();
    let needles = Needles::new(&set);
    assert!(classes_found(&needles, format!("ip={ip};").as_bytes()).contains(&Class::Ipv4));
    assert!(classes_found(&needles, ip.as_bytes()).contains(&Class::Ipv4));
    assert!(
        classes_found(&needles, format!("{ip}1").as_bytes()).is_empty(),
        "digit after"
    );
    assert!(
        classes_found(&needles, format!("2{ip}").as_bytes()).is_empty(),
        "digit before"
    );
}

#[test]
fn redaction_never_prints_a_canary() {
    for seed in 1..=20u64 {
        let set = generate(seed);
        let needles = Needles::new(&set);
        for canary in &set.canaries {
            let text = &canary.text;
            let redacted = needles.redact(&format!("to {text} now"));
            assert_eq!(
                redacted,
                format!("to <canary:{}> now", canary.class.name()),
                "seed {seed}"
            );
            let chars: Vec<char> = text.chars().collect();
            for window in chars.windows(16.min(chars.len())) {
                let part: String = window.iter().collect();
                assert!(
                    !redacted.contains(&part),
                    "{} leaked a piece",
                    canary.class.name()
                );
            }
            // Cut short, with letters around it: the whole run still goes.
            if text.len() > 30
                && text
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "+/=_-".contains(c))
            {
                let cut: String = text.chars().take(30).collect();
                let red = needles.redact(&format!("name {cut}XYZ.leak.example.net"));
                assert!(red.starts_with("name <canary:"), "{red}");
                assert!(red.ends_with(">.leak.example.net"), "{red}");
            }
        }
        let shape = needles.redact(&format!("body gdlabcanary-{}", "ab".repeat(32)));
        assert_eq!(shape, "body <secret:gdlabcanary>");
    }
    assert_eq!(Needles::new(&generate(1)).shape_count(), 5);
}
