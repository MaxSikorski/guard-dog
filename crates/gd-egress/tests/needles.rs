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
        // A digit right before an IPv4 address makes it a different number, on purpose.
        prop_assume!(class != Class::Ipv4 || prefix.iter().all(|b| !b.is_ascii_digit()));
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
        let set = generate(1);
        let needles = Needles::new(&set);
        prop_assert!(needles.scan(&bytes).is_empty());
        // Positive twin: the same traffic with a canary appended is not clean.
        let mut tainted = bytes.clone();
        tainted.push(b' ');
        tainted.extend(set.text(Class::Nsec).as_bytes());
        prop_assert!(needles.scan(&tainted).contains(&HitKind::Canary(Class::Nsec)));
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
    // Positive twins: with the boundary character separated off, the address is found.
    assert!(classes_found(&needles, format!("{ip} 1").as_bytes()).contains(&Class::Ipv4));
    assert!(classes_found(&needles, format!("2 {ip}").as_bytes()).contains(&Class::Ipv4));
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

fn dotted(value: u32) -> String {
    std::net::Ipv4Addr::from(value).to_string()
}

#[test]
fn ip_values_parse_every_supported_form() {
    use gd_egress::needle::ip_values;
    let want: u32 = 0xc633_648b; // 198.51.100.139
    for (text, label) in [
        ("ip 198.51.100.139 x", "dotted"),
        ("a=3325256843;", "decimal integer"),
        ("0xc633648b", "0x hex"),
        ("0XC633648B,", "0X hex upper"),
        ("[198.51.100.139]:443", "bracketed"),
    ] {
        assert!(ip_values(text.as_bytes()).v4.contains(&want), "{label}");
    }
    // Boundaries: more digits, a leading zero, a longer hex run, or a fifth part is a different thing.
    for text in [
        "13325256843",
        "03325256843",
        "0xc633648b0",
        "1198.51.100.139",
    ] {
        assert!(!ip_values(text.as_bytes()).v4.contains(&want), "{text}");
    }
    let v6 = |text: &str| ip_values(text.as_bytes()).v6;
    let canonical = "2001:db8::1"
        .parse::<std::net::Ipv6Addr>()
        .unwrap()
        .octets();
    for text in [
        "addr 2001:db8::1 end",
        "2001:0db8:0000:0000:0000:0000:0000:0001",
        "2001:DB8:0:0:0:0:0:1.",
        "[2001:db8::1]:80",
        "2001:db8::0.0.0.1",
    ] {
        assert!(v6(text).contains(&canonical), "{text}");
    }
    assert!(
        v6("::ffff:1.2.3.4").contains(
            &"::ffff:1.2.3.4"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        )
    );
    assert!(v6("not an address: nothing").is_empty());
    // The raw 16 bytes of the canary are a needle of their own.
    let set = generate(1);
    let needles = Needles::new(&set);
    let mut hay = b"junk".to_vec();
    hay.extend(set.get(Class::Ipv6).unwrap().bytes.clone().unwrap());
    assert!(classes_found(&needles, &hay).contains(&Class::Ipv6));
    assert!(classes_found(&needles, b"junk").is_empty());
}

#[test]
fn ip_near_misses_are_not_found() {
    let set = generate(1);
    let needles = Needles::new(&set);
    let ip: std::net::Ipv4Addr = set.text(Class::Ipv4).parse().unwrap();
    let value = u32::from(ip);
    let forms = |v: u32| [dotted(v), v.to_string(), format!("0x{v:08x}")];
    for (exact, near) in forms(value)
        .iter()
        .zip(forms(value + 1).iter().zip(forms(value - 1).iter()))
    {
        assert!(
            classes_found(&needles, format!(" {exact} ").as_bytes()).contains(&Class::Ipv4),
            "twin {exact}"
        );
        for miss in [near.0, near.1] {
            assert!(
                classes_found(&needles, format!(" {miss} ").as_bytes()).is_empty(),
                "{miss}"
            );
        }
    }
    // Every octet and every IPv6 group moved by one.
    for octet in 0..4 {
        let mut o = ip.octets();
        o[octet] = o[octet].wrapping_add(1);
        let miss = std::net::Ipv4Addr::from(o).to_string();
        assert!(
            classes_found(&needles, format!(" {miss} ").as_bytes()).is_empty(),
            "{miss}"
        );
    }
    let v6: std::net::Ipv6Addr = set.text(Class::Ipv6).parse().unwrap();
    assert!(
        classes_found(&needles, format!(" {v6} ").as_bytes()).contains(&Class::Ipv6),
        "twin"
    );
    for group in 0..8 {
        let mut g = v6.segments();
        g[group] = g[group].wrapping_add(1);
        let miss = std::net::Ipv6Addr::from(g).to_string();
        assert!(
            classes_found(&needles, format!(" {miss} ").as_bytes()).is_empty(),
            "{miss}"
        );
    }
    // The same near misses inside base64 and base32 tokens.
    let encoded = |text: &str| {
        [
            BASE64.encode(text.as_bytes()),
            BASE32_NOPAD.encode(text.as_bytes()),
        ]
    };
    for text in encoded(&ip.to_string()) {
        assert!(
            classes_found(&needles, text.as_bytes()).contains(&Class::Ipv4),
            "twin {text}"
        );
    }
    for text in encoded(&dotted(value + 1))
        .into_iter()
        .chain(encoded(&dotted(value - 1)))
    {
        assert!(
            classes_found(&needles, text.as_bytes()).is_empty(),
            "{text}"
        );
    }
}

fn encode_for(kind: usize, set: &gd_egress::canary::CanarySet, class: Class) -> Option<String> {
    let text = set.text(class);
    let bytes = set.get(class).and_then(|c| c.bytes.clone());
    match kind {
        0 => Some(BASE64.encode(text.as_bytes())),
        1 => Some(HEXLOWER.encode(text.as_bytes())),
        2 => Some(BASE32_NOPAD.encode(text.as_bytes())),
        3 => bytes.map(|b| BASE64.encode(&b)),
        4 => bytes.map(|b| HEXLOWER.encode(&b)),
        _ => bytes.map(|b| BASE32_NOPAD.encode(&b)),
    }
}

fn split_every(text: &str, every: usize, separator: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    chars
        .chunks(every)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(separator)
}

proptest! {
    #![proptest_config(proptest_config())]

    #[test]
    fn wrapped_and_separated_forms_are_found(
        seed in 1u64..100_000,
        class_index in 0usize..11,
        kind in 0usize..6,
        every in 1usize..17,
        sep_index in 0usize..6,
        before in "[ -~]{0,20}",
    ) {
        let class = Class::ALL[class_index];
        let set = generate(seed);
        let needles = Needles::new(&set);
        const SEPARATORS: [&str; 6] = [" ", "\n", "\r\n", "-", ":", "."];
        // Encoded forms survive line wrapping (white space inside the token); the plain text
        // survives any separator, which the separator-stripped view takes out.
        if let Some(encoded) = encode_for(kind, &set, class) {
            let sep = SEPARATORS[sep_index % 3];
            // Only base64 wraps lines; hex and base32 stay whole.
            let body = if kind != 0 && kind != 3 { encoded } else { split_every(&encoded, every.max(4), sep) };
            let hay = format!("{before}\n{body}\n");
            prop_assert!(classes_found(&needles, hay.as_bytes()).contains(&class), "{} kind {kind}", class.name());
        }
        // The IPv4 text keeps its dots (a changed separator is a different address).
        if !matches!(class, Class::Ipv4) {
            let text = set.text(class);
            let sep = SEPARATORS[sep_index];
            // Keep each piece at least 4 characters so the needles' own punctuation survives.
            let hay = format!("{before}\n{}\n", split_every(text, every.max(4), sep));
            prop_assert!(classes_found(&needles, hay.as_bytes()).contains(&class), "text {} sep {sep:?}", class.name());
        }
    }

    #[test]
    fn redaction_never_prints_canary_derived_text(
        seed in 1u64..100_000,
        class_index in 0usize..11,
        form in 0usize..8,
        shape_host in any::<bool>(),
    ) {
        let class = Class::ALL[class_index];
        let set = generate(seed);
        let needles = Needles::new(&set);
        let canary = set.get(class).unwrap();
        let text = &canary.text;
        let encoded = match form {
            0 => text.clone(),
            1 => text.to_uppercase(),
            2 => HEXLOWER.encode(text.as_bytes()),
            3 => BASE64.encode(text.as_bytes()),
            4 => BASE64URL.encode(text.as_bytes()),
            5 => BASE32_NOPAD.encode(text.as_bytes()),
            6 => text.bytes().map(|b| format!("%{b:02x}")).collect(),
            _ => text.bytes().map(|b| format!("\\u00{b:02x}")).collect(),
        };
        let printed_from = if shape_host { format!("{encoded}.leak.example.net") } else { format!("dns {encoded}") };
        let printed = needles.redact(&printed_from);
        prop_assert!(printed.contains("<canary:") || printed.contains("<secret:"), "unchanged: {printed}");
        let lowered = printed.to_lowercase();
        let hex_of_bytes = canary.bytes.as_ref().map(|b| HEXLOWER.encode(b)).unwrap_or_default();
        for source in [text.to_lowercase(), hex_of_bytes] {
            for window in source.as_bytes().windows(8) {
                let piece = String::from_utf8_lossy(window);
                prop_assert!(!lowered.contains(piece.as_ref()), "{} left {piece:?} in {printed:?}", class.name());
            }
        }
    }
}
