//! Finding canaries in every encoding, and redacting them for printing.

// Test-only crate: see `crates/gd-core/tests/judge_d_injection.rs` for why helpers need this.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod support;

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

fn key_bytes(set: &gd_egress::canary::CanarySet, class: Class) -> Vec<u8> {
    set.get(class).and_then(|c| c.bytes.clone()).unwrap()
}

#[test]
fn key_bytes_written_as_source_code_are_found() {
    let set = generate(7);
    let needles = Needles::new(&set);
    let list = |bytes: &[u8], each: &dyn Fn(u8) -> String, sep: &str| {
        bytes.iter().map(|b| each(*b)).collect::<Vec<_>>().join(sep)
    };
    for class in [
        Class::Nsec,
        Class::SeedPhrase,
        Class::Macaroon,
        Class::ClnRune,
        Class::Onion,
        Class::NodePubkey,
    ] {
        let bytes = key_bytes(&set, class);
        let forms = [
            (
                "rust hex list",
                format!("[{}]", list(&bytes, &|b| format!("0x{b:02x}"), ", ")),
            ),
            (
                "upper hex list",
                format!("{{{}}}", list(&bytes, &|b| format!("0X{b:02X}"), ",")),
            ),
            (
                "go byte slice",
                format!(
                    "[]byte{{{}}}",
                    list(&bytes, &|b| format!("0x{b:02x}"), ", ")
                ),
            ),
            ("rust debug", format!("{bytes:?}")),
            (
                "json array",
                format!("[{}]", list(&bytes, &|b| b.to_string(), ",")),
            ),
            (
                "space separated decimal",
                list(&bytes, &|b| b.to_string(), " "),
            ),
            ("padded decimal", list(&bytes, &|b| format!("{b:03}"), ", ")),
            (
                "python escapes",
                format!("b'{}'", list(&bytes, &|b| format!("\\x{b:02x}"), "")),
            ),
            (
                "python escapes upper",
                list(&bytes, &|b| format!("\\x{b:02X}"), ""),
            ),
            (
                "hex with spaces",
                list(&bytes, &|b| format!("{b:02x}"), " "),
            ),
        ];
        for (label, text) in forms {
            let hay = format!("payload = {text};\n");
            assert!(
                classes_found(&needles, hay.as_bytes()).contains(&class),
                "{} as {label}",
                class.name()
            );
        }
        // Negative twins: one byte changed, or only a few bytes. (A macaroon's and a node key's
        // text is the hex of their bytes, and the first and last 12 bytes of those are needles on
        // their own, so a change to the last byte still leaves a long piece that is rightly found.)
        let mut changed = bytes.clone();
        let last = changed.len() - 1;
        changed[last] ^= 0x55;
        let mut twins = vec![
            format!("{:?}", &bytes[..6]),
            list(&bytes[..6], &|b| format!("\\x{b:02x}"), ""),
        ];
        if !matches!(class, Class::Macaroon | Class::NodePubkey) {
            twins.extend([
                format!("{changed:?}"),
                format!("[{}]", list(&changed, &|b| format!("0x{b:02x}"), ", ")),
                list(&changed, &|b| format!("\\x{b:02x}"), ""),
            ]);
        }
        for text in twins {
            assert!(
                classes_found(&needles, text.as_bytes()).is_empty(),
                "{} twin {text}",
                class.name()
            );
        }
    }
}

fn xpub_with_version(set: &gd_egress::canary::CanarySet, version: [u8; 4]) -> String {
    let mut payload = version.to_vec();
    payload.extend(&key_bytes(set, Class::Xpub)[4..]);
    gd_egress::encode::base58check(&payload)
}

#[test]
fn an_xpub_written_with_other_version_bytes_is_found() {
    let set = generate(7);
    let needles = Needles::new(&set);
    assert_eq!(
        xpub_with_version(&set, [0x04, 0x88, 0xb2, 0x1e]),
        set.text(Class::Xpub),
        "the helper reproduces the planted xpub"
    );
    // zpub, ypub, tpub, vpub, upub, Zpub, Ypub, and a made-up version.
    for (name, version) in [
        ("zpub", [0x04, 0xb2, 0x47, 0x46]),
        ("ypub", [0x04, 0x9d, 0x7c, 0xb2]),
        ("tpub", [0x04, 0x35, 0x87, 0xcf]),
        ("vpub", [0x04, 0x5f, 0x1c, 0xf6]),
        ("upub", [0x04, 0x4a, 0x52, 0x62]),
        ("Zpub", [0x02, 0xaa, 0x7e, 0xd3]),
        ("Ypub", [0x02, 0x95, 0xb4, 0x3f]),
        ("made up", [0x01, 0x02, 0x03, 0x04]),
    ] {
        let text = xpub_with_version(&set, version);
        for hay in [
            text.clone(),
            format!("{{\"key\": \"{text}\"}}"),
            format!("descriptor wpkh({text}/0/*)"),
        ] {
            assert!(
                classes_found(&needles, hay.as_bytes()).contains(&Class::Xpub),
                "{name}: {hay}"
            );
        }
    }
    // Negative twin: another seed's key under the same version is not ours.
    let other = generate(8);
    let foreign = xpub_with_version(&other, [0x04, 0xb2, 0x47, 0x46]);
    assert!(classes_found(&needles, foreign.as_bytes()).is_empty());
}

fn ip_forms(set: &gd_egress::canary::CanarySet) -> (Vec<String>, Vec<String>) {
    let ip: std::net::Ipv4Addr = set.text(Class::Ipv4).parse().unwrap();
    let o = ip.octets();
    let value = u32::from(ip);
    let mapped = |v: u32| {
        vec![
            format!("::ffff:{:x}:{:x}", v >> 16, v & 0xffff),
            format!("::ffff:{}", std::net::Ipv4Addr::from(v)),
            format!("[::ffff:{:x}:{:x}]:443", v >> 16, v & 0xffff),
            format!("0:0:0:0:0:ffff:{:04x}:{:04x}", v >> 16, v & 0xffff),
        ]
    };
    let forms = |o: [u8; 4], v: u32| {
        let mut out = vec![
            format!("ip-{}-{}-{}-{}", o[0], o[1], o[2], o[3]),
            format!(
                "ec2-{}-{}-{}-{}.compute-1.example.net",
                o[0], o[1], o[2], o[3]
            ),
            format!("ip_{}_{}_{}_{}", o[0], o[1], o[2], o[3]),
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]),
            format!("{}.{}.{}.{}.IN-ADDR.ARPA.", o[3], o[2], o[1], o[0]),
        ];
        out.extend(mapped(v));
        out
    };
    let near = {
        let mut n = o;
        n[3] = n[3].wrapping_add(1);
        forms(n, value.wrapping_add(1))
    };
    (forms(o, value), near)
}

#[test]
fn ip_addresses_in_host_name_and_mapped_forms_are_found() {
    let set = generate(1);
    let needles = Needles::new(&set);
    let (exact, near) = ip_forms(&set);
    for text in &exact {
        assert!(
            classes_found(&needles, format!(" {text} ").as_bytes()).contains(&Class::Ipv4),
            "{text}"
        );
    }
    for text in &near {
        assert!(
            classes_found(&needles, format!(" {text} ").as_bytes()).is_empty(),
            "near miss {text}"
        );
    }
    // The reversed numbers without the arpa name are a different address.
    let o = set
        .text(Class::Ipv4)
        .parse::<std::net::Ipv4Addr>()
        .unwrap()
        .octets();
    let reversed = format!("{}.{}.{}.{}", o[3], o[2], o[1], o[0]);
    assert!(classes_found(&needles, format!(" {reversed} ").as_bytes()).is_empty());
    // ip_values reads the mapped form as an IPv4 value too.
    let value = u32::from(std::net::Ipv4Addr::from(o));
    let values = gd_egress::needle::ip_values(
        format!("::ffff:{:x}:{:x}", value >> 16, value & 0xffff).as_bytes(),
    );
    assert!(values.v4.contains(&value));
}

#[test]
fn an_ipv6_address_as_a_reverse_lookup_name_is_found() {
    let set = generate(1);
    let needles = Needles::new(&set);
    let bytes = key_bytes(&set, Class::Ipv6);
    let nibbles: Vec<String> = bytes
        .iter()
        .flat_map(|b| [b >> 4, b & 15])
        .rev()
        .map(|n| format!("{n:x}"))
        .collect();
    let name = format!("{}.ip6.arpa", nibbles.join("."));
    assert!(classes_found(&needles, format!(" {name} ").as_bytes()).contains(&Class::Ipv6));
    assert!(
        classes_found(
            &needles,
            format!("{}.IP6.ARPA.", nibbles.join(".")).as_bytes()
        )
        .contains(&Class::Ipv6)
    );
    // One nibble different: another address.
    let mut changed = nibbles.clone();
    changed[3] = if changed[3] == "0" {
        "1".into()
    } else {
        "0".into()
    };
    assert!(
        classes_found(
            &needles,
            format!(" {}.ip6.arpa ", changed.join(".")).as_bytes()
        )
        .is_empty()
    );
}

fn prefix(word: &str) -> &str {
    &word[..word.len().min(4)]
}

#[test]
fn seed_words_as_four_letter_prefixes_and_seedqr_digits_are_found() {
    let set = generate(5);
    let needles = Needles::new(&set);
    let phrase = set.text(Class::SeedPhrase).to_string();
    let words: Vec<&str> = phrase.split(' ').collect();
    let prefixes: Vec<&str> = words.iter().map(|w| prefix(w)).collect();
    for separator in [" ", ",", "\n", "-", "\", \""] {
        let hay = format!("backup: {}", prefixes.join(separator));
        assert!(
            classes_found(&needles, hay.as_bytes()).contains(&Class::SeedPhrase),
            "prefixes with {separator:?}"
        );
    }
    let three = prefixes[5..8].join(" ");
    assert!(classes_found(&needles, three.as_bytes()).contains(&Class::SeedPhrase));
    assert!(classes_found(&needles, prefixes[5..7].join(" ").as_bytes()).is_empty());
    let other = generate(6);
    let other_phrase = other.text(Class::SeedPhrase).to_string();
    let others: Vec<&str> = other_phrase.split(' ').map(prefix).collect();
    assert!(classes_found(&needles, others.join(" ").as_bytes()).is_empty());

    // SeedQR: each word as its position in the list, four digits, zero-padded, run together.
    let list = gd_egress::bip39::words();
    let index = |w: &str| list.iter().position(|x| *x == w).unwrap();
    let digits = |ws: &[&str]| {
        ws.iter()
            .map(|w| format!("{:04}", index(w)))
            .collect::<String>()
    };
    assert_eq!(digits(&words).len(), 96);
    for (label, text) in [
        ("24 words", digits(&words)),
        ("first 12", digits(&words[..12])),
        ("three words", digits(&words[9..12])),
        ("inside text", format!("qr=\"{}\"\n", digits(&words[3..9]))),
    ] {
        assert!(
            classes_found(&needles, text.as_bytes()).contains(&Class::SeedPhrase),
            "{label}"
        );
    }
    // With a space or a line break between indices the stripped view still reads it.
    let spaced = words[..12]
        .iter()
        .map(|w| format!("{:04}", index(w)))
        .collect::<Vec<_>>();
    for sep in [" ", "\n", ","] {
        assert!(
            classes_found(&needles, spaced.join(sep).as_bytes()).contains(&Class::SeedPhrase),
            "{sep:?}"
        );
    }
    // Negative twins: two indices only, one digit changed, another seed's indices.
    assert!(classes_found(&needles, digits(&words[..2]).as_bytes()).is_empty());
    let mut broken = digits(&words[..12]).into_bytes();
    for at in [3usize, 15, 27, 39] {
        broken[at] = if broken[at] == b'7' { b'8' } else { b'7' };
    }
    assert!(classes_found(&needles, &broken).is_empty());
    let other_words: Vec<&str> = other_phrase.split(' ').collect();
    assert!(classes_found(&needles, digits(&other_words).as_bytes()).is_empty());
}

/// A seed whose nsec key has small bytes (so unpadded hex differs) and bytes above 0x7f.
fn set_with_small_and_high_bytes() -> gd_egress::canary::CanarySet {
    (1u64..)
        .map(generate)
        .find(|s| {
            let key = key_bytes(s, Class::Nsec);
            key.iter().filter(|b| **b < 0x10).count() >= 3
                && key.iter().filter(|b| **b >= 0x80).count() >= 3
        })
        .unwrap()
}

#[test]
fn byte_lists_as_real_formatters_print_them_are_found() {
    let set = set_with_small_and_high_bytes();
    let needles = Needles::new(&set);
    let join = |bytes: &[u8], each: &dyn Fn(u8) -> String, sep: &str| {
        bytes.iter().map(|b| each(*b)).collect::<Vec<_>>().join(sep)
    };
    for class in [
        Class::Nsec,
        Class::SeedPhrase,
        Class::Macaroon,
        Class::ClnRune,
        Class::Onion,
        Class::NodePubkey,
    ] {
        let bytes = key_bytes(&set, class);
        let rows = bytes
            .chunks(4)
            .map(|c| format!("[{}]", join(c, &|b| b.to_string(), ",")))
            .collect::<Vec<_>>()
            .join(",");
        let json_escapes: String = bytes.iter().map(|b| format!("\\u{b:04x}")).collect();
        let forms = [
            ("rust {:x?}", format!("{bytes:x?}")),
            ("rust {:#x?}", format!("{bytes:#x?}")),
            ("rust {:X?}", format!("{bytes:X?}")),
            (
                "python hex()",
                format!("[{}]", join(&bytes, &|b| format!("{b:#x}"), ", ")),
            ),
            (
                "java signed",
                format!("[{}]", join(&bytes, &|b| (b as i8).to_string(), ", ")),
            ),
            ("python repr", support::python_bytes_repr(&bytes)),
            ("rows of four", format!("[{rows}]")),
            (
                "typed array",
                format!(
                    "Uint8Array({}) [ {} ]",
                    bytes.len(),
                    join(&bytes, &|b| b.to_string(), ", ")
                ),
            ),
            ("json escapes", format!("{{\"k\":\"{json_escapes}\"}}")),
        ];
        for (label, text) in forms {
            assert!(
                classes_found(&needles, text.as_bytes()).contains(&class),
                "{} as {label}: {text}",
                class.name()
            );
        }
        // Twins: a byte changed, or only a few bytes.
        let mut changed = bytes.clone();
        let last = changed.len() - 1;
        changed[last] ^= 0x55;
        let mut twins = vec![
            format!("{:x?}", &bytes[..6]),
            support::python_bytes_repr(&bytes[..6]),
        ];
        if !matches!(class, Class::Macaroon | Class::NodePubkey) {
            twins.extend([
                format!("{changed:x?}"),
                support::python_bytes_repr(&changed),
                format!("[{}]", join(&changed, &|b| (b as i8).to_string(), ", ")),
            ]);
        }
        for text in twins {
            assert!(
                classes_found(&needles, text.as_bytes()).is_empty(),
                "{} twin {text}",
                class.name()
            );
        }
    }
}

#[test]
fn an_xpub_with_a_character_in_front_or_next_to_another_key_is_found() {
    let set = generate(7);
    let needles = Needles::new(&set);
    let zpub = xpub_with_version(&set, [0x04, 0xb2, 0x47, 0x46]);
    let other = generate(8);
    let foreign = xpub_with_version(&other, [0x04, 0xb2, 0x47, 0x46]);
    let ypub = xpub_with_version(&set, [0x04, 0x9d, 0x7c, 0xb2]);
    let long_run = format!("{}{zpub}{}", "A".repeat(150), "B".repeat(150));
    for (label, text) in [
        ("one character in front", format!("k{zpub}")),
        ("three characters in front", format!("abc{zpub}")),
        ("another key first", format!("{foreign}{zpub}")),
        ("another key after", format!("{zpub}{foreign}")),
        ("a long run", long_run),
        ("ypub in a long run", format!("{}{ypub}", "Z".repeat(300))),
    ] {
        assert!(
            classes_found(&needles, text.as_bytes()).contains(&Class::Xpub),
            "{label}"
        );
    }
    assert!(classes_found(&needles, format!("k{foreign}{foreign}").as_bytes()).is_empty());
}

#[test]
fn compressed_data_inside_text_tokens_is_unpacked() {
    let set = generate(7);
    let needles = Needles::new(&set);
    let nsec = set.text(Class::Nsec).as_bytes().to_vec();
    let packed = support::gzip(&nsec);
    let zlib_packed = support::zlib(&nsec);
    for (label, text) in [
        (
            "base64 gzip in JSON",
            format!("{{\"blob\":\"{}\"}}", BASE64.encode(&packed)),
        ),
        ("base64url gzip", BASE64URL.encode(&packed)),
        ("hex gzip", HEXLOWER.encode(&packed)),
        ("base32 gzip", BASE32_NOPAD.encode(&packed)),
        (
            "base64 zlib",
            format!("data={}", BASE64.encode(&zlib_packed)),
        ),
        ("hex zlib", HEXLOWER.encode(&zlib_packed)),
    ] {
        assert!(
            classes_found(&needles, text.as_bytes()).contains(&Class::Nsec),
            "{label}"
        );
    }
    // Twin: the same packing of something harmless is nothing.
    let harmless = support::gzip(b"nothing secret in here at all, just words");
    assert!(classes_found(&needles, BASE64.encode(&harmless).as_bytes()).is_empty());
}
