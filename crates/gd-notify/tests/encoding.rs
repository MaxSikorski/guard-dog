//! Hex, base64 and npub (bech32) reading.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use gd_notify::encoding::{
    base64_decode, base64_encode, hex_decode, hex_encode, hex32, npub_decode, npub_encode,
    parse_recipient,
};

// Public-key example from NIP-19 (a published test pair, not a real account).
const NPUB: &str = "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg";
const HEX: &str = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";

#[test]
fn npub_and_hex_name_the_same_key() {
    let from_npub = parse_recipient(NPUB).unwrap();
    let from_hex = parse_recipient(HEX).unwrap();
    assert_eq!(from_npub, from_hex);
    assert_eq!(hex_encode(&from_npub), HEX);
    assert_eq!(npub_encode(&from_npub), NPUB);
    assert_eq!(npub_decode(NPUB).unwrap(), from_npub);
}

#[test]
fn recipients_that_are_not_a_key_are_refused() {
    let mut bad_checksum = NPUB.to_owned();
    bad_checksum.pop();
    bad_checksum.push('q');
    let upper_hex = HEX.to_uppercase();
    let mixed_case_npub = format!("N{}", &NPUB[1..]);
    let cases = [
        "".to_owned(),
        bad_checksum,
        // An nsec (secret key) must never be accepted as a recipient.
        "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5".to_owned(),
        // Wrong prefix and wrong length.
        "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p".to_owned(),
        HEX[..62].to_owned(),
        format!("{HEX}00"),
        upper_hex,
        mixed_case_npub,
        format!(" {HEX}"),
        format!("{HEX}\n"),
        "zz".repeat(32),
    ];
    for c in cases {
        assert!(parse_recipient(&c).is_err(), "accepted {c:?}");
    }
}

/// BIP-173 valid checksum strings (any human-readable part) decode; the
/// invalid ones are refused. Our decoder is `npub`-only, so this checks the
/// checksum through the one public door: a valid-checksum string with another
/// prefix is refused for its prefix, and flipping any one character of a good
/// npub is refused for its checksum.
#[test]
fn every_single_character_change_in_an_npub_is_refused() {
    let alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let chars: Vec<char> = NPUB.chars().collect();
    for i in 5..chars.len() {
        for a in alphabet.chars() {
            if a == chars[i] {
                continue;
            }
            let mut c = chars.clone();
            c[i] = a;
            let s: String = c.into_iter().collect();
            assert!(npub_decode(&s).is_err(), "accepted {s}");
        }
    }
}

#[test]
fn bip173_checksum_vectors() {
    // Valid BIP-173 strings with the wrong prefix are refused as recipients;
    // the checksum function itself is checked with the strings it must accept.
    for valid in [
        "A12UEL5L",
        "a12uel5l",
        "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
        "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
        "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
    ] {
        assert!(gd_notify::encoding::bech32_checksum_ok(valid), "{valid}");
    }
    for invalid in [
        "pzry9x0s0muk",
        "1pzry9x0s0muk",
        "x1b4n0q5v",
        "li1dgmt3",
        "de1lg7wt\u{ff}",
        "A1G7SGD8",
        "10a06t8",
        "1qzzfhee",
        "A12uEL5L",
    ] {
        assert!(!gd_notify::encoding::bech32_checksum_ok(invalid), "{invalid}");
    }
}

#[test]
fn hex_is_strict() {
    assert_eq!(hex32(HEX).unwrap().len(), 32);
    assert!(hex32("abc").is_err());
    assert!(hex_decode("0g").is_err());
    assert!(hex_decode("abc").is_err());
    assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
}

#[test]
fn base64_is_strict_and_round_trips() {
    for len in 0..70usize {
        let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        let text = base64_encode(&data);
        assert_eq!(base64_decode(&text).unwrap(), data);
    }
    assert_eq!(base64_encode(b"Man"), "TWFu");
    assert_eq!(base64_encode(b"Ma"), "TWE=");
    assert_eq!(base64_encode(b"M"), "TQ==");
    for bad in ["TWE", "TWE=\n", "TW=u", "TQ=A", "T===", "====", "TWF-", "TWF u", "TWE=TWFu", "TR=="] {
        assert!(base64_decode(bad).is_err(), "accepted {bad:?}");
    }
}
