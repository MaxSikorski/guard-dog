//! Known-answer tests for the generator and every encoder, plus a property
//! test that checks our hand-written encoders against `data-encoding`.

// Test-only crate: see `crates/gd-core/tests/judge_d_injection.rs` for why helpers need this.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use data_encoding::{BASE32_NOPAD, BASE64, BASE64URL, BASE64URL_NOPAD, HEXLOWER};
use gd_egress::bip39;
use gd_egress::encode::*;
use gd_egress::prng::SplitMix64;
use proptest::prelude::*;

#[test]
fn prng_matches_the_reference_splitmix64() {
    // Printed by the reference C (prng.di.unimi.it/splitmix64.c) compiled with clang, seed 1234567.
    let mut rng = SplitMix64::new(1_234_567);
    let got: Vec<u64> = (0..5).map(|_| rng.next_u64()).collect();
    assert_eq!(
        got,
        [
            6_457_827_717_110_365_317,
            3_203_168_211_198_807_973,
            9_817_491_932_198_370_423,
            4_593_380_528_125_082_431,
            16_408_922_859_458_223_821
        ]
    );
    // Bytes are the values in little-endian order, and a call never shares a value.
    let mut a = SplitMix64::new(1_234_567);
    assert_eq!(a.fill_bytes(8), 6_457_827_717_110_365_317u64.to_le_bytes());
    assert_eq!(
        a.fill_bytes(3),
        3_203_168_211_198_807_973u64.to_le_bytes()[..3]
    );
    assert_eq!(
        a.fill_bytes(1),
        9_817_491_932_198_370_423u64.to_le_bytes()[..1]
    );
}

#[test]
fn bech32_matches_the_nip19_example() {
    let key =
        hex_decode("67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa").unwrap();
    // NIP-19 lists this key with exactly this nsec. (The implementer brief printed a different string;
    // that one is not this key's encoding.) The BIP-173 spec vector `a12uel5l` pins the checksum itself.
    assert_eq!(
        bech32("nsec", &key),
        "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"
    );
    assert_eq!(bech32("a", &[]), "a12uel5l");
}

#[test]
fn base58check_matches_bip32_test_vector_1() {
    let mut payload = hex_decode("0488b21e").unwrap();
    payload.extend([0u8]); // depth 0
    payload.extend([0u8; 4]); // parent fingerprint
    payload.extend([0u8; 4]); // child number
    payload.extend(
        hex_decode("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508").unwrap(),
    );
    payload.extend(
        hex_decode("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2").unwrap(),
    );
    assert_eq!(
        base58check(&payload),
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
    );
}

#[test]
fn onion_checksum_accepts_a_real_v3_address() {
    let real = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";
    let raw = base32_decode_lower(real.trim_end_matches(".onion")).unwrap();
    assert_eq!(raw.len(), 35);
    assert_eq!(raw[34], 3, "version byte");
    assert!(onion_is_valid(real));
    // Our own generator agrees with the real address's pubkey.
    assert_eq!(format!("{}.onion", onion_label(&raw[..32])), real);
    // One wrong character breaks the checksum.
    assert!(!onion_is_valid(
        "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczae.onion"
    ));
    assert!(!onion_is_valid("short.onion"));
}

#[test]
fn bip39_matches_the_trezor_vectors() {
    let zeros = bip39::mnemonic(&[0u8; 32]).unwrap();
    assert_eq!(zeros, format!("{}art", "abandon ".repeat(23)));
    assert_eq!(
        bip39::mnemonic(&[0x7f; 16]).unwrap(),
        "legal winner thank year wave sausage worth useful legal winner thank yellow"
    );
    assert!(bip39::mnemonic(&[0u8; 15]).is_none());
}

#[test]
fn bip39_wordlist_is_the_published_one() {
    assert_eq!(
        HEXLOWER.encode(&sha256(bip39::WORDLIST_TEXT.as_bytes())),
        "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
    );
    assert_eq!(bip39::words().len(), 2048);
}

#[test]
fn ipv6_text_follows_rfc_5952() {
    assert_eq!(
        ipv6_canonical("2001:db8:0:0:1:0:0:1").unwrap(),
        "2001:db8::1:0:0:1"
    );
    assert_eq!(
        ipv6_canonical("2001:db8:0:1:1:1:1:1").unwrap(),
        "2001:db8:0:1:1:1:1:1"
    );
    assert_eq!(
        ipv6_canonical("2001:db8:0:0:0:0:2:1").unwrap(),
        "2001:db8::2:1"
    );
    assert_eq!(
        ipv6_canonical("2001:DB8:0:0:0:0:2:1").unwrap(),
        "2001:db8::2:1"
    );
    assert_eq!(ipv6_text([0; 8]), "::");
    assert_eq!(ipv6_text([0, 0, 0, 0, 0, 0, 0, 1]), "::1");
    assert_eq!(ipv6_text([1, 0, 0, 0, 0, 0, 0, 0]), "1::");
}

proptest! {
    #![proptest_config(proptest_config())]

    #[test]
    fn own_encoders_agree_with_data_encoding(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
        prop_assert_eq!(hex(&bytes), HEXLOWER.encode(&bytes));
        prop_assert_eq!(base64(&bytes, false, true), BASE64.encode(&bytes));
        prop_assert_eq!(base64(&bytes, true, true), BASE64URL.encode(&bytes));
        prop_assert_eq!(base64(&bytes, true, false), BASE64URL_NOPAD.encode(&bytes));
        prop_assert_eq!(base32_lower(&bytes, false), BASE32_NOPAD.encode(&bytes).to_lowercase());
        prop_assert_eq!(base32_lower(&bytes, true), data_encoding::BASE32.encode(&bytes).to_lowercase());
        prop_assert_eq!(base64_decode(&BASE64.encode(&bytes)), Some(bytes.clone()));
        prop_assert_eq!(base64_decode(&BASE64URL_NOPAD.encode(&bytes)), Some(bytes.clone()));
        prop_assert_eq!(base32_decode_lower(&base32_lower(&bytes, false)), Some(bytes.clone()));
        prop_assert_eq!(hex_decode(&hex(&bytes)), Some(bytes));
    }
}

fn proptest_config() -> ProptestConfig {
    // The house pattern: a fixed seed by default, `GD_PROPTEST_SEED=<n>` to explore (see tests/README.md).
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
