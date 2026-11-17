//! `Untrusted<T>` in JSON: always `{"untrusted": <raw>}`, read back only from
//! that exact shape, and never any more readable than before (`Debug` still
//! hides it, the byte count shows no text).

// Test-only crate: failed checks are panics. See expected_matches.rs.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use gd_core::Untrusted;
use proptest::prelude::*;

/// Hostile characters from `untrusted.rs`'s own generator: escapes, bidi
/// controls, quotes, a NUL, tag characters.
fn hostile_text() -> impl Strategy<Value = String> {
    const DANGEROUS: &str = "\u{0}\u{7}\t\n\r\u{1b}\u{7f}\u{85}\u{9b}\\&<>\"'\u{ad}\u{61c}\
        \u{200b}\u{200d}\u{200f}\u{2028}\u{202e}\u{2066}\u{2069}\u{2800}\u{feff}\u{fe0f}\
        \u{e0041}\u{e007f}\u{e0100}\u{338}\u{301}\u{1d173}{}[]:,";
    let dangerous = proptest::sample::select(DANGEROUS.chars().collect::<Vec<_>>());
    proptest::collection::vec(prop_oneof![any::<char>(), dangerous], 0..64)
        .prop_map(|chars| chars.into_iter().collect())
}

/// Fixed seed, like every property test here; `GD_PROPTEST_SEED` explores another.
fn config() -> ProptestConfig {
    let seed = std::env::var("GD_PROPTEST_SEED")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(0x6764_5f70_726f_7074);
    ProptestConfig {
        rng_seed: proptest::test_runner::RngSeed::Fixed(seed),
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn json_round_trips_and_keeps_the_wrapper(text in hostile_text()) {
        let json = serde_json::to_string(&Untrusted::new(text.clone())).unwrap();
        prop_assert!(json.starts_with(r#"{"untrusted":"#), "{json}");
        let back: Untrusted<String> = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(back.expose_untrusted(), &text);
        // The re-serialised form is byte-identical.
        prop_assert_eq!(serde_json::to_string(&back).unwrap(), json);
    }

    #[test]
    fn debug_and_length_never_show_the_text(text in hostile_text()) {
        let wrapped = Untrusted::new(text.clone());
        prop_assert_eq!(format!("{wrapped:?}"), "Untrusted(<hidden>)");
        prop_assert_eq!(wrapped.byte_len(), text.len());
    }
}

#[test]
fn only_the_exact_wrapper_shape_is_read() {
    for bad in [
        r#""bare string""#,
        r#"{"raw":"x"}"#,
        r#"{"untrusted":"x","extra":1}"#,
        r#"{"untrusted":1}"#,
        r#"["x"]"#,
        "null",
    ] {
        assert!(
            serde_json::from_str::<Untrusted<String>>(bad).is_err(),
            "accepted {bad}"
        );
    }
    assert!(serde_json::from_str::<Untrusted<String>>(r#"{"untrusted":"x"}"#).is_ok());
}

proptest! {
    #![proptest_config(config())]

    /// Serialising writes the raw text, JSON-escaped (only ASCII controls, quotes and
    /// backslashes: C1 and bidi controls stay raw, which is why every display still
    /// goes through `escape_for_*`): the output holds no raw ASCII control character, and the text appears only as the wrapper's value.
    #[test]
    fn serialised_text_has_no_raw_control_characters(text in hostile_text()) {
        let json = serde_json::to_string(&Untrusted::new(text.clone())).unwrap();
        prop_assert!(!json.chars().any(|c| c < ' '), "{json:?}");
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let object = value.as_object().unwrap();
        prop_assert_eq!(object.len(), 1);
        prop_assert_eq!(object["untrusted"].as_str().unwrap(), text.as_str());
    }
}
