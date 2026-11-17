//! Checks against values made by other people's code: a hand-written NIP-01
//! id, and the gift wraps printed in the NIP-59 and NIP-17 specifications.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use gd_notify::Keys;
use gd_notify::event::{Event, UnsignedEvent, unwrap_any, unwrap_dm};
use serde_json::Value;

/// The canonical array is written out by hand below (never built by
/// `serde_json`), and its SHA-256 was computed by Python's `hashlib`, so the
/// expected id has nothing in common with the code under test. The content has
/// a newline, a quote, a backslash, a control character (U+0001, written
/// `\u0001` as JSON.stringify and every JSON library do) and a non-ASCII letter.
#[test]
fn event_id_matches_an_independently_computed_vector() {
    let event = UnsignedEvent {
        pubkey: "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e".to_owned(),
        created_at: 1_700_000_000,
        kind: 1,
        tags: vec![vec!["t".to_owned(), "x".to_owned()]],
        content: "a\nb\"c\\d\u{1}é".to_owned(),
    };
    let by_hand = r#"[0,"7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e",1700000000,1,[["t","x"]],"a\nb\"c\\d\u0001é"]"#;
    assert!(by_hand.contains(r#"\u0001"#) && by_hand.contains(r#"\\d"#));
    assert_eq!(
        event.id(),
        "d7c6af4ef21f0059fcefa40c2c2a8ce4a12c4168dbc94c265dce58411f777014"
    );
}

fn examples() -> Value {
    serde_json::from_str(include_str!("vectors/nip59_nip17_examples.json")).unwrap()
}

fn open(name: &str, any_kind: bool) {
    let all = examples();
    let case = &all[name];
    let recipient =
        Keys::from_secret_hex(case["recipient_secret"].as_str().unwrap()).unwrap();
    let wrap = Event::from_json(&case["wrap"].to_string()).unwrap();
    wrap.verify().unwrap();
    let opened = if any_kind {
        unwrap_any(&recipient, &wrap).unwrap()
    } else {
        unwrap_dm(&recipient, &wrap).unwrap()
    };
    assert_eq!(opened.rumor.content, case["expect_content"].as_str().unwrap());
    assert_eq!(opened.rumor.kind, case["expect_rumor_kind"].as_u64().unwrap());
    opened.seal.verify().unwrap();
    assert_eq!(opened.rumor.pubkey, opened.seal.pubkey);
}

#[test]
fn we_open_the_gift_wrap_printed_in_nip_59() {
    open("nip59_example", true);
    // It is a kind-1 rumor, not a direct message, so the DM opener refuses it.
    let all = examples();
    let case = &all["nip59_example"];
    let recipient = Keys::from_secret_hex(case["recipient_secret"].as_str().unwrap()).unwrap();
    let wrap = Event::from_json(&case["wrap"].to_string()).unwrap();
    assert!(unwrap_dm(&recipient, &wrap).is_err());
}

#[test]
fn we_open_the_direct_message_printed_in_nip_17() {
    open("nip17_example", false);
}
