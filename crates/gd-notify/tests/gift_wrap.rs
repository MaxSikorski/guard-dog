//! NIP-17 direct message: rumor (14), seal (13), gift wrap (1059).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use common::{FixedClock, NOW, SeqEntropy};
use gd_notify::event::{Event, unwrap_dm};
use gd_notify::test_support::gift_wrap_dm;
use gd_notify::{Keys, nip44};

const TWO_DAYS: u64 = 2 * 24 * 60 * 60;

fn keys(seed: u64) -> Keys {
    Keys::generate(&mut SeqEntropy(seed)).unwrap()
}

#[test]
fn wrap_unwrap_round_trip() {
    let sender = keys(1);
    let recipient = keys(2);
    let mut entropy = SeqEntropy(1000);
    let wrap = gift_wrap_dm(
        &sender,
        &recipient.public_x().unwrap(),
        "line one\nline two with a dog: 🐕",
        &FixedClock(NOW),
        &mut entropy,
    )
    .unwrap();

    // The outer event: kind 1059, tagged for the recipient, signed by a
    // throwaway key (never Guard Dog's own), id and signature valid.
    assert_eq!(wrap.kind, 1059);
    assert_eq!(
        wrap.tags,
        vec![vec!["p".to_owned(), recipient.public_hex().unwrap()]]
    );
    assert_ne!(wrap.pubkey, sender.public_hex().unwrap());
    assert_ne!(wrap.pubkey, recipient.public_hex().unwrap());
    wrap.verify().unwrap();
    assert!(wrap.created_at <= NOW && wrap.created_at >= NOW - TWO_DAYS);

    let opened = unwrap_dm(&recipient, &wrap).unwrap();
    // The seal inside was signed by Guard Dog's key.
    assert_eq!(opened.sender, sender.public_hex().unwrap());
    assert_eq!(opened.seal.kind, 13);
    assert!(opened.seal.tags.is_empty());
    assert_eq!(opened.seal.pubkey, sender.public_hex().unwrap());
    opened.seal.verify().unwrap();
    assert!(opened.seal.created_at <= NOW && opened.seal.created_at >= NOW - TWO_DAYS);
    // The rumor: kind 14, unsigned, one p tag, the message, written by the sender.
    assert_eq!(opened.rumor.kind, 14);
    assert_eq!(opened.rumor.content, "line one\nline two with a dog: 🐕");
    assert_eq!(
        opened.rumor.tags,
        vec![vec!["p".to_owned(), recipient.public_hex().unwrap()]]
    );
    assert_eq!(opened.rumor.pubkey, sender.public_hex().unwrap());
    assert_eq!(opened.rumor.id(), opened.rumor_id);
}

#[test]
fn only_the_recipient_can_open_it() {
    let sender = keys(1);
    let recipient = keys(2);
    let stranger = keys(3);
    let wrap = gift_wrap_dm(
        &sender,
        &recipient.public_x().unwrap(),
        "hello",
        &FixedClock(NOW),
        &mut SeqEntropy(50),
    )
    .unwrap();
    assert!(unwrap_dm(&stranger, &wrap).is_err());
    // The sender can't open it either (the wrap key is thrown away).
    assert!(unwrap_dm(&sender, &wrap).is_err());
}

#[test]
fn created_at_is_randomised_inside_the_window() {
    let sender = keys(1);
    let recipient = keys(2);
    let mut entropy = SeqEntropy(7);
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..40 {
        let wrap = gift_wrap_dm(
            &sender,
            &recipient.public_x().unwrap(),
            "x",
            &FixedClock(NOW),
            &mut entropy,
        )
        .unwrap();
        assert!(wrap.created_at <= NOW && wrap.created_at >= NOW - TWO_DAYS);
        let opened = unwrap_dm(&recipient, &wrap).unwrap();
        assert!(opened.seal.created_at <= NOW && opened.seal.created_at >= NOW - TWO_DAYS);
        seen.insert(wrap.created_at);
    }
    assert!(seen.len() > 30, "timestamps are not random enough");
}

#[test]
fn the_same_inputs_give_the_same_wrap() {
    let sender = keys(1);
    let recipient = keys(2);
    let make = || {
        gift_wrap_dm(
            &sender,
            &recipient.public_x().unwrap(),
            "x",
            &FixedClock(NOW),
            &mut SeqEntropy(9),
        )
        .unwrap()
        .to_json()
    };
    assert_eq!(make(), make());
}

#[test]
fn event_id_is_the_sha256_of_the_canonical_array() {
    use sha2::{Digest, Sha256};
    let sender = keys(1);
    let recipient = keys(2);
    let wrap = gift_wrap_dm(
        &sender,
        &recipient.public_x().unwrap(),
        "x",
        &FixedClock(NOW),
        &mut SeqEntropy(3),
    )
    .unwrap();
    let array = serde_json::to_string(&serde_json::json!([
        0,
        wrap.pubkey,
        wrap.created_at,
        wrap.kind,
        wrap.tags,
        wrap.content
    ]))
    .unwrap();
    let want: String = Sha256::digest(array.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(wrap.id, want);
}

#[test]
fn a_tampered_event_fails_verification() {
    let sender = keys(1);
    let recipient = keys(2);
    let wrap = gift_wrap_dm(
        &sender,
        &recipient.public_x().unwrap(),
        "x",
        &FixedClock(NOW),
        &mut SeqEntropy(3),
    )
    .unwrap();
    let mut changed = wrap.clone();
    changed.content.push('A');
    assert!(changed.verify().is_err());
    let mut resigned: Event = wrap.clone();
    resigned.sig = "00".repeat(64);
    assert!(resigned.verify().is_err());
    let mut bad_id = wrap.clone();
    bad_id.id = "00".repeat(32);
    assert!(bad_id.verify().is_err());
    wrap.verify().unwrap();
}

#[test]
fn json_form_is_a_plain_nostr_event() {
    let sender = keys(1);
    let recipient = keys(2);
    let wrap = gift_wrap_dm(
        &sender,
        &recipient.public_x().unwrap(),
        "x",
        &FixedClock(NOW),
        &mut SeqEntropy(3),
    )
    .unwrap();
    let v: serde_json::Value = serde_json::from_str(&wrap.to_json()).unwrap();
    let mut names: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "content",
            "created_at",
            "id",
            "kind",
            "pubkey",
            "sig",
            "tags"
        ]
    );
    let parsed = Event::from_json(&wrap.to_json()).unwrap();
    assert_eq!(parsed, wrap);
    // The wrap content is a NIP-44 payload: version byte 2 after base64.
    let raw = gd_notify::encoding::base64_decode(&wrap.content).unwrap();
    assert_eq!(raw[0], 2);
    let _ = nip44::calc_padded_len(1);
}

#[test]
fn oversized_messages_are_refused() {
    let sender = keys(1);
    let recipient = keys(2);
    let huge = "a".repeat(70_000);
    assert!(
        gift_wrap_dm(
            &sender,
            &recipient.public_x().unwrap(),
            &huge,
            &FixedClock(NOW),
            &mut SeqEntropy(3)
        )
        .is_err()
    );
}
