//! NIP-44 v2 against the official test vectors (see `vectors/README.md`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use common::SeqEntropy;
use gd_notify::encoding::{hex_decode, hex_encode, hex32};
use gd_notify::nip44;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn v2() -> Value {
    let all: Value = serde_json::from_str(include_str!("vectors/nip44.vectors.json")).unwrap();
    all["v2"].clone()
}

fn s(v: &Value, key: &str) -> String {
    v[key].as_str().unwrap().to_owned()
}

fn secret_to_pub_x(secret_hex: &str) -> [u8; 32] {
    gd_notify::Keys::from_secret_hex(secret_hex)
        .unwrap()
        .public_x()
        .unwrap()
}

#[test]
fn nip44_conversation_keys_match_the_vectors() {
    let list = v2()["valid"]["get_conversation_key"].clone();
    assert_eq!(list.as_array().unwrap().len(), 35);
    for case in list.as_array().unwrap() {
        let sec = hex32(&s(case, "sec1")).unwrap();
        let public = hex32(&s(case, "pub2")).unwrap();
        let key = nip44::conversation_key(&sec, &public).unwrap();
        assert_eq!(hex_encode(key.as_slice()), s(case, "conversation_key"));
    }
}

#[test]
fn nip44_message_keys_match_the_vectors() {
    let block = v2()["valid"]["get_message_keys"].clone();
    let ck = hex32(&s(&block, "conversation_key")).unwrap();
    let keys = block["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 32);
    for case in keys {
        let nonce = hex32(&s(case, "nonce")).unwrap();
        let got = nip44::message_keys(&ck, &nonce).unwrap();
        assert_eq!(hex_encode(&got.chacha_key), s(case, "chacha_key"));
        assert_eq!(hex_encode(&got.chacha_nonce), s(case, "chacha_nonce"));
        assert_eq!(hex_encode(&got.hmac_key), s(case, "hmac_key"));
    }
}

#[test]
fn nip44_padding_lengths_match_the_vectors() {
    let list = v2()["valid"]["calc_padded_len"].clone();
    assert_eq!(list.as_array().unwrap().len(), 24);
    for pair in list.as_array().unwrap() {
        let unpadded = pair[0].as_u64().unwrap() as usize;
        let padded = pair[1].as_u64().unwrap() as usize;
        assert_eq!(nip44::calc_padded_len(unpadded), padded, "for {unpadded}");
    }
}

#[test]
fn nip44_encrypt_and_decrypt_match_the_vectors() {
    let list = v2()["valid"]["encrypt_decrypt"].clone();
    assert_eq!(list.as_array().unwrap().len(), 10);
    for case in list.as_array().unwrap() {
        let sec1 = s(case, "sec1");
        let sec2 = s(case, "sec2");
        let want_key = s(case, "conversation_key");
        // Both directions of the key agreement give the vector's key.
        let a = nip44::conversation_key(&hex32(&sec1).unwrap(), &secret_to_pub_x(&sec2)).unwrap();
        let b = nip44::conversation_key(&hex32(&sec2).unwrap(), &secret_to_pub_x(&sec1)).unwrap();
        assert_eq!(hex_encode(a.as_slice()), want_key);
        assert_eq!(hex_encode(b.as_slice()), want_key);

        let nonce = hex32(&s(case, "nonce")).unwrap();
        let plaintext = s(case, "plaintext");
        let payload = s(case, "payload");
        let got = nip44::encrypt_with_nonce(&a, &nonce, &plaintext).unwrap();
        assert_eq!(got, payload);
        assert_eq!(nip44::decrypt(&a, &payload).unwrap(), plaintext);
    }
}

#[test]
fn nip44_long_messages_match_the_vectors() {
    let list = v2()["valid"]["encrypt_decrypt_long_msg"].clone();
    assert_eq!(list.as_array().unwrap().len(), 3);
    for case in list.as_array().unwrap() {
        let ck = hex32(&s(case, "conversation_key")).unwrap();
        let nonce = hex32(&s(case, "nonce")).unwrap();
        let plaintext = s(case, "pattern").repeat(case["repeat"].as_u64().unwrap() as usize);
        assert_eq!(
            hex_encode(&Sha256::digest(plaintext.as_bytes())),
            s(case, "plaintext_sha256")
        );
        let payload = nip44::encrypt_with_nonce(&ck, &nonce, &plaintext).unwrap();
        assert_eq!(
            hex_encode(&Sha256::digest(payload.as_bytes())),
            s(case, "payload_sha256")
        );
        assert_eq!(nip44::decrypt(&ck, &payload).unwrap(), plaintext);
    }
}

#[test]
fn nip44_invalid_conversation_key_inputs_are_refused() {
    let list = v2()["invalid"]["get_conversation_key"].clone();
    assert_eq!(list.as_array().unwrap().len(), 8);
    for case in list.as_array().unwrap() {
        let refused = match (hex32(&s(case, "sec1")), hex32(&s(case, "pub2"))) {
            (Ok(sec), Ok(public)) => nip44::conversation_key(&sec, &public).is_err(),
            _ => true,
        };
        assert!(refused, "accepted: {}", s(case, "note"));
    }
}

#[test]
fn nip44_invalid_message_lengths_are_refused() {
    let list = v2()["invalid"]["encrypt_msg_lengths"].clone();
    assert_eq!(list.as_array().unwrap().len(), 4);
    let ck = [7u8; 32];
    let mut entropy = SeqEntropy(0);
    for n in list.as_array().unwrap() {
        let text = "a".repeat(n.as_u64().unwrap() as usize);
        assert!(nip44::encrypt(&ck, &text, &mut entropy).is_err(), "len {n}");
    }
}

#[test]
fn nip44_invalid_payloads_are_refused() {
    let list = v2()["invalid"]["decrypt"].clone();
    assert_eq!(list.as_array().unwrap().len(), 12);
    for case in list.as_array().unwrap() {
        let ck = hex32(&s(case, "conversation_key")).unwrap();
        let payload = s(case, "payload");
        assert!(
            nip44::decrypt(&ck, &payload).is_err(),
            "accepted: {}",
            s(case, "note")
        );
    }
}

#[test]
fn nip44_random_round_trip_and_tampering() {
    let mut entropy = SeqEntropy(100);
    let ck = [9u8; 32];
    for text in ["a", "hello", &"x".repeat(1000), "héllo 🐕"] {
        let payload = nip44::encrypt(&ck, text, &mut entropy).unwrap();
        assert_eq!(nip44::decrypt(&ck, &payload).unwrap(), text);
        // Flip one character in the middle: the MAC must refuse it.
        let mut bytes = payload.into_bytes();
        let mid = bytes.len() / 2;
        bytes[mid] = if bytes[mid] == b'A' { b'B' } else { b'A' };
        let broken = String::from_utf8(bytes).unwrap();
        assert!(nip44::decrypt(&ck, &broken).is_err());
    }
    // Wrong key.
    let payload = nip44::encrypt(&ck, "secret", &mut entropy).unwrap();
    assert!(nip44::decrypt(&[8u8; 32], &payload).is_err());
    // hex round trip helper sanity.
    assert_eq!(hex_decode("00ff").unwrap(), vec![0, 255]);
}
