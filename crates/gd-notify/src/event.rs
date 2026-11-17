//! Nostr events (NIP-01) and the private direct message built from them:
//! a kind-14 rumor, sealed (kind 13, NIP-59) and gift wrapped (kind 1059).

use crate::encoding::{hex_decode, hex_encode, hex32};
use crate::keys::Keys;
use crate::{Clock, Entropy, NotifyError, nip44};
use k256::schnorr::{Signature, VerifyingKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fmt;

/// Seal and wrap timestamps are moved up to this far into the past.
pub const TIMESTAMP_WINDOW_SECS: u64 = 2 * 24 * 60 * 60;

/// An event before it is signed. A rumor is one of these, and is never signed.
/// `Debug` hides the content.
#[derive(Clone, PartialEq, Eq)]
pub struct UnsignedEvent {
    /// Author, 64 lowercase hex characters.
    pub pubkey: String,
    /// Unix time.
    pub created_at: u64,
    /// Event kind.
    pub kind: u64,
    /// Tags.
    pub tags: Vec<Vec<String>>,
    /// Content (plaintext for a rumor).
    pub content: String,
}

impl fmt::Debug for UnsignedEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnsignedEvent(<redacted>)")
    }
}

impl UnsignedEvent {
    /// NIP-01 id: SHA-256 of `[0, pubkey, created_at, kind, tags, content]`
    /// written as compact JSON.
    pub fn id(&self) -> String {
        let canonical = json!([
            0,
            self.pubkey,
            self.created_at,
            self.kind,
            self.tags,
            self.content
        ]);
        hex_encode(&Sha256::digest(canonical.to_string().as_bytes()))
    }
}

/// A signed event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// SHA-256 id, 64 hex characters.
    pub id: String,
    /// Author, 64 hex characters.
    pub pubkey: String,
    /// Unix time.
    pub created_at: u64,
    /// Event kind.
    pub kind: u64,
    /// Tags.
    pub tags: Vec<Vec<String>>,
    /// Content.
    pub content: String,
    /// BIP-340 signature, 128 hex characters.
    pub sig: String,
}

impl Event {
    /// Signs `unsigned` with `keys`. The author must be `keys`' own public key.
    pub fn sign(
        unsigned: UnsignedEvent,
        keys: &Keys,
        entropy: &mut dyn Entropy,
    ) -> Result<Event, NotifyError> {
        if unsigned.pubkey != keys.public_hex()? {
            return Err(NotifyError::Crypto("event author is not the signing key"));
        }
        let id = unsigned.id();
        let id_bytes = hex32(&id)?;
        let mut aux = [0u8; 32];
        entropy.fill(&mut aux)?;
        let sig = keys
            .signing_key()
            .sign_raw(&id_bytes, &aux)
            .map_err(|_| NotifyError::Crypto("signing failed"))?;
        Ok(Event {
            id,
            pubkey: unsigned.pubkey,
            created_at: unsigned.created_at,
            kind: unsigned.kind,
            tags: unsigned.tags,
            content: unsigned.content,
            sig: hex_encode(&sig.to_bytes()),
        })
    }

    fn unsigned(&self) -> UnsignedEvent {
        UnsignedEvent {
            pubkey: self.pubkey.clone(),
            created_at: self.created_at,
            kind: self.kind,
            tags: self.tags.clone(),
            content: self.content.clone(),
        }
    }

    /// Checks that the id is the hash of the content and the signature is
    /// valid for the author.
    pub fn verify(&self) -> Result<(), NotifyError> {
        let bad = NotifyError::Crypto("event id or signature is wrong");
        let id = self.unsigned().id();
        if id != self.id {
            return Err(bad);
        }
        let key =
            VerifyingKey::from_slice(&hex32(&self.pubkey).map_err(|_| bad)?).map_err(|_| bad)?;
        let sig =
            Signature::from_slice(&hex_decode(&self.sig).map_err(|_| bad)?).map_err(|_| bad)?;
        key.verify_raw(&hex32(&id).map_err(|_| bad)?, &sig)
            .map_err(|_| bad)
    }

    /// The event as the JSON object relays expect.
    pub fn to_json(&self) -> String {
        json!({
            "id": self.id,
            "pubkey": self.pubkey,
            "created_at": self.created_at,
            "kind": self.kind,
            "tags": self.tags,
            "content": self.content,
            "sig": self.sig,
        })
        .to_string()
    }

    /// Reads an event from JSON. Only the seven standard fields are read; the
    /// id and signature are not checked here (call [`Event::verify`]).
    pub fn from_json(text: &str) -> Result<Event, NotifyError> {
        let value: Value =
            serde_json::from_str(text).map_err(|_| NotifyError::Invalid("event is not JSON"))?;
        let core = core_fields(&value)?;
        let sig = string_field(&value, "sig")?;
        Ok(Event {
            id: string_field(&value, "id")?,
            pubkey: core.pubkey,
            created_at: core.created_at,
            kind: core.kind,
            tags: core.tags,
            content: core.content,
            sig,
        })
    }
}

fn string_field(value: &Value, name: &'static str) -> Result<String, NotifyError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(NotifyError::Invalid("event field missing or not text"))
}

fn core_fields(value: &Value) -> Result<UnsignedEvent, NotifyError> {
    let bad = NotifyError::Invalid("event field missing or wrong type");
    let mut tags = Vec::new();
    for tag in value.get("tags").and_then(Value::as_array).ok_or(bad)? {
        let mut row = Vec::new();
        for item in tag.as_array().ok_or(bad)? {
            row.push(item.as_str().ok_or(bad)?.to_owned());
        }
        tags.push(row);
    }
    Ok(UnsignedEvent {
        pubkey: string_field(value, "pubkey")?,
        created_at: value.get("created_at").and_then(Value::as_u64).ok_or(bad)?,
        kind: value.get("kind").and_then(Value::as_u64).ok_or(bad)?,
        tags,
        content: string_field(value, "content")?,
    })
}

/// `now` minus a random number of seconds from 0 to two days.
fn randomised_past(clock: &dyn Clock, entropy: &mut dyn Entropy) -> Result<u64, NotifyError> {
    let mut bytes = [0u8; 8];
    entropy.fill(&mut bytes)?;
    let back = u64::from_be_bytes(bytes) % (TIMESTAMP_WINDOW_SECS + 1);
    Ok(clock.now_unix()?.saturating_sub(back))
}

/// Builds the private message for `recipient`: a kind-14 rumor with a `p`
/// tag, sealed with `sender`'s key (kind 13), wrapped with a fresh throwaway
/// key (kind 1059). Returns the outer wrap, ready to publish.
pub fn gift_wrap_dm(
    sender: &Keys,
    recipient: &[u8; 32],
    message: &str,
    clock: &dyn Clock,
    entropy: &mut dyn Entropy,
) -> Result<Event, NotifyError> {
    let recipient_hex = hex_encode(recipient);
    let p_tag = vec![vec!["p".to_owned(), recipient_hex]];

    let rumor = UnsignedEvent {
        pubkey: sender.public_hex()?,
        created_at: clock.now_unix()?,
        kind: 14,
        tags: p_tag.clone(),
        content: message.to_owned(),
    };
    let rumor_json = json!({
        "id": rumor.id(),
        "pubkey": rumor.pubkey,
        "created_at": rumor.created_at,
        "kind": rumor.kind,
        "tags": rumor.tags,
        "content": rumor.content,
    })
    .to_string();

    let seal_key = nip44::conversation_key_for(sender.signing_key(), recipient)?;
    let seal = Event::sign(
        UnsignedEvent {
            pubkey: sender.public_hex()?,
            created_at: randomised_past(clock, entropy)?,
            kind: 13,
            tags: Vec::new(),
            content: nip44::encrypt(&seal_key, &rumor_json, entropy)?,
        },
        sender,
        entropy,
    )?;

    let wrap_keys = Keys::generate(entropy)?;
    let wrap_key = nip44::conversation_key_for(wrap_keys.signing_key(), recipient)?;
    Event::sign(
        UnsignedEvent {
            pubkey: wrap_keys.public_hex()?,
            created_at: randomised_past(clock, entropy)?,
            kind: 1059,
            tags: p_tag,
            content: nip44::encrypt(&wrap_key, &seal.to_json(), entropy)?,
        },
        &wrap_keys,
        entropy,
    )
}

/// What the recipient sees after opening a gift wrap. `Debug` hides it all.
#[derive(Clone, PartialEq, Eq)]
pub struct UnwrappedDm {
    /// The author of the seal, 64 hex characters (the real sender).
    pub sender: String,
    /// The verified seal (kind 13).
    pub seal: Event,
    /// The rumor (kind 14), unsigned.
    pub rumor: UnsignedEvent,
    /// The rumor's id as written in the message.
    pub rumor_id: String,
}

impl fmt::Debug for UnwrappedDm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnwrappedDm(<redacted>)")
    }
}

/// Opens a gift wrap addressed to `recipient` and requires the rumor to be a
/// direct message (kind 14). See [`unwrap_any`] for the checks.
pub fn unwrap_dm(recipient: &Keys, wrap: &Event) -> Result<UnwrappedDm, NotifyError> {
    let opened = unwrap_any(recipient, wrap)?;
    if opened.rumor.kind != 14 {
        return Err(NotifyError::Crypto("gift wrap is not a direct message"));
    }
    Ok(opened)
}

/// Opens a gift wrap addressed to `recipient`, whatever the rumor's kind,
/// checking every layer: the wrap's and seal's ids and signatures, their
/// kinds, that the rumor was written by the seal's author, and the rumor's id.
/// Used to check our code against other implementations' wraps.
pub fn unwrap_any(recipient: &Keys, wrap: &Event) -> Result<UnwrappedDm, NotifyError> {
    let bad = NotifyError::Crypto("gift wrap refused");
    if wrap.kind != 1059 {
        return Err(bad);
    }
    wrap.verify()?;
    let wrap_author = hex32(&wrap.pubkey).map_err(|_| bad)?;
    let wrap_key = nip44::conversation_key_for(recipient.signing_key(), &wrap_author)?;
    let seal = Event::from_json(&nip44::decrypt(&wrap_key, &wrap.content)?).map_err(|_| bad)?;
    if seal.kind != 13 {
        return Err(bad);
    }
    seal.verify()?;
    let seal_author = hex32(&seal.pubkey).map_err(|_| bad)?;
    let seal_key = nip44::conversation_key_for(recipient.signing_key(), &seal_author)?;
    let rumor_text = nip44::decrypt(&seal_key, &seal.content)?;
    let value: Value = serde_json::from_str(&rumor_text).map_err(|_| bad)?;
    let rumor = core_fields(&value).map_err(|_| bad)?;
    let rumor_id = string_field(&value, "id").map_err(|_| bad)?;
    if rumor.pubkey != seal.pubkey || rumor.id() != rumor_id {
        return Err(bad);
    }
    Ok(UnwrappedDm {
        sender: seal.pubkey.clone(),
        seal,
        rumor,
        rumor_id,
    })
}
