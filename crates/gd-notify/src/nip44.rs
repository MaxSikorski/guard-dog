//! NIP-44 version 2 encryption, composed from RustCrypto primitives.
//!
//! The conversation key comes from ECDH and HKDF-extract; message keys from
//! HKDF-expand; the text is padded, encrypted with ChaCha20 and authenticated
//! with HMAC-SHA256. Checked against the official test vectors.

use crate::encoding::{base64_decode, base64_encode};
use crate::{Entropy, NotifyError};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use k256::schnorr::{SigningKey, VerifyingKey};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

const MIN_PLAINTEXT: usize = 1;
const MAX_PLAINTEXT: usize = 65_535;

/// The three keys one message uses. Wiped from memory when dropped.
pub struct MessageKeys {
    /// ChaCha20 key.
    pub chacha_key: [u8; 32],
    /// ChaCha20 nonce.
    pub chacha_nonce: [u8; 12],
    /// HMAC-SHA256 key.
    pub hmac_key: [u8; 32],
}

impl Drop for MessageKeys {
    fn drop(&mut self) {
        self.chacha_key.zeroize();
        self.chacha_nonce.zeroize();
        self.hmac_key.zeroize();
    }
}

fn take<const N: usize>(slice: Option<&[u8]>) -> Result<[u8; N], NotifyError> {
    slice
        .and_then(|s| s.try_into().ok())
        .ok_or(NotifyError::Crypto("internal length error"))
}

/// The conversation key between `secret` and the peer's x-only public key.
/// Refuses a secret that is not a valid key or a public key that is not a point.
pub fn conversation_key(
    secret: &[u8; 32],
    public_x: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, NotifyError> {
    let signing = SigningKey::from_slice(secret)
        .map_err(|_| NotifyError::Crypto("not a valid secret key"))?;
    conversation_key_for(&signing, public_x)
}

pub(crate) fn conversation_key_for(
    signing: &SigningKey,
    public_x: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, NotifyError> {
    let peer = VerifyingKey::from_slice(public_x)
        .map_err(|_| NotifyError::Crypto("not a valid public key"))?;
    // Only the x coordinate of the shared point is used, so which of the two
    // points shares that x (the key's parity) does not matter.
    let shared = k256::ecdh::diffie_hellman(signing.as_nonzero_scalar(), peer.as_affine());
    let (prk, _) = Hkdf::<Sha256>::extract(Some(b"nip44-v2"), shared.raw_secret_bytes().as_slice());
    let prk = Zeroizing::new(prk);
    Ok(Zeroizing::new(take(Some(prk.as_slice()))?))
}

/// The keys for one message, from the conversation key and a 32-byte nonce.
pub fn message_keys(
    conversation_key: &[u8; 32],
    nonce: &[u8; 32],
) -> Result<MessageKeys, NotifyError> {
    let hk = Hkdf::<Sha256>::from_prk(conversation_key)
        .map_err(|_| NotifyError::Crypto("bad conversation key"))?;
    let mut okm = Zeroizing::new([0u8; 76]);
    hk.expand(nonce, okm.as_mut_slice())
        .map_err(|_| NotifyError::Crypto("key expansion failed"))?;
    Ok(MessageKeys {
        chacha_key: take(okm.get(0..32))?,
        chacha_nonce: take(okm.get(32..44))?,
        hmac_key: take(okm.get(44..76))?,
    })
}

/// The padded length for a message of `unpadded` bytes (1 or more). Worked in
/// `u128`, so the exact value is returned whenever it fits in a `usize`; only
/// a length whose padded size does not fit gives `usize::MAX` (no real message
/// is anywhere near that; both callers first limit the length to 65,535).
pub fn calc_padded_len(unpadded: usize) -> usize {
    if unpadded <= 32 {
        return 32;
    }
    let below = (unpadded - 1) as u128;
    let bits = u128::BITS - below.leading_zeros();
    let next_power = 1u128 << bits;
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power / 8
    };
    usize::try_from((below / chunk + 1) * chunk).unwrap_or(usize::MAX)
}

fn mac_of(
    hmac_key: &[u8; 32],
    nonce: &[u8; 32],
    ciphertext: &[u8],
) -> Result<Hmac<Sha256>, NotifyError> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(hmac_key)
        .map_err(|_| NotifyError::Crypto("bad mac key"))?;
    mac.update(nonce);
    mac.update(ciphertext);
    Ok(mac)
}

/// Encrypts `plaintext` (1 to 65,535 bytes) with an explicit nonce. Tests use
/// this with the vectors' nonces; callers use [`encrypt`].
pub fn encrypt_with_nonce(
    conversation_key: &[u8; 32],
    nonce: &[u8; 32],
    plaintext: &str,
) -> Result<String, NotifyError> {
    let bytes = plaintext.as_bytes();
    let len = bytes.len();
    if !(MIN_PLAINTEXT..=MAX_PLAINTEXT).contains(&len) {
        return Err(NotifyError::Crypto(
            "message length must be 1 to 65535 bytes",
        ));
    }
    let keys = message_keys(conversation_key, nonce)?;
    let padded = calc_padded_len(len);
    let prefix = u16::try_from(len).map_err(|_| NotifyError::Crypto("message too long"))?;
    let mut buf = Zeroizing::new(Vec::with_capacity(2 + padded));
    buf.extend_from_slice(&prefix.to_be_bytes());
    buf.extend_from_slice(bytes);
    buf.resize(2 + padded, 0);
    let mut cipher = ChaCha20::new((&keys.chacha_key).into(), (&keys.chacha_nonce).into());
    cipher.apply_keystream(buf.as_mut_slice());
    let tag = mac_of(&keys.hmac_key, nonce, &buf)?.finalize().into_bytes();
    let mut out = Vec::with_capacity(1 + 32 + buf.len() + 32);
    out.push(2);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&buf);
    out.extend_from_slice(tag.as_slice());
    Ok(base64_encode(&out))
}

/// Encrypts `plaintext` with a fresh random nonce.
pub fn encrypt(
    conversation_key: &[u8; 32],
    plaintext: &str,
    entropy: &mut dyn Entropy,
) -> Result<String, NotifyError> {
    let mut nonce = [0u8; 32];
    entropy.fill(&mut nonce)?;
    encrypt_with_nonce(conversation_key, &nonce, plaintext)
}

/// Decrypts a NIP-44 v2 payload. Anything malformed, unauthentic or
/// mis-padded is refused with the same kind of error.
pub fn decrypt(conversation_key: &[u8; 32], payload: &str) -> Result<String, NotifyError> {
    let bad = NotifyError::Crypto("payload refused");
    if payload.starts_with('#') || !(132..=87_472).contains(&payload.len()) {
        return Err(bad);
    }
    let data = base64_decode(payload).map_err(|_| bad)?;
    if !(99..=65_603).contains(&data.len()) || data.first() != Some(&2) {
        return Err(bad);
    }
    let nonce: [u8; 32] = take(data.get(1..33)).map_err(|_| bad)?;
    let mac_at = data.len() - 32;
    let ciphertext = data.get(33..mac_at).ok_or(bad)?;
    let tag = data.get(mac_at..).ok_or(bad)?;
    let keys = message_keys(conversation_key, &nonce).map_err(|_| bad)?;
    // Constant-time comparison of the tag.
    mac_of(&keys.hmac_key, &nonce, ciphertext)?
        .verify_slice(tag)
        .map_err(|_| bad)?;
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    let mut cipher = ChaCha20::new((&keys.chacha_key).into(), (&keys.chacha_nonce).into());
    cipher.apply_keystream(buf.as_mut_slice());
    let len = usize::from(u16::from_be_bytes(take(buf.get(0..2)).map_err(|_| bad)?));
    if len < MIN_PLAINTEXT || buf.len() != calc_padded_len(len).saturating_add(2) {
        return Err(bad);
    }
    let text = buf.get(2..2 + len).ok_or(bad)?;
    String::from_utf8(text.to_vec()).map_err(|_| bad)
}
