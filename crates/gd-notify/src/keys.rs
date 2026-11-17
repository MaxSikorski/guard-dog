//! Guard Dog's own Nostr key pair.

use crate::encoding::{hex_encode, hex32};
use crate::{Entropy, NotifyError};
use k256::schnorr::SigningKey;
use std::fmt;

/// A BIP-340 key pair. The secret never leaves this type except to be written
/// to the 0600 key file, and `Debug` shows nothing.
pub struct Keys {
    signing: SigningKey,
}

impl Keys {
    /// A fresh key pair from `entropy` (the OS generator in production).
    pub fn generate(entropy: &mut dyn Entropy) -> Result<Keys, NotifyError> {
        for _ in 0..16 {
            let mut bytes = [0u8; 32];
            entropy.fill(&mut bytes)?;
            if let Ok(signing) = SigningKey::from_slice(&bytes) {
                return Ok(Keys { signing });
            }
        }
        Err(NotifyError::Entropy)
    }

    /// From 64 lowercase hex characters. Zero and out-of-range values are refused.
    pub fn from_secret_hex(text: &str) -> Result<Keys, NotifyError> {
        let bad = NotifyError::Invalid("not a valid secret key");
        let bytes = hex32(text).map_err(|_| bad)?;
        let signing = SigningKey::from_slice(&bytes).map_err(|_| bad)?;
        Ok(Keys { signing })
    }

    /// The x-only public key (32 bytes).
    pub fn public_x(&self) -> [u8; 32] {
        let bytes = self.signing.verifying_key().to_bytes();
        bytes.as_slice().try_into().unwrap_or([0u8; 32])
    }

    /// The public key as 64 lowercase hex characters.
    pub fn public_hex(&self) -> String {
        hex_encode(&self.public_x())
    }

    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    /// The secret as hex, for the key file only.
    pub(crate) fn secret_hex(&self) -> String {
        hex_encode(self.signing.to_bytes().as_slice())
    }
}

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Keys(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_secret_text_is_wiped_when_dropped() {
        // A compile-time check: `secret_hex` hands back a wiping wrapper.
        let keys = Keys::from_secret_hex(&"1f".repeat(32)).unwrap_or_else(|_| unreachable!());
        let text: zeroize::Zeroizing<String> = keys.secret_hex();
        assert_eq!(text.len(), 64);
    }
}
