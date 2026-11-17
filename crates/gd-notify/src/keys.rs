//! Guard Dog's own Nostr key pair.

use crate::encoding::{hex_encode, hex32_secret};
use crate::{Entropy, NotifyError};
use k256::schnorr::SigningKey;
use std::fmt;
use zeroize::Zeroizing;

/// A BIP-340 key pair. The secret never leaves this type except to be written
/// to the 0600 key file, and `Debug` shows nothing.
pub struct Keys {
    signing: SigningKey,
}

impl Keys {
    /// A fresh key pair from `entropy` (the OS generator in production).
    pub fn generate(entropy: &mut dyn Entropy) -> Result<Keys, NotifyError> {
        for _ in 0..16 {
            let mut bytes = Zeroizing::new([0u8; 32]);
            entropy.fill(bytes.as_mut_slice())?;
            if let Ok(signing) = SigningKey::from_slice(bytes.as_slice()) {
                return Ok(Keys { signing });
            }
        }
        Err(NotifyError::Entropy)
    }

    /// From 64 lowercase hex characters. Zero and out-of-range values are refused.
    pub fn from_secret_hex(text: &str) -> Result<Keys, NotifyError> {
        let bad = NotifyError::Invalid("not a valid secret key");
        let bytes = hex32_secret(text).map_err(|_| bad)?;
        let signing = SigningKey::from_slice(bytes.as_slice()).map_err(|_| bad)?;
        Ok(Keys { signing })
    }

    /// The x-only public key (32 bytes).
    pub fn public_x(&self) -> Result<[u8; 32], NotifyError> {
        let bytes = self.signing.verifying_key().to_bytes();
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| NotifyError::Crypto("internal length error"))
    }

    /// The public key as 64 lowercase hex characters.
    pub fn public_hex(&self) -> Result<String, NotifyError> {
        Ok(hex_encode(&self.public_x()?))
    }

    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    /// The secret as hex, for the key file only.
    pub(crate) fn secret_hex(&self) -> Zeroizing<String> {
        let bytes = Zeroizing::new(self.signing.to_bytes());
        Zeroizing::new(hex_encode(bytes.as_slice()))
    }
}

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Keys(<redacted>)")
    }
}
