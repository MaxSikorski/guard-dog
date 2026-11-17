use std::fmt;

/// Every error carries a fixed sentence and nothing else, so no key, message
/// text or relay reply can leak through an error value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyError {
    /// An input that is not in the accepted form.
    Invalid(&'static str),
    /// Encryption, decryption, signing or verification refused.
    Crypto(&'static str),
    /// The key file or its folder is not safe to use.
    KeyFile(&'static str),
    /// The relay did not behave, or could not be reached in time.
    Relay(&'static str),
    /// Guard Dog refuses to do this on purpose.
    Refused(&'static str),
    /// The operating system could not give random bytes.
    Entropy,
    /// The key store is not available on this operating system.
    UnsupportedPlatform,
}

impl fmt::Display for NotifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(m) => write!(f, "invalid input: {m}"),
            Self::Crypto(m) => write!(f, "cryptography refused: {m}"),
            Self::KeyFile(m) => write!(f, "notify key file: {m}"),
            Self::Relay(m) => write!(f, "relay: {m}"),
            Self::Refused(m) => write!(f, "refused: {m}"),
            Self::Entropy => f.write_str("the operating system gave no random bytes"),
            Self::UnsupportedPlatform => f.write_str(
                "The notifier's key store runs only on Linux, where Guard Dog can prove no other account can read the key. On this system it cannot, so no key is created or read.",
            ),
        }
    }
}

impl std::error::Error for NotifyError {}
