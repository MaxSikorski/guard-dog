use crate::NotifyError;
use std::time::{SystemTime, UNIX_EPOCH};

/// Where random bytes come from. Production uses the operating system; tests
/// use a fixed sequence.
pub trait Entropy {
    /// Fills `buf` with random bytes.
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), NotifyError>;
}

/// Where the time comes from.
pub trait Clock {
    /// Seconds since 1970-01-01 UTC, or an error when the clock cannot say
    /// (nothing is sent then; a wrong time is never guessed).
    fn now_unix(&self) -> Result<u64, NotifyError>;
}

/// The operating system's random number generator.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), NotifyError> {
        getrandom::fill(buf).map_err(|_| NotifyError::Entropy)
    }
}

/// The system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> Result<u64, NotifyError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| NotifyError::Refused("the system clock is before 1970; not sending"))
    }
}
