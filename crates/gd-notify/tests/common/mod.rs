//! Shared helpers: a deterministic entropy source and a fixed clock.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use gd_notify::{Clock, Entropy, NotifyError};
use sha2::{Digest, Sha256};

/// Bytes from SHA-256 of a counter: the same every run, different every call.
pub struct SeqEntropy(pub u64);

impl Entropy for SeqEntropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), NotifyError> {
        let mut done = 0;
        while done < buf.len() {
            self.0 += 1;
            let block = Sha256::digest(self.0.to_be_bytes());
            let n = (buf.len() - done).min(32);
            buf[done..done + n].copy_from_slice(&block[..n]);
            done += n;
        }
        Ok(())
    }
}

pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0
    }
}

/// 2026-11-17 12:00:00 UTC.
pub const NOW: u64 = 1_795_000_000;
