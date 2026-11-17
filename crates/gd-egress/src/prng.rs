//! SplitMix64, exactly as in the reference C at prng.di.unimi.it/splitmix64.c.
//!
//! Not for security: it makes reproducible lab canaries from a seed, so a run
//! can be repeated with the seed it printed.

/// The generator. One stream per run; the order of draws is fixed in `canary.rs`.
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Starts a stream at `seed`.
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// The next 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// `len` bytes: successive values in little-endian order. A value is never
    /// shared between two calls, so any bytes left over from the last value are dropped.
    pub fn fill_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len.saturating_add(8));
        while out.len() < len {
            out.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        out.truncate(len);
        out
    }
}
