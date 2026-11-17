//! Decoding compressed request bodies before they are scanned.
//!
//! PLACEHOLDER for the tests-first commit: decodes nothing and reports nothing.

use std::collections::BTreeSet;

/// Decoded output is cut at this many bytes per body.
pub const MAX_OUTPUT: usize = 16 * 1024 * 1024;
/// Decoded output may be at most this many times its input.
pub const MAX_RATIO: usize = 1000;
/// Nested decoding stops after this many layers.
pub const MAX_LAYERS: usize = 3;
/// A coding that is not decoded, or a stream that is corrupt.
pub const UNDECODED: &str = "undecoded-content-encoding";
/// A bound was hit: output size, ratio or layers.
pub const BOUND: &str = "decode-bound";

/// What decoding one body gave.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Decoded {
    /// Every decoded output, one per layer (not the body itself).
    pub layers: Vec<Vec<u8>>,
    /// Problem codes: [`UNDECODED`] or [`BOUND`].
    pub problems: BTreeSet<&'static str>,
}

/// Decodes `body` as its headers (and its magic bytes) say.
pub fn decode_body(_headers: &[(Vec<u8>, Vec<u8>)], _body: &[u8]) -> Decoded {
    Decoded::default()
}
