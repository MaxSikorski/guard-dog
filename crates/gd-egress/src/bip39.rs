//! BIP39 English mnemonics, so the seed-phrase canary has a valid checksum.
//!
//! The wordlist is the published `english.txt` (python-mnemonic, MIT; see
//! `LICENSE-bip39-wordlist`). A test pins its SHA-256.

use crate::encode::sha256;

/// The published English wordlist, one word per line.
pub const WORDLIST_TEXT: &str = include_str!("bip39-english.txt");

/// The 2,048 words, in order.
pub fn words() -> Vec<&'static str> {
    WORDLIST_TEXT.lines().collect()
}

/// The mnemonic for `entropy` (16 to 32 bytes, a multiple of 4), words joined by single spaces.
/// `None` for any other length.
pub fn mnemonic(entropy: &[u8]) -> Option<String> {
    if !(16..=32).contains(&entropy.len()) || !entropy.len().is_multiple_of(4) {
        return None;
    }
    let checksum_bits = entropy.len() / 4;
    let mut bits: Vec<bool> = entropy
        .iter()
        .flat_map(|&b| (0..8).rev().map(move |i| (b >> i) & 1 == 1))
        .collect();
    let hash = sha256(entropy);
    let first = hash.first().copied().unwrap_or(0);
    bits.extend((0..checksum_bits).map(|i| (first >> (7 - i)) & 1 == 1));
    let list = words();
    let mut out = Vec::new();
    for chunk in bits.as_chunks::<11>().0 {
        let index = chunk
            .iter()
            .fold(0usize, |acc, &bit| (acc << 1) | usize::from(bit));
        out.push(*list.get(index)?);
    }
    Some(out.join(" "))
}
