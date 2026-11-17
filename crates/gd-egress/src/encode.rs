//! Small encoders and decoders, written by hand so the canaries and needles
//! need no extra crates. The tests check each one against the independent
//! `data-encoding` crate and against published test vectors.

use sha2::{Digest, Sha256};
use sha3::Sha3_256;

const HEX: &[u8] = b"0123456789abcdef";
const B64_STD: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B32_LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
const BECH32: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn pick(alphabet: &[u8], index: u32) -> char {
    usize::try_from(index)
        .ok()
        .and_then(|i| alphabet.get(i))
        .map_or('?', |&b| char::from(b))
}

/// Lowercase hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        out.push(pick(HEX, u32::from(b >> 4)));
        out.push(pick(HEX, u32::from(b & 15)));
    }
    out
}

/// Decodes lowercase or uppercase hexadecimal; `None` on odd length or a bad digit.
pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = text
        .bytes()
        .map(|c| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        })
        .collect::<Option<_>>()?;
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    Some(
        digits
            .as_chunks::<2>()
            .0
            .iter()
            .map(|[hi, lo]| (hi << 4) | lo)
            .collect(),
    )
}

/// Packs bytes into groups of `bits` bits (5 or 6), most significant first,
/// zero-padding the last group.
fn regroup(bytes: &[u8], bits: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let (mut acc, mut have) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        have += 8;
        while have >= bits {
            out.push((acc >> (have - bits)) & ((1 << bits) - 1));
            have -= bits;
        }
        acc &= (1 << have) - 1;
    }
    if have > 0 {
        out.push((acc << (bits - have)) & ((1 << bits) - 1));
    }
    out
}

/// Base64 (standard alphabet, or URL-safe when `url`), with `=` padding when `pad`.
pub fn base64(bytes: &[u8], url: bool, pad: bool) -> String {
    let alphabet = if url { B64_URL } else { B64_STD };
    let mut out: String = regroup(bytes, 6)
        .into_iter()
        .map(|v| pick(alphabet, v))
        .collect();
    if pad {
        while !out.len().is_multiple_of(4) {
            out.push('=');
        }
    }
    out
}

/// Decodes base64 in either alphabet, with or without padding; `None` on any
/// other character or an impossible length.
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let trimmed = text.trim_end_matches('=');
    if trimmed.len() % 4 == 1 {
        return None;
    }
    let mut values = Vec::with_capacity(trimmed.len());
    for c in trimmed.bytes() {
        let v = B64_STD
            .iter()
            .position(|&a| a == c)
            .or_else(|| B64_URL.iter().position(|&a| a == c))?;
        values.push(u32::try_from(v).ok()?);
    }
    Some(ungroup(&values, 6))
}

/// Inverse of [`regroup`]: drops the zero bits left over at the end.
fn ungroup(values: &[u32], bits: u32) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut acc, mut have) = (0u32, 0u32);
    for &v in values {
        acc = (acc << bits) | v;
        have += bits;
        if have >= 8 {
            out.push(u8::try_from((acc >> (have - 8)) & 0xff).unwrap_or(0));
            have -= 8;
        }
        acc &= (1 << have) - 1;
    }
    out
}

/// Lowercase base32 (RFC 4648 alphabet), with `=` padding when `pad`.
pub fn base32_lower(bytes: &[u8], pad: bool) -> String {
    let mut out: String = regroup(bytes, 5)
        .into_iter()
        .map(|v| pick(B32_LOWER, v))
        .collect();
    if pad {
        while !out.len().is_multiple_of(8) {
            out.push('=');
        }
    }
    out
}

/// Decodes unpadded lowercase base32; `None` on any other character.
pub fn base32_decode_lower(text: &str) -> Option<Vec<u8>> {
    let mut values = Vec::with_capacity(text.len());
    for c in text.trim_end_matches('=').bytes() {
        values.push(u32::try_from(B32_LOWER.iter().position(|&a| a == c)?).ok()?);
    }
    Some(ungroup(&values, 5))
}

fn bech32_polymod(values: &[u32]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk = 1u32;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ v;
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// Bech32 (BIP-173, not bech32m) of `data` under the human-readable part `hrp`.
pub fn bech32(hrp: &str, data: &[u8]) -> String {
    let groups = regroup(data, 5);
    let mut values: Vec<u32> = hrp.bytes().map(|c| u32::from(c >> 5)).collect();
    values.push(0);
    values.extend(hrp.bytes().map(|c| u32::from(c & 31)));
    values.extend(&groups);
    values.extend([0u32; 6]);
    let polymod = bech32_polymod(&values) ^ 1;
    let mut out = format!("{hrp}1");
    out.extend(groups.iter().map(|&v| pick(BECH32, v)));
    for i in 0..6u32 {
        out.push(pick(BECH32, (polymod >> (5 * (5 - i))) & 31));
    }
    out
}

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

/// Base58 of `payload` followed by the first four bytes of its double SHA-256.
pub fn base58check(payload: &[u8]) -> String {
    let mut data = payload.to_vec();
    data.extend(sha256(&sha256(payload)).iter().take(4));
    // Little-endian base-58 digits of the big number.
    let mut digits: Vec<u32> = Vec::new();
    for &byte in &data {
        let mut carry = u32::from(byte);
        for d in &mut digits {
            carry += *d * 256;
            *d = carry % 58;
            carry /= 58;
        }
        while carry > 0 {
            digits.push(carry % 58);
            carry /= 58;
        }
    }
    let zeros = data.iter().take_while(|&&b| b == 0).count();
    let mut out = String::new();
    out.extend(std::iter::repeat_n('1', zeros));
    out.extend(digits.iter().rev().map(|&d| pick(BASE58, d)));
    out
}

/// A version 3 onion address (without `.onion`) for a 32-byte public key.
pub fn onion_label(pubkey: &[u8]) -> String {
    let mut hash = Sha3_256::new();
    hash.update(b".onion checksum");
    hash.update(pubkey);
    hash.update([3u8]);
    let checksum = hash.finalize();
    let mut raw = pubkey.to_vec();
    raw.extend(checksum.iter().take(2));
    raw.push(3);
    base32_lower(&raw, false)
}

/// Whether `address` (with or without `.onion`) is a v3 address with a valid checksum.
pub fn onion_is_valid(address: &str) -> bool {
    let label = address.strip_suffix(".onion").unwrap_or(address);
    let Some(raw) = base32_decode_lower(label) else {
        return false;
    };
    if raw.len() != 35 {
        return false;
    }
    let (pubkey, tail) = raw.split_at(32);
    onion_label(pubkey).as_str() == label && tail.last() == Some(&3)
}

/// An IPv6 address as RFC 5952 text: lowercase, no leading zeros, and the first
/// longest run of two or more zero groups collapsed to `::`.
pub fn ipv6_text(groups: [u16; 8]) -> String {
    let (mut best_start, mut best_len) = (0usize, 0usize);
    let mut i = 0;
    while i < groups.len() {
        let run = groups.iter().skip(i).take_while(|&&g| g == 0).count();
        if run > best_len {
            (best_start, best_len) = (i, run);
        }
        i += run.max(1);
    }
    let show = |range: &[u16]| {
        range
            .iter()
            .map(|g| format!("{g:x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    if best_len < 2 {
        return show(&groups);
    }
    let head = groups.get(..best_start).unwrap_or(&[]);
    let tail = groups.get(best_start + best_len..).unwrap_or(&[]);
    format!("{}::{}", show(head), show(tail))
}

/// Reads any text form of an IPv6 address and returns its RFC 5952 form.
pub fn ipv6_canonical(text: &str) -> Option<String> {
    let addr: std::net::Ipv6Addr = text.parse().ok()?;
    Some(ipv6_text(addr.segments()))
}
