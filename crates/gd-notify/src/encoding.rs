//! Hex, base64 and npub (bech32), each small and strict.

use crate::NotifyError;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        for nibble in [b >> 4, b & 15] {
            out.push(char::from(
                HEX.get(usize::from(nibble)).copied().unwrap_or(b'0'),
            ));
        }
    }
    out
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Lowercase hex only, even length.
pub fn hex_decode(text: &str) -> Result<Vec<u8>, NotifyError> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(NotifyError::Invalid("hex has an odd length"));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for &[hi, lo] in bytes.as_chunks::<2>().0 {
        match (hex_val(hi), hex_val(lo)) {
            (Some(h), Some(l)) => out.push((h << 4) | l),
            _ => return Err(NotifyError::Invalid("hex must be lowercase 0-9a-f")),
        }
    }
    Ok(out)
}

/// Exactly 32 bytes of lowercase hex (64 characters).
pub fn hex32(text: &str) -> Result<[u8; 32], NotifyError> {
    hex_decode(text)?
        .try_into()
        .map_err(|_| NotifyError::Invalid("expected 64 hex characters"))
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding.
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                let idx = usize::try_from((n >> shift) & 63).unwrap_or(0);
                out.push(char::from(B64.get(idx).copied().unwrap_or(b'A')));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn b64_val(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Strict standard base64: padded, no whitespace, canonical (unused bits zero).
pub fn base64_decode(text: &str) -> Result<Vec<u8>, NotifyError> {
    let bad = NotifyError::Invalid("bad base64");
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err(bad);
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let groups = bytes.len() / 4;
    for (gi, quad) in bytes.as_chunks::<4>().0.iter().enumerate() {
        let last = gi + 1 == groups;
        let pad = quad.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return Err(bad);
        }
        let mut n: u32 = 0;
        for (i, &c) in quad.iter().enumerate() {
            let v = if i >= 4 - pad {
                0
            } else {
                b64_val(c).ok_or(bad)?
            };
            n = (n << 6) | v;
        }
        // Unused low bits must be zero, or two texts would mean the same bytes.
        if (pad == 1 && n & 0xff != 0) || (pad == 2 && n & 0xffff != 0) {
            return Err(bad);
        }
        for (i, shift) in [16u32, 8, 0].into_iter().enumerate() {
            if i < 3 - pad {
                out.push(u8::try_from((n >> shift) & 0xff).unwrap_or(0));
            }
        }
    }
    Ok(out)
}

const BECH32: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn polymod(values: impl Iterator<Item = u8>) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = hrp.iter().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(hrp.iter().map(|c| c & 31));
    v
}

/// Splits a lowercase-or-uppercase BIP-173 string into its human-readable
/// part and 5-bit values after checking every BIP-173 rule, the checksum
/// included. `None` if any rule fails.
fn bech32_split(text: &str) -> Option<(String, Vec<u8>)> {
    if text.len() > 90 || !text.is_ascii() {
        return None;
    }
    let has_lower = text.bytes().any(|c| c.is_ascii_lowercase());
    let has_upper = text.bytes().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return None;
    }
    let lower = text.to_ascii_lowercase();
    let pos = lower.rfind('1')?;
    let (hrp, rest) = lower.split_at(pos);
    let data = rest.get(1..)?;
    if hrp.is_empty() || data.len() < 6 {
        return None;
    }
    if !hrp.bytes().all(|c| (33..=126).contains(&c)) {
        return None;
    }
    let mut values = Vec::with_capacity(data.len());
    for c in data.bytes() {
        let idx = BECH32.iter().position(|&a| a == c)?;
        values.push(u8::try_from(idx).ok()?);
    }
    let all = hrp_expand(hrp.as_bytes())
        .into_iter()
        .chain(values.iter().copied());
    if polymod(all) != 1 {
        return None;
    }
    let payload_len = values.len() - 6;
    values.truncate(payload_len);
    Some((hrp.to_owned(), values))
}

/// True if `text` is a valid BIP-173 string (checksum and every format rule).
pub fn bech32_checksum_ok(text: &str) -> bool {
    bech32_split(text).is_some()
}

/// Reads an `npub1...` (NIP-19) into its 32 key bytes. Lowercase only.
pub fn npub_decode(text: &str) -> Result<[u8; 32], NotifyError> {
    let bad = NotifyError::Invalid("not a valid npub");
    if text.bytes().any(|c| c.is_ascii_uppercase()) {
        return Err(bad);
    }
    let (hrp, values) = bech32_split(text).ok_or(bad)?;
    if hrp != "npub" {
        return Err(bad);
    }
    // 5-bit groups to bytes; leftover bits must be fewer than 5 and zero.
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(32);
    for v in values {
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).map_err(|_| bad)?);
            acc &= (1 << bits) - 1;
        }
    }
    if bits >= 5 || acc != 0 {
        return Err(bad);
    }
    out.try_into().map_err(|_| bad)
}

/// Writes 32 key bytes as an `npub1...`.
pub fn npub_encode(key: &[u8; 32]) -> String {
    let mut values = Vec::with_capacity(52);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in key {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            values.push(u8::try_from((acc >> bits) & 31).unwrap_or(0));
            acc &= (1 << bits) - 1;
        }
    }
    if bits > 0 {
        values.push(u8::try_from((acc << (5 - bits)) & 31).unwrap_or(0));
    }
    let hrp = b"npub";
    let all = hrp_expand(hrp)
        .into_iter()
        .chain(values.iter().copied())
        .chain([0u8; 6]);
    let check = polymod(all) ^ 1;
    for i in 0..6u32 {
        values.push(u8::try_from((check >> (5 * (5 - i))) & 31).unwrap_or(0));
    }
    let mut out = String::from("npub1");
    for v in values {
        out.push(char::from(
            BECH32.get(usize::from(v)).copied().unwrap_or(b'q'),
        ));
    }
    out
}

/// A recipient given as an `npub1...` or as 64 lowercase hex characters.
/// Anything else (an `nsec`, a profile, a name) is refused.
pub fn parse_recipient(text: &str) -> Result<[u8; 32], NotifyError> {
    if text.starts_with("npub1") {
        npub_decode(text)
    } else {
        hex32(text)
            .map_err(|_| NotifyError::Invalid("recipient must be an npub or 64 hex characters"))
    }
}
