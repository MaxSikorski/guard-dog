//! Finding canaries in any encoding, and keeping them out of printed text.
//!
//! Every haystack is looked at through several views (raw, percent-decoded,
//! JSON-unescaped; each also lowercase, separator-stripped and letters-only).
//! Each canary is searched for as its text, its hex, its alignments, its raw
//! bytes, and (for IP addresses) by value in every textual form. Base64,
//! base32 and hex tokens are decoded and scanned again, two layers deep.
//! Key bytes written out as source code (`0x8d, 0x1f`, `[141, 31]`, `\x8d\x1f`), an xpub
//! re-encoded under another version, and IP addresses in host-name, reverse-lookup and
//! IPv4-mapped forms are read too. Shape detectors catch lab-style secrets this run did not plant.

use crate::canary::{CanarySet, Class};
use crate::encode::{
    base32_decode_loose, base32_lower, base58_decode, base64, base64_decode_loose, hex, is_base58,
};
use regex::bytes::Regex;
use std::cell::Cell;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::Ipv6Addr;

/// What a hit means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HitKind {
    /// A planted canary of this class.
    Canary(Class),
    /// A secret-looking value of this shape that this run did not plant.
    Shape(&'static str),
}

/// At most this many bytes are scanned in one run (all layers, all haystacks).
pub const TOTAL_BUDGET: u64 = 256 * 1024 * 1024;
/// At most this many tokens are decoded per top-level haystack.
pub const TOKEN_BUDGET: usize = 4096;
/// Tokens shorter than this are not decoded.
const MIN_TOKEN: usize = 16;
/// Base58 runs shorter or longer than this are not decoded (an extended key is about 111).
const MIN_BASE58: usize = 100;
const MAX_BASE58: usize = 200;
/// An extended key: 111 base58 characters.
const KEY_BASE58: usize = 111;
/// Token decoding goes this many layers deep (the haystack is layer 0).
const MAX_LAYER: u8 = 2;

#[derive(Debug)]
struct Pat {
    class: Class,
    bytes: Vec<u8>,
    /// No ASCII digit may touch either end (IPv4 text).
    digit_boundary: bool,
}

/// Many byte patterns searched in one pass, indexed by their first four bytes.
#[derive(Debug, Default)]
struct PatternSet {
    items: Vec<Pat>,
    index: HashMap<[u8; 4], Vec<usize>>,
}

fn key4(bytes: &[u8]) -> Option<[u8; 4]> {
    bytes.get(..4).and_then(|k| k.try_into().ok())
}

impl PatternSet {
    fn add(&mut self, class: Class, bytes: Vec<u8>, digit_boundary: bool) {
        let Some(key) = key4(&bytes) else { return };
        self.index.entry(key).or_default().push(self.items.len());
        self.items.push(Pat {
            class,
            bytes,
            digit_boundary,
        });
    }

    /// Every match as (start, end, class).
    fn find(&self, hay: &[u8]) -> Vec<(usize, usize, Class)> {
        let mut out = Vec::new();
        if self.items.is_empty() {
            return out;
        }
        for (start, window) in hay.windows(4).enumerate() {
            let Some(candidates) = key4(window).and_then(|k| self.index.get(&k)) else {
                continue;
            };
            for &i in candidates {
                let Some(pat) = self.items.get(i) else {
                    continue;
                };
                let end = start + pat.bytes.len();
                if hay.get(start..end) == Some(pat.bytes.as_slice())
                    && (!pat.digit_boundary || digit_free(hay, start, pat.bytes.len()))
                {
                    out.push((start, end, pat.class));
                }
            }
        }
        out
    }
}

/// Every needle for one run's canaries.
#[derive(Debug)]
pub struct Needles {
    /// Searched in each view, lowercased.
    text: PatternSet,
    /// Searched in each view as it is (binary needles).
    raw: PatternSet,
    /// Searched in each view reduced to `[a-z0-9]`.
    stripped: PatternSet,
    /// Searched in each view reduced to letters (seed-phrase windows).
    letters: PatternSet,
    shapes: Vec<Shape>,
    canary_texts: Vec<Vec<u8>>,
    ipv4: Option<u32>,
    ipv6: Option<[u8; 16]>,
    grams: HashSet<Vec<u8>>,
    control_token: String,
}

#[derive(Debug)]
struct Shape {
    regex: Regex,
    name: &'static str,
    /// Matched on the view as it is (base58 is case-sensitive), not lowercased.
    case_sensitive: bool,
}

const SHAPES: [(&str, &str, bool); 5] = [
    ("gdlabcanary-[0-9a-f]{64}", "gdlabcanary", false),
    ("gdcanary-host-[a-z2-7]{10}", "gdcanary-host", false),
    ("nsec1[02-9ac-hj-np-z]{58}", "nsec", false),
    ("[xtyzuv]prv[1-9A-HJ-NP-Za-km-z]{100,112}", "xprv", true),
    ("0201036c6e64[0-9a-f]{88,}", "macaroon", false),
];

// ---- views ------------------------------------------------------------------

fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// `%XX` decoded (either case), `+` as a space, bad escapes left alone. Case is kept.
fn percent_decode(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&c) = bytes.get(i) {
        let decoded = (c == b'%')
            .then(|| {
                let hi = bytes.get(i + 1).copied().and_then(hex_value)?;
                let lo = bytes.get(i + 2).copied().and_then(hex_value)?;
                Some((hi << 4) | lo)
            })
            .flatten();
        match (decoded, c) {
            (Some(b), _) => {
                out.push(b);
                i += 3;
            }
            (None, b'+') => {
                out.push(b' ');
                i += 1;
            }
            (None, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

fn hex4(bytes: &[u8], at: usize) -> Option<u32> {
    let digits = bytes.get(at..at + 4)?;
    digits
        .iter()
        .try_fold(0u32, |acc, &d| Some((acc << 4) | u32::from(hex_value(d)?)))
}

/// JSON string escapes undone: `\" \\ \/ \b \f \n \r \t` and `\uXXXX` (with
/// surrogate pairs). An invalid or unfinished escape is left as it is. Case is kept.
fn json_unescape(bytes: &[u8]) -> Vec<u8> {
    json_unescape_with(bytes, false)
}

/// As [`json_unescape`]; with `latin1`, a `\u00XX` escape (and any `\uXXXX` up to `\u00FF`) is the
/// one byte `XX` rather than its UTF-8 form, which is how raw key bytes are written into JSON.
fn json_unescape_with(bytes: &[u8], latin1: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&c) = bytes.get(i) {
        if c != b'\\' {
            out.push(c);
            i += 1;
            continue;
        }
        let simple = match bytes.get(i + 1) {
            Some(b'"') => Some(b'"'),
            Some(b'\\') => Some(b'\\'),
            Some(b'/') => Some(b'/'),
            Some(b'b') => Some(8),
            Some(b'f') => Some(12),
            Some(b'n') => Some(b'\n'),
            Some(b'r') => Some(b'\r'),
            Some(b't') => Some(b'\t'),
            _ => None,
        };
        if let Some(b) = simple {
            out.push(b);
            i += 2;
            continue;
        }
        let unicode = (bytes.get(i + 1) == Some(&b'u'))
            .then(|| {
                let first = hex4(bytes, i + 2)?;
                match first {
                    0xD800..=0xDBFF => {
                        let tail = (bytes.get(i + 6) == Some(&b'\\')
                            && bytes.get(i + 7) == Some(&b'u'))
                        .then(|| hex4(bytes, i + 8))
                        .flatten()
                        .filter(|low| (0xDC00..=0xDFFF).contains(low))?;
                        let code = 0x10000 + ((first - 0xD800) << 10) + (tail - 0xDC00);
                        Some((char::from_u32(code)?, 12))
                    }
                    0xDC00..=0xDFFF => None,
                    _ => Some((char::from_u32(first)?, 6)),
                }
            })
            .flatten();
        match unicode {
            Some((ch, used)) => {
                match u8::try_from(u32::from(ch)) {
                    Ok(byte) if latin1 => out.push(byte),
                    _ => {
                        let mut buf = [0u8; 4];
                        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                    }
                }
                i += used;
            }
            None => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

fn stripped(lowered: &[u8]) -> Vec<u8> {
    lowered
        .iter()
        .filter(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        .copied()
        .collect()
}

fn letters(lowered: &[u8]) -> Vec<u8> {
    lowered
        .iter()
        .filter(|b| b.is_ascii_lowercase())
        .copied()
        .collect()
}

/// `0x` and `\x` markers taken out, so `[0x8d, 0x1f]` and `\x8d\x1f` read as plain hex pairs.
/// A `0x` only counts at the start of a number, not inside a longer word.
fn without_hex_markers(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&c) = bytes.get(i) {
        let marker = match (c, bytes.get(i + 1)) {
            (b'\\', Some(b'x' | b'X')) => true,
            (b'0', Some(b'x' | b'X')) => {
                let boundary = i
                    .checked_sub(1)
                    .and_then(|p| bytes.get(p))
                    .is_none_or(|p| !p.is_ascii_alphanumeric());
                boundary && bytes.get(i + 2).copied().and_then(hex_value).is_some()
            }
            _ => false,
        };
        if marker {
            i += 2;
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// One decimal number as a byte: 0 to 255, or a signed byte -128 to -1 (Java prints those).
fn decimal_byte(token: &[u8]) -> Option<u8> {
    match token.split_first() {
        Some((b'-', digits)) => {
            let n = small_number(digits, 3)?;
            u8::try_from(256u64.checked_sub(n).filter(|_| (1..=128).contains(&n))?).ok()
        }
        _ => u8::try_from(small_number(token, 3)?).ok(),
    }
}

/// One or two hex digits as a byte, with an optional `0x` in front (`b9`, `1`, `0x1`, `0XB9`).
fn hex_byte(token: &[u8]) -> Option<u8> {
    let digits = token
        .strip_prefix(b"0x")
        .or_else(|| token.strip_prefix(b"0X"))
        .unwrap_or(token);
    if digits.is_empty() || digits.len() > 2 {
        return None;
    }
    digits
        .iter()
        .try_fold(0u8, |acc, &d| Some((acc << 4) | hex_value(d)?))
}

/// Byte lists written out as numbers: decimal (`141, 31`, signed `-71`) and hex (`b9, 1`, `0x1`),
/// separated by commas, semicolons, white space or brackets, eight or more in a row, turned into
/// the bytes they stand for. One pass; a token that is neither ends both runs it breaks.
fn listed_byte_runs(view: &[u8]) -> Vec<Vec<u8>> {
    let separator = |b: &u8| {
        matches!(
            *b,
            b',' | b';' | b' ' | b'\t' | b'\r' | b'\n' | b'[' | b']' | b'(' | b')' | b'{' | b'}'
        )
    };
    let mut runs: Vec<Vec<u8>> = Vec::new();
    let (mut dec, mut hexes): (Vec<u8>, Vec<u8>) = (Vec::new(), Vec::new());
    let end = |run: &mut Vec<u8>, runs: &mut Vec<Vec<u8>>| {
        if run.len() >= 8 {
            runs.push(std::mem::take(run));
        }
        run.clear();
    };
    for token in view.split(separator).filter(|t| !t.is_empty()) {
        match decimal_byte(token) {
            Some(b) => dec.push(b),
            None => end(&mut dec, &mut runs),
        }
        match hex_byte(token) {
            Some(b) => hexes.push(b),
            None => end(&mut hexes, &mut runs),
        }
    }
    end(&mut dec, &mut runs);
    end(&mut hexes, &mut runs);
    runs
}

/// The bytes inside Python `b'...'` and `b"..."` literals, as `repr(bytes)` prints them:
/// printable characters as themselves, `\xNN`, `\n \r \t \\ \' \"` and `\0`.
/// Literals of eight or more bytes only.
fn python_bytes_literals(view: &[u8]) -> Vec<Vec<u8>> {
    let mut runs = Vec::new();
    let mut at = 0;
    while let Some(&c) = view.get(at) {
        let opens = c == b'b'
            && matches!(view.get(at + 1), Some(b'\'' | b'"'))
            && at
                .checked_sub(1)
                .and_then(|p| view.get(p))
                .is_none_or(|p| !p.is_ascii_alphanumeric());
        if !opens {
            at += 1;
            continue;
        }
        let quote = view.get(at + 1).copied().unwrap_or(b'\'');
        let mut bytes = Vec::new();
        let mut i = at + 2;
        while let Some(&b) = view.get(i) {
            if b == quote {
                break;
            }
            if b != b'\\' {
                bytes.push(b);
                i += 1;
                continue;
            }
            match view.get(i + 1) {
                Some(b'x') => {
                    let pair = view.get(i + 2..i + 4).and_then(|d| {
                        Some((hex_value(*d.first()?)? << 4) | hex_value(*d.get(1)?)?)
                    });
                    if let Some(byte) = pair {
                        bytes.push(byte);
                        i += 4;
                        continue;
                    }
                    bytes.push(b);
                    i += 1;
                }
                Some(&e) => {
                    bytes.push(match e {
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        b'0' => 0,
                        other => other,
                    });
                    i += 2;
                }
                None => i += 1,
            }
        }
        if bytes.len() >= 8 {
            runs.push(bytes);
        }
        at = i + 1;
    }
    runs
}

fn digit_free(hay: &[u8], start: usize, len: usize) -> bool {
    let before = start.checked_sub(1).and_then(|i| hay.get(i));
    let after = hay.get(start + len);
    !before.is_some_and(u8::is_ascii_digit) && !after.is_some_and(u8::is_ascii_digit)
}

// ---- IP addresses by value -----------------------------------------------------

/// The IP addresses a view mentions, in every supported textual form.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IpValues {
    /// IPv4 addresses: dotted quads, decimal integers and `0x` plus 8 hex digits.
    pub v4: BTreeSet<u32>,
    /// IPv6 addresses: any text `Ipv6Addr` reads, including a dotted IPv4 tail.
    pub v6: BTreeSet<[u8; 16]>,
}

fn small_number(digits: &[u8], max_len: usize) -> Option<u64> {
    if digits.is_empty() || digits.len() > max_len {
        return None;
    }
    digits.iter().try_fold(0u64, |acc, &d| {
        d.is_ascii_digit().then(|| acc * 10 + u64::from(d - b'0'))
    })
}

/// Records an IPv6 address, and the IPv4 address inside it when it is an IPv4-mapped one
/// (`::ffff:198.51.100.7`, which is also written `::ffff:c633:6407`).
fn add_v6(out: &mut IpValues, addr: Ipv6Addr) {
    out.v6.insert(addr.octets());
    if let Some(v4) = addr.to_ipv4_mapped() {
        out.v4.insert(u32::from(v4));
    }
}

/// The longest run at the end of `label` whose bytes all satisfy `member`.
fn trailing(label: &[u8], member: fn(&u8) -> bool) -> &[u8] {
    let start = label.iter().rposition(|b| !member(b)).map_or(0, |p| p + 1);
    label.get(start..).unwrap_or(&[])
}

/// Where reverse-lookup names end in `view`: for each `in-addr.arpa` and `ip6.arpa` (any case),
/// the offset where that suffix starts and whether it is the IPv6 one. One pass.
fn arpa_suffixes(view: &[u8]) -> Vec<(usize, bool)> {
    let mut found = Vec::new();
    for (at, window) in view.windows(4).enumerate() {
        if !window.eq_ignore_ascii_case(b"arpa") {
            continue;
        }
        let before = view.get(..at).unwrap_or(&[]);
        let ends = |suffix: &[u8]| {
            before
                .len()
                .checked_sub(suffix.len())
                .and_then(|from| before.get(from..))
                .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
        };
        if ends(b"in-addr.") {
            found.push((at - 8, false));
        } else if ends(b"ip6.") {
            found.push((at - 4, true));
        }
    }
    found
}

/// Finds the IP addresses in `view`.
pub fn ip_values(view: &[u8]) -> IpValues {
    let mut out = IpValues::default();
    // Four numbers in a row, separated by dots, dashes or underscores: `198.51.100.7`,
    // `ip-198-51-100-7`, `ip_198_51_100_7`. Single numbers are read as decimal integers.
    for run in view.split(|b| !(b.is_ascii_digit() || matches!(*b, b'.' | b'-' | b'_'))) {
        let parts: Vec<&[u8]> = run.split(|b| matches!(*b, b'.' | b'-' | b'_')).collect();
        for window in parts.windows(4) {
            let octets: Option<Vec<u8>> = window
                .iter()
                .map(|p| small_number(p, 3).and_then(|n| u8::try_from(n).ok()))
                .collect();
            if let Some(o) = octets.and_then(|o| <[u8; 4]>::try_from(o).ok()) {
                out.v4.insert(u32::from_be_bytes(o));
            }
        }
        for part in parts {
            let plain = part.len() == 1 || part.first() != Some(&b'0');
            let number = small_number(part, 10)
                .filter(|_| plain)
                .and_then(|n| u32::try_from(n).ok());
            out.v4.extend(number);
        }
    }
    // A reverse lookup name: the four numbers backwards, then `in-addr.arpa`. The first label may
    // have other text stuck to it, so only its trailing digits count.
    let arpa = arpa_suffixes(view);
    for at in arpa.iter().filter(|(_, v6)| !v6).map(|(at, _)| *at) {
        let before = view.get(..at.saturating_sub(1)).unwrap_or(&[]);
        let labels: Vec<&[u8]> = before.rsplit(|b| *b == b'.').take(4).collect();
        let octets: Option<Vec<u8>> = labels
            .iter()
            .enumerate()
            .map(|(i, label)| {
                let label = if i == 3 {
                    trailing(label, u8::is_ascii_digit)
                } else {
                    label
                };
                small_number(label, 3).and_then(|n| u8::try_from(n).ok())
            })
            .collect();
        // The name runs last number first, so reading it from the end gives the address in order.
        if let Some(o) = octets.and_then(|o| <[u8; 4]>::try_from(o).ok()) {
            out.v4.insert(u32::from_be_bytes(o));
        }
    }
    // The IPv6 form: 32 single-digit labels, the last nibble first, then `ip6.arpa`.
    for at in arpa.iter().filter(|(_, v6)| *v6).map(|(at, _)| *at) {
        let before = view.get(..at.saturating_sub(1)).unwrap_or(&[]);
        let nibbles: Vec<u8> = before
            .rsplit(|b| *b == b'.')
            .take(32)
            .enumerate()
            .filter_map(|(i, label)| {
                let label = if i == 31 {
                    trailing(label, u8::is_ascii_hexdigit)
                } else {
                    label
                };
                match label {
                    [c] => hex_value(*c),
                    _ => None,
                }
            })
            .collect();
        if nibbles.len() == 32 {
            // Read from the end of the name, the nibbles come in the address's own order.
            let mut octets = [0u8; 16];
            for (octet, pair) in octets.iter_mut().zip(nibbles.chunks(2)) {
                if let [hi, lo] = pair {
                    *octet = (hi << 4) | lo;
                }
            }
            add_v6(&mut out, Ipv6Addr::from(octets));
        }
    }
    for (i, window) in view.windows(10).enumerate() {
        let prefix = matches!(window.get(..2), Some(b"0x" | b"0X"));
        let digits = window.get(2..).and_then(|d| {
            d.iter()
                .try_fold(0u32, |acc, &c| Some((acc << 4) | u32::from(hex_value(c)?)))
        });
        let ends = !view.get(i + 10).copied().and_then(hex_value).is_some();
        if let (true, Some(n), true) = (prefix, digits, ends) {
            out.v4.insert(n);
        }
    }
    for run in view.split(|b| !(b.is_ascii_hexdigit() || *b == b':' || *b == b'.')) {
        if run.len() < 2 || !run.contains(&b':') {
            continue;
        }
        let trimmed = run
            .iter()
            .rposition(|b| *b != b'.')
            .and_then(|end| run.get(..=end))
            .unwrap_or(run);
        for candidate in [run, trimmed] {
            if let Some(addr) = std::str::from_utf8(candidate)
                .ok()
                .and_then(|s| s.parse::<Ipv6Addr>().ok())
            {
                add_v6(&mut out, addr);
            }
        }
    }
    out
}

// ---- tokens ----------------------------------------------------------------------

fn is_b64(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'-' | b'_')
}

/// Maximal base64 or base64url runs. CR, LF and space between alphabet
/// characters continue a run (line wrapping); `=` ends it.
fn base64_runs(view: &[u8]) -> Vec<Vec<u8>> {
    let mut runs = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    for &c in view {
        if is_b64(c) {
            current.push(c);
        } else if matches!(c, b'\r' | b'\n' | b' ') && !current.is_empty() {
            continue;
        } else {
            if current.len() >= MIN_TOKEN {
                runs.push(std::mem::take(&mut current));
            }
            current.clear();
        }
    }
    if current.len() >= MIN_TOKEN {
        runs.push(current);
    }
    runs
}

fn plain_runs(view: &[u8], member: fn(u8) -> bool) -> Vec<&[u8]> {
    view.split(|b| !member(*b))
        .filter(|r| r.len() >= MIN_TOKEN)
        .collect()
}

fn is_b32(c: u8) -> bool {
    c.is_ascii_alphabetic() || (b'2'..=b'7').contains(&c)
}

fn is_hex(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

// ---- the scanner -------------------------------------------------------------------

/// A scan session. It counts the bytes it has looked at, so a hostile capture
/// cannot make the judge run forever; going over the budget is reported by
/// [`Scanner::budget_exceeded`].
#[derive(Debug)]
pub struct Scanner<'a> {
    needles: &'a Needles,
    scanned: Cell<u64>,
    over: Cell<bool>,
    /// What this session may still unpack out of tokens.
    decode_left: Cell<crate::decode::Budget>,
}

impl Scanner<'_> {
    /// True once any budget (total bytes or tokens) has been exceeded.
    pub fn budget_exceeded(&self) -> bool {
        self.over.get()
    }

    fn charge(&self, len: usize) -> bool {
        let total = self.scanned.get().saturating_add(len as u64);
        self.scanned.set(total);
        if total > TOTAL_BUDGET {
            self.over.set(true);
        }
        !self.over.get()
    }

    /// Every canary class and secret shape found in `hay`: in its views, and in
    /// base64, base32 and hex tokens decoded up to two layers deep.
    pub fn scan(&self, hay: &[u8]) -> BTreeSet<HitKind> {
        let mut hits = BTreeSet::new();
        let mut tokens = 0usize;
        self.layer(hay, 0, &mut hits, &mut tokens);
        hits
    }

    /// Scans `hay`, then (while the shared two-layer bound allows) every way of
    /// unwrapping it one step: percent-decoded, JSON-unescaped, reduced to letters
    /// and digits only, and each base64, base32 or hex token decoded. A secret
    /// wrapped twice in any mix of these is still found; a third wrap is out of scope.
    fn layer(&self, hay: &[u8], depth: u8, hits: &mut BTreeSet<HitKind>, tokens: &mut usize) {
        if !self.charge(hay.len()) {
            return;
        }
        self.needles.scan_view(hay, hits);
        if depth >= MAX_LAYER {
            return;
        }
        let alnum: Vec<u8> = hay
            .iter()
            .filter(|b| b.is_ascii_alphanumeric())
            .copied()
            .collect();
        // Hex written with `0x` or `\x` markers reads as plain hex once they are gone.
        let has_marker = hay
            .windows(2)
            .any(|w| matches!(w, [b'\\' | b'0', b'x' | b'X']));
        let marker_free: Vec<u8> = if has_marker {
            without_hex_markers(hay)
                .into_iter()
                .filter(u8::is_ascii_alphanumeric)
                .collect()
        } else {
            Vec::new()
        };
        // Raw key bytes written into JSON as `\u00XX`: one byte per escape, not UTF-8.
        let latin1 = if hay.windows(2).any(|w| w == b"\\u") {
            json_unescape_with(hay, true)
        } else {
            Vec::new()
        };
        let mut children: Vec<Vec<u8>> = Vec::new();
        for candidate in [
            percent_decode(hay),
            json_unescape(hay),
            alnum,
            marker_free,
            latin1,
        ] {
            if !candidate.is_empty() && candidate != hay && !children.contains(&candidate) {
                children.push(candidate);
            }
        }
        children.extend(self.decode_tokens(hay, tokens));
        // Anything that now starts like gzip or zlib (a base64 or hex token holding a packed file)
        // is unpacked too, within the scanner's own decode budget. A stream that will not unpack
        // is taken for chance; a bound is a failed run.
        let mut unpacked: Vec<Vec<u8>> = Vec::new();
        for child in children
            .iter()
            .filter(|c| crate::decode::starts_compressed(c))
        {
            let mut budget = self.decode_left.get();
            let decoded = crate::decode::decode_with(&[], child, &mut budget);
            self.decode_left.set(budget);
            if decoded.problems.contains(crate::decode::BOUND) {
                self.over.set(true);
            }
            unpacked.extend(decoded.layers);
        }
        children.extend(unpacked);
        for child in children {
            self.layer(&child, depth + 1, hits, tokens);
        }
    }

    fn decode_tokens(&self, view: &[u8], tokens: &mut usize) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let take = |count: &mut usize| {
            *count += 1;
            if *count > TOKEN_BUDGET {
                self.over.set(true);
            }
            !self.over.get()
        };
        for run in base64_runs(view) {
            if !take(tokens) {
                return out;
            }
            for offset in 0..4 {
                out.push(base64_decode_loose(run.get(offset..).unwrap_or(&[])));
            }
        }
        for run in plain_runs(view, is_b32) {
            if !take(tokens) {
                return out;
            }
            for offset in 0..8 {
                out.push(base32_decode_loose(run.get(offset..).unwrap_or(&[])));
            }
        }
        for run in plain_runs(view, is_hex) {
            if !take(tokens) {
                return out;
            }
            for offset in 0..2 {
                let digits = run.get(offset..).unwrap_or(&[]);
                let usable = digits.get(..digits.len() - digits.len() % 2).unwrap_or(&[]);
                out.push(
                    crate::encode::hex_decode(&String::from_utf8_lossy(usable)).unwrap_or_default(),
                );
            }
        }
        // A key re-encoded under another version (xpub as zpub, ypub, tpub, ...) is a base58 run
        // of about 111 characters; decoded, the key data inside is the same. Whole runs of 100 to
        // 200 characters are decoded, and in any run the 111 characters that start at each
        // extended-key prefix, so a character stuck in front, or another key beside it, does not hide it.
        for run in plain_runs(view, is_base58) {
            let whole = (MIN_BASE58..=MAX_BASE58).contains(&run.len());
            if whole {
                if !take(tokens) {
                    return out;
                }
                out.extend(base58_decode(run));
            }
            for (at, window) in run.windows(4).enumerate() {
                let prefix = matches!(
                    window,
                    [
                        b'x' | b'y' | b'z' | b't' | b'u' | b'v' | b'Y' | b'Z' | b'U' | b'V',
                        b'p',
                        b'u',
                        b'b'
                    ]
                );
                let key = run.get(at..at + KEY_BASE58).filter(|_| prefix);
                if let Some(key) = key.filter(|_| !(whole && at == 0)) {
                    if !take(tokens) {
                        return out;
                    }
                    out.extend(base58_decode(key));
                }
            }
        }
        // Key bytes written as lists of numbers (`[141, 31, ...]`, `[b9, 1, ...]`, `-71`), and
        // Python bytes literals (`b'\xb9\x01T...'`).
        for bytes in listed_byte_runs(view)
            .into_iter()
            .chain(python_bytes_literals(view))
        {
            if !take(tokens) {
                return out;
            }
            out.push(bytes);
        }
        out
    }
}

// ---- building the needles -------------------------------------------------------------

/// Base64 forms at the three alignments: encode `k` zero bytes plus the data,
/// drop the first group when `k > 0` and always the last, keep 16 or more characters.
fn base64_forms(data: &[u8], url: bool) -> Vec<String> {
    (0..3usize)
        .filter_map(|k| aligned(data, k, |d| base64(d, url, true), 4))
        .collect()
}

fn base32_forms(data: &[u8]) -> Vec<String> {
    (0..5usize)
        .filter_map(|k| aligned(data, k, |d| base32_lower(d, true), 8))
        .collect()
}

fn aligned(
    data: &[u8],
    k: usize,
    encode: impl Fn(&[u8]) -> String,
    group: usize,
) -> Option<String> {
    let mut input = vec![0u8; k];
    input.extend_from_slice(data);
    let text = encode(&input);
    let skip = if k > 0 { group } else { 0 };
    let keep = text.len().checked_sub(group)?.checked_sub(skip)?;
    let slice = text.get(skip..skip + keep)?;
    (slice.len() >= 16).then(|| slice.to_ascii_lowercase())
}

impl Needles {
    /// Builds every needle for `set`.
    pub fn new(set: &CanarySet) -> Needles {
        let mut text = PatternSet::default();
        let mut raw = PatternSet::default();
        let mut stripped_set = PatternSet::default();
        let mut letters_set = PatternSet::default();
        let mut canary_texts = Vec::new();
        let mut grams: HashSet<Vec<u8>> = HashSet::new();
        let (mut ipv4, mut ipv6) = (None, None);
        for canary in &set.canaries {
            let class = canary.class;
            let lowered = canary.text.to_ascii_lowercase();
            canary_texts.push(lowered.clone().into_bytes());
            let is_ip = matches!(class, Class::Ipv4 | Class::Ipv6);
            // Encodings are made from the text as written (a rune is case-sensitive);
            // only the comparison is lowercase.
            let original = canary.text.as_bytes();
            let mut add = |s: String, boundary: bool| {
                text.add(class, s.to_ascii_lowercase().into_bytes(), boundary);
            };
            add(lowered.clone(), class == Class::Ipv4);
            add(hex(original), false);
            if !is_ip {
                for s in base64_forms(original, false)
                    .into_iter()
                    .chain(base64_forms(original, true))
                    .chain(base32_forms(original))
                {
                    add(s, false);
                }
            }
            if lowered.len() >= 40 {
                add(lowered.chars().take(24).collect(), false);
                add(
                    lowered
                        .chars()
                        .skip(lowered.chars().count().saturating_sub(24))
                        .collect(),
                    false,
                );
            }
            if let Some(bytes) = &canary.bytes {
                raw.add(class, bytes.clone(), false);
                for g in hex(bytes).as_bytes().windows(8) {
                    grams.insert(g.to_vec());
                }
                match class {
                    Class::Macaroon => {
                        for s in base64_forms(bytes, false)
                            .into_iter()
                            .chain(base64_forms(bytes, true))
                        {
                            add(s, false);
                        }
                    }
                    Class::Xpub => {
                        // The key data without its four version bytes (a zpub or tpub carries
                        // the same), the chain code and the key, found on their own.
                        for part in [bytes.get(4..78), bytes.get(13..45), bytes.get(45..78)]
                            .into_iter()
                            .flatten()
                        {
                            raw.add(class, part.to_vec(), false);
                        }
                    }
                    _ => {}
                }
            }
            match class {
                Class::SeedPhrase => {
                    let words: Vec<&str> = lowered.split(' ').collect();
                    for window in words.windows(3) {
                        letters_set.add(class, window.concat().into_bytes(), false);
                    }
                    // Words cut to their first four letters (the list's words differ in them).
                    let short: Vec<&str> = words.iter().map(|w| w.get(..4).unwrap_or(w)).collect();
                    for window in short.windows(3) {
                        letters_set.add(class, window.concat().into_bytes(), false);
                    }
                    // SeedQR: each word as its position in the list, four digits, run together.
                    let list = crate::bip39::words();
                    let digits: Vec<String> = words
                        .iter()
                        .filter_map(|w| list.iter().position(|x| x == w))
                        .map(|i| format!("{i:04}"))
                        .collect();
                    for window in digits.windows(3) {
                        stripped_set.add(class, window.concat().into_bytes(), false);
                    }
                }
                Class::Ipv4 => ipv4 = parse_ipv4(&canary.text),
                Class::Ipv6 => {
                    ipv6 = canary.text.parse::<Ipv6Addr>().ok().map(|a| a.octets());
                    if let Ok(addr) = canary.text.parse::<Ipv6Addr>() {
                        let full: Vec<String> =
                            addr.segments().iter().map(|g| format!("{g:04x}")).collect();
                        add(full.join(":"), false);
                    }
                }
                _ => {}
            }
            if !matches!(class, Class::Ipv4 | Class::SeedPhrase) {
                let reduced = stripped(lowered.as_bytes());
                if reduced.len() >= 20 {
                    stripped_set.add(class, reduced, false);
                }
            }
            for g in lowered.as_bytes().windows(8) {
                grams.insert(g.to_vec());
            }
        }
        let shapes = SHAPES
            .iter()
            .filter_map(|(pattern, name, case_sensitive)| {
                Regex::new(pattern).ok().map(|regex| Shape {
                    regex,
                    name,
                    case_sensitive: *case_sensitive,
                })
            })
            .collect();
        Needles {
            text,
            raw,
            stripped: stripped_set,
            letters: letters_set,
            shapes,
            canary_texts,
            ipv4,
            ipv6,
            grams,
            control_token: set.control_token.clone(),
        }
    }

    /// How many shape detectors compiled (five, always).
    pub fn shape_count(&self) -> usize {
        self.shapes.len()
    }

    /// A fresh scan session with its own budget.
    pub fn scanner(&self) -> Scanner<'_> {
        Scanner {
            needles: self,
            scanned: Cell::new(0),
            over: Cell::new(false),
            decode_left: Cell::new(crate::decode::Budget::capture()),
        }
    }

    /// Every canary class and secret shape found in `hay` (a fresh session).
    pub fn scan(&self, hay: &[u8]) -> BTreeSet<HitKind> {
        self.scanner().scan(hay)
    }

    fn explained(&self, matched: &[u8]) -> bool {
        let lowered = matched.to_ascii_lowercase();
        self.canary_texts.iter().any(|t| {
            t.windows(lowered.len().max(1))
                .any(|w| w == lowered.as_slice())
        })
    }

    /// Looks at one view with every kind of needle.
    fn scan_view(&self, view: &[u8], hits: &mut BTreeSet<HitKind>) {
        let lowered = view.to_ascii_lowercase();
        let mut found = |class: Class| {
            hits.insert(HitKind::Canary(class));
        };
        for (_, _, class) in self.text.find(&lowered) {
            found(class);
        }
        for (_, _, class) in self.raw.find(view) {
            found(class);
        }
        for (_, _, class) in self.stripped.find(&stripped(&lowered)) {
            found(class);
        }
        for (_, _, class) in self.letters.find(&letters(&lowered)) {
            found(class);
        }
        if self.ipv4.is_some() || self.ipv6.is_some() {
            let values = ip_values(view);
            if self.ipv4.is_some_and(|v| values.v4.contains(&v)) {
                found(Class::Ipv4);
            }
            if self.ipv6.is_some_and(|v| values.v6.contains(&v)) {
                found(Class::Ipv6);
            }
        }
        for shape in &self.shapes {
            let target = if shape.case_sensitive { view } else { &lowered };
            if shape
                .regex
                .find_iter(target)
                .any(|m| !self.explained(m.as_bytes()))
            {
                hits.insert(HitKind::Shape(shape.name));
            }
        }
    }

    /// Where hits sit in the raw bytes of `text`: (start, end, label).
    fn located(&self, text: &[u8]) -> Vec<(usize, usize, String)> {
        let lowered = text.to_ascii_lowercase();
        let mut ranges: Vec<(usize, usize, String)> = Vec::new();
        for (s, e, class) in self
            .text
            .find(&lowered)
            .into_iter()
            .chain(self.raw.find(text))
        {
            ranges.push((s, e, format!("<canary:{}>", class.name())));
        }
        for shape in &self.shapes {
            let target = if shape.case_sensitive { text } else { &lowered };
            for m in shape.regex.find_iter(target) {
                if !self.explained(m.as_bytes()) {
                    ranges.push((m.start(), m.end(), format!("<secret:{}>", shape.name)));
                }
            }
        }
        ranges
    }

    /// `text` made safe to print. The control token becomes `<control>`. If a
    /// canary or secret is in it, the hit's whole token run is replaced when
    /// it can be located in the raw bytes and nothing canary-derived remains;
    /// otherwise the whole string becomes `<canary:CLASS>` (or `<secret:SHAPE>`).
    pub fn redact(&self, text: &str) -> String {
        let text = replace_ignore_case(text, &self.control_token, "<control>");
        let hits = self.scan(text.as_bytes());
        let Some(first) = hits.iter().next() else {
            return text;
        };
        let whole = match first {
            HitKind::Canary(class) => format!("<canary:{}>", class.name()),
            HitKind::Shape(shape) => format!("<secret:{shape}>"),
        };
        let bytes = text.as_bytes();
        let mut ranges = self.located(bytes);
        if ranges.is_empty() {
            return whole;
        }
        let in_run =
            |b: &u8| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-');
        for (start, end, _) in &mut ranges {
            while start
                .checked_sub(1)
                .and_then(|i| bytes.get(i))
                .is_some_and(in_run)
            {
                *start -= 1;
            }
            while bytes.get(*end).is_some_and(in_run) {
                *end += 1;
            }
        }
        ranges.sort();
        let mut out = Vec::new();
        let mut kept_parts: Vec<Vec<u8>> = Vec::new();
        let mut cursor = 0usize;
        let mut ranges = ranges.into_iter().peekable();
        while let Some((start, mut end, label)) = ranges.next() {
            while let Some((_, next_end, _)) = ranges.next_if(|(s, _, _)| *s <= end) {
                end = end.max(next_end);
            }
            if let Some(kept) = bytes.get(cursor..start) {
                out.extend_from_slice(kept);
                kept_parts.push(kept.to_ascii_lowercase());
            }
            out.extend_from_slice(label.as_bytes());
            cursor = end;
        }
        if let Some(rest) = bytes.get(cursor..) {
            out.extend_from_slice(rest);
            kept_parts.push(rest.to_ascii_lowercase());
        }
        let partial = String::from_utf8_lossy(&out).into_owned();
        // The labels themselves name classes, so only the text kept between them is checked.
        let leftover = kept_parts
            .iter()
            .any(|part| part.windows(8).any(|w| self.grams.contains(w)));
        if leftover || !self.scan(partial.as_bytes()).is_empty() {
            return whole;
        }
        partial
    }
}

fn parse_ipv4(text: &str) -> Option<u32> {
    text.parse::<std::net::Ipv4Addr>().ok().map(u32::from)
}

fn replace_ignore_case(text: &str, needle: &str, with: &str) -> String {
    if needle.is_empty() {
        return text.to_string();
    }
    let (lowered, pattern) = (text.to_ascii_lowercase(), needle.to_ascii_lowercase());
    let mut out = String::new();
    let mut cursor = 0usize;
    for (at, _) in lowered.match_indices(&pattern) {
        if let Some(kept) = text.get(cursor..at) {
            out.push_str(kept);
        }
        out.push_str(with);
        cursor = at + pattern.len();
    }
    out.push_str(text.get(cursor..).unwrap_or(""));
    out
}
