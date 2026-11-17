//! Finding canaries in any encoding, and keeping them out of printed text.
//!
//! Every haystack is looked at through several views (raw, lowercase,
//! percent-decoded, `\/`-unescaped, letters only). Each canary is searched for
//! as its text, its hex, its base64, base64url and base32 at every alignment,
//! and (for long ones) its first and last 24 characters. Shape detectors catch
//! lab-style secrets whose value this run did not plant.

use crate::canary::{CanarySet, Class};
use crate::encode::{base32_lower, base64, hex};
use regex::bytes::Regex;
use std::collections::BTreeSet;

/// What a hit means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HitKind {
    /// A planted canary of this class.
    Canary(Class),
    /// A secret-looking value of this shape that this run did not plant.
    Shape(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Where {
    /// The lowercase, percent-decoded and unescaped views.
    Text,
    /// The raw bytes only (binary needles).
    Raw,
    /// The letters-only view (seed-phrase windows).
    Letters,
}

#[derive(Debug, Clone)]
struct Pattern {
    class: Class,
    bytes: Vec<u8>,
    place: Where,
    /// No ASCII digit may touch either end (IPv4 text).
    digit_boundary: bool,
}

/// Every needle for one run's canaries.
#[derive(Debug)]
pub struct Needles {
    patterns: Vec<Pattern>,
    shapes: Vec<(Regex, &'static str)>,
    canary_texts: Vec<Vec<u8>>,
}

const SHAPES: [(&str, &str); 5] = [
    ("gdlabcanary-[0-9a-f]{64}", "gdlabcanary"),
    ("gdcanary-host-[a-z2-7]{10}", "gdcanary-host"),
    ("nsec1[02-9ac-hj-np-z]{58}", "nsec"),
    ("[xtyzuv]prv[1-9a-hj-np-z]{100,112}", "xprv"),
    ("0201036c6e64[0-9a-f]{88,}", "macaroon"),
];

fn lower(bytes: &[u8]) -> Vec<u8> {
    bytes.to_ascii_lowercase()
}

fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// `%XX` decoded (either case), `+` as a space, bad escapes left alone, then lowercased.
fn percent_decoded(bytes: &[u8]) -> Vec<u8> {
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
    lower(&out)
}

/// `\/` turned into `/` (JSON escaping), then lowercased.
fn unescaped(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&c) = bytes.get(i) {
        if c == b'\\' && bytes.get(i + 1) == Some(&b'/') {
            out.push(b'/');
            i += 2;
        } else {
            out.push(c);
            i += 1;
        }
    }
    lower(&out)
}

fn letters_only(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .filter(|b| b.is_ascii_alphabetic())
        .map(u8::to_ascii_lowercase)
        .collect()
}

fn positions<'a>(hay: &'a [u8], pat: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    let first = pat.first().copied();
    let width = pat.len().max(1);
    hay.windows(width)
        .enumerate()
        .filter(move |(_, w)| w.first().copied() == first && *w == pat)
        .map(|(i, _)| i)
}

fn digit_free(hay: &[u8], start: usize, len: usize) -> bool {
    let before = start.checked_sub(1).and_then(|i| hay.get(i));
    let after = hay.get(start + len);
    !before.is_some_and(u8::is_ascii_digit) && !after.is_some_and(u8::is_ascii_digit)
}

fn occurs(hay: &[u8], pattern: &Pattern) -> bool {
    positions(hay, &pattern.bytes)
        .any(|i| !pattern.digit_boundary || digit_free(hay, i, pattern.bytes.len()))
}

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
        let mut patterns = Vec::new();
        let mut canary_texts = Vec::new();
        for canary in &set.canaries {
            let class = canary.class;
            let text = canary.text.to_ascii_lowercase();
            canary_texts.push(text.clone().into_bytes());
            let mut added: Vec<Pattern> = Vec::new();
            let mut add = |s: String, place: Where, digit_boundary: bool| {
                added.push(Pattern {
                    class,
                    bytes: s.to_ascii_lowercase().into_bytes(),
                    place,
                    digit_boundary,
                });
            };
            add(text.clone(), Where::Text, class == Class::Ipv4);
            // Encodings are made from the text as written (a rune is case-sensitive); only the comparison is lowercase.
            let original = canary.text.as_bytes();
            add(hex(original), Where::Text, false);
            for s in base64_forms(original, false)
                .into_iter()
                .chain(base64_forms(original, true))
            {
                add(s, Where::Text, false);
            }
            for s in base32_forms(original) {
                add(s, Where::Text, false);
            }
            if text.len() >= 40 {
                add(text.chars().take(24).collect(), Where::Text, false);
                add(
                    text.chars()
                        .skip(text.chars().count().saturating_sub(24))
                        .collect(),
                    Where::Text,
                    false,
                );
            }
            match class {
                Class::Macaroon => {
                    if let Some(bytes) = &canary.bytes {
                        patterns.push(Pattern {
                            class,
                            bytes: bytes.clone(),
                            place: Where::Raw,
                            digit_boundary: false,
                        });
                        for s in base64_forms(bytes, false)
                            .into_iter()
                            .chain(base64_forms(bytes, true))
                        {
                            add(s, Where::Text, false);
                        }
                    }
                }
                Class::SeedPhrase => {
                    let words: Vec<&str> = text.split(' ').collect();
                    for window in words.windows(3) {
                        add(window.concat(), Where::Letters, false);
                    }
                }
                Class::Ipv6 => {
                    if let Ok(addr) = canary.text.parse::<std::net::Ipv6Addr>() {
                        let full: Vec<String> =
                            addr.segments().iter().map(|g| format!("{g:04x}")).collect();
                        add(full.join(":"), Where::Text, false);
                    }
                }
                _ => {}
            }
            patterns.extend(added);
        }
        let shapes = SHAPES
            .iter()
            .filter_map(|(pattern, name)| Regex::new(pattern).ok().map(|r| (r, *name)))
            .collect();
        Needles {
            patterns,
            shapes,
            canary_texts,
        }
    }

    /// How many shape detectors compiled (five, always).
    pub fn shape_count(&self) -> usize {
        self.shapes.len()
    }

    fn explained(&self, matched: &[u8]) -> bool {
        self.canary_texts
            .iter()
            .any(|t| t.windows(matched.len().max(1)).any(|w| w == matched))
    }

    /// Every canary class and secret shape found in `hay`, in any view.
    pub fn scan(&self, hay: &[u8]) -> BTreeSet<HitKind> {
        let lowered = lower(hay);
        let decoded = percent_decoded(hay);
        let unescaped = unescaped(hay);
        let letters = letters_only(hay);
        let mut hits = BTreeSet::new();
        for p in &self.patterns {
            let found = match p.place {
                Where::Raw => occurs(hay, p),
                Where::Letters => occurs(&letters, p),
                Where::Text => [&lowered, &decoded, &unescaped]
                    .into_iter()
                    .any(|view| occurs(view, p)),
            };
            if found {
                hits.insert(HitKind::Canary(p.class));
            }
        }
        for (regex, name) in &self.shapes {
            for view in [&lowered, &decoded] {
                if regex.find_iter(view).any(|m| !self.explained(m.as_bytes())) {
                    hits.insert(HitKind::Shape(name));
                }
            }
        }
        hits
    }

    /// `text` with every canary or secret in it replaced by `<canary:CLASS>` or
    /// `<secret:SHAPE>`. Each hit grows to the whole run of base64-ish characters
    /// around it, so a canary cut short still disappears completely.
    pub fn redact(&self, text: &str) -> String {
        let bytes = text.as_bytes();
        let lowered = lower(bytes);
        let mut ranges: Vec<(usize, usize, String)> = Vec::new();
        for p in self.patterns.iter().filter(|p| p.place == Where::Text) {
            for i in positions(&lowered, &p.bytes) {
                if !p.digit_boundary || digit_free(&lowered, i, p.bytes.len()) {
                    ranges.push((i, i + p.bytes.len(), format!("<canary:{}>", p.class.name())));
                }
            }
        }
        for (regex, name) in &self.shapes {
            for m in regex.find_iter(&lowered) {
                if !self.explained(m.as_bytes()) {
                    ranges.push((m.start(), m.end(), format!("<secret:{name}>")));
                }
            }
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
        let mut cursor = 0usize;
        let mut ranges = ranges.into_iter().peekable();
        while let Some((start, mut end, label)) = ranges.next() {
            while let Some((_, next_end, _)) = ranges.next_if(|(s, _, _)| *s <= end) {
                end = end.max(next_end);
            }
            if let Some(kept) = bytes.get(cursor..start) {
                out.extend_from_slice(kept);
            }
            out.extend_from_slice(label.as_bytes());
            cursor = end;
        }
        if let Some(rest) = bytes.get(cursor..) {
            out.extend_from_slice(rest);
        }
        String::from_utf8_lossy(&out).into_owned()
    }
}
