//! Core Lightning runes: accept only one limited to `getinfo` with no parameters.
//!
//! # What is read
//!
//! The rune string (at most 1 KiB) is URL-safe base64, with or without `=`
//! padding; any other character is refused. The first 32 decoded bytes are the
//! SHA-256 state and are not read. The rest is the restriction text:
//!
//! - restrictions are separated by `&`, alternatives within one by `|`;
//! - an alternative is `<field><condition><value>`, the condition being the
//!   first unescaped one of `!=/^$~<>{}#`;
//! - `\` escapes the next character;
//! - the unique id is a restriction with an empty field and `=`, whose value
//!   is digits with an optional `-<digits>` (for example `=0` or `=7-1`).
//!
//! Accepted: exactly one unique id, plus exactly the two single-alternative
//! restrictions `method=getinfo` and `pnum=0`, in either order.

use std::fmt;

/// The largest rune string read, in bytes.
pub const MAX_INPUT_BYTES: usize = 1024;
const MAX_RESTRICTIONS: usize = 64;
const CONDITIONS: &[u8] = b"!=/^$~<>{}#";

/// A rune proved limited to `getinfo` with no parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NarrowRune {}

/// Why a rune was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuneRefusal {
    /// More than 1 KiB.
    Oversize,
    /// Not a rune Guard Dog can read; the reason is a fixed phrase.
    Malformed {
        /// A fixed, non-secret phrase saying which part was wrong.
        why: &'static str,
    },
    /// No restrictions apart from its id: it can do anything.
    Unrestricted,
    /// Some restriction offers alternatives (`|`).
    Alternatives,
    /// Not limited to the `getinfo` method.
    NotLimitedToGetinfo,
    /// Limited to `getinfo` but not to calling it with no parameters.
    NotLimitedToNoParameters,
    /// Restrictions Guard Dog doesn't understand, or a wrong number of ids.
    UncheckableRestrictions,
}

impl fmt::Display for RuneRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const FIX: &str = "Create one with `lightning-cli createrune restrictions='[[\"method=getinfo\"],[\"pnum=0\"]]'`";
        match self {
            RuneRefusal::Oversize => {
                write!(f, "This rune is too long to be one (over 1 KiB). {FIX}.")
            }
            RuneRefusal::Malformed { why } => {
                write!(
                    f,
                    "This isn't a rune Guard Dog can read ({why}). Check you gave it the whole rune and nothing else. {FIX}."
                )
            }
            RuneRefusal::Unrestricted => {
                write!(
                    f,
                    "This rune has no restrictions, so it can do anything on your node. {FIX}."
                )
            }
            RuneRefusal::Alternatives => write!(
                f,
                "This rune offers a choice of conditions (a `|`), so it may allow more than getinfo. {FIX}."
            ),
            RuneRefusal::NotLimitedToGetinfo => write!(
                f,
                "This rune is not limited to getinfo, so it may allow other calls. {FIX}."
            ),
            RuneRefusal::NotLimitedToNoParameters => write!(
                f,
                "This rune can call getinfo with parameters; Guard Dog wants it limited to calling it with none. {FIX}."
            ),
            RuneRefusal::UncheckableRestrictions => {
                write!(
                    f,
                    "This rune has restrictions Guard Dog can't check, so it won't use it. {FIX}."
                )
            }
        }
    }
}

impl std::error::Error for RuneRefusal {}

fn bad(why: &'static str) -> RuneRefusal {
    RuneRefusal::Malformed { why }
}

/// Decodes URL-safe base64, padded or not. Nothing else is accepted.
fn base64url(text: &[u8]) -> Option<Vec<u8>> {
    let mut data = text;
    let mut pad = 0;
    while let Some((b'=', rest)) = data.split_last() {
        data = rest;
        pad += 1;
    }
    if pad > 2 || (pad > 0 && text.len() % 4 != 0) || data.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(data.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in data {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        acc = acc << 6 | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Splits on `sep` where it is not escaped by a backslash. Segments keep their
/// escapes. A backslash at the very end is an error.
fn split_unescaped(text: &[u8], sep: u8) -> Result<Vec<&[u8]>, RuneRefusal> {
    let mut parts = Vec::new();
    let (mut start, mut i) = (0usize, 0usize);
    while let Some(&c) = text.get(i) {
        if c == b'\\' {
            if i + 1 >= text.len() {
                return Err(bad("it ends with a lone backslash"));
            }
            i += 2;
            continue;
        }
        if c == sep {
            parts.push(text.get(start..i).unwrap_or_default());
            start = i + 1;
        }
        i += 1;
    }
    parts.push(text.get(start..).unwrap_or_default());
    Ok(parts)
}

fn unescape(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    let mut iter = text.iter();
    while let Some(&c) = iter.next() {
        if c == b'\\' {
            if let Some(&next) = iter.next() {
                out.push(next);
            }
        } else {
            out.push(c);
        }
    }
    out
}

struct Alternative {
    field: Vec<u8>,
    condition: u8,
    value: Vec<u8>,
}

fn alternative(text: &[u8]) -> Result<Alternative, RuneRefusal> {
    let mut i = 0usize;
    while let Some(&c) = text.get(i) {
        if c == b'\\' {
            i += 2;
            continue;
        }
        if CONDITIONS.contains(&c) {
            return Ok(Alternative {
                field: unescape(text.get(..i).unwrap_or_default()),
                condition: c,
                value: unescape(text.get(i + 1..).unwrap_or_default()),
            });
        }
        i += 1;
    }
    Err(bad("a restriction has no condition"))
}

fn is_unique_id(alt: &Alternative) -> bool {
    if !alt.field.is_empty() || alt.condition != b'=' {
        return false;
    }
    let mut parts = alt.value.split(|b| *b == b'-');
    let digits = |p: &[u8]| !p.is_empty() && p.iter().all(u8::is_ascii_digit);
    let first_ok = parts.next().is_some_and(digits);
    let second_ok = parts.next().is_none_or(digits);
    first_ok && second_ok && parts.next().is_none()
}

fn is_exactly(alt: &Alternative, field: &[u8], value: &[u8]) -> bool {
    alt.field == field && alt.condition == b'=' && alt.value == value
}

/// Proves a rune narrow, or says why not. See the module docs.
pub fn check(input: &[u8]) -> Result<NarrowRune, RuneRefusal> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(RuneRefusal::Oversize);
    }
    let decoded = base64url(input).ok_or(bad("it is not URL-safe base64"))?;
    let text = decoded
        .get(32..)
        .ok_or(bad("it is too short to be a rune"))?;
    if text.is_empty() {
        return Err(RuneRefusal::Unrestricted);
    }
    if !text.iter().all(|b| (0x20..0x7f).contains(b)) {
        return Err(bad("its restrictions are not plain text"));
    }

    let mut restrictions: Vec<Vec<Alternative>> = Vec::new();
    for segment in split_unescaped(text, b'&')? {
        if segment.is_empty() {
            return Err(bad("it has an empty restriction"));
        }
        if restrictions.len() >= MAX_RESTRICTIONS {
            return Err(bad("it has too many restrictions"));
        }
        let alts = split_unescaped(segment, b'|')?
            .into_iter()
            .map(alternative)
            .collect::<Result<Vec<_>, _>>()?;
        restrictions.push(alts);
    }

    let mut ids = 0usize;
    let mut others: Vec<&Vec<Alternative>> = Vec::new();
    for restriction in &restrictions {
        match restriction.as_slice() {
            [single] if is_unique_id(single) => ids += 1,
            _ => others.push(restriction),
        }
    }
    if others.is_empty() {
        return Err(RuneRefusal::Unrestricted);
    }
    if others.iter().any(|r| r.len() > 1) {
        return Err(RuneRefusal::Alternatives);
    }

    let (mut method, mut pnum, mut unknown) = (0usize, 0usize, 0usize);
    for restriction in &others {
        match restriction.as_slice() {
            [alt] if is_exactly(alt, b"method", b"getinfo") => method += 1,
            [alt] if is_exactly(alt, b"pnum", b"0") => pnum += 1,
            _ => unknown += 1,
        }
    }
    if unknown > 0 || ids != 1 || method > 1 || pnum > 1 {
        return Err(RuneRefusal::UncheckableRestrictions);
    }
    if method == 0 {
        return Err(RuneRefusal::NotLimitedToGetinfo);
    }
    if pnum == 0 {
        return Err(RuneRefusal::NotLimitedToNoParameters);
    }
    Ok(NarrowRune {})
}
