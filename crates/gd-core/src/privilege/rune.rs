//! Core Lightning runes: accept only one limited to `getinfo` with no parameters.
//!
//! # What is read
//!
//! The rune string (at most 1 KiB, trailing whitespace ignored) is URL-safe
//! base64, with or without `=` padding; any other character is refused. The
//! first 32 decoded bytes are the rune's SHA-256 state (its authentication code) and are not read. The
//! rest is the restriction text, and it is decided on its raw bytes:
//!
//! - any backslash refuses the rune (Guard Dog won't guess at escaping);
//! - restrictions are separated by `&`, alternatives within one by `|`, both
//!   split on the raw byte;
//! - the unique id is a restriction matching `^=[0-9]+(-[0-9]+)?$`.
//!
//! Accepted: exactly three restrictions. The first is the id; the other two
//! are byte-for-byte `method=getinfo` and `pnum=0`, in either order. An id
//! anywhere else, or any other restriction, refuses.

use std::fmt;

/// The largest rune string read, in bytes.
pub const MAX_INPUT_BYTES: usize = 1024;
const MAX_RESTRICTIONS: usize = 64;

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
    /// No restrictions apart from one id: it can do anything.
    Unrestricted,
    /// Its only restrictions are ids (more than one), so what it allows is unknown.
    OnlyIds,
    /// The restriction text contains a backslash.
    Backslash,
    /// Some restriction offers alternatives (`|`).
    Alternatives,
    /// Not limited to the `getinfo` method.
    NotLimitedToGetinfo,
    /// Limited to `getinfo` but not to calling it with no parameters.
    NotLimitedToNoParameters,
    /// Restrictions Guard Dog doesn't understand, or in the wrong places.
    UncheckableRestrictions,
}

impl fmt::Display for RuneRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const FIX: &str = "Create one with `lightning-cli createrune restrictions='[[\"method=getinfo\"],[\"pnum=0\"]]'`";
        match self {
            RuneRefusal::Oversize => {
                write!(f, "This rune is too long to be one (over 1 KiB). {FIX}.")
            }
            RuneRefusal::Malformed { why } => write!(
                f,
                "This isn't a rune Guard Dog can read ({why}). Check you gave it the whole rune and nothing else. {FIX}."
            ),
            RuneRefusal::Unrestricted => write!(
                f,
                "This rune has no restrictions, so it can do anything on your node. {FIX}."
            ),
            RuneRefusal::OnlyIds => write!(
                f,
                "This rune is no use to Guard Dog: its only restrictions are ids, so Guard Dog can't tell what it allows. {FIX}."
            ),
            RuneRefusal::Backslash => write!(
                f,
                "This rune has restrictions Guard Dog can't check: Guard Dog can't check restrictions containing a backslash. {FIX}."
            ),
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
            RuneRefusal::UncheckableRestrictions => write!(
                f,
                "This rune has restrictions Guard Dog can't check, so it won't use it. {FIX}."
            ),
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
    if pad > 2 || (pad > 0 && !text.len().is_multiple_of(4)) || data.len() % 4 == 1 {
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

/// Matches `^=[0-9]+(-[0-9]+)?$`.
fn is_unique_id(restriction: &[u8]) -> bool {
    let Some((b'=', value)) = restriction.split_first() else {
        return false;
    };
    let digits = |p: &[u8]| !p.is_empty() && p.iter().all(u8::is_ascii_digit);
    let mut parts = value.split(|b| *b == b'-');
    let first = parts.next().is_some_and(digits);
    let second = parts.next().is_none_or(digits);
    first && second && parts.next().is_none()
}

/// Proves a rune narrow, or says why not. See the module docs.
pub fn check(input: &[u8]) -> Result<NarrowRune, RuneRefusal> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(RuneRefusal::Oversize);
    }
    let end = input
        .iter()
        .rposition(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .map_or(0, |i| i + 1);
    let trimmed = input.get(..end).unwrap_or_default();
    let decoded = base64url(trimmed).ok_or(bad("it is not URL-safe base64"))?;
    let text = decoded
        .get(32..)
        .ok_or(bad("it is too short to be a rune"))?;
    if text.is_empty() {
        return Err(RuneRefusal::Unrestricted);
    }
    if text.contains(&b'\\') {
        return Err(RuneRefusal::Backslash);
    }
    if !text.iter().all(|b| (0x20..0x7f).contains(b)) {
        return Err(bad("its restrictions are not plain text"));
    }

    let restrictions: Vec<&[u8]> = text.split(|b| *b == b'&').collect();
    if restrictions.len() > MAX_RESTRICTIONS {
        return Err(bad("it has too many restrictions"));
    }
    if restrictions.iter().any(|r| r.is_empty()) {
        return Err(bad("it has an empty restriction"));
    }
    if restrictions.iter().any(|r| r.contains(&b'|')) {
        return Err(RuneRefusal::Alternatives);
    }
    if restrictions.iter().all(|r| is_unique_id(r)) {
        return Err(if restrictions.len() == 1 {
            RuneRefusal::Unrestricted
        } else {
            RuneRefusal::OnlyIds
        });
    }

    const METHOD: &[u8] = b"method=getinfo";
    const PNUM: &[u8] = b"pnum=0";
    match restrictions.as_slice() {
        [id, a, b] if is_unique_id(id) => match (*a, *b) {
            (METHOD, PNUM) | (PNUM, METHOD) => Ok(NarrowRune {}),
            _ => Err(RuneRefusal::UncheckableRestrictions),
        },
        [id, only] if is_unique_id(id) => match *only {
            METHOD => Err(RuneRefusal::NotLimitedToNoParameters),
            PNUM => Err(RuneRefusal::NotLimitedToGetinfo),
            _ => Err(RuneRefusal::UncheckableRestrictions),
        },
        _ => Err(RuneRefusal::UncheckableRestrictions),
    }
}
