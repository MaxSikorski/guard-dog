//! LND macaroons: accept only one that allows exactly `info:read`.
//!
//! # What is read
//!
//! The input is the macaroon file's bytes, or the hex text of them (hex is
//! recognised only when every byte is an ASCII hex digit; the first byte of a
//! binary macaroon is 0x02, never one).
//! At most 4 KiB. The binary form is macaroon v2 (as in `macaroon.v2`):
//!
//! ```text
//! 0x02
//! [location 1] identifier 2   EOS(0)          header section
//! ( [location 1] identifier 2 [verification id 4]  EOS(0) )*   one per caveat
//! EOS(0)                                      ends the caveats
//! signature 6 (32 bytes)
//! ```
//!
//! Each field is `type varint, length varint, data`; EOS is a lone 0.
//!
//! Strictness: the header section, the signature, the end of input and the
//! identifier are read strictly; any other shape is refused. Caveats are read
//! tolerantly but bounded (at most 256, fields 1, 2 and 4 once each, in any
//! order inside a caveat): caveats can only narrow a macaroon, so their text
//! is only counted, never read or shown. A caveat with a verification id
//! (field 4) is a third-party caveat; it too only narrows, and is counted
//! separately.
//!
//! LND's identifier is a version byte (3) then a protobuf:
//! `MacaroonId { bytes nonce = 1; bytes storageId = 2; repeated Op ops = 3; }`
//! with `Op { string entity = 1; repeated string actions = 2; }`. Only the
//! varint and length-delimited wire types are read; others are refused. At
//! most 64 ops, 64 actions each, strings of at most 64 printable ASCII bytes.

use super::Reader;
use std::fmt;

/// The largest input read, in bytes (the hex form counts in full).
pub const MAX_INPUT_BYTES: usize = 4096;
const MAX_OPS: usize = 64;
const MAX_ACTIONS: usize = 64;
const MAX_NAME: u64 = 64;
const MAX_CAVEATS: usize = 256;

/// Permissions a macaroon can hold that Guard Dog knows by name, in the fixed
/// order they are listed to the user. Anything else is "an unknown permission".
const KNOWN: [&str; 10] = [
    "onchain:read",
    "offchain:read",
    "address:read",
    "message:read",
    "peers:read",
    "info:read",
    "invoices:read",
    "signer:read",
    "macaroon:read",
    "macaroon:generate",
];
const INFO_READ: usize = 5;

/// A macaroon proved to allow exactly `info:read`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarrowMacaroon {
    first_party: usize,
    third_party: usize,
}

impl NarrowMacaroon {
    /// How many first-party caveats it carries (each can only narrow it).
    pub fn first_party_caveats(&self) -> usize {
        self.first_party
    }

    /// How many third-party caveats it carries (each can only narrow it).
    pub fn third_party_caveats(&self) -> usize {
        self.third_party
    }
}

/// Why a macaroon was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MacaroonRefusal {
    /// More than 4 KiB.
    Oversize,
    /// Not a macaroon Guard Dog can read; the reason is a fixed phrase.
    Malformed {
        /// A fixed, non-secret phrase saying which part was wrong.
        why: &'static str,
    },
    /// Not macaroon format 2, or not an LND identifier version 3.
    WrongVersion,
    /// It holds no permissions at all.
    EmptyOps,
    /// It can change things (any `write` permission).
    Admin,
    /// Read-only, but more than `info:read`.
    TooWide {
        /// The known extra permissions, in a fixed order.
        extra: Vec<&'static str>,
        /// Whether it also holds a permission not on Guard Dog's list.
        unknown: bool,
    },
}

impl fmt::Display for MacaroonRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const FIX: &str = "Bake one with only `info:read`: `lncli bakemacaroon info:read`";
        match self {
            MacaroonRefusal::Oversize => write!(
                f,
                "This macaroon file is too big to be one (over 4 KiB). {FIX}."
            ),
            MacaroonRefusal::Malformed { why } => {
                write!(
                    f,
                    "This isn't a macaroon Guard Dog can read ({why}). Check you gave it the right file. {FIX}."
                )
            }
            MacaroonRefusal::WrongVersion => {
                write!(
                    f,
                    "This macaroon is in a format Guard Dog doesn't read (it expects an LND macaroon, format 2). {FIX}."
                )
            }
            MacaroonRefusal::EmptyOps => write!(
                f,
                "This macaroon allows nothing, so it can't read your node's version. {FIX}."
            ),
            MacaroonRefusal::Admin => write!(
                f,
                "This macaroon can change things on your node (it has write permissions, as the admin macaroon does). Guard Dog only logs in with one that can read the node's version. {FIX}."
            ),
            MacaroonRefusal::TooWide { extra, unknown } => {
                write!(
                    f,
                    "This macaroon can do more than read your node's version: it also has "
                )?;
                let mut parts: Vec<String> = extra.iter().map(|name| format!("`{name}`")).collect();
                if *unknown {
                    parts.push("an unknown permission".to_string());
                }
                write!(f, "{}. {FIX}.", parts.join(", "))
            }
        }
    }
}

impl std::error::Error for MacaroonRefusal {}

fn bad(why: &'static str) -> MacaroonRefusal {
    MacaroonRefusal::Malformed { why }
}

/// Proves a macaroon narrow, or says why not. See the module docs.
pub fn check(input: &[u8]) -> Result<NarrowMacaroon, MacaroonRefusal> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(MacaroonRefusal::Oversize);
    }
    if input.is_empty() {
        return Err(bad("it is empty"));
    }
    if input.iter().all(u8::is_ascii_hexdigit) {
        let decoded = from_hex(input).ok_or(bad("its hex text has an odd number of digits"))?;
        parse(&decoded)
    } else {
        parse(input)
    }
}

fn from_hex(text: &[u8]) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let digit = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    };
    text.chunks_exact(2)
        .map(|pair| match pair {
            [hi, lo] => Some(digit(*hi)? << 4 | digit(*lo)?),
            _ => None,
        })
        .collect()
}

/// One section of fields up to its EOS: location, identifier, verification id.
struct Section<'a> {
    identifier: Option<&'a [u8]>,
    has_vid: bool,
}

/// Reads a section. `Ok(None)` means the next byte was an EOS right away.
fn section<'a>(r: &mut Reader<'a>) -> Result<Option<Section<'a>>, MacaroonRefusal> {
    let mut out = Section {
        identifier: None,
        has_vid: false,
    };
    let mut seen = [false; 5];
    let mut first = true;
    loop {
        let field = r.varint().ok_or(bad("it ends too early"))?;
        if field == 0 {
            return Ok(if first { None } else { Some(out) });
        }
        first = false;
        let len = r.varint().ok_or(bad("it ends too early"))?;
        let data = r.take(len).ok_or(bad("a field is longer than the file"))?;
        let slot = match field {
            1 | 2 | 4 => {
                usize::try_from(field).map_err(|_| bad("a field number is out of range"))?
            }
            _ => return Err(bad("it has a field Guard Dog doesn't know")),
        };
        match seen.get_mut(slot) {
            Some(already) if !*already => *already = true,
            _ => return Err(bad("a field appears twice")),
        }
        match field {
            2 => out.identifier = Some(data),
            4 => out.has_vid = true,
            _ => {}
        }
    }
}

fn parse(bytes: &[u8]) -> Result<NarrowMacaroon, MacaroonRefusal> {
    let mut r = Reader::new(bytes);
    if r.byte() != Some(2) {
        return Err(MacaroonRefusal::WrongVersion);
    }
    let header = section(&mut r)?.ok_or(bad("it has no identifier"))?;
    if header.has_vid {
        return Err(bad("its identifier section is wrong"));
    }
    let identifier = header.identifier.ok_or(bad("it has no identifier"))?;

    let (mut first_party, mut third_party) = (0usize, 0usize);
    while let Some(caveat) = section(&mut r)? {
        if caveat.identifier.is_none() {
            return Err(bad("a caveat has no text"));
        }
        if first_party + third_party >= MAX_CAVEATS {
            return Err(bad("it has too many caveats"));
        }
        if caveat.has_vid {
            third_party += 1;
        } else {
            first_party += 1;
        }
    }

    if r.varint() != Some(6) {
        return Err(bad("it has no signature"));
    }
    let signature = r
        .varint()
        .and_then(|len| r.take(len))
        .ok_or(bad("its signature is cut short"))?;
    if signature.len() != 32 || !r.is_empty() {
        return Err(bad("its signature or its ending is wrong"));
    }

    classify(identifier)?;
    Ok(NarrowMacaroon {
        first_party,
        third_party,
    })
}

/// What the permissions amount to.
#[derive(Default)]
struct Permissions {
    any: bool,
    write: bool,
    known: [bool; KNOWN.len()],
    unknown: bool,
}

fn name(r: &mut Reader<'_>) -> Result<String, MacaroonRefusal> {
    let len = r.varint().ok_or(bad("a permission is cut short"))?;
    if len > MAX_NAME {
        return Err(bad("a permission name is too long"));
    }
    let raw = r.take(len).ok_or(bad("a permission is cut short"))?;
    if !raw.iter().all(u8::is_ascii_graphic) {
        return Err(bad("a permission name is not plain text"));
    }
    Ok(raw.iter().map(|b| char::from(*b)).collect())
}

/// Skips a field value of a wire type we read (varint or length-delimited).
fn skip(r: &mut Reader<'_>, wire: u64) -> Result<(), MacaroonRefusal> {
    match wire {
        0 => r.varint().map(|_| ()).ok_or(bad("a number is cut short")),
        2 => r
            .varint()
            .and_then(|len| r.take(len))
            .map(|_| ())
            .ok_or(bad("a field is longer than the file")),
        _ => Err(bad("it uses a data type Guard Dog doesn't read")),
    }
}

fn op(data: &[u8], perms: &mut Permissions) -> Result<(), MacaroonRefusal> {
    let mut r = Reader::new(data);
    let mut entity: Option<String> = None;
    let mut actions: Vec<String> = Vec::new();
    while !r.is_empty() {
        let tag = r.varint().ok_or(bad("a permission is cut short"))?;
        let (field, wire) = (tag >> 3, tag & 7);
        match (field, wire) {
            (1, 2) => {
                if entity.is_some() {
                    return Err(bad("a permission names two entities"));
                }
                entity = Some(name(&mut r)?);
            }
            (2, 2) => {
                if actions.len() >= MAX_ACTIONS {
                    return Err(bad("a permission has too many actions"));
                }
                actions.push(name(&mut r)?);
            }
            (0, _) | (1, _) | (2, _) => return Err(bad("a permission has the wrong shape")),
            _ => skip(&mut r, wire)?,
        }
    }
    let Some(entity) = entity else {
        return if actions.is_empty() {
            Ok(())
        } else {
            Err(bad("a permission has no entity"))
        };
    };
    for action in actions {
        perms.any = true;
        if action == "write" {
            perms.write = true;
        }
        let full = format!("{entity}:{action}");
        match KNOWN.iter().position(|k| *k == full) {
            Some(i) => {
                if let Some(slot) = perms.known.get_mut(i) {
                    *slot = true;
                }
            }
            None => perms.unknown = true,
        }
    }
    Ok(())
}

fn classify(identifier: &[u8]) -> Result<(), MacaroonRefusal> {
    let (version, proto) = identifier
        .split_first()
        .ok_or(bad("its identifier is empty"))?;
    if *version != 3 {
        return Err(MacaroonRefusal::WrongVersion);
    }
    let mut r = Reader::new(proto);
    let mut perms = Permissions::default();
    let mut ops = 0usize;
    while !r.is_empty() {
        let tag = r.varint().ok_or(bad("its identifier is cut short"))?;
        let (field, wire) = (tag >> 3, tag & 7);
        match (field, wire) {
            (0, _) => return Err(bad("its identifier has the wrong shape")),
            (3, 2) => {
                ops += 1;
                if ops > MAX_OPS {
                    return Err(bad("it has too many permissions"));
                }
                let len = r.varint().ok_or(bad("its identifier is cut short"))?;
                let data = r.take(len).ok_or(bad("a field is longer than the file"))?;
                op(data, &mut perms)?;
            }
            (3, _) => return Err(bad("its identifier has the wrong shape")),
            _ => skip(&mut r, wire)?,
        }
    }

    if !perms.any {
        return Err(MacaroonRefusal::EmptyOps);
    }
    if perms.write {
        return Err(MacaroonRefusal::Admin);
    }
    let extra: Vec<&'static str> = KNOWN
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != INFO_READ && perms.known.get(*i).copied().unwrap_or(false))
        .map(|(_, name)| *name)
        .collect();
    let has_info_read = perms.known.get(INFO_READ).copied().unwrap_or(false);
    if has_info_read && extra.is_empty() && !perms.unknown {
        Ok(())
    } else {
        Err(MacaroonRefusal::TooWide {
            extra,
            unknown: perms.unknown,
        })
    }
}
