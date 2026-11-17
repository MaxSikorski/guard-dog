//! The `git-describe` scheme (strfry) and the describe suffix CLN shares
//! (design 2.1, section 2, "Git-describe").
//!
//! A description is `<tag>-<distance>-g<hash>`, optionally followed by a dirty
//! marker. It is parsed from the right, so the tag may hold hyphens itself. The
//! tag is a version; the distance and hash are evidence about one build, never a
//! release: `1.1.2-148-g4cd3cf6` is neither `1.1.2` nor proved below `1.1.3`, and
//! it must never reach a SemVer parser, where `148-g4cd3cf6` would read as a
//! prerelease and sort it below `1.1.2`.

use std::cmp::Ordering;
use std::fmt;

use super::calver::{Dec, MAX_COMPONENTS, MAX_LEN};
use super::{Candidate, VersionError, VersionScheme};

/// The commit part of a git description.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commit {
    /// Commits since the tag, as plain decimal digits.
    pub distance: String,
    /// The abbreviated commit id: 4 to 64 lowercase hex digits, without the `g`.
    pub hash: String,
}

/// A parsed git description, with every field kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Described<V> {
    /// The tag the build descends from.
    pub tag: V,
    /// The distance and hash, if the build is not exactly at a tag.
    pub commit: Option<Commit>,
    /// Whether the working tree was modified (`-dirty`, or CLN's `-modded`).
    pub dirty: bool,
}

/// The canonical text of every field, for identity comparisons.
pub(super) fn identity_text<V: fmt::Display>(d: &Described<V>) -> String {
    let mut s = d.tag.to_string();
    if let Some(c) = &d.commit {
        s.push_str(&format!("-{}-g{}", c.distance, c.hash));
    }
    if d.dirty {
        s.push_str("-dirty");
    }
    s
}

/// A description cut into its parts, before the tag is read.
pub(super) struct Split<'a> {
    pub(super) tag: &'a str,
    pub(super) commit: Option<Commit>,
    pub(super) dirty: bool,
}

/// Cuts a description from the right: one dirty marker, then
/// `-<decimal distance>-g<4..64 lowercase hex>`, leaving the tag text.
///
/// Text that has the shape `-<digits>-g<something>` but is not a valid hash is
/// an error, never a tag: otherwise it would fall through to a SemVer parser as
/// a prerelease.
pub(super) fn split_describe<'a>(
    raw: &'a str,
    markers: &[&str],
) -> Result<Split<'a>, VersionError> {
    if raw.len() > MAX_LEN {
        return Err(VersionError::TooLong);
    }
    let mut rest = raw;
    let mut dirty = false;
    for marker in markers {
        if let Some(r) = rest.strip_suffix(marker) {
            rest = r;
            dirty = true;
            break;
        }
    }
    let mut commit = None;
    if let Some((left, last)) = rest.rsplit_once('-')
        && let Some(hash) = last.strip_prefix('g')
        && let Some((tag, distance)) = left.rsplit_once('-')
        && !distance.is_empty()
        && distance.bytes().all(|b| b.is_ascii_digit())
    {
        let hash_ok = (4..=64).contains(&hash.len())
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !hash_ok || (distance.len() > 1 && distance.starts_with('0')) {
            return Err(VersionError::Malformed);
        }
        commit = Some(Commit {
            distance: distance.to_string(),
            hash: hash.to_string(),
        });
        rest = tag;
    }
    if rest.is_empty() {
        return Err(VersionError::Malformed);
    }
    Ok(Split {
        tag: rest,
        commit,
        dirty,
    })
}

/// Whether `s` holds `-<digits>-g<more>` anywhere: a description inside what
/// should be a plain tag.
fn holds_a_description(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.windows(2).any(|w| match w {
        [d, g] => {
            !d.is_empty()
                && d.bytes().all(|b| b.is_ascii_digit())
                && g.strip_prefix('g').is_some_and(|h| !h.is_empty())
        }
        _ => false,
    })
}

/// One prerelease identifier: numeric ones sort below text ones.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Ident {
    Num(Dec),
    Text(String),
}

/// A strfry release tag: SemVer `X.Y.Z[-prerelease][+metadata]`.
///
/// A small private comparator for tags only, written here so this scheme does
/// not wait for the SemVer scheme; it is to be unified with that scheme's
/// parser once both are merged. Metadata is kept but ignored by `Ord`, and `Eq`
/// agrees with `Ord`.
#[derive(Clone, Debug)]
pub struct TagVersion {
    major: Dec,
    minor: Dec,
    patch: Dec,
    pre: Option<Vec<Ident>>,
    meta: Option<String>,
}

impl Ord for TagVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then_with(|| self.minor.cmp(&other.minor))
            .then_with(|| self.patch.cmp(&other.patch))
            .then_with(|| match (&self.pre, &other.pre) {
                (None, None) => Ordering::Equal,
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                // Identifier by identifier; a shorter equal prefix is first.
                (Some(a), Some(b)) => a.cmp(b),
            })
    }
}

impl PartialOrd for TagVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for TagVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for TagVersion {}

/// The tag as written, with numbers normalized: `X.Y.Z[-pre][+metadata]`.
impl fmt::Display for TagVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(pre) = &self.pre {
            let ids: Vec<String> = pre
                .iter()
                .map(|i| match i {
                    Ident::Num(n) => n.to_string(),
                    Ident::Text(t) => t.clone(),
                })
                .collect();
            write!(f, "-{}", ids.join("."))?;
        }
        if let Some(m) = &self.meta {
            write!(f, "+{m}")?;
        }
        Ok(())
    }
}

fn identifier_chars(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Reads a strfry tag: strict SemVer, no leading `v`.
fn parse_tag(raw: &str) -> Result<TagVersion, VersionError> {
    if raw.len() > MAX_LEN {
        return Err(VersionError::TooLong);
    }
    if holds_a_description(raw) {
        return Err(VersionError::Malformed);
    }
    let (rest, meta) = match raw.split_once('+') {
        Some((r, m)) => (r, Some(m)),
        None => (raw, None),
    };
    let (core, pre) = match rest.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (rest, None),
    };
    let plain = |t: &str| Dec::parse_plain(t).ok_or(VersionError::Malformed);
    let numbers: Vec<&str> = core.split('.').collect();
    let [major, minor, patch] = numbers.as_slice() else {
        return Err(VersionError::Malformed);
    };
    let mut count = 3;
    let pre = match pre {
        None => None,
        Some(p) => {
            let mut ids = Vec::new();
            for id in p.split('.') {
                if !identifier_chars(id) {
                    return Err(VersionError::Malformed);
                }
                ids.push(if id.bytes().all(|b| b.is_ascii_digit()) {
                    Ident::Num(plain(id)?)
                } else {
                    Ident::Text(id.to_string())
                });
            }
            count += ids.len();
            Some(ids)
        }
    };
    if let Some(m) = meta {
        if !m.split('.').all(identifier_chars) {
            return Err(VersionError::Malformed);
        }
        count += m.split('.').count();
    }
    if count > MAX_COMPONENTS {
        return Err(VersionError::TooLong);
    }
    Ok(TagVersion {
        major: plain(major)?,
        minor: plain(minor)?,
        patch: plain(patch)?,
        pre,
        meta: meta.map(str::to_string),
    })
}

/// strfry's version scheme: a SemVer tag plus separate commit evidence.
///
/// Tags are ordered; a build between tags is an interval above its tag, never a
/// version of its own.
#[derive(Clone, Copy, Debug, Default)]
pub struct GitDescribe;

impl GitDescribe {
    /// Reads a description, a bare tag or a dirty tag, keeping every field.
    ///
    /// # Errors
    /// [`VersionError::Malformed`] if the tag is not SemVer, or the text has the
    /// shape of a description but an invalid hash or distance;
    /// [`VersionError::TooLong`] past 256 bytes or 64 components.
    pub fn parse_describe(&self, raw: &str) -> Result<Described<TagVersion>, VersionError> {
        let split = split_describe(raw, &["-dirty"])?;
        Ok(Described {
            tag: parse_tag(split.tag)?,
            commit: split.commit,
            dirty: split.dirty,
        })
    }
}

impl VersionScheme for GitDescribe {
    type Version = TagVersion;

    /// Reads a tag only. A description or a dirty tag is refused: it is not a
    /// release, and `1.1.2-148-g4cd3cf6` must never be read as a SemVer
    /// prerelease.
    fn parse(&self, raw: &str) -> Result<TagVersion, VersionError> {
        let split = split_describe(raw, &["-dirty"])?;
        if split.dirty || split.commit.is_some() {
            return Err(VersionError::Malformed);
        }
        parse_tag(split.tag)
    }

    /// A clean description descends from its tag: it is at or after the tag and
    /// nothing more is known (distance zero equals the tag only with a verified
    /// tag-to-commit mapping, which is not available; a bare tag has no commit at
    /// all). A dirty build or an unreadable tag gives nothing.
    fn candidate(&self, raw: &str) -> Result<Candidate<TagVersion>, VersionError> {
        let d = self.parse_describe(raw)?;
        if d.dirty {
            return Err(VersionError::Malformed);
        }
        Ok(Candidate::Between {
            low: d.tag,
            high: None,
        })
    }

    /// Identity is every field: the tag, the distance, the hash and the dirty
    /// marker.
    fn same_identity(&self, a: &str, b: &str) -> Option<bool> {
        let a = self.parse_describe(a).ok()?;
        let b = self.parse_describe(b).ok()?;
        Some(identity_text(&a) == identity_text(&b))
    }

    fn reads_semver_ranges(&self) -> bool {
        false
    }

    fn orders(&self) -> bool {
        true
    }
}
