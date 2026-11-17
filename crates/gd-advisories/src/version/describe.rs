//! The `git-describe` scheme (strfry) and the describe suffix CLN shares
//! (design 2.1, section 2, "Git-describe").
//!
//! A description is `<tag>-<distance>-g<hash>`, optionally followed by a dirty
//! marker (`-dirty`; git's `-broken` and CLN's `-modded` inside a tag are
//! refused). It is parsed from the right, so the tag may hold hyphens itself.
//! The tag is a version; the distance and hash are evidence about one build,
//! never a release: `1.1.2-148-g4cd3cf6` is neither `1.1.2` nor proved below
//! `1.1.3`. Only the tag, never the whole description, goes to the SemVer
//! scheme, where `148-g4cd3cf6` would read as a prerelease and sort it below
//! `1.1.2`.

use std::fmt;

use super::num::MAX_COMPONENTS;
use super::semver::{SemVer, SemVerVersion, check_length};
use super::{Candidate, VersionError, VersionScheme};

/// A strfry release tag is a SemVer version, read by the SemVer scheme. Its
/// identity is the SemVer one: the tag's own spelling (metadata included).
pub type TagVersion = SemVerVersion;

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
    check_length(raw)?;
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

/// Whether `s` holds a describe fragment `-<digits>-g<hex>*` that ends the text
/// or is followed by `.`, `+` or `-`, even with an empty or short hash. After
/// the outer description is stripped, none may remain in the tag.
fn holds_describe_fragment(s: &str) -> bool {
    s.match_indices('-').any(|(i, _)| {
        let after = s.get(i + 1..).unwrap_or("");
        let rest = after.trim_start_matches(|c: char| c.is_ascii_digit());
        if rest.len() == after.len() {
            return false;
        }
        let Some(hash_and_more) = rest.strip_prefix("-g") else {
            return false;
        };
        let tail = hash_and_more.trim_start_matches(|c: char| matches!(c, '0'..='9' | 'a'..='f'));
        tail.is_empty() || tail.starts_with(['.', '+', '-'])
    })
}

/// Reads a strfry tag with the SemVer scheme: strict `X.Y.Z[-pre][+meta]`, no
/// leading `v` (strfry's own tags have none, so a `v1.1.2` tag is refused until
/// a real strfry record shows otherwise). A description hidden inside the
/// tag, or a working-tree marker (`-dirty`, git's `-broken`, CLN's `-modded`,
/// also when build metadata follows it), is refused instead of being read as a
/// prerelease.
fn parse_tag(raw: &str) -> Result<TagVersion, VersionError> {
    let (head, meta) = raw.split_once('+').map_or((raw, ""), |(h, m)| (h, m));
    let marked = |part: &str| {
        ["-modded", "-broken", "-dirty"]
            .iter()
            .any(|m| part.ends_with(m))
    };
    if holds_a_description(raw)
        || holds_describe_fragment(raw)
        || marked(raw)
        || marked(head)
        || marked(meta)
    {
        return Err(VersionError::Malformed);
    }
    let version = SemVer.parse(raw)?;
    // One budget for the whole version: release, prerelease and metadata
    // components together (the same total PEP 440 enforces).
    let pre = head
        .split_once('-')
        .map_or(0, |(_, p)| p.split('.').count());
    let build = if raw.contains('+') {
        meta.split('.').count()
    } else {
        0
    };
    if 3 + pre + build > MAX_COMPONENTS {
        return Err(VersionError::TooLong);
    }
    Ok(version)
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

    /// Even a bare tag is an interval here (unlike CLN's, whose tarball and
    /// `getinfo` builds report the release itself): strfry's text comes from
    /// `git describe`, and a build can be a commit after the tag it names.
    ///
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
