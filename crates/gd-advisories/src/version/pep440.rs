//! PEP 440 ordering for Nutshell (`PyPI cashu`) (design 2.1, section 2,
//! "PyPI / PEP 440").
//!
//! The grammar follows the regular expression in the specification, so what it
//! accepts matches `packaging.version.Version`: outer ASCII whitespace, one
//! `v`, any case, the separators `.`, `-` and `_`, the spellings `alpha`, `beta`,
//! `c`, `pre`, `preview`, `r` and `rev`, omitted numbers (zero), and the
//! implicit post-release (`1.0-1`). Ordering is version ordering, not pip's
//! specifier filtering.

use std::cmp::Ordering;
use std::fmt;

use super::calver::{Dec, MAX_COMPONENTS, MAX_LEN};
use super::{VersionError, VersionScheme};

/// The kind of a pre-release, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PreKind {
    Alpha,
    Beta,
    Rc,
}

impl PreKind {
    fn name(self) -> &'static str {
        match self {
            Self::Alpha => "a",
            Self::Beta => "b",
            Self::Rc => "rc",
        }
    }
}

/// One dot-separated piece of a local label: text sorts below numbers.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum LocalSegment {
    Text(String),
    Num(Dec),
}

/// A missing pre-release is below everything for a dev-only release and above
/// everything otherwise.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum PreKey<'a> {
    Below,
    Pre(PreKind, &'a Dec),
    Above,
}

/// A missing dev number is above every number.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum DevKey<'a> {
    Num(&'a Dec),
    Absent,
}

/// The PEP 440 version scheme.
#[derive(Clone, Copy, Debug, Default)]
pub struct Pep440;

/// One parsed PEP 440 version.
///
/// `Ord` is the specification's order (epoch, release with trailing zeros
/// ignored, pre, post, dev, local) and `Eq` agrees with it: `1.0` equals
/// `1.0.0`. Equal by order is not the same identity; see
/// [`Pep440::same_identity`].
#[derive(Clone, Debug)]
pub struct Pep440Version {
    epoch: Dec,
    release: Vec<Dec>,
    pre: Option<(PreKind, Dec)>,
    post: Option<Dec>,
    dev: Option<Dec>,
    local: Option<Vec<LocalSegment>>,
}

impl Pep440Version {
    /// The epoch (`0` when not written).
    #[must_use]
    pub fn epoch(&self) -> &str {
        self.epoch.as_str()
    }

    /// The release numbers as written, with leading zeros removed.
    #[must_use]
    pub fn release(&self) -> Vec<&str> {
        self.release.iter().map(Dec::as_str).collect()
    }

    /// The pre-release as its normalized letters (`a`, `b` or `rc`) and number.
    #[must_use]
    pub fn pre(&self) -> Option<(&'static str, &str)> {
        self.pre.as_ref().map(|(k, n)| (k.name(), n.as_str()))
    }

    /// The post-release number.
    #[must_use]
    pub fn post(&self) -> Option<&str> {
        self.post.as_ref().map(Dec::as_str)
    }

    /// The dev-release number.
    #[must_use]
    pub fn dev(&self) -> Option<&str> {
        self.dev.as_ref().map(Dec::as_str)
    }

    /// The normalized local label (lowercase, dot-separated, numbers without
    /// leading zeros).
    #[must_use]
    pub fn local(&self) -> Option<String> {
        self.local.as_ref().map(|segs| {
            segs.iter()
                .map(|s| match s {
                    LocalSegment::Text(t) => t.clone(),
                    LocalSegment::Num(n) => n.to_string(),
                })
                .collect::<Vec<_>>()
                .join(".")
        })
    }

    fn pre_key(&self) -> PreKey<'_> {
        match &self.pre {
            Some((kind, n)) => PreKey::Pre(*kind, n),
            None if self.post.is_none() && self.dev.is_some() => PreKey::Below,
            None => PreKey::Above,
        }
    }

    fn dev_key(&self) -> DevKey<'_> {
        self.dev.as_ref().map_or(DevKey::Absent, DevKey::Num)
    }

    /// The release without its trailing zeros: `1.0` and `1.0.0` compare equal.
    fn trimmed_release(&self) -> &[Dec] {
        let mut end = self.release.len();
        while end > 0 && self.release.get(end - 1).is_some_and(Dec::is_zero) {
            end -= 1;
        }
        self.release.get(..end).unwrap_or_default()
    }
}

impl Ord for Pep440Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.epoch
            .cmp(&other.epoch)
            .then_with(|| self.trimmed_release().cmp(other.trimmed_release()))
            .then_with(|| self.pre_key().cmp(&other.pre_key()))
            // Absent post sorts first (`None` is below every `Some`).
            .then_with(|| self.post.cmp(&other.post))
            .then_with(|| self.dev_key().cmp(&other.dev_key()))
            // Absent local sorts first; segments compare one by one, a shorter
            // equal prefix first.
            .then_with(|| self.local.cmp(&other.local))
    }
}

impl PartialOrd for Pep440Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Pep440Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Pep440Version {}

/// The normalized text, as `packaging` writes it:
/// `[N!]release[aN|bN|rcN][.postN][.devN][+local]`. Reading it back gives an
/// equal version, and writing that gives the same text.
impl fmt::Display for Pep440Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.epoch.is_zero() {
            write!(f, "{}!", self.epoch)?;
        }
        f.write_str(&self.release().join("."))?;
        if let Some((kind, n)) = &self.pre {
            write!(f, "{}{n}", kind.name())?;
        }
        if let Some(n) = &self.post {
            write!(f, ".post{n}")?;
        }
        if let Some(n) = &self.dev {
            write!(f, ".dev{n}")?;
        }
        if let Some(local) = self.local() {
            write!(f, "+{local}")?;
        }
        Ok(())
    }
}

/// A cursor over ASCII text; it only ever advances over ASCII bytes, so it
/// stays on character boundaries.
struct Cursor<'a> {
    s: &'a str,
    i: usize,
}

impl<'a> Cursor<'a> {
    fn rest(&self) -> &'a str {
        self.s.get(self.i..).unwrap_or("")
    }

    fn peek(&self) -> Option<u8> {
        self.rest().as_bytes().first().copied()
    }

    fn eat(&mut self, b: u8) -> bool {
        if self.peek() == Some(b) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    /// One of `.`, `-`, `_`.
    fn eat_sep(&mut self) -> bool {
        if matches!(self.peek(), Some(b'.' | b'-' | b'_')) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn eat_word(&mut self, word: &str) -> bool {
        if self.rest().starts_with(word) {
            self.i += word.len();
            true
        } else {
            false
        }
    }

    fn digits(&mut self) -> Option<&'a str> {
        let rest = self.rest();
        let n = rest.bytes().take_while(u8::is_ascii_digit).count();
        if n == 0 {
            return None;
        }
        self.i += n;
        rest.get(..n)
    }

    fn alphanumerics(&mut self) -> Option<&'a str> {
        let rest = self.rest();
        let n = rest.bytes().take_while(u8::is_ascii_alphanumeric).count();
        if n == 0 {
            return None;
        }
        self.i += n;
        rest.get(..n)
    }

    fn at_end(&self) -> bool {
        self.i >= self.s.len()
    }
}

/// Pre-release labels in the order the specification's expression tries them.
const PRE_LABELS: [(&str, PreKind); 8] = [
    ("alpha", PreKind::Alpha),
    ("a", PreKind::Alpha),
    ("beta", PreKind::Beta),
    ("b", PreKind::Beta),
    ("preview", PreKind::Rc),
    ("pre", PreKind::Rc),
    ("c", PreKind::Rc),
    ("rc", PreKind::Rc),
];

const POST_LABELS: [&str; 3] = ["post", "rev", "r"];

fn number(d: &str) -> Result<Dec, VersionError> {
    Dec::parse(d).ok_or(VersionError::Malformed)
}

fn parse_version(raw: &str) -> Result<Pep440Version, VersionError> {
    if raw.len() > MAX_LEN {
        return Err(VersionError::TooLong);
    }
    let lower = raw.trim_ascii().to_ascii_lowercase();
    let mut c = Cursor { s: &lower, i: 0 };

    c.eat(b'v');

    // Epoch: digits followed by `!`; otherwise the digits are the release.
    let start = c.i;
    let epoch = match c.digits() {
        Some(d) if c.eat(b'!') => number(d)?,
        _ => {
            c.i = start;
            number("0")?
        }
    };

    // Release: digits, then `.digits` as long as a digit follows the dot.
    let mut release = vec![number(c.digits().ok_or(VersionError::Malformed)?)?];
    loop {
        let before = c.i;
        if c.eat(b'.')
            && let Some(d) = c.digits()
        {
            release.push(number(d)?);
        } else {
            c.i = before;
            break;
        }
    }
    if release.len() > MAX_COMPONENTS {
        return Err(VersionError::TooLong);
    }

    // Pre-release: optional separator, a label, optional separator, optional
    // number. A separator is taken even when no number follows.
    let mut pre = None;
    let before = c.i;
    c.eat_sep();
    if let Some((_, kind)) = PRE_LABELS.iter().find(|(label, _)| c.eat_word(label)) {
        c.eat_sep();
        let n = c.digits().map_or_else(|| number("0"), number)?;
        pre = Some((*kind, n));
    } else {
        c.i = before;
    }

    // Post-release: `-N`, or an optional separator, `post`/`rev`/`r`, an
    // optional separator and an optional number.
    let mut post = None;
    let before = c.i;
    if c.eat(b'-')
        && let Some(d) = c.digits()
    {
        post = Some(number(d)?);
    } else {
        c.i = before;
        c.eat_sep();
        if POST_LABELS.iter().any(|label| c.eat_word(label)) {
            c.eat_sep();
            post = Some(c.digits().map_or_else(|| number("0"), number)?);
        } else {
            c.i = before;
        }
    }

    // Dev-release: optional separator, `dev`, optional separator, optional number.
    let mut dev = None;
    let before = c.i;
    c.eat_sep();
    if c.eat_word("dev") {
        c.eat_sep();
        dev = Some(c.digits().map_or_else(|| number("0"), number)?);
    } else {
        c.i = before;
    }

    // Local label: `+`, then alphanumeric segments separated by `.`, `-` or `_`.
    let mut local = None;
    if c.eat(b'+') {
        let mut segments = Vec::new();
        loop {
            let seg = c.alphanumerics().ok_or(VersionError::Malformed)?;
            segments.push(match Dec::parse(seg) {
                Some(n) => LocalSegment::Num(n),
                None => LocalSegment::Text(seg.to_string()),
            });
            if !c.eat_sep() {
                break;
            }
        }
        if segments.len() > MAX_COMPONENTS {
            return Err(VersionError::TooLong);
        }
        local = Some(segments);
    }

    if !c.at_end() {
        return Err(VersionError::Malformed);
    }
    Ok(Pep440Version {
        epoch,
        release,
        pre,
        post,
        dev,
        local,
    })
}

impl VersionScheme for Pep440 {
    type Version = Pep440Version;

    fn parse(&self, raw: &str) -> Result<Pep440Version, VersionError> {
        parse_version(raw)
    }

    /// Identity is the normalized text: every spelling of one version (`V01.0RC`
    /// and `1.0rc0`, `1.0-1` and `1.0.post1`, `0!1.0` and `1.0`) shares it, while
    /// `1.0` and `1.0.0` (equal by order), different local labels and different
    /// epochs do not.
    fn same_identity(&self, a: &str, b: &str) -> Option<bool> {
        let a = parse_version(a).ok()?;
        let b = parse_version(b).ok()?;
        Some(a.to_string() == b.to_string())
    }

    fn reads_semver_ranges(&self) -> bool {
        false
    }

    fn orders(&self) -> bool {
        true
    }
}
