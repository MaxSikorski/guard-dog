//! Package identities: one canonical form per package, so a catalog entry and
//! an advisory that spell the same package differently still meet.
//!
//! The rules (design 2.1, section 1):
//! - PyPI: PEP 503. ASCII lowercase, every run of `-`, `_` or `.` becomes one `-`.
//! - GIT: a repository URL. Scheme and host are lowercased; on `github.com`
//!   the owner and repository are lowercased too, elsewhere the path keeps its
//!   case. Trailing `/` and then a terminal `.git` are stripped. Credentials,
//!   a query, a fragment, percent-escapes, empty path parts (`//`) and other
//!   ambiguous forms are refused. The scheme's default port (443, 80, 9418, and 22 for ssh)
//!   is dropped, never guessed at. Nothing here ever fetches a URL.
//! - Go: the module path is used exactly, with its case and its major-version
//!   suffix. Nothing is lowercased or rewritten. It must follow Go's path rules
//!   (no leading or trailing `/`, no empty, `.` or `..` element).
//!
//! A canonical key only ever holds printable ASCII from a short character
//! set, so it is safe to print, but still never a file path or shell word.

use std::fmt;

/// The longest package name accepted, in bytes.
pub const MAX_PACKAGE_NAME: usize = 512;

/// The ecosystems Guard Dog can name a package in so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Ecosystem {
    /// A repository, named by its URL (`GIT`). It identifies the project; it
    /// does not choose how commits are ordered.
    Git,
    /// A Go module (`Go`).
    Go,
    /// A Python Package Index project (`PyPI`).
    PyPi,
}

impl Ecosystem {
    /// The ecosystem's name as OSV spells it.
    pub fn osv_name(self) -> &'static str {
        match self {
            Self::Git => "GIT",
            Self::Go => "Go",
            Self::PyPi => "PyPI",
        }
    }
}

/// A package in canonical form. Two keys are equal exactly when the packages
/// are the same under the rules in this module's documentation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PackageKey {
    ecosystem: Ecosystem,
    name: String,
}

impl PackageKey {
    /// The package's ecosystem.
    pub fn ecosystem(&self) -> Ecosystem {
        self.ecosystem
    }

    /// The canonical name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Why a package name could not be put in canonical form. Each is reported as
/// a coverage gap; none is ever treated as "no such package".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PackageError {
    /// The ecosystem is not one Guard Dog names packages in yet.
    UnsupportedEcosystem,
    /// The name is empty.
    Empty,
    /// The name is longer than [`MAX_PACKAGE_NAME`].
    TooLong,
    /// The name has a character that is not allowed in this ecosystem.
    BadCharacters,
    /// A GIT name that is not an `scheme://` URL.
    NotAUrl,
    /// A GIT URL scheme other than http, https, git or ssh.
    UnsupportedScheme,
    /// A GIT URL with a user name or password in it.
    Credentials,
    /// A GIT URL with a query string.
    Query,
    /// A GIT URL with a fragment.
    Fragment,
    /// A GIT URL with a percent-escape in it.
    PercentEncoding,
    /// A GIT URL host that is empty or not a plain host name.
    BadHost,
    /// A GIT URL port that is empty, zero or out of range.
    BadPort,
    /// A GIT URL with no path.
    EmptyPath,
    /// A GIT URL path with an empty, `.` or `..` part.
    BadPathSegment,
    /// A `github.com` URL that is not exactly `/owner/repository`.
    NotARepository,
    /// A path that still ends in `/` or `.git` after stripping, so the stripping
    /// would not be stable.
    AmbiguousSuffix,
}

impl PackageError {
    /// A stable short code for logs and tests.
    pub fn code(self) -> &'static str {
        match self {
            Self::UnsupportedEcosystem => "unsupported_ecosystem",
            Self::Empty => "empty",
            Self::TooLong => "too_long",
            Self::BadCharacters => "bad_characters",
            Self::NotAUrl => "not_a_url",
            Self::UnsupportedScheme => "unsupported_scheme",
            Self::Credentials => "credentials",
            Self::Query => "query",
            Self::Fragment => "fragment",
            Self::PercentEncoding => "percent_encoding",
            Self::BadHost => "bad_host",
            Self::BadPort => "bad_port",
            Self::EmptyPath => "empty_path",
            Self::BadPathSegment => "bad_path_segment",
            Self::NotARepository => "not_a_repository",
            Self::AmbiguousSuffix => "ambiguous_suffix",
        }
    }
}

impl fmt::Display for PackageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for PackageError {}

/// Puts an OSV `(ecosystem, package name)` pair in canonical form.
///
/// The ecosystem must be spelled exactly `GIT`, `Go` or `PyPI`; anything else
/// (including a `PyPI:suffix` form) is [`PackageError::UnsupportedEcosystem`].
/// Canonicalising a canonical name changes nothing.
pub fn canonical_package(ecosystem: &str, name: &str) -> Result<PackageKey, PackageError> {
    let (ecosystem, name) = match ecosystem {
        "PyPI" => (Ecosystem::PyPi, checked(name).and_then(canonical_pypi)),
        "Go" => (Ecosystem::Go, checked(name).and_then(canonical_go)),
        "GIT" => (Ecosystem::Git, checked(name).and_then(canonical_git)),
        _ => return Err(PackageError::UnsupportedEcosystem),
    };
    Ok(PackageKey {
        ecosystem,
        name: name?,
    })
}

fn checked(name: &str) -> Result<&str, PackageError> {
    if name.is_empty() {
        Err(PackageError::Empty)
    } else if name.len() > MAX_PACKAGE_NAME {
        Err(PackageError::TooLong)
    } else if !name.bytes().all(|b| b.is_ascii_graphic()) {
        Err(PackageError::BadCharacters)
    } else {
        Ok(name)
    }
}

fn canonical_pypi(name: &str) -> Result<String, PackageError> {
    let is_sep = |c: char| matches!(c, '-' | '_' | '.');
    let valid = name.chars().all(|c| c.is_ascii_alphanumeric() || is_sep(c))
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name.ends_with(|c: char| c.is_ascii_alphanumeric());
    if !valid {
        return Err(PackageError::BadCharacters);
    }
    let mut out = String::with_capacity(name.len());
    let mut in_sep = false;
    for c in name.chars() {
        if is_sep(c) {
            if !in_sep {
                out.push('-');
            }
            in_sep = true;
        } else {
            out.push(c.to_ascii_lowercase());
            in_sep = false;
        }
    }
    Ok(out)
}

fn canonical_go(name: &str) -> Result<String, PackageError> {
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '~' | '/' | '-'))
    {
        return Err(PackageError::BadCharacters);
    }
    // Go module path rules: no leading or trailing `/`, no empty, `.` or `..` element.
    if name
        .split('/')
        .any(|element| element.is_empty() || element == "." || element == "..")
    {
        return Err(PackageError::BadPathSegment);
    }
    Ok(name.to_string())
}

fn canonical_git(name: &str) -> Result<String, PackageError> {
    let (scheme, rest) = name.split_once("://").ok_or(PackageError::NotAUrl)?;
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https" | "git" | "ssh") {
        return Err(PackageError::UnsupportedScheme);
    }
    if rest.contains('#') {
        return Err(PackageError::Fragment);
    }
    if rest.contains('?') {
        return Err(PackageError::Query);
    }
    if rest.contains('%') {
        return Err(PackageError::PercentEncoding);
    }
    let (authority, path) = match rest.find('/') {
        Some(at) => rest.split_at(at),
        None => (rest, ""),
    };
    if authority.contains('@') {
        return Err(PackageError::Credentials);
    }
    let (host, port) = split_host_port(authority, &scheme)?;

    let path = path.trim_end_matches('/');
    if path.is_empty() {
        return Err(PackageError::EmptyPath);
    }
    let github = host == "github.com";
    let mut path = if github {
        path.to_ascii_lowercase()
    } else {
        path.to_string()
    };
    if path.ends_with(".git") {
        path.truncate(path.len().saturating_sub(".git".len()));
    }
    if path.is_empty() || path.ends_with('/') || path.ends_with(".git") {
        return Err(PackageError::AmbiguousSuffix);
    }
    let mut segments = 0usize;
    for segment in path.strip_prefix('/').unwrap_or(&path).split('/') {
        segments = segments.saturating_add(1);
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(PackageError::BadPathSegment);
        }
        if !segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '~' | '-'))
        {
            return Err(PackageError::BadCharacters);
        }
    }
    if github && segments != 2 {
        return Err(PackageError::NotARepository);
    }
    Ok(format!("{scheme}://{host}{port}{path}"))
}

/// Splits `host[:port]`, lowercasing the host and rewriting the port without
/// leading zeros (as `":8080"`, or `""` for none, and none for the scheme's
/// default port).
fn split_host_port(authority: &str, scheme: &str) -> Result<(String, String), PackageError> {
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    let label_ok = |label: &str| {
        !label.is_empty()
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    };
    if !host.split('.').all(label_ok) {
        return Err(PackageError::BadHost);
    }
    let port = match port {
        None => String::new(),
        Some(digits) => {
            let valid = !digits.is_empty()
                && digits.len() <= 5
                && digits.bytes().all(|b| b.is_ascii_digit());
            match digits.parse::<u16>() {
                Ok(n) if valid && n != 0 => {
                    let default = matches!(
                        (scheme, n),
                        ("https", 443) | ("http", 80) | ("git", 9418) | ("ssh", 22)
                    );
                    if default {
                        String::new()
                    } else {
                        format!(":{n}")
                    }
                }
                _ => return Err(PackageError::BadPort),
            }
        }
    };
    Ok((host.to_ascii_lowercase(), port))
}
