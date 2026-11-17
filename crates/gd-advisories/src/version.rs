//! The contract a version scheme gives the range evaluator.
//!
//! The catalog picks the scheme for a product; an OSV range type never picks a
//! parser (design 2.1, "scheme authority"). The schemes themselves (SemVer,
//! Bitcoin Core, PEP 440, ...) arrive in later pull requests and implement this
//! trait. The evaluator in [`crate::range`] only needs the four things below.

use std::fmt;

/// Why a scheme could not read a version string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum VersionError {
    /// The string is not a version of this scheme.
    Malformed,
    /// The string is longer than the scheme accepts.
    TooLong,
}

impl fmt::Display for VersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "not a version of this scheme",
            Self::TooLong => "version is too long",
        })
    }
}

impl std::error::Error for VersionError {}

/// One ordered version scheme.
///
/// Rules every implementation must keep:
/// - `parse` consumes the whole string and never guesses; anything it cannot
///   read is an error, never a partial or lexical fallback.
/// - `Version`'s `Ord` is the scheme's precedence order, and `Eq` agrees with it.
///   Precedence equality is not identity: build metadata or a local label can
///   differ between two versions that compare equal.
/// - `same_identity` compares exact identity after only the scheme's documented
///   normalization. `None` means the scheme cannot say (a string it cannot read).
pub trait VersionScheme {
    /// A parsed version, ordered by precedence.
    type Version: Ord + Clone;

    /// Reads one version string.
    fn parse(&self, raw: &str) -> Result<Self::Version, VersionError>;

    /// Whether two raw strings name the same exact version, or `None` if either
    /// cannot be read.
    fn same_identity(&self, a: &str, b: &str) -> Option<bool>;

    /// Whether this scheme has declared that it can evaluate `SEMVER` ranges.
    /// A scheme that has not declared it makes a `SEMVER` range `Unknown`,
    /// never a SemVer fallback.
    fn reads_semver_ranges(&self) -> bool;
}
