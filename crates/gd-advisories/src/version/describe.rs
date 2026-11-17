//! Stub for the failing-tests commit; the real parser replaces this file.

use super::{VersionError, VersionScheme};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commit {
    pub distance: String,
    pub hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Described<V> {
    pub tag: V,
    pub commit: Option<Commit>,
    pub dirty: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct GitDescribe;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TagVersion;

impl fmt::Display for TagVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("")
    }
}

impl GitDescribe {
    pub fn parse_describe(&self, _raw: &str) -> Result<Described<TagVersion>, VersionError> {
        Err(VersionError::Malformed)
    }
}

impl VersionScheme for GitDescribe {
    type Version = TagVersion;
    fn parse(&self, _raw: &str) -> Result<TagVersion, VersionError> {
        Err(VersionError::Malformed)
    }
    fn same_identity(&self, _a: &str, _b: &str) -> Option<bool> {
        None
    }
    fn reads_semver_ranges(&self) -> bool {
        false
    }
    fn orders(&self) -> bool {
        true
    }
}
