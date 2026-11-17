//! Stub for the failing-tests commit; the real parser replaces this file.

use super::{VersionError, VersionScheme};
use std::fmt;

#[derive(Clone, Copy, Debug, Default)]
pub struct Pep440;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pep440Version;

impl Pep440Version {
    pub fn epoch(&self) -> &str {
        ""
    }
    pub fn release(&self) -> Vec<&str> {
        Vec::new()
    }
    pub fn pre(&self) -> Option<(&'static str, &str)> {
        None
    }
    pub fn post(&self) -> Option<&str> {
        None
    }
    pub fn dev(&self) -> Option<&str> {
        None
    }
    pub fn local(&self) -> Option<String> {
        None
    }
}

impl fmt::Display for Pep440Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("")
    }
}

impl VersionScheme for Pep440 {
    type Version = Pep440Version;
    fn parse(&self, _raw: &str) -> Result<Pep440Version, VersionError> {
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
