//! Stub for the failing-tests commit; the real parser replaces this file.

use super::{VersionError, VersionScheme};
use std::fmt;

use super::describe::Described;

#[derive(Clone, Copy, Debug, Default)]
pub struct Calver;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ClnVersion;

impl ClnVersion {
    pub fn is_legacy(&self) -> bool {
        false
    }
}

impl fmt::Display for ClnVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("")
    }
}

impl Calver {
    pub fn parse_describe(&self, _raw: &str) -> Result<Described<ClnVersion>, VersionError> {
        Err(VersionError::Malformed)
    }
}

impl VersionScheme for Calver {
    type Version = ClnVersion;
    fn parse(&self, _raw: &str) -> Result<ClnVersion, VersionError> {
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
