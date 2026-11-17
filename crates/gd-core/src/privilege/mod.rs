//! Least privilege: Guard Dog logs into a node only with credentials it has
//! proved narrow, and refuses wider ones with a plain-English reason and fix.
//!
//! Everything here is pure: no files, no network, no clock. The caller reads
//! the credential (from systemd's `LoadCredential=` directory, never an
//! environment variable or argument) and hands the bytes in.
//!
//! - [`macaroon`]: an LND macaroon must allow exactly `info:read`.
//! - [`rune`]: a Core Lightning rune must allow exactly `getinfo` with no
//!   parameters.
//! - [`bitcoind`]: a Bitcoin Core login must be refused a canary call by
//!   `rpcwhitelist`.
//! - [`check`]: Guard Dog's own process must not be root.
//!
//! No refusal or accepted value ever holds credential bytes, so none can
//! print them with `Display` or `Debug`.

use std::fmt;

pub mod bitcoind;
pub mod macaroon;
pub mod rune;

/// What the binary learned about Guard Dog's own process.
///
/// Capabilities, groups and socket access are added here later; the struct is
/// `#[non_exhaustive]` so adding them breaks no caller.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProcessFacts {
    /// The effective user id the process runs as.
    pub euid: u32,
}

impl ProcessFacts {
    /// Facts for a process running as this effective user id.
    pub fn new(euid: u32) -> Self {
        Self { euid }
    }
}

/// A reason Guard Dog's own process is not safe to start.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// The process runs as root (user id 0).
    RunningAsRoot,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::RunningAsRoot => f.write_str(
                "Guard Dog never runs as root: a watchdog with full control of the machine is itself something to guard against. \
                 Start it as its own unprivileged user (the packaged service does this with User=guard-dog).",
            ),
        }
    }
}

impl std::error::Error for Refusal {}

/// Refuses an unsafe start. `Ok` means every check passed; `Err` lists every
/// reason, in a fixed order.
pub fn check(facts: &ProcessFacts) -> Result<(), Vec<Refusal>> {
    let mut refusals = Vec::new();
    if facts.euid == 0 {
        refusals.push(Refusal::RunningAsRoot);
    }
    if refusals.is_empty() {
        Ok(())
    } else {
        Err(refusals)
    }
}

/// A tiny bounded reader over bytes, shared by the macaroon decoder.
/// It never indexes, so it cannot panic.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub(crate) fn byte(&mut self) -> Option<u8> {
        let (first, rest) = self.data.split_first()?;
        self.data = rest;
        Some(*first)
    }

    /// An unsigned LEB128 number of at most 10 bytes.
    pub(crate) fn varint(&mut self) -> Option<u64> {
        let mut value: u64 = 0;
        for i in 0..10u32 {
            let b = self.byte()?;
            let low = u64::from(b & 0x7f);
            if i == 9 && low > 1 {
                return None;
            }
            value |= low.checked_shl(7 * i)?;
            if b & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    /// The next `n` bytes, if that many are left.
    pub(crate) fn take(&mut self, n: u64) -> Option<&'a [u8]> {
        let n = usize::try_from(n).ok()?;
        if n > self.data.len() {
            return None;
        }
        let (head, rest) = self.data.split_at(n);
        self.data = rest;
        Some(head)
    }
}
