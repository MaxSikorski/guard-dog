//! Judge C's tooling: makes the planted canary secrets and checks an egress
//! capture against `allowlist.toml`.
//!
//! This is test tooling. It is never part of a release archive, and it holds
//! no real secret: every value it makes is generated from a seed.
//!
//! Where things live:
//! - [`prng`], [`encode`], [`bip39`]: the seeded generator and the encoders the canaries need.
//! - [`canary`] and [`setup`]: the eleven canary classes, and the file tree that plants them.
//! - [`needle`]: finding a canary in any encoding, and redacting it for printing.
//! - [`allowlist`]: the `allowlist.toml` reader.
//! - [`capture`] and [`rules`]: readers for the three capture sources and the live firewall rules.
//! - [`verdict`]: the findings and the byte-stable report.

pub mod allowlist;
pub mod bip39;
pub mod canary;
pub mod capture;
pub mod encode;
pub mod needle;
pub mod prng;
pub mod rules;
pub mod setup;
pub mod verdict;
