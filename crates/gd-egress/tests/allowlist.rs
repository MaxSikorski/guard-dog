//! `allowlist.toml` reading and matching.

// Test-only crate: see `crates/gd-core/tests/judge_d_injection.rs` for why helpers need this.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use gd_egress::allowlist::{Allowlist, AllowlistError as E};
use std::mem::discriminant;

fn entry(host: &str, ports: &str) -> String {
    format!(
        "format = 1\n[[destination]]\nhost = \"{host}\"\nports = {ports}\nwhy = \"a reason\"\nphase = \"0.6\"\n"
    )
}

#[test]
fn an_empty_allowlist_parses() {
    assert!(
        Allowlist::parse("format = 1\n")
            .unwrap()
            .destinations
            .is_empty()
    );
    assert!(
        Allowlist::parse("format = 1\ndestination = []\n")
            .unwrap()
            .destinations
            .is_empty()
    );
}

#[test]
fn allowlist_rejects_each_bad_entry() {
    let long_label = format!("{}.example.org", "a".repeat(64));
    let cases: Vec<(&str, String, E)> = vec![
        ("wildcard", entry("*.example.org", "[443]"), E::Wildcard),
        ("ipv4", entry("192.0.2.1", "[443]"), E::Ipv4Literal),
        ("ipv6", entry("2001:db8::1", "[443]"), E::Ipv6Literal),
        ("uppercase", entry("Api.example.org", "[443]"), E::Uppercase),
        ("trailing dot", entry("api.example.org.", "[443]"), E::TrailingDot),
        ("single label", entry("localhost", "[443]"), E::SingleLabel),
        ("long label", entry(&long_label, "[443]"), E::LabelTooLong),
        ("empty ports", entry("api.example.org", "[]"), E::EmptyPorts),
        ("port zero", entry("api.example.org", "[0]"), E::PortOutOfRange),
        ("unsorted ports", entry("api.example.org", "[443, 80]"), E::PortsNotSorted),
        ("duplicate port", entry("api.example.org", "[80, 80]"), E::DuplicatePort),
        (
            "duplicate host",
            format!("{}[[destination]]\nhost = \"api.example.org\"\nports = [80]\nwhy = \"x\"\nphase = \"1\"\n", entry("api.example.org", "[443]")),
            E::DuplicateHost,
        ),
        ("unknown top-level key", "format = 1\nextra = 1\n".to_string(), E::UnknownTopLevelKey),
        (
            "unknown entry key",
            format!("{}note = \"x\"\n", entry("api.example.org", "[443]")),
            E::UnknownEntryKey,
        ),
        (
            "missing why",
            "format = 1\n[[destination]]\nhost = \"api.example.org\"\nports = [443]\nphase = \"1\"\n".to_string(),
            E::MissingKey("why"),
        ),
        ("format 2", "format = 2\n".to_string(), E::UnsupportedFormat),
        ("no format", "destination = []\n".to_string(), E::MissingFormat),
        ("not toml", "format = = 1".to_string(), E::NotToml),
    ];
    for (name, text, want) in &cases {
        assert_eq!(Allowlist::parse(text).unwrap_err(), *want, "{name}");
    }
    let kinds: std::collections::BTreeSet<String> = cases
        .iter()
        .map(|(_, _, e)| format!("{:?}", discriminant(e)))
        .collect();
    let distinct: std::collections::BTreeSet<_> =
        cases.iter().map(|(_, _, e)| format!("{e:?}")).collect();
    assert_eq!(distinct.len(), cases.len(), "each case has its own error");
    assert!(kinds.len() >= cases.len() - 1);
}

#[test]
fn allowlist_matches_exact_host_and_port() {
    let list = Allowlist::parse(&entry("api.example.org", "[80, 443]")).unwrap();
    assert!(list.host_listed("api.example.org"));
    assert!(list.host_listed("API.example.org."));
    assert!(!list.host_listed("example.org"));
    assert!(!list.host_listed("x.api.example.org"));
    assert!(list.listed("api.example.org", 443));
    assert!(list.listed("api.example.org", 80));
    assert!(!list.listed("api.example.org", 8080));
    assert!(!list.listed("192.0.2.1", 443));
    assert!(!Allowlist::default().listed("api.example.org", 443));
}
