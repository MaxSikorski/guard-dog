//! The 18 synthetic capture scenarios. Each expected report in
//! `tests/egress/synthetic/` was written before the checker existed.
//! None of these is a real capture.

// Test-only crate: see `crates/gd-core/tests/judge_d_injection.rs` for why helpers need this.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod support;

use data_encoding::BASE64URL_NOPAD;
use gd_egress::canary::Class;
use support::*;

const API_ALLOWLIST: &str = "format = 1\n\n[[destination]]\nhost = \"api.example.org\"\nports = [443]\nwhy = \"test\"\nphase = \"0.6\"\n";

fn https_post(s: &mut Scenario, host: &str, body: &[u8]) {
    s.dns_query(host);
    let c = s.connect("198.18.0.1", 443);
    s.tls(c, Some(host), true);
    s.http(
        c,
        "https",
        "POST",
        host,
        443,
        "/collect",
        &[],
        body,
        false,
        false,
    );
}

fn s03(seed: u64) -> Scenario {
    let mut s = Scenario::new("s03", seed);
    let nsec = s.canary(Class::Nsec);
    https_post(&mut s, "leak.example.net", nsec.as_bytes());
    s
}

fn s04(seed: u64) -> Scenario {
    let mut s = Scenario::new("s04", seed);
    let label: String = s.canary(Class::Macaroon).chars().take(60).collect();
    s.dns_query(&format!("{label}.leak.example.net"));
    s
}

fn s05(seed: u64) -> Scenario {
    let mut s = Scenario::new("s05", seed);
    let words = s.canary(Class::SeedPhrase).replace(' ', ",");
    s.sink_udp("203.0.113.77", 9999, words.as_bytes());
    s
}

fn s06(seed: u64) -> Scenario {
    let mut s = Scenario::new("s06", seed);
    let xpub = s.canary(Class::Xpub);
    let bytes = xpub.as_bytes();
    let (a, rest) = bytes.split_at(bytes.len() / 3);
    let (b, c) = rest.split_at(rest.len() / 2);
    let (len_a, len_b) = (a.len() as u32, b.len() as u32);
    let conn = s.connect("192.0.2.7", 7777);
    s.tcp_event(conn, bytes);
    // Out of order, with the middle segment sent twice.
    s.wire_data(conn, &[(len_a, b), (0, a), (len_a + len_b, c), (len_a, b)]);
    s
}

fn s07(seed: u64) -> Scenario {
    let mut s = Scenario::new("s07", seed);
    s.sink_tcp_syn("2001:db8::1", 80);
    s
}

fn s08(seed: u64) -> Scenario {
    let mut s = Scenario::new("s08", seed);
    let mut data = b"ab".to_vec();
    data.extend(s.set.macaroon_bytes());
    let value = BASE64URL_NOPAD.encode(&data);
    s.dns_query("plain.leak.example.net");
    let c = s.connect("198.18.0.1", 80);
    s.http(
        c,
        "http",
        "GET",
        "plain.leak.example.net",
        80,
        "/",
        &[("X-Note", &value)],
        b"",
        false,
        true,
    );
    s
}

fn api_get(s: &mut Scenario, method: &str, body: &[u8]) {
    s.allowlist = API_ALLOWLIST.to_string();
    s.dns_query("api.example.org");
    let c = s.connect("198.18.0.1", 443);
    s.tls(c, Some("api.example.org"), true);
    s.http(
        c,
        "https",
        method,
        "api.example.org",
        443,
        "/",
        &[],
        body,
        false,
        false,
    );
}

fn s11(seed: u64) -> Scenario {
    let mut s = Scenario::new("s11", seed);
    s.extra_syn_ack();
    s
}

fn s15(seed: u64) -> Scenario {
    let mut s = Scenario::new("s15", seed);
    s.rules = s
        .rules
        .lines()
        .filter(|l| !l.contains("--uid-owner"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    s
}

fn s16(seed: u64) -> Scenario {
    let mut s = Scenario::new("s16", seed);
    let body = format!("gdlabcanary-{}", "0123456789abcdef".repeat(4));
    https_post(&mut s, "leak.example.net", body.as_bytes());
    s
}

/// All 18, as (file stem, scenario).
fn all(seed: u64) -> Vec<(&'static str, Scenario)> {
    let mut s02 = Scenario::bare("s02", seed);
    s02.control(false, false);
    let mut s09 = Scenario::new("s09", seed);
    api_get(&mut s09, "GET", b"");
    let mut s10 = Scenario::new("s10", seed);
    let body = s10.canary(Class::RpcPassword).replace('-', "%2D");
    api_get(&mut s10, "POST", body.as_bytes());
    let mut s12 = Scenario::bare("s12", seed);
    s12.control(true, true);
    let mut s13 = Scenario::new("s13", seed);
    s13.sink_tcp_syn("198.18.0.1", 443);
    let mut s14 = Scenario::new("s14", seed);
    s14.dns_query("pinned.example.com");
    let c = s14.connect("198.18.0.1", 443);
    s14.tls(c, Some("pinned.example.com"), false);
    let mut s17 = Scenario::new("s17", seed);
    s17.raw_mitm_line("{\"conn\":1,\"event\":\"weird\"}");
    let mut s18 = Scenario::new("s18", seed);
    s18.link_type = 1;
    vec![
        ("S01-clean-baseline", Scenario::new("s01", seed)),
        ("S02-blind-mitm", s02),
        ("S03-https-body-leak", s03(seed)),
        ("S04-dns-name-leak", s04(seed)),
        ("S05-raw-udp-leak", s05(seed)),
        ("S06-raw-tcp-split", s06(seed)),
        ("S07-ipv6-literal", s07(seed)),
        ("S08-base64-header", s08(seed)),
        ("S09-allowlisted-clean", s09),
        ("S10-allowlisted-with-canary", s10),
        ("S11-sources-disagree", s11(seed)),
        ("S12-truncated-body", s12),
        ("S13-upstream-attempt", s13),
        ("S14-opaque-tls", s14),
        ("S15-rules-differ", s15(seed)),
        ("S16-lab-cred-shape", s16(seed)),
        ("S17-unknown-event", s17),
        ("S18-wrong-link-type", s18),
    ]
}

#[test]
fn every_synthetic_scenario_gives_its_expected_report() {
    let scenarios = all(1);
    assert_eq!(scenarios.len(), 18);
    let mut failures = Vec::new();
    for (stem, scenario) in &scenarios {
        let (got, want) = (scenario.report(), expected_report(stem));
        if got != want {
            failures.push(format!("--- {stem}: expected\n{want}--- got\n{got}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} scenario(s) differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn report_is_independent_of_seed() {
    for (index, stem) in [(2usize, "S03"), (3, "S04"), (4, "S05"), (7, "S08")] {
        let reports: Vec<String> = [1u64, 2, 3]
            .iter()
            .map(|&seed| all(seed).remove(index).1.report())
            .collect();
        assert_eq!(reports[0], reports[1], "{stem}");
        assert_eq!(reports[0], reports[2], "{stem}");
    }
}

#[test]
fn report_is_independent_of_event_order() {
    for index in [2usize, 5] {
        let base = all(1).remove(index).1.report();
        for rotate in [1usize, 2, 3, 5] {
            let mut s = all(1).remove(index).1;
            s.reorder_lines(rotate);
            assert_eq!(s.report(), base, "scenario {index} rotated by {rotate}");
        }
    }
}
