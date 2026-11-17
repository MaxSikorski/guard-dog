//! The 54 synthetic capture scenarios. Each expected report in
//! `tests/egress/synthetic/` was written before the code that makes it pass.
//! None of these is a real capture.

// Test-only crate: see `crates/gd-core/tests/judge_d_injection.rs` for why helpers need this.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod support;

use data_encoding::{BASE32_NOPAD, BASE64URL_NOPAD, HEXLOWER};
use gd_egress::canary::Class;
use support::*;

const API: &str = "api.example.org";

/// An allowlisted host reached the right way: its DNS question, the fake address, its SNI.
fn api_conn(s: &mut Scenario, dns: bool, ip: &str, dst_port: u16, sni: &str) -> Conn {
    s.allowlist = API_ALLOWLIST.to_string();
    if dns {
        s.dns_query(API);
    }
    let c = s.connect(ip, dst_port);
    s.tls(c, Some(sni), true);
    c
}

fn post(s: &mut Scenario, c: Conn, method: &str, headers: &[(&str, &str)], body: &[u8]) {
    s.http(
        c, "https", method, API, 443, "/", headers, body, false, false,
    );
}

/// A clean allowlisted request with the given body.
fn api_post(s: &mut Scenario, body: &[u8]) {
    let c = api_conn(s, true, "198.18.0.1", 443, API);
    post(s, c, "POST", &[], body);
}

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

fn with_api_body(name: &str, seed: u64, make: impl Fn(&Scenario) -> Vec<u8>) -> Scenario {
    let mut s = Scenario::new(name, seed);
    let body = make(&s);
    api_post(&mut s, &body);
    s
}

fn near_misses(ip: &str) -> Vec<String> {
    let (head, last) = ip.rsplit_once('.').unwrap();
    let n: u32 = last.parse().unwrap();
    [n - 1, n + 1]
        .into_iter()
        .filter(|v| (1..=254).contains(v))
        .map(|v| format!("{head}.{v}"))
        .collect()
}

fn ipv4_value(s: &Scenario) -> u32 {
    s.canary(Class::Ipv4)
        .parse::<std::net::Ipv4Addr>()
        .unwrap()
        .into()
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

fn s30(seed: u64) -> Scenario {
    let mut s = Scenario::new("s30", seed);
    let phrase = s.canary(Class::SeedPhrase);
    let words: Vec<&str> = phrase.split(' ').collect();
    s.dns_query(&format!("{}.leak.example.net", words[3..6].concat()));
    s
}

fn s31(seed: u64) -> Scenario {
    let mut s = Scenario::new("s31", seed);
    let rpc = s.canary(Class::RpcPassword);
    let host = format!("{}.example.net", rpc.replace('-', "%2d"));
    let c = s.connect("198.18.0.1", 80);
    s.http(
        c,
        "http",
        "GET",
        &host,
        80,
        "/",
        &[("Host", &host)],
        b"",
        false,
        true,
    );
    s
}

fn s33(seed: u64) -> Scenario {
    let mut s = Scenario::new("s33", seed);
    let xpub = s.canary(Class::Xpub);
    let (a, b) = xpub.as_bytes().split_at(40);
    let c = s.connect("192.0.2.7", 7777);
    s.tcp_event(c, a);
    s.tcp_event(c, b);
    s.wire_data(c, &[(0, a), (40, b)]);
    s
}

fn s34(seed: u64) -> Scenario {
    let mut s = Scenario::bare("s34", seed);
    let c = s.control("pre", FULL_CONTROL);
    s.http(
        c,
        "https",
        "GET",
        "evil.invalid",
        443,
        "/",
        &[],
        b"",
        false,
        false,
    );
    s
}

fn s41(seed: u64) -> Scenario {
    let mut s = Scenario::new("s41", seed);
    // Only the first 20 characters go in the TXT strings: a whole nsec would also be caught as a leak
    // (it is, the separator-stripped view reads through the length bytes), but this scenario is about
    // the unexpected section failing closed.
    let nsec: String = s.canary(Class::Nsec).chars().take(20).collect();
    s.allowlist = API_ALLOWLIST.to_string();
    s.log_dns_only(API);
    // An additional TXT record whose strings carry the nsec in 8-byte pieces.
    let mut txt = vec![0u8, 0, 16, 0, 1, 0, 0, 0, 0];
    let strings: Vec<u8> = nsec
        .as_bytes()
        .chunks(8)
        .flat_map(|c| [&[c.len() as u8][..], c].concat())
        .collect();
    txt.extend(u16::try_from(strings.len()).unwrap().to_be_bytes());
    txt.extend(strings);
    s.wire_dns_with(API, 1, true, Some(&txt));
    let c = s.connect("198.18.0.1", 443);
    s.tls(c, Some(API), true);
    post(&mut s, c, "POST", &[], b"x");
    s
}

fn s49(seed: u64) -> Scenario {
    let mut s = Scenario::new("s49", seed);
    let nsec = s.canary(Class::Nsec);
    let pieces: Vec<&[u8]> = nsec.as_bytes().chunks(10).collect();
    let first = api_conn(&mut s, true, "198.18.0.1", 443, API);
    let second = api_conn(&mut s, false, "198.18.0.1", 443, API);
    for (i, piece) in pieces.iter().enumerate() {
        post(
            &mut s,
            if i < 4 { first } else { second },
            "POST",
            &[],
            piece,
        );
    }
    s
}

/// All 54, as (file stem, scenario).
fn all(seed: u64) -> Vec<(&'static str, Scenario)> {
    let mut s02 = Scenario::bare("s02", seed);
    s02.control(
        "pre",
        Control {
            http: false,
            ..FULL_CONTROL
        },
    );
    let mut s09 = Scenario::new("s09", seed);
    api_post(&mut s09, b"");
    let mut s10 = Scenario::new("s10", seed);
    let body = s10.canary(Class::RpcPassword).replace('-', "%2D");
    api_post(&mut s10, body.as_bytes());
    let mut s12 = Scenario::bare("s12", seed);
    s12.control(
        "pre",
        Control {
            truncated: true,
            ..FULL_CONTROL
        },
    );
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

    let s19 = with_api_body("s19", seed, |s| {
        HEXLOWER.encode(&s.canary_bytes(Class::Nsec)).into_bytes()
    });
    let s20 = with_api_body("s20", seed, |s| {
        b64(&s.canary_bytes(Class::SeedPhrase)).into_bytes()
    });
    let s21 = with_api_body("s21", seed, |s| {
        HEXLOWER
            .encode(&s.canary_bytes(Class::Xpub)[13..45])
            .into_bytes()
    });
    let s22 = with_api_body("s22", seed, |s| {
        let nsec = s.canary(Class::Nsec);
        nsec.as_bytes()
            .chunks(4)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join(" ")
            .into_bytes()
    });
    let s23 = with_api_body("s23", seed, |s| {
        let encoded = b64(s.set.macaroon_bytes());
        encoded
            .as_bytes()
            .chunks(76)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join("\r\n")
            .into_bytes()
    });
    let s24 = with_api_body("s24", seed, |s| {
        let rpc = s.canary(Class::RpcPassword);
        rpc.as_bytes()
            .chunks(10)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes()
    });
    let mut s25 = Scenario::new("s25", seed);
    let c = api_conn(&mut s25, true, "198.18.0.1", 443, "evil.invalid");
    post(&mut s25, c, "POST", &[], b"x");
    let mut s26 = Scenario::new("s26", seed);
    let c = api_conn(&mut s26, true, "198.18.0.1", 8443, API);
    post(&mut s26, c, "POST", &[], b"x");
    let mut s27 = Scenario::new("s27", seed);
    let c = api_conn(&mut s27, true, "192.0.2.9", 443, API);
    post(&mut s27, c, "POST", &[], b"x");
    let mut s28 = Scenario::new("s28", seed);
    let c = api_conn(&mut s28, false, "198.18.0.1", 443, API);
    post(&mut s28, c, "POST", &[], b"x");
    let mut s29 = Scenario::new("s29", seed);
    s29.cut_post_pcap = true;
    let mut s32 = Scenario::new("s32", seed);
    api_post(&mut s32, format!("xprv{}", "1io".repeat(36)).as_bytes());
    let mut s35 = Scenario::new("s35", seed);
    s35.fragment(50_500, 5353, &[0u8; 12]);
    let mut s36 = Scenario::bare("s36", seed);
    s36.control(
        "pre",
        Control {
            payload: false,
            ..FULL_CONTROL
        },
    );
    let mut s37 = Scenario::new("s37", seed);
    s37.wire_dns("evil.invalid", 1, false);
    let mut s38 = Scenario::new("s38", seed);
    let nsec = s38.canary(Class::Nsec);
    let c = api_conn(&mut s38, true, "198.18.0.1", 443, API);
    post(&mut s38, c, &nsec, &[], b"");
    let s39 = with_api_body("s39", seed, |s| {
        let escaped: String = s
            .canary(Class::Nsec)
            .bytes()
            .map(|b| format!("\\u00{b:02x}"))
            .collect();
        format!("{{\"k\":\"{escaped}\"}}").into_bytes()
    });
    let mut s40 = Scenario::new("s40", seed);
    let nsec = s40.canary(Class::Nsec);
    let c = api_conn(&mut s40, true, "198.18.0.1", 443, API);
    post(
        &mut s40,
        c,
        "POST",
        &[("Content-Encoding", "gzip")],
        &gzip_fixed_huffman(nsec.as_bytes()),
    );
    let mut s42 = Scenario::new("s42", seed);
    s42.raw_lo_tcp_dns(51_000, &[0x00, 0x40, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66]);
    let mut s43 = Scenario::new("s43", seed);
    s43.raw_lo_udp(51_001, 5353, &[0u8; 6]);
    let s44 = with_api_body("s44", seed, |s| {
        b64(format!("x{}", s.canary(Class::Ipv4)).as_bytes()).into_bytes()
    });
    let s45 = with_api_body("s45", seed, |s| {
        let ip = s.canary(Class::Ipv4);
        near_misses(&ip)
            .iter()
            .flat_map(|m| [BASE32_NOPAD.encode(m.as_bytes()), b64(m.as_bytes())])
            .collect::<Vec<_>>()
            .join(";")
            .into_bytes()
    });
    let s46 = with_api_body("s46", seed, |s| ipv4_value(s).to_string().into_bytes());
    let s47 = with_api_body("s47", seed, |s| {
        format!("0x{:08x}", ipv4_value(s)).into_bytes()
    });
    let s48 = with_api_body("s48", seed, |s| {
        let bytes = s.canary_bytes(Class::Ipv6);
        let groups: Vec<String> = bytes
            .chunks(2)
            .take(6)
            .map(|g| format!("{:x}", u16::from_be_bytes([g[0], g[1]])))
            .collect();
        format!(
            "{}:{}.{}.{}.{}",
            groups.join(":"),
            bytes[12],
            bytes[13],
            bytes[14],
            bytes[15]
        )
        .into_bytes()
    });
    let mut s50 = Scenario::new("s50", seed);
    let c = s50.connect("192.0.2.7", 7777);
    s50.wire_data(c, &[(0, b"0123456789"), (20, b"abcdefghij")]);
    let mut s51 = Scenario::new("s51", seed);
    let xpub = s51.canary(Class::Xpub);
    let c = s51.connect("192.0.2.7", 7777);
    s51.wire_data(c, &[(0, &[b'A'; 40]), (0, xpub.as_bytes())]);
    let mut s52 = Scenario::new("s52", seed);
    s52.lo_duplicate_outgoing = true;
    let mut s53 = Scenario::bare("s53", seed);
    s53.next_conn = 2;
    s53.control("pre", FULL_CONTROL);
    s53.allowlist = API_ALLOWLIST.to_string();
    s53.dns_query(API);
    let c = s53.connect_as(1, "198.18.0.1", 443);
    s53.tls(c, Some(API), true);
    post(&mut s53, c, "POST", &[], b"x");
    let mut s54 = Scenario::new("s54", seed);
    s54.end = false;

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
        ("S19-nsec-raw-hex", s19),
        ("S20-seed-entropy-base64", s20),
        ("S21-xpub-chain-code-hex", s21),
        ("S22-nsec-spaced", s22),
        ("S23-macaroon-base64-wrapped", s23),
        ("S24-rpc-newline-split", s24),
        ("S25-sni-mismatch", s25),
        ("S26-port-mismatch", s26),
        ("S27-ip-literal", s27),
        ("S28-no-dns-question", s28),
        ("S29-pcap-cut-before-post", s29),
        ("S30-redact-seed-window", s30(seed)),
        ("S31-redact-percent-host", s31(seed)),
        ("S32-xprv-full-alphabet", s32),
        ("S33-tcp-events-split", s33(seed)),
        ("S34-control-conn-extra-request", s34(seed)),
        ("S35-ipv4-fragment", s35),
        ("S36-control-handshake-only", s36),
        ("S37-unanswered-wire-question", s37),
        ("S38-nsec-as-method", s38),
        ("S39-nsec-json-u-escaped", s39),
        ("S40-gzip-body", s40),
        ("S41-dns-txt-additional", s41(seed)),
        ("S42-tcp-dns-short-frame", s42),
        ("S43-dns-short-header", s43),
        ("S44-ipv4-base64-offset", s44),
        ("S45-ipv4-near-miss", s45),
        ("S46-ipv4-integer", s46),
        ("S47-ipv4-hex", s47),
        ("S48-ipv6-embedded-ipv4", s48),
        ("S49-nsec-split-across-requests", s49(seed)),
        ("S50-tcp-gap", s50),
        ("S51-tcp-overlap-conflict", s51),
        ("S52-lo-duplicate-outgoing", s52),
        ("S53-workload-before-pre", s53),
        ("S54-mitm-no-end", s54),
    ]
}

fn find(seed: u64, prefix: &str) -> Scenario {
    all(seed)
        .into_iter()
        .find(|(stem, _)| stem.starts_with(prefix))
        .unwrap()
        .1
}

#[test]
fn every_synthetic_scenario_gives_its_expected_report() {
    let scenarios = all(1);
    assert_eq!(scenarios.len(), 54);
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
    for prefix in [
        "S03", "S04", "S05", "S08", "S22", "S25", "S30", "S31", "S44", "S49",
    ] {
        let reports: Vec<String> = [1u64, 2, 3]
            .iter()
            .map(|&seed| find(seed, prefix).report())
            .collect();
        assert_eq!(reports[0], reports[1], "{prefix}");
        assert_eq!(reports[0], reports[2], "{prefix}");
    }
}

#[test]
fn report_is_independent_of_event_order() {
    for prefix in ["S03", "S06"] {
        let base = find(1, prefix).report();
        for rotate in [1usize, 2, 3, 5] {
            let mut s = find(1, prefix);
            s.reorder_lines(rotate);
            assert_eq!(s.report(), base, "{prefix} rotated by {rotate}");
        }
    }
    // Connections may come in any order; the order of events inside a connection is kept.
    let base = find(1, "S49").report();
    for rotate in [1usize, 2, 3] {
        let mut s = find(1, "S49");
        s.reorder_conns(rotate);
        assert_eq!(s.report(), base, "S49 rotated by {rotate}");
    }
}
