//! The three capture readers and the rules comparison.

// Test-only crate: see `crates/gd-core/tests/judge_d_injection.rs` for why helpers need this.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod support;

use gd_egress::capture::pcap::{self, L4};
use gd_egress::capture::{dns_log, mitm};
use gd_egress::rules;
use proptest::prelude::*;
use support::*;

fn three_frames() -> Vec<Vec<u8>> {
    let a = sll2(
        LO,
        0x0800,
        4,
        &ipv4(
            [127, 0, 0, 1],
            [127, 0, 0, 1],
            17,
            &udp(50_000, 5353, b"hello"),
        ),
    );
    let b = sll2(
        SINK,
        0x0800,
        4,
        &ipv4(
            [198, 18, 255, 1],
            [203, 0, 113, 7],
            6,
            &tcp(1, 2, 3, SYN, b""),
        ),
    );
    let incoming = sll2(
        LO,
        0x0800,
        0,
        &ipv4([127, 0, 0, 1], [127, 0, 0, 1], 17, &udp(1, 2, b"skip me")),
    );
    vec![a, b, incoming]
}

#[test]
fn pcap_reads_sll2_both_byte_orders_and_nanoseconds() {
    let frames = three_frames();
    let mut seen = Vec::new();
    for order in [Order::Little, Order::Big] {
        for nanos in [false, true] {
            let parsed = pcap::parse(&pcap_file(order, nanos, 276, &frames));
            assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
            assert_eq!(parsed.packets.len(), 2, "the incoming packet is skipped");
            seen.push(parsed.packets);
        }
    }
    assert!(seen.windows(2).all(|w| w[0] == w[1]));
    let packets = &seen[0];
    assert_eq!(packets[0].ifindex, LO);
    assert!(matches!(&packets[0].l4, L4::Udp { dport: 5353, payload, .. } if payload == b"hello"));
    assert!(matches!(
        &packets[1].l4,
        L4::Tcp {
            dport: 2,
            flags: 2,
            ..
        }
    ));
}

#[test]
fn pcap_rejects_truncated_files() {
    let frames = three_frames();
    let file = pcap_file(Order::Little, false, 276, &frames);
    // A prefix that ends exactly between two records is a well-formed, shorter capture
    // (nothing in the file says how many records were meant to follow), so those cannot be told apart.
    let mut boundaries = vec![24usize];
    for frame in &frames {
        boundaries.push(boundaries.last().unwrap() + 16 + frame.len());
    }
    assert_eq!(*boundaries.last().unwrap(), file.len());
    for len in 0..file.len() {
        let parsed = pcap::parse(&file[..len]);
        if boundaries.contains(&len) && len >= 24 {
            assert!(
                parsed.errors.is_empty(),
                "prefix {len} ends between records"
            );
        } else {
            assert!(
                parsed.errors.contains("truncated"),
                "prefix {len}: {:?}",
                parsed.errors
            );
        }
    }
    assert!(pcap::parse(&file).errors.is_empty());
}

#[test]
fn pcap_rejects_a_wrong_link_type_and_a_bad_header() {
    let wrong = pcap::parse(&pcap_file(Order::Little, false, 1, &three_frames()));
    assert!(wrong.errors.contains("link-type") && wrong.packets.is_empty());
    assert!(
        pcap::parse(b"not a pcap file at all, but long enough")
            .errors
            .contains("bad-header")
    );
}

proptest! {
    #![proptest_config(ProptestConfig { rng_seed: proptest::test_runner::RngSeed::Fixed(0x6764_5f65_6772_6573), ..ProptestConfig::default() })]

    #[test]
    fn pcap_parser_never_panics(random in proptest::collection::vec(any::<u8>(), 0..600), as_frame in any::<bool>()) {
        let _ = pcap::parse(&random);
        let _ = pcap::parse_dns(&random);
        let _ = pcap::parse_links(&String::from_utf8_lossy(&random));
        // Also go deeper: a valid header and one record around random bytes.
        let frames = vec![random.clone()];
        let file = if as_frame { pcap_file(Order::Little, false, 276, &frames) } else { random };
        let parsed = pcap::parse(&file);
        let _ = pcap::analyze(&parsed.packets, &pcap::parse_links("1: lo: x\n2: gdsink0: x\n").unwrap());
    }
}

#[test]
fn dns_log_decodes_escapes_and_rejects_stray_lines() {
    let ok = "[INFO] GDQ A IN Foo\\.Bar.Example.COM. udp NOERROR\n[INFO] GDQ AAAA IN a\\032b.example.com. udp NOERROR\n[INFO] GDQ A IN x\\046y.test. udp NOERROR\n[INFO] plugin/reload: Running configuration\n.:5353\n";
    let log = dns_log::parse(ok.as_bytes());
    assert!(log.errors.is_empty());
    let names: Vec<&str> = log.records.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(
        names,
        ["foo.bar.example.com", "a b.example.com", "x.y.test"]
    );
    assert_eq!(log.records[1].qtype, "AAAA");
    for bad in [
        "[INFO] GDQ A IN x udp\n",
        "[INFO] GDQ A IN x udp NOERROR extra\n",
        "[ERROR] plugin/errors: oops\n",
        "[FATAL] plugin/forward: no\n",
        "something GDQ in the middle\n",
        "[WARNING] GDQ A IN x udp NOERROR\n",
    ] {
        assert!(
            dns_log::parse(bad.as_bytes()).errors.contains("bad-line"),
            "{bad:?}"
        );
    }
}

#[test]
fn mitm_jsonl_rejects_unknown_events_and_keys() {
    let header = "{\"gd_capture\":1,\"tool\":\"mitmproxy\",\"tool_version\":\"12.3.1\"}";
    let connect = "{\"event\":\"connect\",\"conn\":1,\"client_port\":40001,\"dst_ip\":\"198.18.0.1\",\"dst_port\":443}";
    let parse = |lines: &[&str]| mitm::parse(lines.join("\n").as_bytes());
    let good = parse(&[header, connect, "{\"event\":\"close\",\"conn\":1}"]);
    assert!(good.errors.is_empty(), "{:?}", good.errors);
    assert_eq!(good.conns.len(), 1);
    let cases: [(&[&str], &str); 11] = [
        (
            &[
                "{\"gd_capture\":2,\"tool\":\"mitmproxy\",\"tool_version\":\"x\"}",
                connect,
            ],
            "bad-header",
        ),
        (&["{\"event\":\"connect\"}", connect], "bad-header"),
        (
            &[header, "{\"event\":\"weird\",\"conn\":1}"],
            "unknown-event",
        ),
        (
            &[
                header,
                connect,
                "{\"event\":\"close\",\"conn\":1,\"extra\":1}",
            ],
            "unknown-key",
        ),
        (
            &[
                header,
                "{\"event\":\"connect\",\"conn\":1,\"client_port\":1,\"dst_ip\":\"1.2.3.4\",\"dst_port\":1,\"extra\":2}",
            ],
            "unknown-key",
        ),
        (
            &[
                header,
                "{\"event\":\"connect\",\"conn\":1,\"client_port\":1,\"dst_ip\":\"1.2.3.4\"}",
            ],
            "bad-line",
        ),
        (&[header, "not json"], "bad-line"),
        (&[header, "{\"event\":\"close\",\"conn\":0}"], "bad-line"),
        (&[header, "{\"event\":\"close\",\"conn\":7}"], "bad-line"),
        (
            &[
                header,
                "{\"event\":\"connect\",\"conn\":1,\"client_port\":1,\"dst_ip\":\"nope\",\"dst_port\":1}",
            ],
            "bad-line",
        ),
        (
            &[
                header,
                connect,
                "{\"event\":\"http\",\"conn\":1,\"scheme\":\"ftp\",\"method_b64\":\"\",\"host_b64\":\"\",\"port\":1,\"path_b64\":\"\",\"headers\":[],\"body_b64\":\"\",\"body_truncated\":false}",
            ],
            "bad-line",
        ),
    ];
    for (lines, code) in cases {
        assert!(
            parse(lines).errors.contains(code),
            "{lines:?} should give {code}"
        );
    }
    let truncated = parse(&[
        header,
        connect,
        "{\"event\":\"http\",\"conn\":1,\"scheme\":\"https\",\"method_b64\":\"R0VU\",\"host_b64\":\"YS5i\",\"port\":443,\"path_b64\":\"Lw==\",\"headers\":[[\"WA==\",\"WQ==\"]],\"body_b64\":\"\",\"body_truncated\":true}",
    ]);
    assert!(truncated.errors.contains("body-truncated"));
    assert_eq!(
        truncated.conns[&1].http[0].headers,
        [(b"X".to_vec(), b"Y".to_vec())]
    );
    // Events may come before their connection line.
    assert!(
        parse(&[header, "{\"event\":\"close\",\"conn\":1}", connect])
            .errors
            .is_empty()
    );
}

#[test]
fn rules_normalisation_ignores_comments_and_counters() {
    let dump = "# Generated by iptables-save v1.8.11\n== iptables-save\n*nat\n:OUTPUT ACCEPT [0:0]\n-A OUTPUT -o lo -j RETURN   \n\n-A OUTPUT -p tcp -m comment --comment \"[x]\" [12:34]\nCOMMIT\n# Completed\n";
    let expected = "== iptables-save\n*nat\n:OUTPUT ACCEPT\n-A OUTPUT -o lo -j RETURN\n-A OUTPUT -p tcp -m comment --comment \"[x]\"\nCOMMIT\n";
    assert!(rules::same(dump, expected));
    assert_eq!(rules::normalize("a [1:2]\n  # c\n\nb  \n"), ["a", "b"]);
    assert!(!rules::same(dump, "== iptables-save\n*nat\nCOMMIT\n"));
    assert!(!rules::same("", expected));
}
