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
        0,
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
        3,
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
            assert_eq!(
                parsed.packets.len(),
                2,
                "a record of another packet type is skipped"
            );
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
    let end = "{\"conn\":0,\"event\":\"end\"}";
    let parse = |lines: &[&str]| mitm::parse(lines.join("\n").as_bytes());
    let good = parse(&[header, connect, "{\"event\":\"close\",\"conn\":1}", end]);
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
        parse(&[header, "{\"event\":\"close\",\"conn\":1}", connect, end])
            .errors
            .is_empty()
    );
    // The end marker must be the last line, and must be there.
    assert!(parse(&[header, connect]).errors.contains("no-end"));
    assert!(
        parse(&[header, connect, end, "{\"event\":\"close\",\"conn\":1}"])
            .errors
            .contains("no-end")
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

#[test]
fn lo_reads_host_records_and_sink_reads_outgoing() {
    let links = pcap::parse_links("1: lo: <LOOPBACK>\n2: gdsink0: <NOARP>\n").unwrap();
    let datagram = |ifindex: u32, ptype: u8, port: u16| {
        sll2(
            ifindex,
            0x0800,
            ptype,
            &ipv4([127, 0, 0, 1], [127, 0, 0, 1], 17, &udp(50_000, port, b"x")),
        )
    };
    let frames = vec![
        datagram(LO, 0, 9),   // host copy on lo: read
        datagram(LO, 4, 9),   // outgoing copy on lo: ignored
        datagram(SINK, 4, 9), // outgoing on the sink: read
        datagram(SINK, 0, 9), // host on the sink: ignored
        datagram(LO, 3, 9),   // other host: dropped by the parser
        datagram(7, 0, 9),    // an interface we have no name for
    ];
    let parsed = pcap::parse(&pcap_file(Order::Little, false, 276, &frames));
    assert!(parsed.errors.is_empty());
    assert_eq!(
        parsed.packets.len(),
        5,
        "types 0 and 4 are parsed, others skipped"
    );
    let wire = pcap::analyze(&parsed.packets, &links);
    assert_eq!(wire.sink.len(), 1);
    assert_eq!(wire.ignored_types, 2);
    assert_eq!(
        wire.ignored_loopback, 1,
        "the one host datagram on lo is not to or from the sink ports"
    );
    assert!(wire.errors.contains("unknown-interface"));
    // Positive twin: the same host record, sent to the resolver port, is a loopback client packet.
    let to_resolver = pcap::parse(&pcap_file(
        Order::Little,
        false,
        276,
        &[datagram(LO, 0, 5353)],
    ));
    assert_eq!(
        pcap::analyze(&to_resolver.packets, &links).lo_client.len(),
        1
    );
}

fn analyze_frames(frames: &[Vec<u8>]) -> pcap::Wire {
    let links = pcap::parse_links("1: lo: <LOOPBACK>\n2: gdsink0: <NOARP>\n").unwrap();
    let parsed = pcap::parse(&pcap_file(Order::Little, false, 276, frames));
    pcap::analyze(&parsed.packets, &links)
}

fn client_tcp(seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    sll2(
        LO,
        0x0800,
        0,
        &ipv4(
            [127, 0, 0, 1],
            [127, 0, 0, 1],
            6,
            &tcp(40_001, 8080, seq, flags, payload),
        ),
    )
}

#[test]
fn tcp_gaps_and_conflicts_are_reported() {
    // Clean, in order and out of order with a harmless retransmission: no problem, bytes joined.
    let clean = analyze_frames(&[
        client_tcp(100, SYN, b""),
        client_tcp(106, PSH_ACK, b"world"),
        client_tcp(101, PSH_ACK, b"hello"),
        client_tcp(101, PSH_ACK, b"hello"),
    ]);
    assert!(clean.errors.is_empty(), "{:?}", clean.errors);
    assert_eq!(clean.recorder_streams[0].data, b"helloworld");
    // A hole: bytes 6..11 never arrive. Nothing is invented for them.
    let gap = analyze_frames(&[
        client_tcp(100, SYN, b""),
        client_tcp(101, PSH_ACK, b"hello"),
        client_tcp(111, PSH_ACK, b"later"),
    ]);
    assert!(gap.errors.contains("tcp-gap"));
    assert_eq!(gap.recorder_streams[0].data, b"hellolater");
    // A missing start counts as a gap too.
    assert!(
        analyze_frames(&[client_tcp(100, SYN, b""), client_tcp(105, PSH_ACK, b"x")])
            .errors
            .contains("tcp-gap")
    );
    // A retransmission with different bytes: both versions are kept for scanning.
    let conflict = analyze_frames(&[
        client_tcp(100, SYN, b""),
        client_tcp(101, PSH_ACK, b"AAAAA"),
        client_tcp(101, PSH_ACK, b"BBBBBCC"),
    ]);
    assert!(conflict.errors.contains("tcp-overlap-conflict"));
    assert_eq!(
        conflict.recorder_streams[0].conflicts,
        [b"BBBBBCC".to_vec()]
    );
    assert_eq!(conflict.recorder_streams[0].data, b"AAAAACC");
}

fn hex_bytes(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn dns_queries_with_extra_sections_are_rejected() {
    let plain = support::Scenario::dns_query_bytes("a.example.org", 7, 1, None);
    assert!(!pcap::parse_dns(&plain).unwrap().unexpected_section);
    // One OPT record (type 41, root name) is what a normal resolver sends.
    let opt = [0u8, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0];
    let with_opt = support::Scenario::dns_query_bytes("a.example.org", 7, 1, Some(&opt));
    assert!(!pcap::parse_dns(&with_opt).unwrap().unexpected_section);
    // One TXT record is not.
    let txt = [0u8, 0, 16, 0, 1, 0, 0, 0, 0, 0, 1, 0];
    let with_txt = support::Scenario::dns_query_bytes("a.example.org", 7, 1, Some(&txt));
    let message = pcap::parse_dns(&with_txt).unwrap();
    assert!(message.unexpected_section);
    assert_eq!(
        message.questions,
        [("a.example.org".to_string(), 1)],
        "the question is still read"
    );
    // Any answer or authority record, or two additional records, in a query.
    let record = [0u8, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0];
    for (an, ns, ar) in [(1u8, 0u8, 0u8), (0, 1, 0), (0, 0, 2)] {
        let mut q = plain.clone();
        q[7] = an;
        q[9] = ns;
        q[11] = ar;
        for _ in 0..(an + ns + ar) {
            q.extend(record);
        }
        assert!(
            pcap::parse_dns(&q).unwrap().unexpected_section,
            "{an} {ns} {ar}"
        );
    }
    // A response may carry answers.
    let mut response = plain.clone();
    response[2] = 0x81;
    response[7] = 1;
    response.extend(record);
    assert!(!pcap::parse_dns(&response).unwrap().unexpected_section);
    // Records are read in full: a cut-off OPT, options that do not fill it, trailing bytes.
    let cut = hex_bytes("000101000000000000000001000029");
    assert_eq!(pcap::parse_dns(&cut).unwrap_err(), "dns-framing");
    let mut bad_option = plain.clone();
    bad_option[11] = 1;
    bad_option.extend([0u8, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 3, 0, 8, 0, 9]); // rdlen 3: an option header cut short
    assert_eq!(pcap::parse_dns(&bad_option).unwrap_err(), "dns-framing");
    let mut trailing = plain.clone();
    trailing.push(0);
    assert_eq!(pcap::parse_dns(&trailing).unwrap_err(), "dns-framing");
    let mut good_option = plain.clone();
    good_option[11] = 1;
    good_option.extend([0u8, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 4, 0, 8, 0, 0]); // one empty option
    assert!(!pcap::parse_dns(&good_option).unwrap().unexpected_section);
    // Framing: short header, cut question, compression pointer in a question.
    assert_eq!(pcap::parse_dns(&[0u8; 6]).unwrap_err(), "dns-framing");
    assert_eq!(
        pcap::parse_dns(plain.get(..16).unwrap()).unwrap_err(),
        "dns-framing"
    );
    let mut pointer = plain.clone();
    pointer[12] = 0xC0;
    assert_eq!(pcap::parse_dns(&pointer).unwrap_err(), "dns-framing");
}

#[test]
fn every_dns_question_is_read() {
    let mut q = Vec::new();
    q.extend([0, 9, 0x01, 0, 0, 3, 0, 0, 0, 0, 0, 0]);
    for (name, qtype) in [
        ("first.example.org", 1u16),
        ("second.example.org", 28),
        ("third.example.org", 16),
    ] {
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend(label.as_bytes());
        }
        q.push(0);
        q.extend(qtype.to_be_bytes());
        q.extend([0, 1]);
    }
    let message = pcap::parse_dns(&q).unwrap();
    let names: Vec<&str> = message.questions.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "first.example.org",
            "second.example.org",
            "third.example.org"
        ]
    );
    assert_eq!(pcap::qtype_name(message.questions[1].1), "AAAA");
    assert_eq!(pcap::qtype_name(message.questions[2].1), "TXT");
    // The judge sees all three as separate wire questions.
    let frame = sll2(
        LO,
        0x0800,
        0,
        &ipv4([127, 0, 0, 1], [127, 0, 0, 1], 17, &udp(50_000, 5353, &q)),
    );
    assert_eq!(analyze_frames(&[frame]).dns_questions.len(), 3);
}
