//! Reads the capture and decides: findings F1 to F5 and the byte-stable report.
//!
//! Every way the judge could be fooled or blinded must fail closed: an
//! unreadable source, a missing control, a source that disagrees with another
//! all become findings. Every string that came from the capture is redacted
//! (canaries replaced) and then escaped before it is printed.

use crate::allowlist::Allowlist;
use crate::canary::CanarySet;
use crate::capture::mitm::{Conn, MitmLog};
use crate::capture::pcap::{self, L4, Packet, Wire};
use crate::capture::{RawCapture, dns_log};
use crate::needle::{HitKind, Needles};
use crate::rules;
use gd_core::Untrusted;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

/// The outcome of one check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The report: header, control, destinations, then sorted findings. No counts, no times.
    pub report: String,
    /// Counts per source, for people. Nothing compares it.
    pub details: String,
    /// True when there are no findings.
    pub pass: bool,
}

struct Judge<'a> {
    needles: &'a Needles,
    findings: BTreeSet<String>,
}

impl Judge<'_> {
    /// Redacts, then escapes, a string that came from the capture.
    fn safe(&self, text: &str) -> String {
        Untrusted::new(self.needles.redact(text)).escape_for_terminal()
    }

    fn scan(&mut self, hay: &[u8], location: &str, dest: &str) {
        for hit in self.needles.scan(hay) {
            let dest = self.safe(dest);
            self.findings.insert(match hit {
                HitKind::Canary(class) => {
                    format!("F2 canary-leaked {} in {location} to {dest}", class.name())
                }
                HitKind::Shape(shape) => {
                    format!("F2 secret-shape-leaked {shape} in {location} to {dest}")
                }
            });
        }
    }
}

fn host_port(ip: &str, port: u16) -> String {
    if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_ascii_lowercase()
}

/// How a connection is named in findings, without a scheme.
fn conn_dest(conn: &Conn) -> String {
    if let Some(event) = conn.http.first() {
        return format!("{}:{}", event.host, event.port);
    }
    if let Some((sni, false)) = &conn.tls {
        let name = sni.as_deref().map_or_else(|| conn.dst_ip.clone(), lossy);
        return host_port(&name, conn.dst_port);
    }
    host_port(&conn.dst_ip, conn.dst_port)
}

/// The destination entries of a connection: (name with scheme, host to match, port).
fn conn_destinations(conn: &Conn) -> Vec<(String, Option<(String, u16)>)> {
    if !conn.http.is_empty() {
        return conn
            .http
            .iter()
            .map(|e| {
                (
                    format!("{} {}:{}", e.scheme, e.host, e.port),
                    Some((e.host.clone(), e.port)),
                )
            })
            .collect();
    }
    if let Some((sni, false)) = &conn.tls {
        let name = sni.as_deref().map_or_else(|| conn.dst_ip.clone(), lossy);
        return vec![(
            format!("tls-opaque {}", host_port(&name, conn.dst_port)),
            None,
        )];
    }
    vec![(
        format!("tcp {}", host_port(&conn.dst_ip, conn.dst_port)),
        None,
    )]
}

/// The packet's name when it left through the black hole, or `None` if it has no label.
fn sink_label(packet: &Packet) -> String {
    let ip = |addr: IpAddr| addr.to_string();
    match (&packet.l4, packet.ip) {
        (L4::Tcp { dport, .. }, Some((_, dst))) => format!(
            "{} {}",
            if dst.is_ipv6() { "tcp6" } else { "tcp" },
            host_port(&ip(dst), *dport)
        ),
        (L4::Udp { dport, .. }, Some((_, dst))) => format!(
            "{} {}",
            if dst.is_ipv6() { "udp6" } else { "udp" },
            host_port(&ip(dst), *dport)
        ),
        (L4::Icmp { v6, .. }, Some((_, dst))) => {
            format!("{} {}", if *v6 { "icmp6" } else { "icmp" }, ip(dst))
        }
        (L4::Other { label, .. }, _) => format!("other {label}"),
        _ => "other unknown".to_string(),
    }
}

fn payload(packet: &Packet) -> &[u8] {
    match &packet.l4 {
        L4::Tcp { payload, .. }
        | L4::Udp { payload, .. }
        | L4::Icmp { payload, .. }
        | L4::Other { payload, .. } => payload,
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len().max(1)).any(|w| w == needle)
}

fn is_control_packet(packet: &Packet, token: &str) -> bool {
    let marker = format!("gd-egress-control {token}");
    matches!(
        (&packet.l4, packet.ip),
        (L4::Udp { dport: 9, payload, .. }, Some((_, IpAddr::V4(dst)))) if dst.octets() == [198, 18, 0, 99] && contains(payload, marker.as_bytes())
    )
}

/// Judges a capture. `expected_rules` is the reviewed rules dump.
pub fn judge(
    raw: &RawCapture,
    set: &CanarySet,
    allow: &Allowlist,
    expected_rules: &str,
) -> Verdict {
    let needles = Needles::new(set);
    let mut j = Judge {
        needles: &needles,
        findings: BTreeSet::new(),
    };
    let f5 = |source: &str, code: &str| format!("F5 capture-unreadable {source}: {code}");
    let mut unreadable: BTreeSet<&str> = BTreeSet::new();
    let mut note = |j: &mut Judge, source: &'static str, code: &str| {
        j.findings.insert(f5(source, code));
        unreadable.insert(source);
    };

    // Parse the sources. A source that cannot be read gives an empty result and an F5.
    let dns = match &raw.dns_log {
        Ok(bytes) => dns_log::parse(bytes),
        Err(code) => {
            note(&mut j, "dns-log", code);
            dns_log::DnsLog::default()
        }
    };
    for code in &dns.errors {
        note(&mut j, "dns-log", code);
    }
    let mitm: MitmLog = match &raw.mitm {
        Ok(bytes) => crate::capture::mitm::parse(bytes),
        Err(code) => {
            note(&mut j, "mitm", code);
            MitmLog::default()
        }
    };
    for code in &mitm.errors {
        note(&mut j, "mitm", code);
    }
    let parsed = match &raw.pcap {
        Ok(bytes) => pcap::parse(bytes),
        Err(code) => {
            note(&mut j, "pcap", code);
            pcap::PcapParse::default()
        }
    };
    for code in &parsed.errors {
        note(&mut j, "pcap", code);
    }
    let links = match &raw.links {
        Ok(bytes) => {
            let parsed_links = pcap::parse_links(&String::from_utf8_lossy(bytes));
            if parsed_links.is_none() {
                note(&mut j, "links", "bad-line");
            }
            parsed_links.unwrap_or_default()
        }
        Err(code) => {
            note(&mut j, "links", code);
            BTreeMap::new()
        }
    };
    let wire: Wire = pcap::analyze(&parsed.packets, &links);
    for code in &wire.errors {
        note(&mut j, "pcap", code);
    }
    match &raw.rules {
        Ok(bytes) if !rules::same(&String::from_utf8_lossy(bytes), expected_rules) => {
            note(&mut j, "rules", "rules-differ")
        }
        Ok(_) => {}
        Err(code) => note(&mut j, "rules", code),
    }

    // The control: four things the sealed box must always have seen.
    let token = set.control_token.as_str();
    let control_name = format!("control-{token}.gd-egress-control.invalid");
    let control_path = format!("/control/{token}").into_bytes();
    let dns_ok = dns.records.iter().any(|r| r.name == control_name);
    let https_ok = mitm
        .conns
        .values()
        .flat_map(|c| &c.http)
        .any(|e| e.scheme == "https" && e.host == control_name && e.path == control_path);
    let wire_ok = wire.handshakes >= 1
        && wire
            .dns_queries
            .iter()
            .any(|(_, _, names)| names.contains(&control_name));
    let blocked_ok = wire.sink.iter().any(|p| is_control_packet(p, token));
    for (ok, finding) in [
        (dns_ok, "dns-log"),
        (https_ok, "mitm"),
        (wire_ok, "wire"),
        (blocked_ok, "blocked-path"),
    ] {
        if !ok {
            j.findings.insert(format!("F4 capture-blind {finding}"));
        }
    }
    let control_conns: BTreeSet<u64> = mitm
        .conns
        .values()
        .filter(|c| {
            c.http.iter().any(|e| e.host == control_name)
                || matches!(&c.tls, Some((Some(sni), _)) if lossy(sni) == control_name)
        })
        .map(|c| c.id)
        .collect();

    // Destinations: F1 for unlisted names and addresses, F3 for packets that hit the black hole.
    let (mut unlisted, mut listed) = (BTreeSet::new(), BTreeSet::new());
    for record in dns.records.iter().filter(|r| r.name != control_name) {
        let dest = format!("dns {}", record.name);
        if allow.host_listed(&record.name) {
            listed.insert(dest)
        } else {
            unlisted.insert(dest)
        };
    }
    for conn in mitm
        .conns
        .values()
        .filter(|c| !control_conns.contains(&c.id))
    {
        for (dest, matcher) in conn_destinations(conn) {
            if matcher.is_some_and(|(host, port)| allow.listed(&host, port)) {
                listed.insert(dest)
            } else {
                unlisted.insert(dest)
            };
        }
    }
    for dest in &unlisted {
        let line = format!("F1 unlisted-destination {}", j.safe(dest));
        j.findings.insert(line);
    }
    let blocked: BTreeSet<String> = wire
        .sink
        .iter()
        .filter(|p| !is_control_packet(p, token))
        .map(sink_label)
        .collect();
    for label in &blocked {
        let line = format!("F3 blocked-egress {}", j.safe(label));
        j.findings.insert(line);
    }

    // Canaries and secret shapes, in every place a byte could have gone.
    for record in &dns.records {
        j.scan(record.name.as_bytes(), "dns-name", "dns");
    }
    for conn in mitm.conns.values() {
        let dest = conn_dest(conn);
        if let Some((Some(sni), _)) = &conn.tls {
            j.scan(sni, "tls-sni", &dest);
        }
        for event in &conn.http {
            let event_dest = format!("{}:{}", event.host, event.port);
            j.scan(event.host.as_bytes(), "http-url", &event_dest);
            j.scan(&event.path, "http-url", &event_dest);
            for (name, value) in &event.headers {
                j.scan(name, "http-header", &event_dest);
                j.scan(value, "http-header", &event_dest);
            }
            j.scan(&event.body, "http-body", &event_dest);
        }
        for data in &conn.tcp {
            j.scan(data, "tcp-data", &dest);
        }
    }
    let by_port: BTreeMap<u16, &Conn> = mitm
        .conns
        .values()
        .rev()
        .map(|c| (c.client_port, c))
        .collect();
    for stream in &wire.recorder_streams {
        let dest = by_port
            .get(&stream.sport)
            .map_or_else(|| "unknown".to_string(), |c| conn_dest(c));
        j.scan(&stream.data, "wire", &dest);
    }
    for message in &wire.dns_payloads {
        j.scan(message, "wire", "dns");
    }
    for (_, _, names) in &wire.dns_queries {
        for name in names {
            j.scan(name.as_bytes(), "wire", "dns");
        }
    }
    for packet in &wire.sink {
        j.scan(payload(packet), "blocked-packet", &sink_label(packet));
    }

    // The sources must agree with each other.
    let (mitm_bad, dns_bad, pcap_bad) = (
        unreadable.contains("mitm"),
        unreadable.contains("dns-log"),
        unreadable.contains("pcap") || unreadable.contains("links"),
    );
    if !mitm_bad && !pcap_bad && wire.handshakes != mitm.conns.len() {
        j.findings
            .insert("F5 sources-disagree tcp-handshakes".into());
    }
    if !dns_bad && !pcap_bad && wire.answered_dns != dns.records.len() {
        j.findings.insert("F5 sources-disagree dns-queries".into());
    }

    let ok_word = |ok: bool| if ok { "ok" } else { "MISSING" };
    let destinations = if unlisted.len() + blocked.len() + listed.len() == 0 {
        "none".to_string()
    } else {
        format!(
            "{} unlisted, {} allowlisted",
            unlisted.len() + blocked.len(),
            listed.len()
        )
    };
    let pass = j.findings.is_empty();
    let mut report = format!(
        "Judge C (egress capture): {}\ncontrol: dns {}, https {}, wire {}, blocked-path {}\ndestinations: {destinations}\n",
        if pass { "PASS" } else { "FAIL" },
        ok_word(dns_ok),
        ok_word(https_ok),
        ok_word(wire_ok),
        ok_word(blocked_ok),
    );
    if pass {
        report.push_str("findings: none\n");
    }
    for finding in &j.findings {
        report.push_str(finding);
        report.push('\n');
    }
    let details = format!(
        "dns-log: {} queries\nmitm: {} connections\npcap: {} outgoing packets, {} on the black hole, {} loopback packets ignored\nhandshakes completed: {}\ndns queries answered: {}\ndestinations listed: {}, unlisted: {}, blocked: {}\n",
        dns.records.len(),
        mitm.conns.len(),
        parsed.packets.len(),
        wire.sink.len(),
        wire.ignored_loopback,
        wire.handshakes,
        wire.answered_dns,
        listed.len(),
        unlisted.len(),
        blocked.len(),
    );
    Verdict {
        report,
        details,
        pass,
    }
}
