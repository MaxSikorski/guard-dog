//! Reads the capture and decides: findings F1 to F5 and the byte-stable report.
//!
//! Every way the judge could be fooled or blinded must fail closed: an
//! unreadable source, a missing control, a source that disagrees with another
//! all become findings. Destinations are judged by what the network layer
//! shows (the name asked for, the address reached, the port, the TLS server
//! name), never by one field alone. Every string that came from the capture
//! is redacted (canaries replaced) and then escaped before it is printed.

use crate::allowlist::Allowlist;
use crate::canary::CanarySet;
use crate::capture::mitm::{Conn, HttpEvent, MitmLog};
use crate::capture::pcap::{self, L4, Packet, Wire};
use crate::capture::{RawCapture, dns_log};
use crate::decode;
use crate::needle::{HitKind, Needles, Scanner};
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

/// The fake-DNS answer: every name resolves here, so a request reached by name came here.
const FAKE_DNS_ANSWER: &str = "198.18.0.1";
/// A destination stream larger than this is not scanned (and is a finding).
const STREAM_BUDGET: usize = 64 * 1024 * 1024;

struct Judge<'a> {
    needles: &'a Needles,
    scanner: Scanner<'a>,
    findings: BTreeSet<String>,
    unreadable: BTreeSet<&'static str>,
    /// Classes found in a single field, per printed destination.
    field_hits: BTreeMap<String, BTreeSet<HitKind>>,
}

impl Judge<'_> {
    /// Redacts, then escapes, a string that came from the capture.
    fn safe(&self, text: &str) -> String {
        Untrusted::new(self.needles.redact(text)).escape_for_terminal()
    }

    /// A `host:port` or `[ip]:port` string made printable: the host part is redacted.
    fn safe_host_port(&self, text: &str) -> String {
        match text.rsplit_once(':') {
            Some((host, port)) if !text.starts_with('[') => {
                format!("{}:{port}", self.safe(host))
            }
            _ => self.safe(text),
        }
    }

    /// Records `F5 capture-unreadable <source>: <code>` and marks the source unreadable.
    fn note(&mut self, source: &'static str, code: &str) {
        self.findings
            .insert(format!("F5 capture-unreadable {source}: {code}"));
        self.unreadable.insert(source);
    }

    /// Scans one field and records an F2 per hit. `dest` is already printable.
    fn scan(&mut self, hay: &[u8], location: &str, dest: &str) {
        for hit in self.scanner.scan(hay) {
            self.field_hits
                .entry(dest.to_string())
                .or_default()
                .insert(hit);
            self.record(hit, location, dest);
        }
    }

    fn record(&mut self, hit: HitKind, location: &str, dest: &str) {
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

/// The server name a connection's TLS handshake asked for, if any.
fn sni_of(conn: &Conn) -> Option<String> {
    match &conn.tls {
        Some((Some(sni), _)) => Some(lossy(sni)),
        _ => None,
    }
}

/// How a connection is named in findings, as (host part, port) before redaction.
fn conn_dest_parts(conn: &Conn) -> (String, u16) {
    if let Some(event) = conn.http.first() {
        return (event.host.clone(), conn.dst_port);
    }
    if let Some((sni, false)) = &conn.tls {
        let name = sni.as_deref().map_or_else(|| conn.dst_ip.clone(), lossy);
        return (name, conn.dst_port);
    }
    (conn.dst_ip.clone(), conn.dst_port)
}

/// The packet's name when it left through the black hole.
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

/// One phase of the control: before (`pre`) or after (`post`) the workload.
struct Phase {
    word: &'static str,
    name: String,
    path: Vec<u8>,
    marker: Vec<u8>,
}

impl Phase {
    fn new(word: &'static str, token: &str) -> Phase {
        Phase {
            word,
            name: format!("{word}-{token}.gd-egress-control.invalid"),
            path: format!("/control/{token}/{word}").into_bytes(),
            marker: format!("gd-egress-control {token} {word}\n").into_bytes(),
        }
    }

    /// Whether this request is exactly the control request.
    fn is_request(&self, conn: &Conn, event: &HttpEvent) -> bool {
        event.scheme == "https"
            && event.method == b"GET"
            && event.host == self.name
            && event.port == 443
            && event.path == self.path
            && event.body.is_empty()
            && conn.dst_ip == FAKE_DNS_ANSWER
            && conn.dst_port == 443
            && matches!(&conn.tls, Some((Some(sni), true)) if lossy(sni) == self.name)
    }

    fn is_packet(&self, packet: &Packet) -> bool {
        matches!(
            (&packet.l4, packet.ip),
            (L4::Udp { dport: 9, payload, .. }, Some((_, IpAddr::V4(dst))))
                if dst.octets() == [198, 18, 0, 99] && *payload == self.marker
        )
    }
}

/// What the capture shows of one control phase.
#[derive(Default)]
struct Seen {
    dns: bool,
    /// The connection and request index of the exact control request.
    request: Option<(u64, usize)>,
    /// The control's connection, found by its request or at least its TLS name.
    conn: Option<u64>,
    wire: bool,
    packet: Option<usize>,
}

fn control_seen(phase: &Phase, dns: &dns_log::DnsLog, mitm: &MitmLog, wire: &Wire) -> Seen {
    let mut seen = Seen {
        dns: dns.records.iter().any(|r| r.name == phase.name),
        ..Seen::default()
    };
    for conn in mitm.conns.values() {
        if let Some(i) = conn.http.iter().position(|e| phase.is_request(conn, e)) {
            seen.request = Some((conn.id, i));
            seen.conn = Some(conn.id);
            break;
        }
    }
    if seen.conn.is_none() {
        seen.conn = mitm
            .conns
            .values()
            .find(|c| {
                c.http.is_empty()
                    && matches!(&c.tls, Some((Some(s), true)) if lossy(s) == phase.name)
            })
            .map(|c| c.id);
    }
    let asked = wire.dns_questions.iter().any(|q| q.name == phase.name);
    let talked = seen
        .conn
        .and_then(|id| mitm.conns.get(&id))
        .is_some_and(|conn| {
            let both = |streams: &[pcap::Stream], key: fn(&pcap::Stream) -> u16| {
                streams
                    .iter()
                    .any(|s| key(s) == conn.client_port && !s.data.is_empty() && !s.short)
            };
            both(&wire.recorder_streams, |s| s.sport) && both(&wire.server_streams, |s| s.dport)
        });
    seen.wire = asked && talked;
    seen.packet = wire
        .sink
        .iter()
        .find(|p| phase.is_packet(p))
        .map(|p| p.index);
    seen
}

/// Checks tcpdump's closing summary: all three counts present, nothing dropped, and the number
/// of packets it says it wrote equal to the records in the file (when the file was readable).
fn check_stats(text: &str, records: Option<usize>) -> Option<&'static str> {
    // Every line that says `<number> <what>`; a line with a non-number counts, as `None`.
    let lines = |what: &str| -> Vec<Option<u64>> {
        text.lines()
            .filter_map(|line| {
                let (number, rest) = line.trim().split_once(' ')?;
                (rest.trim() == what).then(|| number.parse::<u64>().ok())
            })
            .collect()
    };
    // Each of the three counts must be there exactly once: a second line could say something else.
    let once = |what: &str| match lines(what).as_slice() {
        [Some(n)] => Some(*n),
        _ => None,
    };
    let (Some(captured), Some(received), Some(dropped)) = (
        once("packets captured"),
        once("packets received by filter"),
        once("packets dropped by kernel"),
    ) else {
        return Some("bad-stats");
    };
    let interface = match lines("packets dropped by interface").as_slice() {
        [] => 0,
        [Some(n)] => *n,
        _ => return Some("bad-stats"),
    };
    if dropped != 0 || interface != 0 || received != captured {
        return Some("capture-drops");
    }
    match records {
        Some(n) if u64::try_from(n).ok() != Some(captured) => Some("stats-mismatch"),
        _ => None,
    }
}

/// The bounds a judge run works under. The defaults are the real ones; tests lower them to
/// reach a bound quickly.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Decoded bytes allowed across every body of the capture.
    pub decode_output: usize,
    /// Decoded layers allowed across every body of the capture.
    pub decode_layers: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            decode_output: crate::decode::MAX_CAPTURE_OUTPUT,
            decode_layers: crate::decode::MAX_CAPTURE_LAYERS,
        }
    }
}

/// Judges a capture. `expected_rules` is the reviewed rules dump.
pub fn judge(
    raw: &RawCapture,
    set: &CanarySet,
    allow: &Allowlist,
    expected_rules: &str,
) -> Verdict {
    judge_with_limits(raw, set, allow, expected_rules, Limits::default())
}

/// [`judge`] under explicit bounds.
pub fn judge_with_limits(
    raw: &RawCapture,
    set: &CanarySet,
    allow: &Allowlist,
    expected_rules: &str,
    limits: Limits,
) -> Verdict {
    let _ = limits;
    let needles = Needles::new(set);
    let mut j = Judge {
        needles: &needles,
        scanner: needles.scanner(),
        findings: BTreeSet::new(),
        unreadable: BTreeSet::new(),
        field_hits: BTreeMap::new(),
    };

    // Parse the sources. A source that cannot be read gives an empty result and an F5.
    let dns = match &raw.dns_log {
        Ok(bytes) => dns_log::parse(bytes),
        Err(code) => {
            j.note("dns-log", code);
            dns_log::DnsLog::default()
        }
    };
    for code in &dns.errors {
        j.note("dns-log", code);
    }
    let mitm: MitmLog = match &raw.mitm {
        Ok(bytes) => crate::capture::mitm::parse(bytes),
        Err(code) => {
            j.note("mitm", code);
            MitmLog::default()
        }
    };
    for code in &mitm.errors {
        j.note("mitm", code);
    }
    let parsed = match &raw.pcap {
        Ok(bytes) => pcap::parse(bytes),
        Err(code) => {
            j.note("pcap", code);
            pcap::PcapParse::default()
        }
    };
    for code in &parsed.errors {
        j.note("pcap", code);
    }
    let links = match &raw.links {
        Ok(bytes) => {
            let parsed_links = pcap::parse_links(&String::from_utf8_lossy(bytes));
            if parsed_links.is_none() {
                j.note("links", "bad-line");
            }
            parsed_links.unwrap_or_default()
        }
        Err(code) => {
            j.note("links", code);
            BTreeMap::new()
        }
    };
    let wire: Wire = pcap::analyze(&parsed.packets, &links);
    for code in &wire.errors {
        j.note("pcap", code);
    }
    match &raw.stats {
        Ok(bytes) => {
            let pcap_clean = raw.pcap.is_ok() && parsed.errors.is_empty();
            if let Some(code) = check_stats(
                &String::from_utf8_lossy(bytes),
                pcap_clean.then_some(parsed.records),
            ) {
                j.note("stats", code);
            }
        }
        Err(code) => j.note("stats", code),
    }
    match &raw.rules {
        Ok(bytes) if !rules::same(&String::from_utf8_lossy(bytes), expected_rules) => {
            j.note("rules", "rules-differ");
        }
        Ok(_) => {}
        Err(code) => j.note("rules", code),
    }

    // The control: before and after the workload, four things each.
    let token = set.control_token.as_str();
    let phases = [Phase::new("pre", token), Phase::new("post", token)];
    let seen: Vec<Seen> = phases
        .iter()
        .map(|p| control_seen(p, &dns, &mitm, &wire))
        .collect();
    let mut ok = [true; 4];
    for (phase, s) in phases.iter().zip(&seen) {
        let checks = [
            (0usize, s.dns, "dns-log"),
            (1, s.request.is_some(), "mitm"),
            (2, s.wire, "wire"),
            (3, s.packet.is_some(), "blocked-path"),
        ];
        for (slot, good, what) in checks {
            if !good {
                if let Some(flag) = ok.get_mut(slot) {
                    *flag = false;
                }
                j.findings
                    .insert(format!("F4 capture-blind {what} {}", phase.word));
            }
        }
    }
    // The pre control has the lowest connection number and the post control the highest.
    let (lowest, highest) = (
        mitm.conns.keys().next().copied(),
        mitm.conns.keys().next_back().copied(),
    );
    let pre_misplaced = seen
        .first()
        .and_then(|s| s.conn)
        .is_some_and(|c| Some(c) != lowest);
    let post_misplaced = seen
        .get(1)
        .and_then(|s| s.conn)
        .is_some_and(|c| Some(c) != highest);
    if pre_misplaced || post_misplaced {
        j.note("mitm", "order");
    }
    // Requests that share a control request's connection (keep-alive) must come in the order the
    // recorder numbered them: after the control if logged after it. The packet order below cannot
    // show this, because the control's connection is left out of the workload there.
    for request in seen.iter().filter_map(|s| s.request) {
        let (id, at) = request;
        let events = mitm
            .conns
            .get(&id)
            .map(|c| c.http.as_slice())
            .unwrap_or(&[]);
        if let Some(base) = events.get(at).map(|e| e.seq) {
            let disordered = events
                .iter()
                .enumerate()
                .any(|(i, e)| (i > at && e.seq <= base) || (i < at && e.seq >= base));
            if disordered {
                j.note("mitm", "order");
            }
        }
    }
    // In capture order, the pre packet comes before all workload traffic and the post packet after it.
    let control_ports: BTreeSet<u16> = seen
        .iter()
        .filter_map(|s| s.conn)
        .filter_map(|id| mitm.conns.get(&id))
        .map(|c| c.client_port)
        .collect();
    let control_names: BTreeSet<&str> = phases.iter().map(|p| p.name.as_str()).collect();
    let workload: Vec<usize> = wire
        .lo_client
        .iter()
        .filter(|c| {
            if c.to_recorder {
                !control_ports.contains(&c.sport)
            } else {
                c.names.is_empty() || !c.names.iter().all(|n| control_names.contains(n.as_str()))
            }
        })
        .map(|c| c.index)
        .chain(
            wire.sink
                .iter()
                .filter(|p| !phases.iter().any(|ph| ph.is_packet(p)))
                .map(|p| p.index),
        )
        .collect();
    let first_work = workload.iter().min().copied();
    let last_work = workload.iter().max().copied();
    let pre_late = seen
        .first()
        .and_then(|s| s.packet)
        .zip(first_work)
        .is_some_and(|(pre, first)| pre > first);
    let post_early = seen
        .get(1)
        .and_then(|s| s.packet)
        .zip(last_work)
        .is_some_and(|(post, last)| post < last);
    if pre_late || post_early {
        j.note("pcap", "order");
    }

    // Destinations: F1 for anything not listed, F3 for packets that hit the black hole.
    // `unlisted` maps a plain key to its printable form; `listed` holds plain keys.
    let mut unlisted: BTreeMap<String, String> = BTreeMap::new();
    let mut listed: BTreeSet<String> = BTreeSet::new();
    let asked: BTreeSet<&str> = wire.dns_questions.iter().map(|q| q.name.as_str()).collect();
    let mut names: BTreeSet<&str> = asked.clone();
    names.extend(dns.records.iter().map(|r| r.name.as_str()));
    for name in names.iter().filter(|n| !control_names.contains(**n)) {
        let key = format!("dns {name}");
        if allow.host_listed(name) {
            listed.insert(key);
        } else {
            let printed = format!("dns {}", j.safe(name));
            unlisted.insert(key, printed);
        }
    }
    let exempt_requests: BTreeSet<(u64, usize)> = seen.iter().filter_map(|s| s.request).collect();
    let exempt_conns: BTreeSet<u64> = seen
        .iter()
        .filter_map(|s| s.conn)
        .filter(|id| mitm.conns.get(id).is_some_and(|c| c.http.is_empty()))
        .collect();
    for conn in mitm.conns.values() {
        if conn.http.is_empty() && !exempt_conns.contains(&conn.id) {
            let opaque = matches!(conn.tls, Some((_, false)));
            let (host, port) = conn_dest_parts(conn);
            let (kind, shown) = if opaque {
                ("tls-opaque", host_port(&host, port))
            } else {
                ("tcp", host_port(&conn.dst_ip, port))
            };
            let printed = format!("{kind} {}", j.safe_host_port(&shown));
            unlisted.insert(format!("{kind} {shown}"), printed);
        }
        for (i, event) in conn.http.iter().enumerate() {
            if exempt_requests.contains(&(conn.id, i)) {
                continue;
            }
            let short = format!("{} {}:{}", event.scheme, event.host, conn.dst_port);
            let entry = allow.destinations.iter().find(|d| d.host == event.host);
            let sni = sni_of(conn);
            let dns_seen = asked.contains(event.host.as_str());
            let tls_ok = if event.scheme == "https" {
                matches!(&conn.tls, Some((Some(_), true)))
                    && sni.as_deref() == Some(event.host.as_str())
            } else {
                conn.tls.is_none()
            };
            let agree = entry.is_some_and(|e| {
                conn.dst_ip == FAKE_DNS_ANSWER
                    && e.ports.contains(&conn.dst_port)
                    && event.port == conn.dst_port
                    && tls_ok
                    && dns_seen
            });
            let printed_short =
                format!("{} {}:{}", event.scheme, j.safe(&event.host), conn.dst_port);
            if agree {
                listed.insert(short);
            } else if entry.is_none() {
                unlisted.insert(short, printed_short);
            } else {
                let tail = |sni: &str, ip: &str| {
                    format!(
                        "(sni {sni}, ip {}, authority-port {}, dns {})",
                        ip,
                        event.port,
                        if dns_seen { "yes" } else { "no" }
                    )
                };
                let plain = tail(sni.as_deref().unwrap_or("none"), &conn.dst_ip);
                let shown = tail(
                    &sni.as_deref()
                        .map_or_else(|| "none".to_string(), |s| j.safe(s)),
                    &j.safe(&conn.dst_ip),
                );
                unlisted.insert(
                    format!("{short} {plain}"),
                    format!("{printed_short} {shown}"),
                );
            }
        }
    }
    for printed in unlisted.values() {
        j.findings
            .insert(format!("F1 unlisted-destination {printed}"));
    }
    let blocked: BTreeSet<String> = wire
        .sink
        .iter()
        .filter(|p| !phases.iter().any(|ph| ph.is_packet(p)))
        .map(sink_label)
        .collect();
    for label in &blocked {
        let line = format!("F3 blocked-egress {}", j.safe(label));
        j.findings.insert(line);
    }

    // Canaries and secret shapes, in every place a byte could have gone.
    scan_everything(&mut j, &dns, &mitm, &wire);

    // The sources must agree with each other.
    let mitm_bad = j.unreadable.contains("mitm");
    let dns_bad = j.unreadable.contains("dns-log");
    let pcap_bad = j.unreadable.contains("pcap") || j.unreadable.contains("links");
    if !mitm_bad && !pcap_bad && wire.handshakes != mitm.conns.len() {
        j.findings
            .insert("F5 sources-disagree tcp-handshakes".into());
    }
    if !dns_bad && !pcap_bad {
        let mut balance: BTreeMap<(String, String, String), i64> = BTreeMap::new();
        for q in &wire.dns_questions {
            *balance
                .entry((
                    q.name.clone(),
                    pcap::qtype_name(q.qtype),
                    q.proto.to_string(),
                ))
                .or_default() += 1;
        }
        for r in &dns.records {
            *balance
                .entry((r.name.clone(), r.qtype.clone(), r.proto.clone()))
                .or_default() -= 1;
        }
        if balance.values().any(|n| *n != 0) {
            j.findings.insert("F5 sources-disagree dns-queries".into());
        }
    }
    if j.scanner.budget_exceeded() {
        j.findings
            .insert("F5 capture-unreadable scan: scan-budget".into());
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
    let [dns_ok, https_ok, wire_ok, blocked_ok] = ok;
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
        "dns-log: {} queries\nmitm: {} connections\npcap: {} packets read, {} on the black hole, {} loopback packets ignored, {} records of the other packet type ignored\nhandshakes completed: {}\ndns questions on the wire: {}, answered: {}\ndestinations listed: {}, unlisted: {}, blocked: {}\n",
        dns.records.len(),
        mitm.conns.len(),
        parsed.packets.len(),
        wire.sink.len(),
        wire.ignored_loopback,
        wire.ignored_types,
        wire.handshakes,
        wire.dns_questions.len(),
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

/// Scans every field and stream of the capture for canaries and secret shapes.
fn scan_everything(j: &mut Judge, dns: &dns_log::DnsLog, mitm: &MitmLog, wire: &Wire) {
    for record in &dns.records {
        j.scan(record.name.as_bytes(), "dns-name", "dns");
        j.scan(record.name.replace('.', "").as_bytes(), "dns-name", "dns");
    }
    // Per destination, byte for byte in the order the requests were made (the recorder's global
    // sequence, across connections): every field, and bodies with raw TCP data only.
    type Piece = (u64, usize, bool, Vec<u8>);
    let mut ordered: BTreeMap<String, Vec<Piece>> = BTreeMap::new();
    let mut counter = 0usize;
    for conn in mitm.conns.values() {
        let (host, port) = conn_dest_parts(conn);
        let conn_dest = j.safe_host_port(&host_port(&host, port));
        if let Some((Some(sni), _)) = &conn.tls {
            j.scan(sni, "tls-sni", &conn_dest);
        }
        for event in &conn.http {
            let dest = format!("{}:{}", j.safe(&event.host), conn.dst_port);
            j.scan(&event.method, "http-method", &dest);
            j.scan(event.host.as_bytes(), "http-header", &dest);
            j.scan(&event.path, "http-url", &dest);
            for (name, value) in &event.headers {
                j.scan(name, "http-header", &dest);
                j.scan(value, "http-header", &dest);
            }
            j.scan(&event.body, "http-body", &dest);
            // Compressed bodies are unpacked and every layer scanned; a body that cannot be
            // unpacked, or hits a bound, is never a pass.
            let decoded = decode::decode_body(&event.headers, &event.body);
            for code in &decoded.problems {
                j.note("mitm", code);
            }
            for layer in &decoded.layers {
                j.scan(layer, "http-body", &dest);
            }
            let pieces = ordered.entry(dest).or_default();
            let mut add = |body: bool, bytes: &[u8]| {
                counter += 1;
                pieces.push((event.seq, counter, body, bytes.to_vec()));
            };
            add(false, &event.method);
            add(false, &event.path);
            for (_, value) in &event.headers {
                add(false, value);
            }
            add(true, &event.body);
            for layer in &decoded.layers {
                add(true, layer);
            }
        }
        let mut joined = Vec::new();
        for (data, seq) in conn.tcp.iter().zip(&conn.tcp_seqs) {
            j.scan(data, "tcp-data", &conn_dest);
            joined.extend_from_slice(data);
            counter += 1;
            ordered
                .entry(conn_dest.clone())
                .or_default()
                .push((*seq, counter, true, data.clone()));
        }
        if conn.tcp.len() > 1 {
            j.scan(&joined, "tcp-data", &conn_dest);
        }
    }
    for (dest, pieces) in &mut ordered {
        pieces.sort_by_key(|p| (p.0, p.1));
        let everything: Vec<u8> = pieces.iter().flat_map(|p| p.3.iter().copied()).collect();
        let bodies: Vec<u8> = pieces
            .iter()
            .filter(|p| p.2)
            .flat_map(|p| p.3.iter().copied())
            .collect();
        if everything.len() > STREAM_BUDGET || bodies.len() > STREAM_BUDGET {
            j.findings
                .insert("F5 capture-unreadable scan: scan-budget".into());
            continue;
        }
        let seen = j.field_hits.get(dest).cloned().unwrap_or_default();
        let mut hits = j.scanner.scan(&everything);
        hits.extend(j.scanner.scan(&bodies));
        for hit in hits.difference(&seen) {
            j.record(*hit, "destination-stream", dest);
        }
    }
    let by_port: BTreeMap<u16, &Conn> = mitm
        .conns
        .values()
        .rev()
        .map(|c| (c.client_port, c))
        .collect();
    for stream in &wire.recorder_streams {
        let dest = by_port.get(&stream.sport).map_or_else(
            || "unknown".to_string(),
            |c| {
                let (host, port) = conn_dest_parts(c);
                j.safe_host_port(&host_port(&host, port))
            },
        );
        j.scan(&stream.data, "wire", &dest);
        for conflict in &stream.conflicts {
            j.scan(conflict, "wire", &dest);
        }
    }
    for message in &wire.dns_payloads {
        j.scan(message, "wire", "dns");
    }
    for q in &wire.dns_questions {
        j.scan(q.name.as_bytes(), "wire", "dns");
        j.scan(q.name.replace('.', "").as_bytes(), "wire", "dns");
    }
    for packet in &wire.sink {
        let label = j.safe(&sink_label(packet));
        j.scan(payload(packet), "blocked-packet", &label);
    }
}
