//! Builds synthetic captures for the tests: the five capture files, a pcap
//! writer, and a control that every healthy capture contains (once before the
//! workload and once after). Nothing here is a real capture; the pcap writer
//! lives only in test code.

#![allow(dead_code)]

use data_encoding::BASE64;
use gd_egress::allowlist::Allowlist;
use gd_egress::canary::{CanarySet, Class, generate};
use gd_egress::capture::RawCapture;
use gd_egress::verdict::judge;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;

pub const LO: u32 = 1;
pub const SINK: u32 = 2;
pub const SYN: u8 = 0x02;
pub const SYN_ACK: u8 = 0x12;
pub const PSH_ACK: u8 = 0x18;
/// Packet types: loopback records are HOST (0), black-hole records OUTGOING (4).
pub const HOST_TYPE: u8 = 0;
pub const OUT_TYPE: u8 = 4;

pub const API_ALLOWLIST: &str = "format = 1\n\n[[destination]]\nhost = \"api.example.org\"\nports = [80, 443]\nwhy = \"test\"\nphase = \"test\"\n";
pub const EMPTY_ALLOWLIST: &str = "format = 1\n";

pub fn expected_rules() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/egress/expected-rules.txt"
    );
    fs::read_to_string(path).unwrap()
}

pub fn expected_report(file: &str) -> String {
    let path = format!(
        "{}/../../tests/egress/synthetic/{file}.expected.txt",
        env!("CARGO_MANIFEST_DIR")
    );
    fs::read_to_string(path).unwrap()
}

// ---- packet and pcap writers ------------------------------------------------

pub fn sll2(ifindex: u32, ethertype: u16, packet_type: u8, body: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend(ethertype.to_be_bytes());
    f.extend([0, 0]);
    f.extend(ifindex.to_be_bytes());
    f.extend(1u16.to_be_bytes()); // ARPHRD_ETHER
    f.push(packet_type);
    f.push(6);
    f.extend([0u8; 8]);
    f.extend(body);
    f
}

pub fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, l4: &[u8]) -> Vec<u8> {
    ipv4_frag(src, dst, proto, 0, l4)
}

/// An IPv4 packet with an explicit flags-and-fragment-offset field.
pub fn ipv4_frag(src: [u8; 4], dst: [u8; 4], proto: u8, frag: u16, l4: &[u8]) -> Vec<u8> {
    let mut p = vec![0x45, 0];
    p.extend(u16::try_from(20 + l4.len()).unwrap().to_be_bytes());
    p.extend([0, 0]);
    p.extend(frag.to_be_bytes());
    p.extend([64, proto, 0, 0]);
    p.extend(src);
    p.extend(dst);
    p.extend(l4);
    p
}

pub fn ipv6(src: [u8; 16], dst: [u8; 16], next: u8, l4: &[u8]) -> Vec<u8> {
    let mut p = vec![0x60, 0, 0, 0];
    p.extend(u16::try_from(l4.len()).unwrap().to_be_bytes());
    p.extend([next, 64]);
    p.extend(src);
    p.extend(dst);
    p.extend(l4);
    p
}

pub fn tcp(sport: u16, dport: u16, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    tcp_ack(sport, dport, seq, 0, flags, payload)
}

/// A TCP segment with an acknowledgement number (what the sender has received so far).
pub fn tcp_ack(sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend(sport.to_be_bytes());
    t.extend(dport.to_be_bytes());
    t.extend(seq.to_be_bytes());
    t.extend(ack.to_be_bytes());
    t.extend([0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    t.extend(payload);
    t
}

pub fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut u = Vec::new();
    u.extend(sport.to_be_bytes());
    u.extend(dport.to_be_bytes());
    u.extend(u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
    u.extend([0, 0]);
    u.extend(payload);
    u
}

#[derive(Clone, Copy)]
pub enum Order {
    Little,
    Big,
}

pub fn pcap_file(order: Order, nanos: bool, link_type: u32, frames: &[Vec<u8>]) -> Vec<u8> {
    let w32 = |v: u32| match order {
        Order::Little => v.to_le_bytes(),
        Order::Big => v.to_be_bytes(),
    };
    let w16 = |v: u16| match order {
        Order::Little => v.to_le_bytes(),
        Order::Big => v.to_be_bytes(),
    };
    let magic: u32 = if nanos { 0xa1b2_3c4d } else { 0xa1b2_c3d4 };
    let mut out = Vec::new();
    out.extend(w32(magic));
    out.extend(w16(2));
    out.extend(w16(4));
    out.extend(w32(0));
    out.extend(w32(0));
    out.extend(w32(262_144));
    out.extend(w32(link_type));
    for (i, frame) in frames.iter().enumerate() {
        let len = u32::try_from(frame.len()).unwrap();
        out.extend(w32(1_700_000_000));
        out.extend(w32(u32::try_from(i).unwrap()));
        out.extend(w32(len));
        out.extend(w32(len));
        out.extend(frame);
    }
    out
}

fn v6(text: &str) -> [u8; 16] {
    match text.parse::<IpAddr>().unwrap() {
        IpAddr::V6(a) => a.octets(),
        IpAddr::V4(_) => panic!("not v6"),
    }
}

pub fn b64(bytes: &[u8]) -> String {
    BASE64.encode(bytes)
}

/// A gzip file (default compression).
pub fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// A gzip file made of stored (uncompressed) blocks: ratio about 1:1, and fast to build.
pub fn gzip_stored(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::none());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// A gzip file at the best compression (for bombs: zeros shrink about 1000 to 1).
pub fn gzip_best(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// `gzip` applied `layers` times.
pub fn gzip_layers(data: &[u8], layers: usize) -> Vec<u8> {
    (0..layers).fold(data.to_vec(), |acc, _| gzip(&acc))
}

/// A zlib stream (what HTTP `Content-Encoding: deflate` is meant to be).
pub fn zlib(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// Raw deflate, no header (what some clients send as `deflate`).
pub fn deflate_raw(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// A brotli stream holding `data` (at most 65,536 bytes) in one uncompressed meta-block, written
/// by hand so no brotli compressor is needed: window bits, meta-block header, the bytes, then the
/// empty last meta-block.
pub fn brotli_stored(data: &[u8]) -> Vec<u8> {
    assert!(!data.is_empty() && data.len() <= 65_536);
    let header = (u32::try_from(data.len() - 1).unwrap() << 4) | (1 << 20);
    let mut out = header.to_le_bytes()[..3].to_vec();
    out.extend(data);
    out.push(0x03);
    out
}

/// What Python's `repr()` prints for a bytes value: printable ASCII as itself, the usual short
/// escapes, everything else as `\xNN`.
pub fn python_bytes_repr(bytes: &[u8]) -> String {
    let mut out = String::from("b'");
    for &b in bytes {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'\'' => out.push_str("\\'"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            0x20..=0x7e => out.push(char::from(b)),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out.push('\'');
    out
}

/// One gRPC message frame: a compressed flag, a four-byte big-endian length, the message.
pub fn grpc_frame(compressed: bool, message: &[u8]) -> Vec<u8> {
    let mut out = vec![u8::from(compressed)];
    out.extend(u32::try_from(message.len()).unwrap().to_be_bytes());
    out.extend(message);
    out
}

// ---- the scenario builder -----------------------------------------------------

#[derive(Clone, Copy)]
pub struct Conn {
    pub id: u64,
    pub port: u16,
    pub client_isn: u32,
}

#[derive(Clone)]
struct Frame {
    ifindex: u32,
    ptype: u8,
    ethertype: u16,
    body: Vec<u8>,
}

/// What a control phase includes. Everything on by default.
#[derive(Clone, Copy)]
pub struct Control {
    pub http: bool,
    pub truncated: bool,
    pub payload: bool,
    /// The first bytes of the control request are captured, the rest is lost, though the
    /// server's acknowledgement covers all of it.
    pub lose_tail: bool,
}

pub const FULL_CONTROL: Control = Control {
    http: true,
    truncated: false,
    payload: true,
    lose_tail: false,
};

#[derive(Clone)]
pub struct Scenario {
    pub name: String,
    pub set: CanarySet,
    pub dns_lines: Vec<String>,
    /// JSONL lines after the header, each with its connection number (0 for none).
    pub mitm_lines: Vec<(u64, String)>,
    frames: Vec<Frame>,
    pub link_type: u32,
    pub rules: String,
    pub links: String,
    pub allowlist: String,
    /// The post control, added when the capture is written. `None` leaves it out.
    pub post: Option<Control>,
    /// Write the closing `end` line.
    pub end: bool,
    /// Cut the pcap just before the post control's packets.
    pub cut_post_pcap: bool,
    /// Add a type-4 copy of every loopback record.
    pub lo_duplicate_outgoing: bool,
    /// Packets tcpdump says the kernel dropped.
    pub kernel_drops: u64,
    pub next_conn: u64,
    /// After the post control, one more request on its connection, logged with this `seq`.
    pub post_extra_seq: Option<u64>,
    /// The next `http` or `tcp` event takes this `seq` instead of the running count.
    force_seq: Option<u64>,
    /// Global request sequence, written as `seq` on http and tcp events.
    seq: u64,
    next_dns_id: u16,
    next_dns_port: u16,
    /// Bytes already sent per (connection, direction), so later requests follow earlier ones.
    sent: BTreeMap<(u64, bool), u32>,
}

impl Scenario {
    /// No control flows at all.
    pub fn bare(name: &str, seed: u64) -> Scenario {
        Scenario {
            name: name.to_string(),
            set: generate(seed),
            dns_lines: Vec::new(),
            mitm_lines: Vec::new(),
            frames: Vec::new(),
            link_type: 276,
            rules: expected_rules(),
            links: "1: lo: <LOOPBACK,UP>\n2: gdsink0: <BROADCAST,NOARP,UP>\n".to_string(),
            allowlist: EMPTY_ALLOWLIST.to_string(),
            post: Some(FULL_CONTROL),
            end: true,
            cut_post_pcap: false,
            lo_duplicate_outgoing: false,
            kernel_drops: 0,
            next_conn: 1,
            post_extra_seq: None,
            force_seq: None,
            seq: 0,
            next_dns_id: 100,
            next_dns_port: 50_000,
            sent: BTreeMap::new(),
        }
    }

    /// A healthy capture: the pre control now, the post control when written.
    pub fn new(name: &str, seed: u64) -> Scenario {
        let mut s = Scenario::bare(name, seed);
        s.control("pre", FULL_CONTROL);
        s
    }

    pub fn control_name(&self, phase: &str) -> String {
        format!(
            "{phase}-{}.gd-egress-control.invalid",
            self.set.control_token
        )
    }

    /// One control phase. Returns its connection.
    pub fn control(&mut self, phase: &str, opts: Control) -> Conn {
        let name = self.control_name(phase);
        for qtype in ["A", "A", "AAAA"] {
            self.dns_query_typed(&name, qtype);
        }
        let c = self.connect("198.18.0.1", 443);
        self.tls(c, Some(&name), true);
        let path = format!("/control/{}/{phase}", self.set.control_token);
        if opts.http {
            self.http_events(
                c,
                "https",
                "GET",
                &name,
                443,
                &path,
                &[],
                b"",
                opts.truncated,
            );
        }
        if opts.payload {
            if opts.lose_tail {
                self.wire_data(c, &[(0, &OPAQUE[..8])]);
                self.sent
                    .insert((c.id, false), u32::try_from(OPAQUE.len()).unwrap());
            } else {
                self.send(c, OPAQUE);
            }
            self.reply(c, OPAQUE_REPLY);
        }
        let marker = format!("gd-egress-control {} {phase}\n", self.set.control_token);
        self.sink_udp("198.18.0.99", 9, marker.as_bytes());
        c
    }

    pub fn dns_query(&mut self, name: &str) {
        self.dns_query_typed(name, "A");
    }

    pub fn dns_query_typed(&mut self, name: &str, qtype: &str) {
        self.dns_lines
            .push(format!("[INFO] GDQ {qtype} IN {name}. udp NOERROR"));
        let number = match qtype {
            "AAAA" => 28,
            "TXT" => 16,
            "PTR" => 12,
            _ => 1,
        };
        self.wire_dns(name, number, true);
    }

    /// A resolver log line with no matching wire question.
    pub fn log_dns_only(&mut self, name: &str) {
        self.dns_lines
            .push(format!("[INFO] GDQ A IN {name}. udp NOERROR"));
    }

    pub fn dns_query_bytes(name: &str, id: u16, qtype: u16, additional: Option<&[u8]>) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend(id.to_be_bytes());
        q.extend([
            0x01,
            0x00,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            u8::from(additional.is_some()),
        ]);
        for label in name.split('.') {
            q.push(u8::try_from(label.len()).unwrap());
            q.extend(label.as_bytes());
        }
        q.push(0);
        q.extend(qtype.to_be_bytes());
        q.extend([0, 1]);
        if let Some(extra) = additional {
            q.extend(extra);
        }
        q
    }

    /// A DNS question on the wire, optionally answered; no resolver log line.
    pub fn wire_dns(&mut self, name: &str, qtype: u16, answered: bool) {
        self.wire_dns_with(name, qtype, answered, None);
    }

    pub fn wire_dns_with(
        &mut self,
        name: &str,
        qtype: u16,
        answered: bool,
        additional: Option<&[u8]>,
    ) {
        let (id, port) = (self.next_dns_id, self.next_dns_port);
        self.next_dns_id += 1;
        self.next_dns_port += 1;
        let q = Scenario::dns_query_bytes(name, id, qtype, additional);
        self.lo(17, udp(port, 5353, &q));
        if answered {
            let mut r = q.clone();
            r[2] = 0x81;
            r[3] = 0x80;
            self.lo(17, udp(5353, port, &r));
        }
    }

    fn lo(&mut self, proto: u8, l4: Vec<u8>) {
        self.lo_frag(proto, 0, l4);
    }

    fn lo_frag(&mut self, proto: u8, frag: u16, l4: Vec<u8>) {
        self.frames.push(Frame {
            ifindex: LO,
            ptype: HOST_TYPE,
            ethertype: 0x0800,
            body: ipv4_frag([127, 0, 0, 1], [127, 0, 0, 1], proto, frag, &l4),
        });
    }

    pub fn connect(&mut self, dst_ip: &str, dst_port: u16) -> Conn {
        let id = self.next_conn;
        self.connect_as(id, dst_ip, dst_port)
    }

    pub fn connect_as(&mut self, id: u64, dst_ip: &str, dst_port: u16) -> Conn {
        self.next_conn = self.next_conn.max(id + 1);
        let port = 40_000 + u16::try_from(id).unwrap();
        let client_isn = 1_000_000 * u32::try_from(id).unwrap();
        self.mitm_lines.push((
            id,
            json!({"event":"connect","conn":id,"client_port":port,"dst_ip":dst_ip,"dst_port":dst_port})
                .to_string(),
        ));
        self.lo(6, tcp(port, 8080, client_isn, SYN, b""));
        self.lo(
            6,
            tcp_ack(
                8080,
                port,
                900_000_000 + client_isn,
                client_isn + 1,
                SYN_ACK,
                b"",
            ),
        );
        Conn {
            id,
            port,
            client_isn,
        }
    }

    /// A SYN-ACK from the recorder that has no `connect` event.
    pub fn extra_syn_ack(&mut self) {
        self.lo(6, tcp(8080, 59_999, 777_777, SYN_ACK, b""));
    }

    pub fn tls(&mut self, c: Conn, sni: Option<&str>, ok: bool) {
        let sni = sni.map_or(Value::Null, |s| Value::String(b64(s.as_bytes())));
        self.mitm_lines.push((
            c.id,
            json!({"event":"tls","conn":c.id,"sni_b64":sni,"ok":ok}).to_string(),
        ));
    }

    fn next_seq(&mut self) -> u64 {
        if let Some(forced) = self.force_seq.take() {
            return forced;
        }
        self.seq += 1;
        self.seq
    }

    /// The `http` event only: nothing on the wire.
    #[allow(clippy::too_many_arguments)]
    pub fn http_events(
        &mut self,
        c: Conn,
        scheme: &str,
        method: &str,
        host: &str,
        port: u16,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        truncated: bool,
    ) {
        let hs: Vec<(String, String)> = headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        self.http_events_bytes(
            c,
            scheme,
            method.as_bytes(),
            host.as_bytes(),
            port,
            path.as_bytes(),
            &hs,
            body,
            truncated,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn http_events_bytes(
        &mut self,
        c: Conn,
        scheme: &str,
        method: &[u8],
        host: &[u8],
        port: u16,
        path: &[u8],
        headers: &[(String, String)],
        body: &[u8],
        truncated: bool,
    ) {
        let pairs: Vec<Value> = headers
            .iter()
            .map(|(n, v)| json!([b64(n.as_bytes()), b64(v.as_bytes())]))
            .collect();
        let seq = self.next_seq();
        self.mitm_lines.push((
            c.id,
            json!({"event":"http","seq":seq,"conn":c.id,"scheme":scheme,"method_b64":b64(method),"host_b64":b64(host),
                   "port":port,"path_b64":b64(path),"headers":pairs,"body_b64":b64(body),"body_truncated":truncated})
            .to_string(),
        ));
    }

    /// An HTTP request: the `http` event plus its bytes on the wire (readable only for plain
    /// `http`) and a server reply.
    #[allow(clippy::too_many_arguments)]
    pub fn http(
        &mut self,
        c: Conn,
        scheme: &str,
        method: &str,
        host: &str,
        port: u16,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        truncated: bool,
        plain_on_wire: bool,
    ) {
        self.http_events(
            c, scheme, method, host, port, path, headers, body, truncated,
        );
        if plain_on_wire {
            let mut text = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
            for (n, v) in headers {
                text.push_str(&format!("{n}: {v}\r\n"));
            }
            text.push_str("\r\n");
            let mut bytes = text.into_bytes();
            bytes.extend(body);
            self.send(c, &bytes);
            self.reply(c, b"HTTP/1.1 503 Service Unavailable\r\n\r\n");
        } else {
            self.send(c, OPAQUE);
            self.reply(c, OPAQUE_REPLY);
        }
    }

    pub fn tcp_event(&mut self, c: Conn, data: &[u8]) {
        let seq = self.next_seq();
        self.mitm_lines.push((
            c.id,
            json!({"event":"tcp","seq":seq,"conn":c.id,"data_b64":b64(data)}).to_string(),
        ));
    }

    /// Client data right after what this connection has already sent.
    pub fn send(&mut self, c: Conn, bytes: &[u8]) {
        let offset = self.sent.get(&(c.id, false)).copied().unwrap_or(0);
        self.wire_data(c, &[(offset, bytes)]);
        self.sent
            .insert((c.id, false), offset + u32::try_from(bytes.len()).unwrap());
    }

    /// Recorder-to-client data right after what it has already sent on this connection.
    pub fn reply(&mut self, c: Conn, bytes: &[u8]) {
        let offset = self.sent.get(&(c.id, true)).copied().unwrap_or(0);
        self.lo(
            6,
            tcp_ack(
                8080,
                c.port,
                900_000_000 + c.client_isn + 1 + offset,
                c.client_isn + 1 + self.sent.get(&(c.id, false)).copied().unwrap_or(0),
                PSH_ACK,
                bytes,
            ),
        );
        self.sent
            .insert((c.id, true), offset + u32::try_from(bytes.len()).unwrap());
    }

    /// Client data on the wire as (offset, bytes) segments, in the order given.
    pub fn wire_data(&mut self, c: Conn, segments: &[(u32, &[u8])]) {
        for (offset, bytes) in segments {
            let heard = self.sent.get(&(c.id, true)).copied().unwrap_or(0);
            self.lo(
                6,
                tcp_ack(
                    c.port,
                    8080,
                    c.client_isn + 1 + offset,
                    900_000_000 + c.client_isn + 1 + heard,
                    PSH_ACK,
                    bytes,
                ),
            );
        }
    }

    pub fn sink_udp(&mut self, dst: &str, port: u16, payload: &[u8]) {
        let dst: [u8; 4] = dst.parse::<std::net::Ipv4Addr>().unwrap().octets();
        let l4 = udp(51_000, port, payload);
        self.frames.push(Frame {
            ifindex: SINK,
            ptype: OUT_TYPE,
            ethertype: 0x0800,
            body: ipv4([198, 18, 255, 1], dst, 17, &l4),
        });
    }

    pub fn sink_tcp_syn(&mut self, dst: &str, port: u16) {
        let l4 = tcp(52_000, port, 1, SYN, b"");
        let (ethertype, body) = match dst.parse::<IpAddr>().unwrap() {
            IpAddr::V4(a) => (0x0800, ipv4([198, 18, 255, 1], a.octets(), 6, &l4)),
            IpAddr::V6(a) => (0x86DD, ipv6(v6("fd67:6465:6772::1"), a.octets(), 6, &l4)),
        };
        self.frames.push(Frame {
            ifindex: SINK,
            ptype: OUT_TYPE,
            ethertype,
            body,
        });
    }

    /// A UDP packet on loopback, as the capture shows it (host type), to any port.
    pub fn raw_lo_udp(&mut self, sport: u16, dport: u16, payload: &[u8]) {
        self.lo(17, udp(sport, dport, payload));
    }

    /// The same, with the IPv4 "more fragments" flag set.
    pub fn fragment(&mut self, sport: u16, dport: u16, payload: &[u8]) {
        self.lo_frag(17, 0x2000, udp(sport, dport, payload));
    }

    /// TCP payload sent to the recorder's port with no handshake before it.
    pub fn raw_lo_tcp_recorder(&mut self, client_port: u16, bytes: &[u8]) {
        self.lo(6, tcp(client_port, 8080, 1, PSH_ACK, bytes));
    }

    /// A DNS-over-TCP stream to the resolver with its handshake, so only its framing is in question.
    pub fn lo_tcp_dns_stream(&mut self, client_port: u16, bytes: &[u8]) {
        self.lo(6, tcp(client_port, 5353, 0, SYN, b""));
        self.lo(6, tcp(client_port, 5353, 1, PSH_ACK, bytes));
    }

    pub fn raw_mitm_line(&mut self, line: &str) {
        self.mitm_lines.push((0, line.to_string()));
    }

    /// Reverses and rotates the line-based sources (order must not matter).
    pub fn reorder_lines(&mut self, rotate: usize) {
        self.dns_lines.reverse();
        let n = self.dns_lines.len().max(1);
        self.dns_lines.rotate_left(rotate % n);
        self.mitm_lines.reverse();
        let n = self.mitm_lines.len().max(1);
        self.mitm_lines.rotate_left(rotate % n);
    }

    /// Reverses and rotates whole connections' lines, keeping the order of lines inside each
    /// connection (the order of a connection's events is part of what the judge reads).
    pub fn reorder_conns(&mut self, rotate: usize) {
        self.dns_lines.reverse();
        let n = self.dns_lines.len().max(1);
        self.dns_lines.rotate_left(rotate % n);
        let mut ids: Vec<u64> = self.mitm_lines.iter().map(|l| l.0).collect();
        ids.sort_unstable();
        ids.dedup();
        ids.reverse();
        let n = ids.len().max(1);
        ids.rotate_left(rotate % n);
        let old = std::mem::take(&mut self.mitm_lines);
        for id in ids {
            self.mitm_lines
                .extend(old.iter().filter(|l| l.0 == id).cloned());
        }
    }

    pub fn mitm_text(&self) -> String {
        let mut text =
            String::from("{\"gd_capture\":1,\"tool\":\"mitmproxy\",\"tool_version\":\"12.3.1\"}\n");
        for (_, line) in &self.mitm_lines {
            text.push_str(line);
            text.push('\n');
        }
        if self.end {
            text.push_str("{\"conn\":0,\"event\":\"end\"}\n");
        }
        text
    }

    /// The scenario with the post control (and the end marker) added.
    fn finished(&self) -> Scenario {
        let mut s = self.clone();
        let cut = s.frames.len();
        if let Some(opts) = s.post {
            let c = s.control("post", opts);
            if let Some(seq) = s.post_extra_seq {
                s.force_seq = Some(seq);
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
            }
        }
        if s.cut_post_pcap {
            s.frames.truncate(cut);
        }
        s
    }

    fn pcap_frames(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for f in &self.frames {
            out.push(sll2(f.ifindex, f.ethertype, f.ptype, &f.body));
            if self.lo_duplicate_outgoing && f.ifindex == LO {
                out.push(sll2(f.ifindex, f.ethertype, OUT_TYPE, &f.body));
            }
        }
        out
    }

    pub fn write(&self) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let s = self.finished();
        let dir = std::env::temp_dir().join(format!(
            "gd-egress-test-{}-{}-{unique}",
            self.name,
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("mitm")).unwrap();
        fs::create_dir_all(dir.join("pcap")).unwrap();
        fs::write(dir.join("dns.log"), s.dns_lines.join("\n") + "\n").unwrap();
        fs::write(dir.join("mitm/capture.jsonl"), s.mitm_text()).unwrap();
        fs::write(
            dir.join("pcap/all.pcap"),
            pcap_file(Order::Little, false, s.link_type, &s.pcap_frames()),
        )
        .unwrap();
        fs::write(dir.join("pcap/links.txt"), &s.links).unwrap();
        let written = s.pcap_frames().len();
        fs::write(
            dir.join("pcap/tcpdump.log"),
            format!(
                "{written} packets captured\n{} packets received by filter\n{} packets dropped by kernel\n",
                written as u64 + s.kernel_drops,
                s.kernel_drops
            ),
        )
        .unwrap();
        fs::write(dir.join("pcap/rules.txt"), &s.rules).unwrap();
        dir
    }

    /// Writes the capture and judges it with this scenario's allowlist.
    pub fn report(&self) -> String {
        let dir = self.write();
        let allow = Allowlist::parse(&self.allowlist).unwrap();
        let verdict = judge(
            &RawCapture::load(&dir),
            &self.set,
            &allow,
            &expected_rules(),
        );
        let _ = fs::remove_dir_all(&dir);
        verdict.report
    }

    /// Like [`Scenario::report`], under explicit bounds.
    pub fn report_with(&self, limits: gd_egress::verdict::Limits) -> String {
        let dir = self.write();
        let allow = Allowlist::parse(&self.allowlist).unwrap();
        let verdict = gd_egress::verdict::judge_with_limits(
            &RawCapture::load(&dir),
            &self.set,
            &allow,
            &expected_rules(),
            limits,
        );
        let _ = fs::remove_dir_all(&dir);
        verdict.report
    }

    pub fn canary(&self, class: Class) -> String {
        self.set.text(class).to_string()
    }

    /// The raw bytes of a canary (the macaroon's, the key behind an nsec, and so on).
    pub fn canary_bytes(&self, class: Class) -> Vec<u8> {
        self.set.get(class).and_then(|c| c.bytes.clone()).unwrap()
    }
}

/// Bytes that look like TLS records; they contain no canary.
pub const OPAQUE: &[u8] = &[
    0x17, 0x03, 0x03, 0x00, 0x10, 0x9a, 0x01, 0x5c, 0xe2, 0x44, 0x71, 0x0b, 0x3d, 0xa8, 0x60, 0x12,
    0xee, 0x35, 0x90, 0x4f, 0x21,
];
pub const OPAQUE_REPLY: &[u8] = &[
    0x17, 0x03, 0x03, 0x00, 0x08, 0x41, 0xd2, 0x07, 0x99, 0x6e, 0xb1, 0x23, 0x5a,
];
