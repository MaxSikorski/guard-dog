//! Builds synthetic captures for the tests: the five capture files, a pcap
//! writer, and a "control" that every healthy capture contains. Nothing here
//! is a real capture; the pcap writer lives only in test code.

#![allow(dead_code)]

use data_encoding::BASE64;
use gd_egress::allowlist::Allowlist;
use gd_egress::canary::{CanarySet, Class, generate};
use gd_egress::capture::RawCapture;
use gd_egress::verdict::judge;
use serde_json::{Value, json};
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;

pub const LO: u32 = 1;
pub const SINK: u32 = 2;
pub const SYN: u8 = 0x02;
pub const SYN_ACK: u8 = 0x12;
pub const PSH_ACK: u8 = 0x18;

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
    let mut p = vec![0x45, 0];
    p.extend(u16::try_from(20 + l4.len()).unwrap().to_be_bytes());
    p.extend([0, 0, 0, 0, 64, proto, 0, 0]);
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
    let mut t = Vec::new();
    t.extend(sport.to_be_bytes());
    t.extend(dport.to_be_bytes());
    t.extend(seq.to_be_bytes());
    t.extend([0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
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

// ---- the scenario builder -----------------------------------------------------

#[derive(Clone, Copy)]
pub struct Conn {
    pub id: u64,
    pub port: u16,
    pub client_isn: u32,
}

pub struct Scenario {
    pub name: String,
    pub set: CanarySet,
    pub dns_lines: Vec<String>,
    pub mitm_lines: Vec<String>,
    pub frames: Vec<Vec<u8>>,
    pub link_type: u32,
    pub rules: String,
    pub links: String,
    pub allowlist: String,
    next_conn: u64,
    next_dns_id: u16,
    next_dns_port: u16,
}

pub const EMPTY_ALLOWLIST: &str = "format = 1\n";

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
            next_conn: 1,
            next_dns_id: 100,
            next_dns_port: 50_000,
        }
    }

    /// A healthy capture: the control's three DNS queries, HTTPS request and blocked UDP packet.
    pub fn new(name: &str, seed: u64) -> Scenario {
        let mut s = Scenario::bare(name, seed);
        s.control(true, false);
        s
    }

    pub fn control_name(&self) -> String {
        format!(
            "control-{}.gd-egress-control.invalid",
            self.set.control_token
        )
    }

    pub fn control(&mut self, with_http: bool, truncated: bool) {
        let name = self.control_name();
        for qtype in ["A", "A", "AAAA"] {
            self.dns_query_typed(&name, qtype);
        }
        let c = self.connect("198.18.0.1", 443);
        self.tls(c, Some(&name), true);
        if with_http {
            let path = format!("/control/{}", self.set.control_token);
            self.http(
                c,
                "https",
                "GET",
                &name,
                443,
                &path,
                &[],
                b"",
                truncated,
                false,
            );
        }
        let marker = format!("gd-egress-control {}\n", self.set.control_token);
        self.sink_udp("198.18.0.99", 9, marker.as_bytes());
    }

    pub fn dns_query(&mut self, name: &str) {
        self.dns_query_typed(name, "A");
    }

    pub fn dns_query_typed(&mut self, name: &str, qtype: &str) {
        self.dns_lines
            .push(format!("[INFO] GDQ {qtype} IN {name}. udp NOERROR"));
        self.wire_dns(name, true);
    }

    /// A DNS query on the wire, optionally answered; no resolver log line.
    pub fn wire_dns(&mut self, name: &str, answered: bool) {
        let (id, port) = (self.next_dns_id, self.next_dns_port);
        self.next_dns_id += 1;
        self.next_dns_port += 1;
        let mut q = Vec::new();
        q.extend(id.to_be_bytes());
        q.extend([0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        for label in name.split('.') {
            q.push(u8::try_from(label.len()).unwrap());
            q.extend(label.as_bytes());
        }
        q.extend([0, 0, 1, 0, 1]);
        self.lo(tcp_or_udp(port, 5353, &q));
        if answered {
            let mut r = q.clone();
            r[2] = 0x81;
            r[3] = 0x80;
            self.lo(udp_reply(5353, port, &r));
        }
    }

    fn lo(&mut self, l4_udp_or_tcp: (u8, Vec<u8>)) {
        let (proto, l4) = l4_udp_or_tcp;
        self.frames.push(sll2(
            LO,
            0x0800,
            4,
            &ipv4([127, 0, 0, 1], [127, 0, 0, 1], proto, &l4),
        ));
    }

    pub fn connect(&mut self, dst_ip: &str, dst_port: u16) -> Conn {
        let id = self.next_conn;
        self.next_conn += 1;
        let port = 40_000 + u16::try_from(id).unwrap();
        let client_isn = 1_000 * u32::try_from(id).unwrap();
        self.mitm_lines.push(
            json!({"event":"connect","conn":id,"client_port":port,"dst_ip":dst_ip,"dst_port":dst_port}).to_string(),
        );
        self.lo((6, tcp(port, 8080, client_isn, SYN, b"")));
        self.lo((6, tcp(8080, port, 900_000 + client_isn, SYN_ACK, b"")));
        Conn {
            id,
            port,
            client_isn,
        }
    }

    /// A SYN-ACK from the recorder that has no `connect` event.
    pub fn extra_syn_ack(&mut self) {
        self.lo((6, tcp(8080, 59_999, 777_777, SYN_ACK, b"")));
    }

    pub fn tls(&mut self, c: Conn, sni: Option<&str>, ok: bool) {
        let sni = sni.map_or(Value::Null, |s| Value::String(b64(s.as_bytes())));
        self.mitm_lines
            .push(json!({"event":"tls","conn":c.id,"sni_b64":sni,"ok":ok}).to_string());
    }

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
        let pairs: Vec<Value> = headers
            .iter()
            .map(|(n, v)| json!([b64(n.as_bytes()), b64(v.as_bytes())]))
            .collect();
        self.mitm_lines.push(
            json!({"event":"http","conn":c.id,"scheme":scheme,"method_b64":b64(method.as_bytes()),"host_b64":b64(host.as_bytes()),
                   "port":port,"path_b64":b64(path.as_bytes()),"headers":pairs,"body_b64":b64(body),"body_truncated":truncated})
            .to_string(),
        );
        let wire: Vec<u8> = if plain_on_wire {
            let mut text = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
            for (n, v) in headers {
                text.push_str(&format!("{n}: {v}\r\n"));
            }
            text.push_str("\r\n");
            let mut bytes = text.into_bytes();
            bytes.extend(body);
            bytes
        } else {
            vec![
                0x17, 0x03, 0x03, 0x00, 0x10, 0x9a, 0x01, 0x5c, 0xe2, 0x44, 0x71, 0x0b, 0x3d, 0xa8,
                0x60, 0x12, 0xee, 0x35, 0x90, 0x4f, 0x21,
            ]
        };
        self.wire_data(c, &[(0, &wire)]);
    }

    pub fn tcp_event(&mut self, c: Conn, data: &[u8]) {
        self.mitm_lines
            .push(json!({"event":"tcp","conn":c.id,"data_b64":b64(data)}).to_string());
    }

    /// Client data on the wire as (offset, bytes) segments, in the order given.
    pub fn wire_data(&mut self, c: Conn, segments: &[(u32, &[u8])]) {
        for (offset, bytes) in segments {
            self.lo((
                6,
                tcp(c.port, 8080, c.client_isn + 1 + offset, PSH_ACK, bytes),
            ));
        }
    }

    pub fn sink_udp(&mut self, dst: &str, port: u16, payload: &[u8]) {
        let dst: [u8; 4] = dst.parse::<std::net::Ipv4Addr>().unwrap().octets();
        let l4 = udp(51_000, port, payload);
        self.frames.push(sll2(
            SINK,
            0x0800,
            4,
            &ipv4([198, 18, 255, 1], dst, 17, &l4),
        ));
    }

    pub fn sink_tcp_syn(&mut self, dst: &str, port: u16) {
        let l4 = tcp(52_000, port, 1, SYN, b"");
        let frame = match dst.parse::<IpAddr>().unwrap() {
            IpAddr::V4(a) => sll2(
                SINK,
                0x0800,
                4,
                &ipv4([198, 18, 255, 1], a.octets(), 6, &l4),
            ),
            IpAddr::V6(a) => sll2(
                SINK,
                0x86DD,
                4,
                &ipv6(v6("fd67:6465:6772::1"), a.octets(), 6, &l4),
            ),
        };
        self.frames.push(frame);
    }

    pub fn raw_mitm_line(&mut self, line: &str) {
        self.mitm_lines.push(line.to_string());
    }

    /// Reverses and rotates the line-based sources (order must not matter).
    pub fn reorder_lines(&mut self, rotate: usize) {
        for lines in [&mut self.dns_lines, &mut self.mitm_lines] {
            lines.reverse();
            let n = lines.len().max(1);
            lines.rotate_left(rotate % n);
        }
    }

    pub fn mitm_text(&self) -> String {
        let mut text =
            String::from("{\"gd_capture\":1,\"tool\":\"mitmproxy\",\"tool_version\":\"12.3.1\"}\n");
        for line in &self.mitm_lines {
            text.push_str(line);
            text.push('\n');
        }
        text
    }

    pub fn write(&self) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "gd-egress-test-{}-{}-{unique}",
            self.name,
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("mitm")).unwrap();
        fs::create_dir_all(dir.join("pcap")).unwrap();
        fs::write(dir.join("dns.log"), self.dns_lines.join("\n") + "\n").unwrap();
        fs::write(dir.join("mitm/capture.jsonl"), self.mitm_text()).unwrap();
        fs::write(
            dir.join("pcap/all.pcap"),
            pcap_file(Order::Little, false, self.link_type, &self.frames),
        )
        .unwrap();
        fs::write(dir.join("pcap/links.txt"), &self.links).unwrap();
        fs::write(dir.join("pcap/rules.txt"), &self.rules).unwrap();
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

    pub fn canary(&self, class: Class) -> String {
        self.set.text(class).to_string()
    }
}

fn tcp_or_udp(sport: u16, dport: u16, payload: &[u8]) -> (u8, Vec<u8>) {
    (17, udp(sport, dport, payload))
}

fn udp_reply(sport: u16, dport: u16, payload: &[u8]) -> (u8, Vec<u8>) {
    (17, udp(sport, dport, payload))
}
