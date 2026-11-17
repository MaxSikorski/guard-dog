//! The kernel's view: a packet capture taken on every interface (`tcpdump -i any
//! -y LINUX_SLL2`). Hand-written reader for pcap, SLL2, IPv4/IPv6, TCP, UDP and
//! DNS names, with TCP stream reassembly. It never panics on bad input: every
//! problem is a short code.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The recorder's port (TCP redirects land here).
pub const RECORDER_PORT: u16 = 8080;
/// The resolver's port (DNS redirects land here).
pub const RESOLVER_PORT: u16 = 5353;
const LINKTYPE_SLL2: u32 = 276;
const SLL2_HEADER: usize = 20;
const OUTGOING: u8 = 4;
const HOST: u8 = 0;

/// Transport layer of a packet.
// The field names are the protocol's own (ports, sequence number, flags, payload).
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L4 {
    /// TCP, with its flags (`0x02` SYN, `0x10` ACK) and sequence number.
    Tcp {
        sport: u16,
        dport: u16,
        seq: u32,
        flags: u8,
        payload: Vec<u8>,
    },
    /// UDP.
    Udp {
        sport: u16,
        dport: u16,
        payload: Vec<u8>,
    },
    /// ICMP (`v6` for ICMPv6).
    Icmp { v6: bool, payload: Vec<u8> },
    /// Anything else: an IP protocol (`0x2f`) or a non-IP ethertype (`0x0806`).
    Other { label: String, payload: Vec<u8> },
}

/// One captured outgoing packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Position in the capture file (all records counted), for order checks.
    pub index: usize,
    /// SLL2 packet type: 0 host (read on `lo`), 4 outgoing (read on the sink).
    pub pkt_type: u8,
    /// Interface index (names come from `links.txt`).
    pub ifindex: u32,
    /// Source and destination; `None` for a non-IP packet.
    pub ip: Option<(IpAddr, IpAddr)>,
    /// The transport layer.
    pub l4: L4,
}

/// The parsed capture file.
#[derive(Debug, Clone, Default)]
pub struct PcapParse {
    /// Outgoing packets, in file order.
    pub packets: Vec<Packet>,
    /// Problem codes: `bad-header`, `link-type`, `truncated`, `bad-packet`.
    pub errors: BTreeSet<&'static str>,
}

fn be16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(o..o + 2)?.try_into().ok()?))
}

fn be32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

/// Parses one SLL2 frame. `Ok(None)` means "not an outgoing packet, skip it".
fn parse_frame(frame: &[u8], index: usize) -> Result<Option<Packet>, &'static str> {
    let bad = "bad-packet";
    let ethertype = be16(frame, 0).ok_or(bad)?;
    let ifindex = be32(frame, 4).ok_or(bad)?;
    let pkt_type = *frame.get(10).ok_or(bad)?;
    if pkt_type != OUTGOING && pkt_type != HOST {
        return Ok(None);
    }
    let rest = frame.get(SLL2_HEADER..).ok_or(bad)?;
    let (src, dst, proto, l4) = match ethertype {
        0x0800 => {
            let first = *rest.first().ok_or(bad)?;
            let ihl = usize::from(first & 15) * 4;
            let total = usize::from(be16(rest, 2).ok_or(bad)?);
            let header = rest.get(..ihl).filter(|_| ihl >= 20).ok_or(bad)?;
            let src: [u8; 4] = header
                .get(12..16)
                .and_then(|s| s.try_into().ok())
                .ok_or(bad)?;
            let dst: [u8; 4] = header
                .get(16..20)
                .and_then(|s| s.try_into().ok())
                .ok_or(bad)?;
            if be16(rest, 6).ok_or(bad)? & 0x3fff != 0 {
                return Err("fragment");
            }
            let end = total.clamp(ihl, rest.len());
            let proto = *header.get(9).ok_or(bad)?;
            (
                IpAddr::V4(Ipv4Addr::from(src)),
                IpAddr::V4(Ipv4Addr::from(dst)),
                proto,
                rest.get(ihl..end).ok_or(bad)?,
            )
        }
        0x86DD => {
            let src: [u8; 16] = rest.get(8..24).and_then(|s| s.try_into().ok()).ok_or(bad)?;
            let dst: [u8; 16] = rest
                .get(24..40)
                .and_then(|s| s.try_into().ok())
                .ok_or(bad)?;
            let mut next = *rest.get(6).ok_or(bad)?;
            let mut offset = 40usize;
            while matches!(next, 0 | 43 | 44 | 60) {
                if next == 44 {
                    return Err("fragment");
                }
                let this = rest.get(offset..).ok_or(bad)?;
                let following = *this.first().ok_or(bad)?;
                let len = if next == 44 {
                    8
                } else {
                    (usize::from(*this.get(1).ok_or(bad)?) + 1) * 8
                };
                next = following;
                offset += len;
            }
            (
                IpAddr::V6(Ipv6Addr::from(src)),
                IpAddr::V6(Ipv6Addr::from(dst)),
                next,
                rest.get(offset..).ok_or(bad)?,
            )
        }
        other => {
            return Ok(Some(Packet {
                index,
                pkt_type,
                ifindex,
                ip: None,
                l4: L4::Other {
                    label: format!("0x{other:04x}"),
                    payload: rest.to_vec(),
                },
            }));
        }
    };
    let l4 = match proto {
        6 => {
            let offset = usize::from(l4.get(12).ok_or(bad)? >> 4) * 4;
            let payload = l4
                .get(offset..)
                .filter(|_| offset >= 20)
                .ok_or(bad)?
                .to_vec();
            L4::Tcp {
                sport: be16(l4, 0).ok_or(bad)?,
                dport: be16(l4, 2).ok_or(bad)?,
                seq: be32(l4, 4).ok_or(bad)?,
                flags: *l4.get(13).ok_or(bad)?,
                payload,
            }
        }
        17 => L4::Udp {
            sport: be16(l4, 0).ok_or(bad)?,
            dport: be16(l4, 2).ok_or(bad)?,
            payload: l4.get(8..).ok_or(bad)?.to_vec(),
        },
        1 | 58 => L4::Icmp {
            v6: proto == 58,
            payload: l4.to_vec(),
        },
        other => L4::Other {
            label: format!("0x{other:02x}"),
            payload: l4.to_vec(),
        },
    };
    Ok(Some(Packet {
        index,
        pkt_type,
        ifindex,
        ip: Some((src, dst)),
        l4,
    }))
}

/// Parses a pcap file (either byte order, microsecond or nanosecond stamps).
pub fn parse(bytes: &[u8]) -> PcapParse {
    let mut out = PcapParse::default();
    let Some(header) = bytes.get(..24) else {
        out.errors.insert("truncated");
        return out;
    };
    let magic: [u8; 4] = header
        .get(..4)
        .and_then(|m| m.try_into().ok())
        .unwrap_or_default();
    let little = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => false,
        _ => {
            out.errors.insert("bad-header");
            return out;
        }
    };
    let u16_at = |o: usize| {
        header
            .get(o..o + 2)
            .and_then(|s| s.try_into().ok())
            .map(|a: [u8; 2]| {
                if little {
                    u16::from_le_bytes(a)
                } else {
                    u16::from_be_bytes(a)
                }
            })
    };
    let u32_of = |s: &[u8]| {
        s.try_into().ok().map(|a: [u8; 4]| {
            if little {
                u32::from_le_bytes(a)
            } else {
                u32::from_be_bytes(a)
            }
        })
    };
    if (u16_at(4), u16_at(6)) != (Some(2), Some(4)) {
        out.errors.insert("bad-header");
        return out;
    }
    if header.get(20..24).and_then(u32_of) != Some(LINKTYPE_SLL2) {
        out.errors.insert("link-type");
        return out;
    }
    let mut at = 24usize;
    let mut index = 0usize;
    while at < bytes.len() {
        let record = bytes
            .get(at..at + 16)
            .and_then(|r| Some((u32_of(r.get(8..12)?)?, u32_of(r.get(12..16)?)?)));
        let Some((caplen, len)) = record else {
            out.errors.insert("truncated");
            break;
        };
        let data = usize::try_from(caplen)
            .ok()
            .and_then(|n| bytes.get(at + 16..at + 16 + n));
        let Some(data) = data.filter(|_| caplen >= len) else {
            out.errors.insert("truncated");
            break;
        };
        index += 1;
        match parse_frame(data, index - 1) {
            Ok(Some(packet)) => out.packets.push(packet),
            Ok(None) => {}
            Err(code) => {
                out.errors.insert(code);
            }
        }
        at += 16 + data.len();
    }
    out
}

/// Interface names by index, from `ip -o link` output. `None` if a line does not parse.
pub fn parse_links(text: &str) -> Option<BTreeMap<u32, String>> {
    let mut map = BTreeMap::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let mut parts = line.splitn(3, ": ");
        let index = parts.next()?.trim().parse::<u32>().ok()?;
        let name = parts.next()?.split('@').next()?.trim();
        if name.is_empty() {
            return None;
        }
        map.insert(index, name.to_string());
    }
    Some(map)
}

/// A DNS message's id, direction and questions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    /// The transaction id.
    pub id: u16,
    /// True for a response.
    pub response: bool,
    /// Every question: the dotted lowercase name and the query type number.
    pub questions: Vec<(String, u16)>,
    /// A query with an answer, authority or non-OPT additional record (`dns-unexpected-section`).
    /// The questions are still read, so the names are still judged.
    pub unexpected_section: bool,
}

/// The CoreDNS spelling of a query type number (`A`, `AAAA`, ..., or `TYPE<n>`).
pub fn qtype_name(qtype: u16) -> String {
    match qtype {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        255 => "ANY".into(),
        other => format!("TYPE{other}"),
    }
}

/// Reads a DNS message: the 12-byte header and every question. A compression
/// pointer in a question or a cut-off message is `dns-framing`. A *query* with
/// any answer or authority record, or with an additional record other than one
/// OPT, is `dns-unexpected-section`: those are places a secret could hide.
pub fn parse_dns(payload: &[u8]) -> Result<DnsMessage, &'static str> {
    let framing = "dns-framing";
    let id = be16(payload, 0).ok_or(framing)?;
    let flags = be16(payload, 2).ok_or(framing)?;
    let counts: Vec<u16> = (4..12)
        .step_by(2)
        .map(|o| be16(payload, o).ok_or(framing))
        .collect::<Result<_, _>>()?;
    let (qd, an, ns, ar) = match counts.as_slice() {
        [a, b, c, d] => (*a, *b, *c, *d),
        _ => return Err(framing),
    };
    let mut at = 12usize;
    let mut questions = Vec::new();
    for _ in 0..qd {
        let mut labels: Vec<String> = Vec::new();
        loop {
            let len = usize::from(*payload.get(at).ok_or(framing)?);
            at += 1;
            if len == 0 {
                break;
            }
            if len > 63 {
                return Err(framing);
            }
            let label = payload.get(at..at + len).ok_or(framing)?;
            labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
            at += len;
        }
        let qtype = be16(payload, at).ok_or(framing)?;
        at += 4;
        if at > payload.len() {
            return Err(framing);
        }
        questions.push((labels.join("."), qtype));
    }
    let response = flags & 0x8000 != 0;
    let mut unexpected_section = false;
    if !response {
        unexpected_section = an != 0 || ns != 0 || ar > 1;
        if ar == 1 && !unexpected_section {
            let first = *payload.get(at).ok_or(framing)?;
            let type_at = match first {
                0 => Some(at + 1),
                b if b & 0xC0 == 0xC0 => Some(at + 2),
                _ => None,
            };
            unexpected_section = match type_at {
                Some(t) => be16(payload, t).ok_or(framing)? != 41,
                None => true,
            };
        }
    }
    Ok(DnsMessage {
        id,
        response,
        questions,
        unexpected_section,
    })
}

/// A reassembled one-way TCP stream.
#[derive(Debug, Clone, Default)]
pub struct Stream {
    /// Source port (the client's, for client-to-recorder streams).
    pub sport: u16,
    /// Destination port.
    pub dport: u16,
    /// The bytes, in order, with nothing invented for a gap.
    pub data: Vec<u8>,
    /// Retransmissions whose bytes differ from what was first seen. Scanned too.
    pub conflicts: Vec<Vec<u8>>,
}

#[derive(Default)]
struct Building {
    sport: u16,
    dport: u16,
    isn: Option<u32>,
    segments: Vec<(u32, Vec<u8>)>,
}

impl Building {
    /// Puts the segments in order. A hole in the sequence numbers is `tcp-gap`;
    /// a retransmission that disagrees with earlier bytes is `tcp-overlap-conflict`.
    fn finish(self) -> (Stream, BTreeSet<&'static str>) {
        let mut errors = BTreeSet::new();
        let base = self.isn.map_or_else(
            || self.segments.iter().map(|s| s.0).min().unwrap_or(0),
            |isn| isn.wrapping_add(1),
        );
        let mut segments: Vec<(u64, Vec<u8>)> = self
            .segments
            .into_iter()
            .map(|(seq, d)| (u64::from(seq.wrapping_sub(base)), d))
            .collect();
        segments.sort_by_key(|s| s.0);
        let (mut data, mut end, mut skipped) = (Vec::new(), 0u64, 0u64);
        let mut conflicts = Vec::new();
        for (rel, chunk) in segments {
            let len = u64::try_from(chunk.len()).unwrap_or(0);
            if rel > end {
                errors.insert("tcp-gap");
                skipped += rel - end;
                data.extend_from_slice(&chunk);
                end = rel + len;
                continue;
            }
            let overlap = usize::try_from(end - rel).unwrap_or(0).min(chunk.len());
            let start = usize::try_from(rel - skipped).unwrap_or(0);
            let have = data.get(start..start + overlap);
            if have != chunk.get(..overlap) {
                errors.insert("tcp-overlap-conflict");
                conflicts.push(chunk.clone());
            }
            if rel + len > end {
                data.extend_from_slice(chunk.get(overlap..).unwrap_or(&[]));
                end = rel + len;
            }
        }
        (
            Stream {
                sport: self.sport,
                dport: self.dport,
                data,
                conflicts,
            },
            errors,
        )
    }
}

/// One DNS question seen on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireQuestion {
    /// The client's port.
    pub client_port: u16,
    /// The DNS transaction id.
    pub id: u16,
    /// `udp` or `tcp`.
    pub proto: &'static str,
    /// The dotted lowercase name.
    pub name: String,
    /// The query type number.
    pub qtype: u16,
}

/// A client packet sent to the recorder or the resolver on the loopback interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoClient {
    /// Position in the capture file.
    pub index: usize,
    /// The client's source port.
    pub sport: u16,
    /// True when sent to the recorder (port 8080); false for the resolver (5353).
    pub to_recorder: bool,
    /// For a UDP DNS query: the names it asks about.
    pub names: Vec<String>,
}

/// What the packet capture says happened on the loopback and black-hole interfaces.
#[derive(Debug, Clone, Default)]
pub struct Wire {
    /// Client-to-recorder TCP streams (destination port 8080).
    pub recorder_streams: Vec<Stream>,
    /// Recorder-to-client TCP streams (source port 8080); `dport` is the client's port.
    pub server_streams: Vec<Stream>,
    /// Raw DNS payloads sent to the resolver (UDP datagrams and TCP messages).
    pub dns_payloads: Vec<Vec<u8>>,
    /// Every DNS question sent to the resolver.
    pub dns_questions: Vec<WireQuestion>,
    /// Client packets to the recorder or resolver, in capture order.
    pub lo_client: Vec<LoClient>,
    /// Queries that also got a response (distinct client port and id). Details only.
    pub answered_dns: usize,
    /// Completed handshakes: distinct SYN-ACKs from the recorder.
    pub handshakes: usize,
    /// Every packet that went out on the black-hole interface.
    pub sink: Vec<Packet>,
    /// Loopback packets that were neither to nor from the recorder or resolver.
    pub ignored_loopback: usize,
    /// Records of another packet type than the one read on their interface.
    pub ignored_types: usize,
    /// Problem codes.
    pub errors: BTreeSet<&'static str>,
}

fn tcp_messages(stream: &[u8]) -> Result<Vec<&[u8]>, &'static str> {
    let mut out = Vec::new();
    let mut rest = stream;
    while !rest.is_empty() {
        let len = usize::from(be16(rest, 0).ok_or("dns-framing")?);
        let body = rest.get(2..2 + len).ok_or("dns-framing")?;
        out.push(body);
        rest = rest.get(2 + len..).unwrap_or(&[]);
    }
    Ok(out)
}

fn done(building: Building, wire: &mut Wire) -> Stream {
    let (stream, errors) = building.finish();
    wire.errors.extend(errors);
    stream
}

/// Sorts packets by interface and rebuilds streams and DNS exchanges.
/// Loopback is read from host-type records (libpcap hides the outgoing copy
/// there); the black hole from outgoing ones.
pub fn analyze(packets: &[Packet], links: &BTreeMap<u32, String>) -> Wire {
    let mut wire = Wire::default();
    let mut building: BTreeMap<(IpAddr, u16, IpAddr, u16), Building> = BTreeMap::new();
    let mut finished: Vec<Stream> = Vec::new();
    let mut syn_acks: BTreeSet<(IpAddr, u16, u32)> = BTreeSet::new();
    let mut responses: BTreeSet<(u16, u16)> = BTreeSet::new();
    let mut queries: BTreeSet<(u16, u16)> = BTreeSet::new();
    let mut udp_dns: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut dns_streams: Vec<(bool, Stream)> = Vec::new();
    let is_sink_port = |p: u16| p == RECORDER_PORT || p == RESOLVER_PORT;

    for packet in packets {
        match links.get(&packet.ifindex).map(String::as_str) {
            Some("gdsink0") if packet.pkt_type == OUTGOING => {
                wire.sink.push(packet.clone());
                continue;
            }
            Some("lo") if packet.pkt_type == HOST => {}
            Some("gdsink0" | "lo") => {
                wire.ignored_types += 1;
                continue;
            }
            _ => {
                wire.errors.insert("unknown-interface");
                continue;
            }
        }
        let (Some((src, dst)), l4) = (packet.ip, &packet.l4) else {
            wire.ignored_loopback += 1;
            continue;
        };
        match l4 {
            L4::Tcp {
                sport,
                dport,
                seq,
                flags,
                payload,
            } if is_sink_port(*sport) || is_sink_port(*dport) => {
                if is_sink_port(*dport) {
                    wire.lo_client.push(LoClient {
                        index: packet.index,
                        sport: *sport,
                        to_recorder: *dport == RECORDER_PORT,
                        names: Vec::new(),
                    });
                }
                let key = (src, *sport, dst, *dport);
                let syn = flags & 0x02 != 0;
                if syn {
                    if let Some(old) = building.remove(&key) {
                        finished.push(done(old, &mut wire));
                    }
                    building.insert(
                        key,
                        Building {
                            sport: *sport,
                            dport: *dport,
                            isn: Some(*seq),
                            segments: Vec::new(),
                        },
                    );
                    if flags & 0x10 != 0 && *sport == RECORDER_PORT {
                        syn_acks.insert((dst, *dport, *seq));
                    }
                }
                if !payload.is_empty() {
                    let entry = building.entry(key).or_insert_with(|| Building {
                        sport: *sport,
                        dport: *dport,
                        ..Building::default()
                    });
                    entry.segments.push((*seq, payload.clone()));
                }
            }
            L4::Udp {
                sport,
                dport,
                payload,
            } if *dport == RESOLVER_PORT => {
                let names = parse_dns(payload)
                    .map(|m| m.questions.into_iter().map(|q| q.0).collect())
                    .unwrap_or_default();
                wire.lo_client.push(LoClient {
                    index: packet.index,
                    sport: *sport,
                    to_recorder: false,
                    names,
                });
                udp_dns.push((*sport, payload.clone()));
            }
            L4::Udp {
                sport,
                dport,
                payload,
            } if *sport == RESOLVER_PORT => match parse_dns(payload) {
                Ok(message) => {
                    responses.insert((*dport, message.id));
                }
                Err(code) => {
                    wire.errors.insert(code);
                }
            },
            _ => wire.ignored_loopback += 1,
        }
    }
    wire.handshakes = syn_acks.len();
    for b in building.into_values() {
        let stream = done(b, &mut wire);
        finished.push(stream);
    }

    for stream in finished {
        if stream.dport == RECORDER_PORT {
            wire.recorder_streams.push(stream);
        } else if stream.sport == RECORDER_PORT {
            wire.server_streams.push(stream);
        } else if stream.dport == RESOLVER_PORT {
            dns_streams.push((true, stream));
        } else if stream.sport == RESOLVER_PORT {
            dns_streams.push((false, stream));
        }
    }
    let mut note = |wire: &mut Wire, client: u16, payload: &[u8], from_client: bool, proto| {
        if parse_dns(payload).is_ok_and(|m| m.unexpected_section) {
            wire.errors.insert("dns-unexpected-section");
        }
        match parse_dns(payload) {
            Ok(m) if from_client && !m.response => {
                queries.insert((client, m.id));
                for (name, qtype) in m.questions {
                    wire.dns_questions.push(WireQuestion {
                        client_port: client,
                        id: m.id,
                        proto,
                        name,
                        qtype,
                    });
                }
            }
            Ok(m) if !from_client && m.response => {
                responses.insert((client, m.id));
            }
            Ok(_) => {}
            Err(code) => {
                wire.errors.insert(code);
            }
        }
    };
    for (client, payload) in &udp_dns {
        wire.dns_payloads.push(payload.clone());
        note(&mut wire, *client, payload, true, "udp");
    }
    for (from_client, stream) in &dns_streams {
        let client = if *from_client {
            stream.sport
        } else {
            stream.dport
        };
        match tcp_messages(&stream.data) {
            Ok(messages) => {
                for message in messages {
                    if *from_client {
                        wire.dns_payloads.push(message.to_vec());
                    }
                    note(&mut wire, client, message, *from_client, "tcp");
                }
            }
            Err(code) => {
                wire.errors.insert(code);
            }
        }
        if *from_client {
            wire.dns_payloads.push(stream.data.clone());
            wire.dns_payloads.extend(stream.conflicts.iter().cloned());
        }
    }
    wire.answered_dns = queries.intersection(&responses).count();
    wire.recorder_streams
        .sort_by(|a, b| (a.sport, &a.data).cmp(&(b.sport, &b.data)));
    wire.server_streams
        .sort_by(|a, b| (a.dport, &a.data).cmp(&(b.dport, &b.data)));
    wire
}
