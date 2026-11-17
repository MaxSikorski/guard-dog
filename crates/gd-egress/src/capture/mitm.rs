//! The recorder's log: one JSON object per line, written by the mitmproxy
//! addon. Every string that came from a client is base64, so nothing hostile
//! sits unescaped in the file. Unknown events or keys are errors, never ignored.

use crate::encode::base64_decode;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

/// One HTTP request the recorder answered with a 503.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HttpEvent {
    /// `http` or `https`.
    pub scheme: String,
    /// Lowercased host.
    pub host: String,
    /// Destination port.
    pub port: u16,
    /// Request path, raw bytes.
    pub path: Vec<u8>,
    /// Header names and values, raw bytes.
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    /// Request body.
    pub body: Vec<u8>,
}

/// One connection the recorder accepted.
#[derive(Debug, Clone, Default)]
pub struct Conn {
    /// Connection number, from 1.
    pub id: u64,
    /// The client's source port (how the packet capture is matched to it).
    pub client_port: u16,
    /// The address the client was really trying to reach.
    pub dst_ip: String,
    /// The port it was trying to reach.
    pub dst_port: u16,
    /// The TLS handshake, if one was seen: (server name, completed).
    pub tls: Option<(Option<Vec<u8>>, bool)>,
    /// HTTP requests, sorted.
    pub http: Vec<HttpEvent>,
    /// Raw client-to-server data.
    pub tcp: Vec<Vec<u8>>,
}

/// The parsed recorder log.
#[derive(Debug, Clone, Default)]
pub struct MitmLog {
    /// Connections by number.
    pub conns: BTreeMap<u64, Conn>,
    /// Problem codes found.
    pub errors: BTreeSet<&'static str>,
}

type Fail = &'static str;

fn b64(obj: &Map<String, Value>, key: &str) -> Result<Vec<u8>, Fail> {
    obj.get(key)
        .and_then(Value::as_str)
        .and_then(base64_decode)
        .ok_or("bad-line")
}

fn port(obj: &Map<String, Value>, key: &str) -> Result<u16, Fail> {
    obj.get(key)
        .and_then(Value::as_u64)
        .and_then(|n| u16::try_from(n).ok())
        .ok_or("bad-line")
}

fn flag(obj: &Map<String, Value>, key: &str) -> Result<bool, Fail> {
    obj.get(key).and_then(Value::as_bool).ok_or("bad-line")
}

fn exact_keys(obj: &Map<String, Value>, allowed: &[&str]) -> Result<(), Fail> {
    if obj
        .keys()
        .any(|k| k != "event" && k != "conn" && !allowed.contains(&k.as_str()))
    {
        return Err("unknown-key");
    }
    if allowed.iter().any(|k| !obj.contains_key(*k)) {
        return Err("bad-line");
    }
    Ok(())
}

enum Event {
    Connect {
        client_port: u16,
        dst_ip: String,
        dst_port: u16,
    },
    Tls {
        sni: Option<Vec<u8>>,
        ok: bool,
    },
    Http {
        event: HttpEvent,
        truncated: bool,
    },
    Tcp(Vec<u8>),
    Marker,
}

fn parse_event(obj: &Map<String, Value>, name: &str) -> Result<Event, Fail> {
    match name {
        "connect" => {
            exact_keys(obj, &["client_port", "dst_ip", "dst_port"])?;
            let dst_ip = obj
                .get("dst_ip")
                .and_then(Value::as_str)
                .ok_or("bad-line")?;
            dst_ip.parse::<IpAddr>().map_err(|_| "bad-line")?;
            Ok(Event::Connect {
                client_port: port(obj, "client_port")?,
                dst_ip: dst_ip.to_string(),
                dst_port: port(obj, "dst_port")?,
            })
        }
        "tls" => {
            exact_keys(obj, &["sni_b64", "ok"])?;
            let sni = match obj.get("sni_b64") {
                Some(Value::Null) => None,
                _ => Some(b64(obj, "sni_b64")?),
            };
            Ok(Event::Tls {
                sni,
                ok: flag(obj, "ok")?,
            })
        }
        "http" => {
            exact_keys(
                obj,
                &[
                    "scheme",
                    "method_b64",
                    "host_b64",
                    "port",
                    "path_b64",
                    "headers",
                    "body_b64",
                    "body_truncated",
                ],
            )?;
            let scheme = obj
                .get("scheme")
                .and_then(Value::as_str)
                .filter(|s| matches!(*s, "http" | "https"))
                .ok_or("bad-line")?;
            b64(obj, "method_b64")?;
            let mut headers = Vec::new();
            for pair in obj
                .get("headers")
                .and_then(Value::as_array)
                .ok_or("bad-line")?
            {
                let pair = pair.as_array().filter(|p| p.len() == 2).ok_or("bad-line")?;
                let decode = |v: Option<&Value>| {
                    v.and_then(Value::as_str)
                        .and_then(base64_decode)
                        .ok_or("bad-line")
                };
                headers.push((decode(pair.first())?, decode(pair.get(1))?));
            }
            let event = HttpEvent {
                scheme: scheme.to_string(),
                host: String::from_utf8_lossy(&b64(obj, "host_b64")?).to_ascii_lowercase(),
                port: port(obj, "port")?,
                path: b64(obj, "path_b64")?,
                headers,
                body: b64(obj, "body_b64")?,
            };
            Ok(Event::Http {
                event,
                truncated: flag(obj, "body_truncated")?,
            })
        }
        "tcp" => {
            exact_keys(obj, &["data_b64"])?;
            Ok(Event::Tcp(b64(obj, "data_b64")?))
        }
        "upstream_blocked" | "close" => {
            exact_keys(obj, &[])?;
            Ok(Event::Marker)
        }
        _ => Err("unknown-event"),
    }
}

fn header_ok(line: &str) -> bool {
    let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(line) else {
        return false;
    };
    obj.len() == 3
        && obj.get("gd_capture") == Some(&Value::from(1))
        && obj.get("tool") == Some(&Value::from("mitmproxy"))
        && obj.get("tool_version").is_some_and(Value::is_string)
}

/// Parses a recorder log. Lines may come in any order after the header.
pub fn parse(bytes: &[u8]) -> MitmLog {
    let text = String::from_utf8_lossy(bytes);
    let mut log = MitmLog::default();
    let mut lines = text.lines();
    if !lines.next().is_some_and(header_ok) {
        log.errors.insert("bad-header");
    }
    let mut events: Vec<(u64, Event)> = Vec::new();
    for line in lines {
        let result = serde_json::from_str::<Value>(line)
            .ok()
            .and_then(|v| match v {
                Value::Object(o) => Some(o),
                _ => None,
            })
            .ok_or("bad-line")
            .and_then(|obj| {
                let conn = obj
                    .get("conn")
                    .and_then(Value::as_u64)
                    .filter(|c| *c >= 1)
                    .ok_or("bad-line")?;
                let name = obj.get("event").and_then(Value::as_str).ok_or("bad-line")?;
                Ok((conn, parse_event(&obj, name)?))
            });
        match result {
            Ok(pair) => events.push(pair),
            Err(code) => {
                log.errors.insert(code);
            }
        }
    }
    for (id, event) in &events {
        if let Event::Connect {
            client_port,
            dst_ip,
            dst_port,
        } = event
        {
            let conn = Conn {
                id: *id,
                client_port: *client_port,
                dst_ip: dst_ip.clone(),
                dst_port: *dst_port,
                ..Conn::default()
            };
            if log.conns.insert(*id, conn).is_some() {
                log.errors.insert("bad-line");
            }
        }
    }
    for (id, event) in events {
        let Some(conn) = log.conns.get_mut(&id) else {
            log.errors.insert("bad-line");
            continue;
        };
        match event {
            Event::Connect { .. } | Event::Marker => {}
            Event::Tls { sni, ok } => {
                if conn.tls.replace((sni, ok)).is_some() {
                    log.errors.insert("bad-line");
                }
            }
            Event::Http { event, truncated } => {
                if truncated {
                    log.errors.insert("body-truncated");
                }
                conn.http.push(event);
            }
            Event::Tcp(data) => conn.tcp.push(data),
        }
    }
    for conn in log.conns.values_mut() {
        conn.http.sort();
        conn.tcp.sort();
    }
    log
}
