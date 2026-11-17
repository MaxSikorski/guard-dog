//! `allowlist.toml`: every place Guard Dog may connect to on its own.
//!
//! Format version 1: exact lowercase DNS names and exact ports. No wildcards,
//! no IP addresses. Anything else is an error with its own name, so a bad
//! entry is rejected loudly and never half-read.

use std::collections::BTreeSet;
use toml::Value;

/// Why an allowlist was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowlistError {
    /// The file is not valid TOML.
    NotToml,
    /// A top-level key other than `format` and `destination`.
    UnknownTopLevelKey,
    /// No `format` key.
    MissingFormat,
    /// `format` is not the integer 1.
    UnsupportedFormat,
    /// `destination` is not an array of tables.
    DestinationShape,
    /// A key in an entry other than `host`, `ports`, `why`, `phase`.
    UnknownEntryKey,
    /// A required key is missing (the name is given).
    MissingKey(&'static str),
    /// A key has the wrong type (the name is given).
    WrongType(&'static str),
    /// The host contains `*`.
    Wildcard,
    /// The host is an IPv4 address.
    Ipv4Literal,
    /// The host is an IPv6 address.
    Ipv6Literal,
    /// The host has an upper-case letter.
    Uppercase,
    /// The host ends with a dot.
    TrailingDot,
    /// The host has fewer than two labels.
    SingleLabel,
    /// A label is empty, over 63 characters, or has a character outside letters, digits and `-`.
    BadLabel,
    /// A label is longer than 63 characters.
    LabelTooLong,
    /// The host is longer than 253 characters.
    HostTooLong,
    /// `ports` is empty.
    EmptyPorts,
    /// A port is not between 1 and 65535.
    PortOutOfRange,
    /// Ports are not strictly increasing (out of order).
    PortsNotSorted,
    /// The same port appears twice.
    DuplicatePort,
    /// `why` or `phase` is empty.
    EmptyText(&'static str),
    /// The same host is listed twice.
    DuplicateHost,
}

/// One listed destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    /// The exact lowercase host name.
    pub host: String,
    /// The allowed ports, strictly increasing.
    pub ports: Vec<u16>,
    /// Plain-English reason.
    pub why: String,
    /// The plan phase that needs it.
    pub phase: String,
}

/// A parsed allowlist.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allowlist {
    /// The entries, in file order.
    pub destinations: Vec<Destination>,
}

fn check_host(host: &str) -> Result<(), AllowlistError> {
    use AllowlistError as E;
    if host.contains('*') {
        return Err(E::Wildcard);
    }
    if host.contains(':') {
        return Err(E::Ipv6Literal);
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return Err(E::Ipv4Literal);
    }
    if host.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(E::Uppercase);
    }
    if host.ends_with('.') {
        return Err(E::TrailingDot);
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.iter().any(|l| l.len() > 63) {
        return Err(E::LabelTooLong);
    }
    let ldh = |l: &&str| {
        !l.is_empty()
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if !labels.iter().all(ldh) {
        return Err(E::BadLabel);
    }
    if labels.len() < 2 {
        return Err(E::SingleLabel);
    }
    if host.len() > 253 {
        return Err(E::HostTooLong);
    }
    Ok(())
}

fn text_key(entry: &toml::Table, key: &'static str) -> Result<String, AllowlistError> {
    match entry.get(key) {
        None => Err(AllowlistError::MissingKey(key)),
        Some(Value::String(s)) if s.trim().is_empty() => Err(AllowlistError::EmptyText(key)),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(_) => Err(AllowlistError::WrongType(key)),
    }
}

fn parse_ports(value: Option<&Value>) -> Result<Vec<u16>, AllowlistError> {
    use AllowlistError as E;
    let Some(Value::Array(items)) = value else {
        return Err(if value.is_none() {
            E::MissingKey("ports")
        } else {
            E::WrongType("ports")
        });
    };
    if items.is_empty() {
        return Err(E::EmptyPorts);
    }
    let mut ports: Vec<u16> = Vec::new();
    for item in items {
        let Value::Integer(n) = item else {
            return Err(E::WrongType("ports"));
        };
        let port = u16::try_from(*n)
            .ok()
            .filter(|p| *p >= 1)
            .ok_or(E::PortOutOfRange)?;
        match ports.last() {
            Some(&last) if last == port => return Err(E::DuplicatePort),
            Some(&last) if last > port => return Err(E::PortsNotSorted),
            _ => ports.push(port),
        }
    }
    Ok(ports)
}

impl Allowlist {
    /// Reads and checks an `allowlist.toml`.
    pub fn parse(text: &str) -> Result<Allowlist, AllowlistError> {
        use AllowlistError as E;
        let table: toml::Table = text.parse().map_err(|_| E::NotToml)?;
        if table.keys().any(|k| k != "format" && k != "destination") {
            return Err(E::UnknownTopLevelKey);
        }
        match table.get("format") {
            None => return Err(E::MissingFormat),
            Some(Value::Integer(1)) => {}
            Some(_) => return Err(E::UnsupportedFormat),
        }
        let entries = match table.get("destination") {
            None => &Vec::new(),
            Some(Value::Array(items)) => items,
            Some(_) => return Err(E::DestinationShape),
        };
        let mut destinations = Vec::new();
        let mut seen = BTreeSet::new();
        for item in entries {
            let Value::Table(entry) = item else {
                return Err(E::DestinationShape);
            };
            if entry
                .keys()
                .any(|k| !matches!(k.as_str(), "host" | "ports" | "why" | "phase"))
            {
                return Err(E::UnknownEntryKey);
            }
            let host = text_key(entry, "host")?;
            check_host(&host)?;
            let ports = parse_ports(entry.get("ports"))?;
            let why = text_key(entry, "why")?;
            let phase = text_key(entry, "phase")?;
            if !seen.insert(host.clone()) {
                return Err(E::DuplicateHost);
            }
            destinations.push(Destination {
                host,
                ports,
                why,
                phase,
            });
        }
        Ok(Allowlist { destinations })
    }

    /// Whether a DNS name is listed. Case and a trailing dot are ignored.
    pub fn host_listed(&self, name: &str) -> bool {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        self.destinations.iter().any(|d| d.host == name)
    }

    /// Whether `host` on `port` is listed. IP addresses never match.
    pub fn listed(&self, host: &str, port: u16) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.destinations
            .iter()
            .any(|d| d.host == host && d.ports.contains(&port))
    }
}
